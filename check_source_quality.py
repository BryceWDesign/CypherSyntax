from __future__ import annotations

import ast
from dataclasses import dataclass
from pathlib import Path
import sys
import tokenize
from typing import Iterable


REPOSITORY_ROOT = Path(__file__).resolve().parent
PACKAGE_ROOT = REPOSITORY_ROOT / "src" / "cyphersyntax"
MAX_LINE_LENGTH = 100
FORBIDDEN_COMMENT_MARKERS = ("todo", "fixme", "xxx", "placeholder")
FORBIDDEN_IMPORT_ROOTS = frozenset(
    {
        "cloudpickle",
        "dill",
        "marshal",
        "pickle",
        "shelve",
    }
)
FORBIDDEN_CALLS = frozenset(
    {
        "__import__",
        "breakpoint",
        "compile",
        "eval",
        "exec",
    }
)
MUTABLE_DEFAULT_CALLS = frozenset({"dict", "list", "set"})


@dataclass(frozen=True, order=True, slots=True)
class QualityViolation:
    path: str
    line: int
    code: str
    message: str

    def render(self) -> str:
        return f"{self.path}:{self.line}: {self.code} {self.message}"


def _relative_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(REPOSITORY_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def _violation(path: Path, line: int, code: str, message: str) -> QualityViolation:
    return QualityViolation(
        path=_relative_path(path),
        line=line,
        code=code,
        message=message,
    )


def _check_text(path: Path, text: str) -> list[QualityViolation]:
    violations: list[QualityViolation] = []
    if text and not text.endswith("\n"):
        violations.append(
            _violation(path, max(1, len(text.splitlines())), "TXT001", "missing final newline")
        )

    for line_number, line in enumerate(text.splitlines(), start=1):
        if "\t" in line:
            violations.append(
                _violation(path, line_number, "TXT002", "tab character is not permitted")
            )
        if line.rstrip() != line:
            violations.append(
                _violation(path, line_number, "TXT003", "trailing whitespace")
            )
        if len(line) > MAX_LINE_LENGTH:
            violations.append(
                _violation(
                    path,
                    line_number,
                    "TXT004",
                    f"line exceeds {MAX_LINE_LENGTH} characters",
                )
            )

    try:
        tokens = tokenize.generate_tokens(iter(text.splitlines(keepends=True)).__next__)
        for token in tokens:
            if token.type != tokenize.COMMENT:
                continue
            normalized = token.string.casefold()
            for marker in FORBIDDEN_COMMENT_MARKERS:
                if marker in normalized:
                    violations.append(
                        _violation(
                            path,
                            token.start[0],
                            "TXT005",
                            f"forbidden unfinished-work marker: {marker}",
                        )
                    )
    except (IndentationError, tokenize.TokenError) as exc:
        line = getattr(exc, "lineno", 1) or 1
        violations.append(
            _violation(path, line, "SYN001", f"tokenization failed: {exc}")
        )
    return violations


def _call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if (
        isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
        and node.func.value.id == "builtins"
    ):
        return node.func.attr
    return None


def _has_mutable_default(node: ast.expr) -> bool:
    if isinstance(
        node,
        (
            ast.Dict,
            ast.DictComp,
            ast.List,
            ast.ListComp,
            ast.Set,
            ast.SetComp,
        ),
    ):
        return True
    return (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id in MUTABLE_DEFAULT_CALLS
    )


def _function_violations(
    path: Path,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> list[QualityViolation]:
    violations: list[QualityViolation] = []
    parameters = [
        *node.args.posonlyargs,
        *node.args.args,
        *node.args.kwonlyargs,
    ]
    for parameter in parameters:
        if parameter.arg in {"self", "cls"}:
            continue
        if parameter.annotation is None:
            violations.append(
                _violation(
                    path,
                    parameter.lineno,
                    "TYP001",
                    f"parameter {parameter.arg!r} is missing a type annotation",
                )
            )
    if node.args.vararg is not None and node.args.vararg.annotation is None:
        violations.append(
            _violation(
                path,
                node.args.vararg.lineno,
                "TYP001",
                f"parameter '*{node.args.vararg.arg}' is missing a type annotation",
            )
        )
    if node.args.kwarg is not None and node.args.kwarg.annotation is None:
        violations.append(
            _violation(
                path,
                node.args.kwarg.lineno,
                "TYP001",
                f"parameter '**{node.args.kwarg.arg}' is missing a type annotation",
            )
        )
    if node.returns is None:
        violations.append(
            _violation(
                path,
                node.lineno,
                "TYP002",
                f"function {node.name!r} is missing a return annotation",
            )
        )

    positional_defaults = node.args.defaults
    keyword_defaults = [default for default in node.args.kw_defaults if default is not None]
    for default in [*positional_defaults, *keyword_defaults]:
        if _has_mutable_default(default):
            violations.append(
                _violation(
                    path,
                    default.lineno,
                    "TYP003",
                    f"function {node.name!r} has a mutable default argument",
                )
            )
    return violations


def _check_ast(path: Path, text: str, *, require_annotations: bool) -> list[QualityViolation]:
    try:
        tree = ast.parse(text, filename=str(path), type_comments=True)
    except SyntaxError as exc:
        return [
            _violation(
                path,
                exc.lineno or 1,
                "SYN002",
                exc.msg,
            )
        ]

    violations: list[QualityViolation] = []
    if require_annotations:
        has_future_annotations = any(
            isinstance(statement, ast.ImportFrom)
            and statement.module == "__future__"
            and any(alias.name == "annotations" for alias in statement.names)
            for statement in tree.body
        )
        if not has_future_annotations:
            violations.append(
                _violation(
                    path,
                    1,
                    "TYP004",
                    "package module must import annotations from __future__",
                )
            )

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.partition(".")[0]
                if root in FORBIDDEN_IMPORT_ROOTS:
                    violations.append(
                        _violation(
                            path,
                            node.lineno,
                            "SEC001",
                            f"forbidden unsafe serialization import: {root}",
                        )
                    )
        elif isinstance(node, ast.ImportFrom):
            if any(alias.name == "*" for alias in node.names):
                violations.append(
                    _violation(path, node.lineno, "IMP001", "wildcard import")
                )
            root = (node.module or "").partition(".")[0]
            if root in FORBIDDEN_IMPORT_ROOTS:
                violations.append(
                    _violation(
                        path,
                        node.lineno,
                        "SEC001",
                        f"forbidden unsafe serialization import: {root}",
                    )
                )
        elif isinstance(node, ast.Call):
            name = _call_name(node)
            if name in FORBIDDEN_CALLS:
                violations.append(
                    _violation(
                        path,
                        node.lineno,
                        "SEC002",
                        f"forbidden dynamic execution call: {name}",
                    )
                )
        elif isinstance(node, ast.Assert):
            violations.append(
                _violation(
                    path,
                    node.lineno,
                    "SEC003",
                    "runtime package code must not use assert",
                )
            )
        elif isinstance(node, ast.ExceptHandler) and node.type is None:
            violations.append(
                _violation(path, node.lineno, "ERR001", "bare except clause")
            )
        elif require_annotations and isinstance(
            node,
            (ast.FunctionDef, ast.AsyncFunctionDef),
        ):
            violations.extend(_function_violations(path, node))
    return violations


def inspect_python_file(
    path: Path,
    *,
    require_annotations: bool,
) -> list[QualityViolation]:
    try:
        text = path.read_text(encoding="utf-8", errors="strict")
    except (OSError, UnicodeError) as exc:
        return [_violation(path, 1, "TXT000", f"failed to read UTF-8 source: {exc}")]
    return [
        *_check_text(path, text),
        *_check_ast(path, text, require_annotations=require_annotations),
    ]


def repository_python_files() -> Iterable[tuple[Path, bool]]:
    for path in sorted(PACKAGE_ROOT.rglob("*.py")):
        yield path, True
    for name in ("check_green.py", "check_source_quality.py", "demo.py"):
        yield REPOSITORY_ROOT / name, False


def collect_repository_violations() -> list[QualityViolation]:
    violations: list[QualityViolation] = []
    for path, require_annotations in repository_python_files():
        if not path.is_file():
            violations.append(
                _violation(path, 1, "REP001", "required Python file is missing")
            )
            continue
        violations.extend(
            inspect_python_file(path, require_annotations=require_annotations)
        )
    return sorted(violations)


def main() -> int:
    violations = collect_repository_violations()
    if violations:
        print("SOURCE QUALITY CHECK FAILED", file=sys.stderr)
        for violation in violations:
            print(violation.render(), file=sys.stderr)
        return 1

    inspected = sum(1 for _ in repository_python_files())
    print(f"SOURCE QUALITY CHECK PASSED ({inspected} files)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
