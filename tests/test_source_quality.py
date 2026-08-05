from __future__ import annotations

from pathlib import Path

from check_source_quality import (
    collect_repository_violations,
    inspect_python_file,
)


def _inspect(tmp_path: Path, source: str, *, typed: bool = True) -> set[str]:
    path = tmp_path / "sample.py"
    path.write_text(source, encoding="utf-8")
    return {
        violation.code
        for violation in inspect_python_file(
            path,
            require_annotations=typed,
        )
    }


def test_current_repository_passes_native_static_assurance():
    assert collect_repository_violations() == []


def test_clean_typed_module_passes(tmp_path):
    source = """from __future__ import annotations


def greet(name: str) -> str:
    return f\"hello {name}\"
"""

    assert _inspect(tmp_path, source) == set()


def test_checker_requires_complete_function_annotations(tmp_path):
    source = """from __future__ import annotations


def incomplete(value):
    return value
"""

    assert _inspect(tmp_path, source) == {"TYP001", "TYP002"}


def test_checker_rejects_mutable_defaults(tmp_path):
    source = """from __future__ import annotations


def collect(values: list[str] = []) -> list[str]:
    return values
"""

    assert "TYP003" in _inspect(tmp_path, source)


def test_checker_rejects_unsafe_execution_and_serialization(tmp_path):
    source = """from __future__ import annotations

import pickle


def execute(source: str) -> object:
    return eval(source)
"""

    assert _inspect(tmp_path, source) == {"SEC001", "SEC002"}


def test_checker_rejects_wildcard_import_bare_except_and_assert(tmp_path):
    source = """from __future__ import annotations

from module import *


def verify(value: bool) -> None:
    try:
        assert value
    except:
        return None
"""

    assert _inspect(tmp_path, source) == {"ERR001", "IMP001", "SEC003"}


def test_checker_rejects_unfinished_markers_and_text_defects(tmp_path):
    source = (
        "from __future__ import annotations\n"
        "\n"
        "# TODO remove this\n"
        "def ready() -> bool:\t\n"
        "    return True"
    )

    assert _inspect(tmp_path, source) == {
        "TXT001",
        "TXT002",
        "TXT003",
        "TXT005",
    }


def test_checker_requires_future_annotations_for_package_modules(tmp_path):
    source = """def ready() -> bool:
    return True
"""

    assert _inspect(tmp_path, source) == {"TYP004"}


def test_checker_can_parse_gate_scripts_without_package_typing_policy(tmp_path):
    source = """def main():
    return 0
"""

    assert _inspect(tmp_path, source, typed=False) == set()
