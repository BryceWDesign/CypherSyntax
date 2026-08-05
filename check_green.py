from __future__ import annotations

import ast
import base64
import csv
from email.parser import Parser
import hashlib
import importlib.util
import io
import os
from pathlib import Path, PurePosixPath
import subprocess
import sys
import tempfile
import zipfile


REPOSITORY_ROOT = Path(__file__).resolve().parent
MINIMUM_PYTHON = (3, 10)
PACKAGE_NAME = "CypherSyntax"
PACKAGE_VERSION = "0.1.0"
EXPECTED_RUNTIME_DEPENDENCY = "cryptography>=46.0.0"
EXPECTED_README_MARKER = (
    "CypherSyntax is a compact authenticated secure-messaging core for Python."
)
EXPECTED_PACKAGE_FILES = frozenset(
    {
        "cyphersyntax/__init__.py",
        "cyphersyntax/errors.py",
        "cyphersyntax/handshake.py",
        "cyphersyntax/identity.py",
        "cyphersyntax/kdf.py",
        "cyphersyntax/persistence.py",
        "cyphersyntax/protocol.py",
        "cyphersyntax/py.typed",
        "cyphersyntax/replay.py",
        "cyphersyntax/session.py",
        "cyphersyntax/store.py",
        "cyphersyntax/wire.py",
    }
)
REQUIRED_MODULES = (
    "coverage",
    "cryptography",
    "pytest",
    "pytest_cov",
    "setuptools",
)


class GreenCheckError(RuntimeError):
    """Raised when the repository cannot complete its local quality gate."""


def _format_command(command: list[str]) -> str:
    return subprocess.list2cmdline(command)


def _run(
    label: str,
    command: list[str],
    *,
    cwd: Path = REPOSITORY_ROOT,
    env: dict[str, str] | None = None,
) -> None:
    print(f"\n=== {label} ===", flush=True)
    print(f"> {_format_command(command)}", flush=True)
    completed = subprocess.run(
        command,
        cwd=cwd,
        env=env,
        check=False,
    )
    if completed.returncode != 0:
        raise GreenCheckError(
            f"{label} failed with exit code {completed.returncode}: "
            f"{_format_command(command)}"
        )


def _check_environment() -> None:
    print("=== Environment ===", flush=True)
    print(f"Python: {sys.version.split()[0]}", flush=True)
    print(f"Repository: {REPOSITORY_ROOT}", flush=True)

    if sys.version_info < MINIMUM_PYTHON:
        required = ".".join(str(part) for part in MINIMUM_PYTHON)
        raise GreenCheckError(f"Python {required} or newer is required")

    missing = [
        name for name in REQUIRED_MODULES if importlib.util.find_spec(name) is None
    ]
    if missing:
        formatted = ", ".join(sorted(missing))
        raise GreenCheckError(
            f"missing development dependencies: {formatted}. "
            "Install the project with: python -m pip install -e .[dev]"
        )


def _validate_python_310_grammar() -> None:
    print("\n=== Validate Python 3.10 grammar compatibility ===", flush=True)
    paths = sorted((REPOSITORY_ROOT / "src").rglob("*.py"))
    paths.extend(sorted((REPOSITORY_ROOT / "tests").rglob("*.py")))
    paths.extend(
        REPOSITORY_ROOT / name
        for name in (
            "check_green.py",
            "check_source_quality.py",
            "demo.py",
        )
    )
    for path in paths:
        try:
            source = path.read_text(encoding="utf-8", errors="strict")
            ast.parse(
                source,
                filename=str(path),
                type_comments=True,
                feature_version=(3, 10),
            )
        except (OSError, UnicodeError, SyntaxError) as exc:
            relative = path.relative_to(REPOSITORY_ROOT).as_posix()
            raise GreenCheckError(
                f"Python 3.10 grammar validation failed for {relative}: {exc}"
            ) from exc
    print(f"Python 3.10 grammar validation passed ({len(paths)} files)", flush=True)


def _safe_wheel_member(name: str) -> bool:
    path = PurePosixPath(name)
    return (
        bool(name)
        and not name.startswith(("/", "\\"))
        and "\\" not in name
        and ".." not in path.parts
    )


def _record_digest(data: bytes) -> str:
    digest = hashlib.sha256(data).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _validate_wheel(wheel_path: Path) -> None:
    print("\n=== Validate wheel contents and metadata ===", flush=True)
    print(f"> {wheel_path.name}", flush=True)

    try:
        with zipfile.ZipFile(wheel_path) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos if not info.is_dir()]
            if len(names) != len(set(names)):
                raise GreenCheckError("wheel contains duplicate archive members")
            unsafe = sorted(name for name in names if not _safe_wheel_member(name))
            if unsafe:
                raise GreenCheckError(
                    f"wheel contains unsafe archive members: {', '.join(unsafe)}"
                )

            name_set = set(names)
            missing_package_files = sorted(EXPECTED_PACKAGE_FILES - name_set)
            if missing_package_files:
                raise GreenCheckError(
                    "wheel is missing package files: "
                    f"{', '.join(missing_package_files)}"
                )

            packaged_python = {
                name
                for name in name_set
                if name.startswith("cyphersyntax/") and name.endswith(".py")
            }
            expected_python = {
                name for name in EXPECTED_PACKAGE_FILES if name.endswith(".py")
            }
            unexpected_python = sorted(packaged_python - expected_python)
            if unexpected_python:
                raise GreenCheckError(
                    "wheel contains unexpected package modules: "
                    f"{', '.join(unexpected_python)}"
                )

            forbidden = sorted(
                name
                for name in name_set
                if name.startswith("tests/")
                or "__pycache__" in name
                or name.endswith((".pyc", ".pem", ".bin", ".coverage"))
            )
            if forbidden:
                raise GreenCheckError(
                    f"wheel contains forbidden files: {', '.join(forbidden)}"
                )

            metadata_names = sorted(
                name for name in name_set if name.endswith(".dist-info/METADATA")
            )
            wheel_names = sorted(
                name for name in name_set if name.endswith(".dist-info/WHEEL")
            )
            record_names = sorted(
                name for name in name_set if name.endswith(".dist-info/RECORD")
            )
            license_names = sorted(
                name
                for name in name_set
                if name.endswith(".dist-info/licenses/LICENSE")
            )
            if not (
                len(metadata_names)
                == len(wheel_names)
                == len(record_names)
                == len(license_names)
                == 1
            ):
                raise GreenCheckError(
                    "wheel must contain exactly one METADATA, WHEEL, RECORD, "
                    "and LICENSE file"
                )
            repository_license = (REPOSITORY_ROOT / "LICENSE").read_bytes()
            if archive.read(license_names[0]) != repository_license:
                raise GreenCheckError("wheel license does not match repository LICENSE")

            metadata = Parser().parsestr(
                archive.read(metadata_names[0]).decode("utf-8", errors="strict")
            )
            if metadata["Name"] != PACKAGE_NAME:
                raise GreenCheckError("wheel metadata contains an unexpected name")
            if metadata["Version"] != PACKAGE_VERSION:
                raise GreenCheckError("wheel metadata contains an unexpected version")
            if metadata["Requires-Python"] != ">=3.10":
                raise GreenCheckError(
                    "wheel metadata contains an unexpected Python requirement"
                )
            if metadata["Description-Content-Type"] != "text/markdown":
                raise GreenCheckError("wheel metadata is missing Markdown README metadata")
            if EXPECTED_README_MARKER not in metadata.get_payload():
                raise GreenCheckError("wheel metadata is missing the repository README")
            runtime_dependencies = metadata.get_all("Requires-Dist", failobj=[])
            direct_runtime_dependencies = [
                dependency
                for dependency in runtime_dependencies
                if "; extra ==" not in dependency
            ]
            if direct_runtime_dependencies != [EXPECTED_RUNTIME_DEPENDENCY]:
                raise GreenCheckError(
                    "wheel metadata contains unexpected runtime dependencies: "
                    f"{direct_runtime_dependencies!r}"
                )

            wheel_metadata = Parser().parsestr(
                archive.read(wheel_names[0]).decode("utf-8", errors="strict")
            )
            if wheel_metadata["Root-Is-Purelib"] != "true":
                raise GreenCheckError("wheel must be platform-independent pure Python")

            record_rows = list(
                csv.reader(
                    io.StringIO(
                        archive.read(record_names[0]).decode(
                            "utf-8",
                            errors="strict",
                        )
                    )
                )
            )
            if any(len(row) != 3 for row in record_rows):
                raise GreenCheckError("wheel RECORD contains malformed rows")
            record_paths = [row[0] for row in record_rows]
            if len(record_paths) != len(set(record_paths)):
                raise GreenCheckError("wheel RECORD contains duplicate paths")
            if set(record_paths) != name_set:
                raise GreenCheckError("wheel RECORD does not match archive contents")

            for path, digest_field, size_field in record_rows:
                if path == record_names[0]:
                    if digest_field or size_field:
                        raise GreenCheckError(
                            "wheel RECORD entry for RECORD must omit hash and size"
                        )
                    continue
                if not digest_field.startswith("sha256="):
                    raise GreenCheckError(
                        f"wheel RECORD entry lacks a SHA-256 digest: {path}"
                    )
                data = archive.read(path)
                if digest_field != f"sha256={_record_digest(data)}":
                    raise GreenCheckError(
                        f"wheel RECORD digest does not match archive member: {path}"
                    )
                if size_field != str(len(data)):
                    raise GreenCheckError(
                        f"wheel RECORD size does not match archive member: {path}"
                    )
    except (OSError, UnicodeError, zipfile.BadZipFile) as exc:
        raise GreenCheckError(f"failed to validate wheel: {exc}") from exc


def _build_and_validate_wheel() -> None:
    with tempfile.TemporaryDirectory(prefix="cyphersyntax-green-") as temporary:
        temporary_root = Path(temporary)
        wheel_directory = temporary_root / "wheel"
        install_directory = temporary_root / "installed"
        smoke_directory = temporary_root / "smoke"
        wheel_directory.mkdir()
        install_directory.mkdir()
        smoke_directory.mkdir()

        _run(
            "Build wheel",
            [
                sys.executable,
                "-m",
                "pip",
                "wheel",
                "--disable-pip-version-check",
                "--no-deps",
                "--no-build-isolation",
                "--wheel-dir",
                str(wheel_directory),
                ".",
            ],
        )

        wheels = sorted(wheel_directory.glob("*.whl"))
        if len(wheels) != 1:
            raise GreenCheckError(
                f"expected exactly one wheel artifact, found {len(wheels)}"
            )
        _validate_wheel(wheels[0])

        _run(
            "Install wheel into isolated target",
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                "--no-deps",
                "--no-compile",
                "--target",
                str(install_directory),
                str(wheels[0]),
            ],
        )

        smoke_code = "\n".join(
            (
                "from pathlib import Path",
                "import os",
                "import cyphersyntax",
                "from cyphersyntax import (",
                "    AeadSuite,",
                "    HandshakeConfirmation,",
                "    HandshakeOffer,",
                "    HandshakeResponse,",
                "    Identity,",
                "    SessionFactory,",
                ")",
                "install_root = Path(os.environ['CYPHERSYNTAX_INSTALL_ROOT']).resolve()",
                "module_path = Path(cyphersyntax.__file__).resolve()",
                "if install_root not in module_path.parents:",
                "    raise RuntimeError(",
                "        f'package imported outside isolated target: {module_path}'",
                "    )",
                "marker_path = module_path.with_name('py.typed')",
                "if not marker_path.is_file():",
                "    raise RuntimeError('installed wheel is missing the PEP 561 marker')",
                "if cyphersyntax.__version__ != '0.1.0':",
                "    raise RuntimeError('installed wheel reports an unexpected version')",
                "alice = Identity.generate('alice')",
                "bob = Identity.generate('bob')",
                "pending_alice = SessionFactory.initiator(",
                "    local_identity=alice,",
                "    remote_name=bob.name,",
                "    remote_signing_public_key=bob.ed25519_public_bytes(),",
                "    suite=AeadSuite.AES_GCM_SIV,",
                ")",
                "received_offer = HandshakeOffer.from_bytes(",
                "    pending_alice.offer.to_bytes()",
                ")",
                "response, pending_bob = SessionFactory.responder(",
                "    local_identity=bob,",
                "    remote_signing_public_key=alice.ed25519_public_bytes(),",
                "    offer=received_offer,",
                ")",
                "received_response = HandshakeResponse.from_bytes(",
                "    response.to_bytes()",
                ")",
                "confirmation, alice_session = pending_alice.complete(",
                "    received_response",
                ")",
                "received_confirmation = HandshakeConfirmation.from_bytes(",
                "    confirmation.to_bytes()",
                ")",
                "bob_session = pending_bob.complete(received_confirmation)",
                "packet = alice_session.encrypt(b'installed-wheel-smoke-test')",
                "if bob_session.decrypt(packet) != b'installed-wheel-smoke-test':",
                "    raise RuntimeError(",
                "        'installed wheel failed encryption round trip'",
                "    )",
            )
        )
        smoke_environment = os.environ.copy()
        smoke_environment["CYPHERSYNTAX_INSTALL_ROOT"] = str(install_directory)
        existing_pythonpath = smoke_environment.get("PYTHONPATH")
        smoke_environment["PYTHONPATH"] = os.pathsep.join(
            part
            for part in (str(install_directory), existing_pythonpath)
            if part
        )

        _run(
            "Smoke-test installed wheel",
            [sys.executable, "-c", smoke_code],
            cwd=smoke_directory,
            env=smoke_environment,
        )


def main() -> int:
    try:
        _check_environment()
        _run(
            "Compile all Python sources",
            [
                sys.executable,
                "-m",
                "compileall",
                "-q",
                "-f",
                "src",
                "tests",
                "demo.py",
                "check_green.py",
                "check_source_quality.py",
            ],
        )
        _validate_python_310_grammar()
        _run(
            "Run repository-native static source assurance",
            [sys.executable, "check_source_quality.py"],
        )
        _run("Run strict test and coverage gate", [sys.executable, "-m", "pytest"])
        source_environment = os.environ.copy()
        existing_pythonpath = source_environment.get("PYTHONPATH")
        source_environment["PYTHONPATH"] = os.pathsep.join(
            part
            for part in (str(REPOSITORY_ROOT / "src"), existing_pythonpath)
            if part
        )
        _run(
            "Run source-tree demo",
            [sys.executable, "demo.py"],
            env=source_environment,
        )
        _build_and_validate_wheel()
    except GreenCheckError as exc:
        print(f"\nGREEN CHECK FAILED: {exc}", file=sys.stderr, flush=True)
        return 1

    print("\nGREEN CHECK PASSED", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
