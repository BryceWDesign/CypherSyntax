from __future__ import annotations

import importlib.util
import os
from pathlib import Path
import subprocess
import sys
import tempfile


REPOSITORY_ROOT = Path(__file__).resolve().parent
MINIMUM_PYTHON = (3, 10)
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

    missing = [name for name in REQUIRED_MODULES if importlib.util.find_spec(name) is None]
    if missing:
        formatted = ", ".join(sorted(missing))
        raise GreenCheckError(
            f"missing development dependencies: {formatted}. "
            "Install the project with: python -m pip install -e .[dev]"
        )


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
                "    raise RuntimeError(f'package imported outside isolated target: {module_path}')",
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
                "received_offer = HandshakeOffer.from_bytes(pending_alice.offer.to_bytes())",
                "response, pending_bob = SessionFactory.responder(",
                "    local_identity=bob,",
                "    remote_signing_public_key=alice.ed25519_public_bytes(),",
                "    offer=received_offer,",
                ")",
                "received_response = HandshakeResponse.from_bytes(response.to_bytes())",
                "confirmation, alice_session = pending_alice.complete(received_response)",
                "received_confirmation = HandshakeConfirmation.from_bytes(confirmation.to_bytes())",
                "bob_session = pending_bob.complete(received_confirmation)",
                "packet = alice_session.encrypt(b'installed-wheel-smoke-test')",
                "if bob_session.decrypt(packet) != b'installed-wheel-smoke-test':",
                "    raise RuntimeError('installed wheel failed encryption round trip')",
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
            ],
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
