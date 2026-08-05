from __future__ import annotations

import os
from pathlib import Path
import tempfile

from .errors import PersistenceError


MIN_PASSPHRASE_BYTES = 16
MAX_PASSPHRASE_BYTES = 1024


def validate_passphrase(passphrase: bytes) -> None:
    if type(passphrase) is not bytes:
        raise TypeError("passphrase must be bytes")
    if len(passphrase) < MIN_PASSPHRASE_BYTES:
        raise ValueError(
            f"passphrase must contain at least {MIN_PASSPHRASE_BYTES} bytes"
        )
    if len(passphrase) > MAX_PASSPHRASE_BYTES:
        raise ValueError(
            f"passphrase must contain at most {MAX_PASSPHRASE_BYTES} bytes"
        )


def _sync_directory(directory: Path) -> None:
    if os.name == "nt":
        return
    descriptor = os.open(directory, os.O_RDONLY)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def atomic_write_bytes(path: Path, data: bytes) -> None:
    if type(data) is not bytes:
        raise TypeError("atomic write data must be bytes")

    destination = Path(path)
    parent = destination.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise PersistenceError(
            f"failed to create persistence directory: {parent}"
        ) from exc

    if destination.is_symlink():
        raise PersistenceError("refusing to replace a symbolic-link destination")

    descriptor = -1
    temporary_path: Path | None = None
    try:
        descriptor, temporary_name = tempfile.mkstemp(
            prefix=f".{destination.name}.",
            suffix=".tmp",
            dir=parent,
        )
        temporary_path = Path(temporary_name)
        try:
            os.fchmod(descriptor, 0o600)
        except (AttributeError, OSError):
            pass

        with os.fdopen(descriptor, "wb") as handle:
            descriptor = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temporary_path, destination)
        temporary_path = None
        try:
            destination.chmod(0o600)
        except OSError:
            pass
        _sync_directory(parent)
    except OSError as exc:
        raise PersistenceError(
            f"failed to atomically write persistence file: {destination}"
        ) from exc
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if temporary_path is not None:
            try:
                temporary_path.unlink()
            except FileNotFoundError:
                pass
            except OSError:
                pass
