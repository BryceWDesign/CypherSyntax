from __future__ import annotations

from collections.abc import Mapping
import json
import os
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from .errors import PersistenceError, StoreError
from .persistence import atomic_write_bytes, validate_passphrase


STORE_MAGIC = b"CypherSyntax/store"
STORE_VERSION = 1
STORE_SALT_BYTES = 16
STORE_NONCE_BYTES = 12
STORE_TAG_BYTES = 16
MAX_STORE_PLAINTEXT_BYTES = 1_048_576
_STORE_HEADER = STORE_MAGIC + bytes((STORE_VERSION,))
_STORE_FIXED_BYTES = len(_STORE_HEADER) + STORE_SALT_BYTES + STORE_NONCE_BYTES
MAX_STORE_FILE_BYTES = _STORE_FIXED_BYTES + MAX_STORE_PLAINTEXT_BYTES + STORE_TAG_BYTES
_STORE_ASSOCIATED_DATA = _STORE_HEADER


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise StoreError(f"duplicate encrypted-store field: {key}")
        result[key] = value
    return result


def _reject_nonfinite_number(value: str) -> None:
    raise StoreError(f"non-finite JSON number is not permitted: {value}")


def _encode_object(obj: Mapping[str, Any]) -> bytes:
    if type(obj) is not dict:
        raise TypeError("encrypted store payload must be a dictionary")
    if any(type(key) is not str for key in obj):
        raise TypeError("encrypted store keys must be strings")
    try:
        encoded = json.dumps(
            obj,
            allow_nan=False,
            ensure_ascii=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeEncodeError) as exc:
        raise StoreError("encrypted store payload is not canonical JSON") from exc
    if len(encoded) > MAX_STORE_PLAINTEXT_BYTES:
        raise StoreError("encrypted store payload exceeds the maximum size")
    return encoded


class EncryptedStore:
    def __init__(self, path: str | Path, passphrase: bytes) -> None:
        validate_passphrase(passphrase)
        self.path = Path(path)
        self._passphrase = passphrase

    def __repr__(self) -> str:
        return f"EncryptedStore(path={self.path!r})"

    def _derive_key(self, salt: bytes) -> bytes:
        if len(salt) != STORE_SALT_BYTES:
            raise StoreError("encrypted store salt has an invalid length")
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        return kdf.derive(self._passphrase)

    def save(self, obj: dict[str, Any]) -> None:
        plaintext = _encode_object(obj)
        salt = os.urandom(STORE_SALT_BYTES)
        nonce = os.urandom(STORE_NONCE_BYTES)
        key = self._derive_key(salt)
        ciphertext = AESGCMSIV(key).encrypt(
            nonce,
            plaintext,
            _STORE_ASSOCIATED_DATA,
        )
        blob = _STORE_HEADER + salt + nonce + ciphertext
        try:
            atomic_write_bytes(self.path, blob)
        except PersistenceError as exc:
            raise StoreError("failed to save encrypted store") from exc

    def load(self) -> dict[str, Any]:
        try:
            blob = self.path.read_bytes()
        except OSError as exc:
            raise StoreError("failed to read encrypted store") from exc

        minimum_size = _STORE_FIXED_BYTES + STORE_TAG_BYTES
        if len(blob) < minimum_size:
            raise StoreError("encrypted store is truncated")
        if len(blob) > MAX_STORE_FILE_BYTES:
            raise StoreError("encrypted store exceeds the maximum file size")
        if not blob.startswith(STORE_MAGIC):
            raise StoreError("encrypted store has an invalid format marker")

        version_offset = len(STORE_MAGIC)
        version = blob[version_offset]
        if version != STORE_VERSION:
            raise StoreError(f"unsupported encrypted store version: {version}")

        salt_start = len(_STORE_HEADER)
        nonce_start = salt_start + STORE_SALT_BYTES
        ciphertext_start = nonce_start + STORE_NONCE_BYTES
        salt = blob[salt_start:nonce_start]
        nonce = blob[nonce_start:ciphertext_start]
        ciphertext = blob[ciphertext_start:]

        key = self._derive_key(salt)
        try:
            plaintext = AESGCMSIV(key).decrypt(
                nonce,
                ciphertext,
                _STORE_ASSOCIATED_DATA,
            )
        except InvalidTag as exc:
            raise StoreError("encrypted store authentication failed") from exc

        if len(plaintext) > MAX_STORE_PLAINTEXT_BYTES:
            raise StoreError("decrypted store payload exceeds the maximum size")
        try:
            raw = json.loads(
                plaintext.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_nonfinite_number,
            )
        except StoreError:
            raise
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
            ValueError,
        ) as exc:
            raise StoreError("decrypted store payload is not valid JSON") from exc

        if type(raw) is not dict:
            raise StoreError("decrypted store payload must be a dictionary")
        if _encode_object(raw) != plaintext:
            raise StoreError("decrypted store payload is not canonically encoded")
        return raw
