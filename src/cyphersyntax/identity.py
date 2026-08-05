from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
from pathlib import Path
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from .errors import IdentityError, InvalidSignatureError, StoreError
from .persistence import validate_passphrase
from .protocol import MAX_PARTICIPANT_NAME_BYTES
from .store import EncryptedStore


_IDENTITY_FORMAT = "CypherSyntax/identity/v1"
_IDENTITY_FIELDS = frozenset(
    {"format", "name", "ed25519_private_key", "x25519_private_key"}
)
_PRIVATE_KEY_BYTES = 32
_HEX_PATTERN = re.compile(r"[0-9a-f]+\Z")


def _validate_identity_name(name: object) -> str:
    if type(name) is not str:
        raise TypeError("identity name must be a string")
    try:
        encoded = name.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("identity name must contain valid Unicode") from exc
    if not encoded or len(encoded) > MAX_PARTICIPANT_NAME_BYTES:
        raise ValueError(
            f"identity name must contain 1 to {MAX_PARTICIPANT_NAME_BYTES} UTF-8 bytes"
        )
    if name != name.strip():
        raise ValueError("identity name must not contain surrounding whitespace")
    if not name.isprintable():
        raise ValueError("identity name must contain only printable characters")
    if name in {".", ".."} or "/" in name or "\\" in name:
        raise ValueError("identity name must not contain path components")
    return name


def _identity_filename(name: str) -> str:
    digest = sha256(name.encode("utf-8")).hexdigest()
    return f"identity-{digest}.bin"


def _decode_private_key(field_name: str, value: object) -> bytes:
    if type(value) is not str:
        raise IdentityError(f"persisted {field_name} must be a string")
    if len(value) != _PRIVATE_KEY_BYTES * 2:
        raise IdentityError(f"persisted {field_name} has an invalid length")
    if _HEX_PATTERN.fullmatch(value) is None:
        raise IdentityError(f"persisted {field_name} is not canonical hexadecimal")
    return bytes.fromhex(value)


@dataclass(slots=True)
class Identity:
    name: str
    signing_private_key: Ed25519PrivateKey = field(repr=False)
    exchange_private_key: X25519PrivateKey = field(repr=False)

    def __post_init__(self) -> None:
        self.name = _validate_identity_name(self.name)
        if not isinstance(self.signing_private_key, Ed25519PrivateKey):
            raise TypeError("signing private key must be Ed25519")
        if not isinstance(self.exchange_private_key, X25519PrivateKey):
            raise TypeError("exchange private key must be X25519")

    @classmethod
    def generate(cls, name: str) -> "Identity":
        return cls(
            name=name,
            signing_private_key=Ed25519PrivateKey.generate(),
            exchange_private_key=X25519PrivateKey.generate(),
        )

    def sign(self, data: bytes) -> bytes:
        if type(data) is not bytes:
            raise TypeError("signature payload must be bytes")
        return self.signing_private_key.sign(data)

    @staticmethod
    def verify_signature(data: bytes, signature: bytes, public_key: bytes) -> None:
        if type(data) is not bytes:
            raise TypeError("signature payload must be bytes")
        if type(signature) is not bytes:
            raise TypeError("signature must be bytes")
        if type(public_key) is not bytes:
            raise TypeError("signing public key must be bytes")
        try:
            key = Ed25519PublicKey.from_public_bytes(public_key)
            key.verify(signature, data)
        except (InvalidSignature, ValueError) as exc:
            raise InvalidSignatureError("signature verification failed") from exc

    def verify(
        self,
        data: bytes,
        signature: bytes,
        public_key: bytes | None = None,
    ) -> None:
        verification_key = (
            public_key if public_key is not None else self.ed25519_public_bytes()
        )
        self.verify_signature(data, signature, verification_key)

    def ed25519_public_bytes(self) -> bytes:
        return self.signing_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def x25519_public_bytes(self) -> bytes:
        return self.exchange_private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    @classmethod
    def storage_path(cls, name: str, directory: str | Path) -> Path:
        validated_name = _validate_identity_name(name)
        return Path(directory) / _identity_filename(validated_name)

    def _storage_payload(self) -> dict[str, Any]:
        signing_raw = self.signing_private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        exchange_raw = self.exchange_private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return {
            "format": _IDENTITY_FORMAT,
            "name": self.name,
            "ed25519_private_key": signing_raw.hex(),
            "x25519_private_key": exchange_raw.hex(),
        }

    def save(self, directory: str | Path, passphrase: bytes) -> None:
        validate_passphrase(passphrase)
        destination = self.storage_path(self.name, directory)
        try:
            EncryptedStore(destination, passphrase).save(self._storage_payload())
        except StoreError as exc:
            raise IdentityError("failed to save identity") from exc

    @classmethod
    def load(cls, name: str, directory: str | Path, passphrase: bytes) -> "Identity":
        validated_name = _validate_identity_name(name)
        validate_passphrase(passphrase)
        source = cls.storage_path(validated_name, directory)
        try:
            raw = EncryptedStore(source, passphrase).load()
        except StoreError as exc:
            raise IdentityError("failed to load identity") from exc

        received_fields = frozenset(raw)
        if received_fields != _IDENTITY_FIELDS:
            missing = sorted(_IDENTITY_FIELDS - received_fields)
            unexpected = sorted(received_fields - _IDENTITY_FIELDS)
            details: list[str] = []
            if missing:
                details.append(f"missing fields: {', '.join(missing)}")
            if unexpected:
                details.append(f"unexpected fields: {', '.join(unexpected)}")
            raise IdentityError(
                f"persisted identity has an invalid schema ({'; '.join(details)})"
            )
        if raw["format"] != _IDENTITY_FORMAT:
            raise IdentityError("persisted identity has an unsupported format")
        if raw["name"] != validated_name:
            raise IdentityError("persisted identity name does not match request")

        signing_raw = _decode_private_key(
            "Ed25519 private key",
            raw["ed25519_private_key"],
        )
        exchange_raw = _decode_private_key(
            "X25519 private key",
            raw["x25519_private_key"],
        )
        signing_key = Ed25519PrivateKey.from_private_bytes(signing_raw)
        exchange_key = X25519PrivateKey.from_private_bytes(exchange_raw)
        return cls(
            name=validated_name,
            signing_private_key=signing_key,
            exchange_private_key=exchange_key,
        )
