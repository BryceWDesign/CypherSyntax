from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from .errors import InvalidSignatureError


@dataclass(slots=True)
class Identity:
    name: str
    signing_private_key: Ed25519PrivateKey
    exchange_private_key: X25519PrivateKey

    @classmethod
    def generate(cls, name: str) -> "Identity":
        return cls(
            name=name,
            signing_private_key=Ed25519PrivateKey.generate(),
            exchange_private_key=X25519PrivateKey.generate(),
        )

    def sign(self, data: bytes) -> bytes:
        return self.signing_private_key.sign(data)

    def verify(self, data: bytes, signature: bytes, public_key: bytes | None = None) -> None:
        key = (
            Ed25519PublicKey.from_public_bytes(public_key)
            if public_key is not None
            else self.signing_private_key.public_key()
        )
        try:
            key.verify(signature, data)
        except InvalidSignature as exc:
            raise InvalidSignatureError("signature verification failed") from exc

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

    def save(self, directory: str | Path, passphrase: bytes) -> None:
        path = Path(directory)
        path.mkdir(parents=True, exist_ok=True)

        signing_pem = self.signing_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
        )
        exchange_pem = self.exchange_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.BestAvailableEncryption(passphrase),
        )

        signing_path = path / f"{self.name}.ed25519.pem"
        exchange_path = path / f"{self.name}.x25519.pem"
        signing_path.write_bytes(signing_pem)
        exchange_path.write_bytes(exchange_pem)
        for item in (signing_path, exchange_path):
            try:
                item.chmod(0o600)
            except OSError:
                pass

    @classmethod
    def load(cls, name: str, directory: str | Path, passphrase: bytes) -> "Identity":
        path = Path(directory)
        signing_key = serialization.load_pem_private_key(
            (path / f"{name}.ed25519.pem").read_bytes(),
            password=passphrase,
        )
        exchange_key = serialization.load_pem_private_key(
            (path / f"{name}.x25519.pem").read_bytes(),
            password=passphrase,
        )
        if not isinstance(signing_key, Ed25519PrivateKey):
            raise TypeError("loaded signing key is not Ed25519")
        if not isinstance(exchange_key, X25519PrivateKey):
            raise TypeError("loaded exchange key is not X25519")
        return cls(name=name, signing_private_key=signing_key, exchange_private_key=exchange_key)
