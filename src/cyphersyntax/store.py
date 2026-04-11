from __future__ import annotations

import json
import os
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt


class EncryptedStore:
    def __init__(self, path: str | Path, passphrase: bytes):
        self.path = Path(path)
        self.passphrase = passphrase

    def _derive_key(self, salt: bytes) -> bytes:
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
        return kdf.derive(self.passphrase)

    def save(self, obj: dict) -> None:
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = self._derive_key(salt)
        aead = AESGCMSIV(key)
        plaintext = json.dumps(obj, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ciphertext = aead.encrypt(nonce, plaintext, b"CypherSyntax/store/v1")
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.path.write_bytes(salt + nonce + ciphertext)
        try:
            self.path.chmod(0o600)
        except OSError:
            pass

    def load(self) -> dict:
        blob = self.path.read_bytes()
        salt = blob[:16]
        nonce = blob[16:28]
        ciphertext = blob[28:]
        key = self._derive_key(salt)
        aead = AESGCMSIV(key)
        plaintext = aead.decrypt(nonce, ciphertext, b"CypherSyntax/store/v1")
        return json.loads(plaintext.decode("utf-8"))
