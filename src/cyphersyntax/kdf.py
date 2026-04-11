from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


def hkdf_expand(secret: bytes, *, length: int, salt: bytes | None, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=length,
        salt=salt,
        info=info,
    ).derive(secret)


def derive_session_root(
    *,
    shared_secret: bytes,
    transcript_hash: bytes,
    supplemental_secret: bytes = b"",
) -> bytes:
    material = shared_secret + supplemental_secret
    return hkdf_expand(
        material,
        length=32,
        salt=transcript_hash,
        info=b"CypherSyntax/session-root/v1",
    )


def derive_message_key(root_key: bytes, sequence: int, suite_name: str) -> tuple[bytes, bytes]:
    info = f"CypherSyntax/message/{suite_name}/v1/{sequence}".encode("utf-8")
    material = hkdf_expand(root_key, length=44, salt=None, info=info)
    return material[:32], material[32:44]
