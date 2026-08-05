from __future__ import annotations

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF


_MAX_SEQUENCE = (1 << 64) - 1


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


def _length_prefixed(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def derive_directional_secret(
    root_key: bytes,
    *,
    suite_name: str,
    sender_public_key: bytes,
    recipient_public_key: bytes,
) -> bytes:
    suite_bytes = suite_name.encode("utf-8")
    info = b"".join(
        (
            b"CypherSyntax/traffic-secret/v1",
            _length_prefixed(suite_bytes),
            _length_prefixed(sender_public_key),
            _length_prefixed(recipient_public_key),
        )
    )
    return hkdf_expand(root_key, length=32, salt=None, info=info)


def derive_message_key(
    root_key: bytes,
    sequence: int,
    suite_name: str,
    *,
    sender_public_key: bytes,
    recipient_public_key: bytes,
) -> tuple[bytes, bytes]:
    if not 0 <= sequence <= _MAX_SEQUENCE:
        raise ValueError("message sequence must fit in an unsigned 64-bit integer")

    directional_secret = derive_directional_secret(
        root_key,
        suite_name=suite_name,
        sender_public_key=sender_public_key,
        recipient_public_key=recipient_public_key,
    )
    info = b"CypherSyntax/message-key/v1" + sequence.to_bytes(8, "big")
    material = hkdf_expand(directional_secret, length=44, salt=None, info=info)
    return material[:32], material[32:44]
