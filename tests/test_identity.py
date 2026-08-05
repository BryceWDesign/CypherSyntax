from __future__ import annotations

from pathlib import Path

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

from cyphersyntax.errors import IdentityError, InvalidSignatureError
from cyphersyntax.identity import Identity
from cyphersyntax.store import EncryptedStore


PASSPHRASE = b"correct horse battery staple"


def test_identity_sign_and_verify():
    alice = Identity.generate("alice")
    message = b"integrity matters"
    signature = alice.sign(message)

    alice.verify(message, signature)


def test_identity_detects_tampering():
    alice = Identity.generate("alice")
    signature = alice.sign(b"good")

    with pytest.raises(InvalidSignatureError, match="verification failed"):
        alice.verify(b"bad", signature)


def test_identity_verifies_with_explicit_trusted_public_key():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    message = b"signed by alice"

    bob.verify(message, alice.sign(message), alice.ed25519_public_bytes())


def test_identity_private_keys_are_excluded_from_repr():
    alice = Identity.generate("alice")
    representation = repr(alice)

    assert "signing_private_key" not in representation
    assert "exchange_private_key" not in representation


@pytest.mark.parametrize(
    "name",
    [
        "",
        " alice",
        "alice ",
        ".",
        "..",
        "../alice",
        "..\\alice",
        "alice/bob",
        "alice\\bob",
        "alice\nadmin",
        "a" * 256,
        "\ud800",
    ],
)
def test_identity_rejects_unsafe_names(name):
    with pytest.raises((TypeError, ValueError), match="identity name"):
        Identity.generate(name)


def test_identity_rejects_non_string_name():
    with pytest.raises(TypeError, match="identity name must be a string"):
        Identity.generate(7)  # type: ignore[arg-type]


def test_identity_rejects_wrong_private_key_types():
    with pytest.raises(TypeError, match="signing private key must be Ed25519"):
        Identity(
            name="alice",
            signing_private_key=X25519PrivateKey.generate(),  # type: ignore[arg-type]
            exchange_private_key=X25519PrivateKey.generate(),
        )

    with pytest.raises(TypeError, match="exchange private key must be X25519"):
        Identity(
            name="alice",
            signing_private_key=Ed25519PrivateKey.generate(),
            exchange_private_key=Ed25519PrivateKey.generate(),  # type: ignore[arg-type]
        )


def test_identity_sign_requires_bytes():
    alice = Identity.generate("alice")

    with pytest.raises(TypeError, match="signature payload must be bytes"):
        alice.sign("message")  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("data", "signature", "public_key", "message"),
    [
        ("data", b"x" * 64, b"y" * 32, "payload must be bytes"),
        (b"data", "signature", b"y" * 32, "signature must be bytes"),
        (b"data", b"x" * 64, "public", "public key must be bytes"),
        (b"data", b"x" * 64, b"short", "verification failed"),
    ],
)
def test_verify_signature_rejects_invalid_inputs(data, signature, public_key, message):
    with pytest.raises((TypeError, InvalidSignatureError), match=message):
        Identity.verify_signature(data, signature, public_key)


def test_identity_save_and_load_roundtrip_uses_single_bundle(tmp_path):
    alice = Identity.generate("alice")

    alice.save(tmp_path, PASSPHRASE)
    loaded = Identity.load("alice", tmp_path, PASSPHRASE)

    assert loaded.name == alice.name
    assert loaded.ed25519_public_bytes() == alice.ed25519_public_bytes()
    assert loaded.x25519_public_bytes() == alice.x25519_public_bytes()
    files = list(tmp_path.iterdir())
    assert files == [Identity.storage_path("alice", tmp_path)]
    assert "alice" not in files[0].name
    assert files[0].suffix == ".bin"


def test_identity_bundle_does_not_expose_private_key_bytes(tmp_path):
    alice = Identity.generate("alice")
    signing_raw = alice.signing_private_key.private_bytes_raw()
    exchange_raw = alice.exchange_private_key.private_bytes_raw()

    alice.save(tmp_path, PASSPHRASE)
    blob = Identity.storage_path("alice", tmp_path).read_bytes()

    assert signing_raw not in blob
    assert exchange_raw not in blob
    assert b"alice" not in blob


def test_identity_storage_path_is_deterministic_and_confined(tmp_path):
    first = Identity.storage_path("alice", tmp_path)
    second = Identity.storage_path("alice", tmp_path)

    assert first == second
    assert first.parent == tmp_path
    assert first.name.startswith("identity-")


def test_identity_load_rejects_wrong_passphrase(tmp_path):
    Identity.generate("alice").save(tmp_path, PASSPHRASE)

    with pytest.raises(IdentityError, match="failed to load identity"):
        Identity.load("alice", tmp_path, b"different passphrase")


def test_identity_load_rejects_corrupted_bundle(tmp_path):
    Identity.generate("alice").save(tmp_path, PASSPHRASE)
    path = Identity.storage_path("alice", tmp_path)
    blob = bytearray(path.read_bytes())
    blob[-1] ^= 1
    path.write_bytes(blob)

    with pytest.raises(IdentityError, match="failed to load identity"):
        Identity.load("alice", tmp_path, PASSPHRASE)


def test_identity_load_rejects_missing_bundle(tmp_path):
    with pytest.raises(IdentityError, match="failed to load identity"):
        Identity.load("alice", tmp_path, PASSPHRASE)


def _write_identity_payload(tmp_path: Path, payload: dict[str, object]) -> None:
    path = Identity.storage_path("alice", tmp_path)
    EncryptedStore(path, PASSPHRASE).save(payload)


def _valid_identity_payload() -> dict[str, object]:
    alice = Identity.generate("alice")
    return {
        "format": "CypherSyntax/identity/v1",
        "name": "alice",
        "ed25519_private_key": alice.signing_private_key.private_bytes_raw().hex(),
        "x25519_private_key": alice.exchange_private_key.private_bytes_raw().hex(),
    }


@pytest.mark.parametrize(
    ("mutation", "message"),
    [
        (lambda payload: payload.pop("name"), "missing fields: name"),
        (lambda payload: payload.update({"extra": True}), "unexpected fields: extra"),
        (
            lambda payload: payload.update({"format": "CypherSyntax/identity/v2"}),
            "unsupported format",
        ),
        (lambda payload: payload.update({"name": "bob"}), "name does not match"),
        (
            lambda payload: payload.update({"ed25519_private_key": "short"}),
            "invalid length",
        ),
        (
            lambda payload: payload.update({"x25519_private_key": "G" * 64}),
            "not canonical hexadecimal",
        ),
        (
            lambda payload: payload.update({"x25519_private_key": 7}),
            "must be a string",
        ),
    ],
)
def test_identity_load_rejects_invalid_authenticated_schema(
    tmp_path,
    mutation,
    message,
):
    payload = _valid_identity_payload()
    mutation(payload)
    _write_identity_payload(tmp_path, payload)

    with pytest.raises(IdentityError, match=message):
        Identity.load("alice", tmp_path, PASSPHRASE)


def test_identity_save_failure_preserves_previous_bundle(tmp_path, monkeypatch):
    original = Identity.generate("alice")
    replacement = Identity.generate("alice")
    original.save(tmp_path, PASSPHRASE)

    def fail_replace(source, destination):
        raise OSError("simulated replace failure")

    monkeypatch.setattr("cyphersyntax.persistence.os.replace", fail_replace)
    with pytest.raises(IdentityError, match="failed to save identity"):
        replacement.save(tmp_path, PASSPHRASE)

    loaded = Identity.load("alice", tmp_path, PASSPHRASE)
    assert loaded.ed25519_public_bytes() == original.ed25519_public_bytes()
    assert loaded.x25519_public_bytes() == original.x25519_public_bytes()
    assert not list(tmp_path.glob("*.tmp"))


def test_identity_rejects_short_passphrase(tmp_path):
    alice = Identity.generate("alice")

    with pytest.raises(ValueError, match="at least 16 bytes"):
        alice.save(tmp_path, b"short")


def test_identity_rejects_non_bytes_passphrase(tmp_path):
    alice = Identity.generate("alice")

    with pytest.raises(TypeError, match="passphrase must be bytes"):
        alice.save(tmp_path, "not bytes")  # type: ignore[arg-type]
