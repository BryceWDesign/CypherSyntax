from __future__ import annotations

import os
from pathlib import Path

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV

from cyphersyntax.errors import PersistenceError, StoreError
from cyphersyntax.persistence import (
    MAX_PASSPHRASE_BYTES,
    atomic_write_bytes,
    validate_passphrase,
)
from cyphersyntax.store import (
    MAX_STORE_FILE_BYTES,
    MAX_STORE_PLAINTEXT_BYTES,
    STORE_MAGIC,
    STORE_NONCE_BYTES,
    STORE_SALT_BYTES,
    STORE_TAG_BYTES,
    STORE_VERSION,
    EncryptedStore,
)


PASSPHRASE = b"correct horse battery staple"
_HEADER = STORE_MAGIC + bytes((STORE_VERSION,))
_AAD = _HEADER


def test_encrypted_store_roundtrip(tmp_path):
    path = tmp_path / "state.bin"
    store = EncryptedStore(path=path, passphrase=PASSPHRASE)
    payload = {"node": "alpha", "counter": 7, "enabled": True}

    store.save(payload)

    assert store.load() == payload


def test_encrypted_store_repr_excludes_passphrase(tmp_path):
    store = EncryptedStore(tmp_path / "state.bin", PASSPHRASE)

    assert "correct horse" not in repr(store)
    assert "state.bin" in repr(store)


def test_encrypted_store_does_not_write_plaintext(tmp_path):
    path = tmp_path / "state.bin"
    store = EncryptedStore(path, PASSPHRASE)
    store.save({"secret": "highly-sensitive-value"})

    blob = path.read_bytes()
    assert b"highly-sensitive-value" not in blob
    assert blob.startswith(_HEADER)


def test_store_ciphertext_changes_across_saves(tmp_path):
    path = tmp_path / "state.bin"
    store = EncryptedStore(path, PASSPHRASE)
    payload = {"counter": 7}

    store.save(payload)
    first = path.read_bytes()
    store.save(payload)
    second = path.read_bytes()

    assert first != second
    assert store.load() == payload


@pytest.mark.parametrize("passphrase", [b"", b"short", b"x" * 15])
def test_store_rejects_short_passphrase(tmp_path, passphrase):
    with pytest.raises(ValueError, match="at least 16 bytes"):
        EncryptedStore(tmp_path / "state.bin", passphrase)


def test_store_rejects_excessively_long_passphrase(tmp_path):
    with pytest.raises(ValueError, match="at most"):
        EncryptedStore(tmp_path / "state.bin", b"x" * (MAX_PASSPHRASE_BYTES + 1))


def test_store_rejects_non_bytes_passphrase(tmp_path):
    with pytest.raises(TypeError, match="passphrase must be bytes"):
        EncryptedStore(tmp_path / "state.bin", "not bytes")  # type: ignore[arg-type]


@pytest.mark.parametrize("payload", [[], "text", 7, None])
def test_store_rejects_non_dictionary_payload(tmp_path, payload):
    store = EncryptedStore(tmp_path / "state.bin", PASSPHRASE)

    with pytest.raises(TypeError, match="must be a dictionary"):
        store.save(payload)  # type: ignore[arg-type]


def test_store_rejects_non_string_keys(tmp_path):
    store = EncryptedStore(tmp_path / "state.bin", PASSPHRASE)

    with pytest.raises(TypeError, match="keys must be strings"):
        store.save({1: "value"})  # type: ignore[dict-item]


@pytest.mark.parametrize("value", [float("nan"), float("inf"), float("-inf")])
def test_store_rejects_nonfinite_numbers(tmp_path, value):
    store = EncryptedStore(tmp_path / "state.bin", PASSPHRASE)

    with pytest.raises(StoreError, match="not canonical JSON"):
        store.save({"value": value})


def test_store_rejects_non_json_value(tmp_path):
    store = EncryptedStore(tmp_path / "state.bin", PASSPHRASE)

    with pytest.raises(StoreError, match="not canonical JSON"):
        store.save({"value": object()})


def test_store_rejects_payload_above_limit_without_writing(tmp_path):
    path = tmp_path / "state.bin"
    store = EncryptedStore(path, PASSPHRASE)

    with pytest.raises(StoreError, match="payload exceeds"):
        store.save({"value": "x" * MAX_STORE_PLAINTEXT_BYTES})

    assert not path.exists()


def test_store_rejects_wrong_passphrase(tmp_path):
    path = tmp_path / "state.bin"
    EncryptedStore(path, PASSPHRASE).save({"value": 7})

    with pytest.raises(StoreError, match="authentication failed"):
        EncryptedStore(path, b"different passphrase").load()


def test_store_rejects_corrupted_ciphertext(tmp_path):
    path = tmp_path / "state.bin"
    store = EncryptedStore(path, PASSPHRASE)
    store.save({"value": 7})
    blob = bytearray(path.read_bytes())
    blob[-1] ^= 1
    path.write_bytes(blob)

    with pytest.raises(StoreError, match="authentication failed"):
        store.load()


@pytest.mark.parametrize(
    ("blob", "message"),
    [
        (b"", "truncated"),
        (b"x" * 32, "truncated"),
        (
            b"WrongFormat"
            + b"x"
            * (STORE_SALT_BYTES + STORE_NONCE_BYTES + STORE_TAG_BYTES + 20),
            "invalid format marker",
        ),
        (
            STORE_MAGIC
            + b"\x02"
            + b"x" * (STORE_SALT_BYTES + STORE_NONCE_BYTES + STORE_TAG_BYTES),
            "unsupported encrypted store version",
        ),
    ],
)
def test_store_rejects_invalid_file_structure(tmp_path, blob, message):
    path = tmp_path / "state.bin"
    path.write_bytes(blob)

    with pytest.raises(StoreError, match=message):
        EncryptedStore(path, PASSPHRASE).load()


def test_store_rejects_oversized_file_before_decryption(tmp_path):
    path = tmp_path / "state.bin"
    path.write_bytes(b"x" * (MAX_STORE_FILE_BYTES + 1))

    with pytest.raises(StoreError, match="maximum file size"):
        EncryptedStore(path, PASSPHRASE).load()


def test_store_rejects_missing_file(tmp_path):
    with pytest.raises(StoreError, match="failed to read"):
        EncryptedStore(tmp_path / "missing.bin", PASSPHRASE).load()


def _write_authenticated_plaintext(path: Path, plaintext: bytes) -> None:
    store = EncryptedStore(path, PASSPHRASE)
    salt = os.urandom(STORE_SALT_BYTES)
    nonce = os.urandom(STORE_NONCE_BYTES)
    key = store._derive_key(salt)
    ciphertext = AESGCMSIV(key).encrypt(nonce, plaintext, _AAD)
    path.write_bytes(_HEADER + salt + nonce + ciphertext)


@pytest.mark.parametrize(
    ("plaintext", "message"),
    [
        (b"not json", "not valid JSON"),
        (b"[]", "must be a dictionary"),
        (b'{"value":NaN}', "non-finite JSON number"),
        (b'{"value":1,"value":2}', "duplicate encrypted-store field"),
        (b'{"value": 1}', "not canonically encoded"),
        (b"\xff", "not valid JSON"),
    ],
)
def test_store_rejects_authenticated_but_invalid_plaintext(
    tmp_path,
    plaintext,
    message,
):
    path = tmp_path / "state.bin"
    _write_authenticated_plaintext(path, plaintext)

    with pytest.raises(StoreError, match=message):
        EncryptedStore(path, PASSPHRASE).load()


def test_store_atomic_replace_failure_preserves_previous_file(tmp_path, monkeypatch):
    path = tmp_path / "state.bin"
    store = EncryptedStore(path, PASSPHRASE)
    store.save({"generation": 1})
    original_blob = path.read_bytes()

    def fail_replace(source, destination):
        raise OSError("simulated replace failure")

    monkeypatch.setattr("cyphersyntax.persistence.os.replace", fail_replace)
    with pytest.raises(StoreError, match="failed to save"):
        store.save({"generation": 2})

    assert path.read_bytes() == original_blob
    assert store.load() == {"generation": 1}
    assert not list(tmp_path.glob("*.tmp"))


def test_atomic_write_rejects_symbolic_link_destination(tmp_path):
    target = tmp_path / "target.bin"
    target.write_bytes(b"original")
    link = tmp_path / "link.bin"
    try:
        link.symlink_to(target)
    except (NotImplementedError, OSError):
        pytest.skip("symbolic links are unavailable in this environment")

    with pytest.raises(PersistenceError, match="symbolic-link"):
        atomic_write_bytes(link, b"replacement")

    assert target.read_bytes() == b"original"


def test_atomic_write_rejects_non_bytes_data(tmp_path):
    with pytest.raises(TypeError, match="data must be bytes"):
        atomic_write_bytes(tmp_path / "state.bin", "text")  # type: ignore[arg-type]


def test_atomic_write_reports_invalid_parent(tmp_path):
    parent = tmp_path / "not-a-directory"
    parent.write_bytes(b"file")

    with pytest.raises(PersistenceError, match="persistence directory"):
        atomic_write_bytes(parent / "state.bin", b"data")


def test_validate_passphrase_accepts_boundary_lengths():
    validate_passphrase(b"x" * 16)
    validate_passphrase(b"x" * MAX_PASSPHRASE_BYTES)
