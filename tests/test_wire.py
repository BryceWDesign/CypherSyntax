import json

import pytest

from cyphersyntax.errors import EnvelopeError
from cyphersyntax.identity import Identity
from cyphersyntax.protocol import (
    MAX_CIPHERTEXT_BYTES,
    MAX_ENVELOPE_BYTES,
    MAX_MESSAGE_SEQUENCE,
    MAX_PARTICIPANT_NAME_BYTES,
    MAX_PLAINTEXT_BYTES,
    MAX_PROTOCOL_VERSION,
    MAX_SUITE_NAME_BYTES,
    PROTOCOL_VERSION,
)
from cyphersyntax.session import AeadSuite, SessionFactory
from cyphersyntax.wire import MessageEnvelope


def _valid_envelope() -> MessageEnvelope:
    return MessageEnvelope(
        version=PROTOCOL_VERSION,
        suite=AeadSuite.AES_GCM_SIV.value,
        sender="alice",
        recipient="bob",
        sequence=7,
        ciphertext=b"x" * 16,
    )


def _canonical_payload(**changes):
    payload = {
        "v": PROTOCOL_VERSION,
        "suite": AeadSuite.AES_GCM_SIV.value,
        "sender": "alice",
        "recipient": "bob",
        "sequence": 7,
        "ciphertext": (b"x" * 16).hex(),
    }
    payload.update(changes)
    return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")


def test_envelope_roundtrip_is_canonical():
    envelope = _valid_envelope()

    encoded = envelope.to_bytes()
    decoded = MessageEnvelope.from_bytes(encoded)

    assert decoded == envelope
    assert decoded.to_bytes() == encoded


def test_associated_data_excludes_ciphertext_and_is_deterministic():
    first = _valid_envelope()
    second = _valid_envelope()
    second.ciphertext = b"y" * 16

    assert first.associated_data() == second.associated_data()
    assert b"ciphertext" not in first.associated_data()


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"not json",
        b"\xff",
        b"[]",
        b"null",
        (b"[" * 1100) + (b"]" * 1100),
    ],
)
def test_parser_rejects_empty_malformed_or_non_object_input(data):
    with pytest.raises(EnvelopeError):
        MessageEnvelope.from_bytes(data)


def test_parser_rejects_non_bytes_input():
    with pytest.raises(EnvelopeError, match="must be bytes"):
        MessageEnvelope.from_bytes("not bytes")  # type: ignore[arg-type]


def test_parser_rejects_duplicate_fields():
    data = (
        b'{"ciphertext":"' + (b"78" * 16) +
        b'","recipient":"bob","sender":"alice","sequence":7,'
        b'"suite":"AES_GCM_SIV","v":1,"v":1}'
    )

    with pytest.raises(EnvelopeError, match="duplicate envelope field: v"):
        MessageEnvelope.from_bytes(data)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        (
            {
                "suite": AeadSuite.AES_GCM_SIV.value,
                "sender": "alice",
                "recipient": "bob",
                "sequence": 7,
                "ciphertext": (b"x" * 16).hex(),
            },
            "missing fields: v",
        ),
        (
            {
                "v": PROTOCOL_VERSION,
                "suite": AeadSuite.AES_GCM_SIV.value,
                "sender": "alice",
                "recipient": "bob",
                "sequence": 7,
                "ciphertext": (b"x" * 16).hex(),
                "extra": True,
            },
            "unexpected fields: extra",
        ),
    ],
)
def test_parser_rejects_missing_and_unexpected_fields(payload, message):
    data = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    with pytest.raises(EnvelopeError, match=message):
        MessageEnvelope.from_bytes(data)


@pytest.mark.parametrize("version", [True, 1.0, "1", 0, -1, MAX_PROTOCOL_VERSION + 1])
def test_parser_rejects_invalid_versions(version):
    with pytest.raises(EnvelopeError, match="version"):
        MessageEnvelope.from_bytes(_canonical_payload(v=version))


@pytest.mark.parametrize(
    "suite",
    [
        None,
        "",
        "aes_gcm_siv",
        "AES-GCM-SIV",
        " AES_GCM_SIV",
        "ÄES_GCM_SIV",
        "A" * (MAX_SUITE_NAME_BYTES + 1),
    ],
)
def test_parser_rejects_invalid_suite_names(suite):
    with pytest.raises(EnvelopeError, match="suite"):
        MessageEnvelope.from_bytes(_canonical_payload(suite=suite))


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("sender", None),
        ("sender", ""),
        ("sender", " alice"),
        ("sender", "alice\nadmin"),
        ("sender", "a" * (MAX_PARTICIPANT_NAME_BYTES + 1)),
        ("recipient", 7),
        ("recipient", ""),
        ("recipient", "bob "),
        ("recipient", "bob\x00admin"),
    ],
)
def test_parser_rejects_invalid_participant_names(field, value):
    with pytest.raises(EnvelopeError, match=field):
        MessageEnvelope.from_bytes(_canonical_payload(**{field: value}))


def test_parser_rejects_invalid_unicode_name():
    data = _canonical_payload(sender="\ud800")

    with pytest.raises(EnvelopeError, match="valid Unicode"):
        MessageEnvelope.from_bytes(data)


def test_parser_rejects_identical_sender_and_recipient():
    with pytest.raises(EnvelopeError, match="must be distinct"):
        MessageEnvelope.from_bytes(_canonical_payload(recipient="alice"))


@pytest.mark.parametrize(
    "sequence",
    [True, 1.0, "7", -1, MAX_MESSAGE_SEQUENCE + 1],
)
def test_parser_rejects_invalid_sequences(sequence):
    with pytest.raises(EnvelopeError, match="sequence"):
        MessageEnvelope.from_bytes(_canonical_payload(sequence=sequence))


@pytest.mark.parametrize(
    "ciphertext",
    [
        None,
        "",
        "0",
        "GG",
        "78 78",
        "AB" * 16,
        "78" * 15,
    ],
)
def test_parser_rejects_invalid_ciphertext_encodings(ciphertext):
    with pytest.raises(EnvelopeError, match="ciphertext"):
        MessageEnvelope.from_bytes(_canonical_payload(ciphertext=ciphertext))


def test_parser_rejects_ciphertext_above_limit():
    data = _canonical_payload(ciphertext=(b"x" * (MAX_CIPHERTEXT_BYTES + 1)).hex())

    with pytest.raises(EnvelopeError, match="maximum size"):
        MessageEnvelope.from_bytes(data)


def test_parser_rejects_oversized_input_before_json_parsing():
    with pytest.raises(EnvelopeError, match="input exceeds"):
        MessageEnvelope.from_bytes(b"x" * (MAX_ENVELOPE_BYTES + 1))


@pytest.mark.parametrize(
    "data",
    [
        b'{"v":1,"suite":"AES_GCM_SIV","sender":"alice","recipient":"bob",'
        b'"sequence":7,"ciphertext":"' + (b"78" * 16) + b'"}',
        _canonical_payload().replace(b'"v":1', b'"v": 1'),
        _canonical_payload() + b"\n",
    ],
)
def test_parser_rejects_noncanonical_json_encoding(data):
    with pytest.raises(EnvelopeError, match="not canonically encoded"):
        MessageEnvelope.from_bytes(data)


def test_to_bytes_rejects_incomplete_ciphertext():
    envelope = _valid_envelope()
    envelope.ciphertext = b""

    with pytest.raises(EnvelopeError, match="shorter than the AEAD tag"):
        envelope.to_bytes()


def test_session_rejects_non_bytes_plaintext():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_session, _ = SessionFactory.pair_for_tests(alice=alice, bob=bob)

    with pytest.raises(TypeError, match="plaintext must be bytes"):
        alice_session.encrypt("not bytes")  # type: ignore[arg-type]


def test_session_rejects_plaintext_above_limit_without_advancing_sequence():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_session, _ = SessionFactory.pair_for_tests(alice=alice, bob=bob)

    with pytest.raises(ValueError, match="maximum message size"):
        alice_session.encrypt(b"x" * (MAX_PLAINTEXT_BYTES + 1))

    assert alice_session.send_sequence == 0


def test_session_accepts_maximum_plaintext_size():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_session, bob_session = SessionFactory.pair_for_tests(alice=alice, bob=bob)
    plaintext = b"x" * MAX_PLAINTEXT_BYTES

    packet = alice_session.encrypt(plaintext)

    assert len(packet) <= MAX_ENVELOPE_BYTES
    assert bob_session.decrypt(packet) == plaintext
