from __future__ import annotations

import json

import pytest

from cyphersyntax.errors import HandshakeError, InvalidSignatureError
from cyphersyntax.handshake import (
    MAX_HANDSHAKE_MESSAGE_BYTES,
    HandshakeConfirmation,
    HandshakeOffer,
    HandshakeResponse,
    handshake_transcript,
)
from cyphersyntax.identity import Identity
from cyphersyntax.protocol import MAX_PARTICIPANT_NAME_BYTES
from cyphersyntax.session import AeadSuite, SessionFactory


def _handshake_messages(
    suite: AeadSuite = AeadSuite.AES_GCM_SIV,
) -> tuple[
    Identity,
    Identity,
    HandshakeOffer,
    HandshakeResponse,
    HandshakeConfirmation,
]:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    pending_alice = SessionFactory.initiator(
        local_identity=alice,
        remote_name=bob.name,
        remote_signing_public_key=bob.ed25519_public_bytes(),
        suite=suite,
    )
    offer = HandshakeOffer.from_bytes(pending_alice.offer.to_bytes())
    response, pending_bob = SessionFactory.responder(
        local_identity=bob,
        remote_signing_public_key=alice.ed25519_public_bytes(),
        offer=offer,
    )
    parsed_response = HandshakeResponse.from_bytes(response.to_bytes())
    confirmation, _ = pending_alice.complete(parsed_response)
    parsed_confirmation = HandshakeConfirmation.from_bytes(
        confirmation.to_bytes()
    )
    pending_bob.complete(parsed_confirmation)
    return alice, bob, offer, parsed_response, parsed_confirmation


@pytest.mark.parametrize(
    "suite",
    [AeadSuite.AES_GCM_SIV, AeadSuite.CHACHA20_POLY1305],
)
def test_complete_authenticated_handshake_crosses_wire_boundaries(suite):
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    pending_alice = SessionFactory.initiator(
        local_identity=alice,
        remote_name=bob.name,
        remote_signing_public_key=bob.ed25519_public_bytes(),
        suite=suite,
    )

    received_offer = HandshakeOffer.from_bytes(pending_alice.offer.to_bytes())
    response, pending_bob = SessionFactory.responder(
        local_identity=bob,
        remote_signing_public_key=alice.ed25519_public_bytes(),
        offer=received_offer,
    )
    received_response = HandshakeResponse.from_bytes(response.to_bytes())
    confirmation, alice_session = pending_alice.complete(received_response)
    received_confirmation = HandshakeConfirmation.from_bytes(
        confirmation.to_bytes()
    )
    bob_session = pending_bob.complete(received_confirmation)

    assert alice_session.root_key == bob_session.root_key
    assert bob_session.decrypt(alice_session.encrypt(b"hello bob")) == b"hello bob"
    assert alice_session.decrypt(bob_session.encrypt(b"hello alice")) == b"hello alice"


def test_all_handshake_messages_roundtrip_canonically():
    _, _, offer, response, confirmation = _handshake_messages()

    for message_type, message in (
        (HandshakeOffer, offer),
        (HandshakeResponse, response),
        (HandshakeConfirmation, confirmation),
    ):
        encoded = message.to_bytes()
        decoded = message_type.from_bytes(encoded)
        assert decoded == message
        assert decoded.to_bytes() == encoded
        assert len(encoded) <= MAX_HANDSHAKE_MESSAGE_BYTES


def test_wire_roundtrip_preserves_signed_transcript():
    alice, bob, offer, response, confirmation = _handshake_messages()
    original_transcript = handshake_transcript(offer, response)
    parsed_offer = HandshakeOffer.from_bytes(offer.to_bytes())
    parsed_response = HandshakeResponse.from_bytes(response.to_bytes())
    parsed_confirmation = HandshakeConfirmation.from_bytes(
        confirmation.to_bytes()
    )

    assert handshake_transcript(parsed_offer, parsed_response) == original_transcript
    Identity.verify_signature(
        parsed_offer.signature_payload(),
        parsed_offer.signature,
        alice.ed25519_public_bytes(),
    )
    Identity.verify_signature(
        parsed_response.signature_payload(parsed_offer),
        parsed_response.signature,
        bob.ed25519_public_bytes(),
    )
    Identity.verify_signature(
        parsed_confirmation.signature_payload(parsed_offer, parsed_response),
        parsed_confirmation.signature,
        alice.ed25519_public_bytes(),
    )


@pytest.mark.parametrize(
    ("message_type", "kind"),
    [
        (HandshakeOffer, "offer"),
        (HandshakeResponse, "response"),
        (HandshakeConfirmation, "confirmation"),
    ],
)
def test_parser_rejects_empty_malformed_and_non_object_inputs(message_type, kind):
    for data in (b"", b"not json", b"\xff", b"[]", b"null"):
        with pytest.raises(HandshakeError):
            message_type.from_bytes(data)

    with pytest.raises(HandshakeError, match=f"expected handshake message kind '{kind}'"):
        message_type.from_bytes(b'{"kind":"wrong"}')


def test_parser_rejects_non_bytes_and_oversized_input():
    with pytest.raises(HandshakeError, match="input must be bytes"):
        HandshakeOffer.from_bytes("not bytes")  # type: ignore[arg-type]

    with pytest.raises(HandshakeError, match="input exceeds"):
        HandshakeOffer.from_bytes(b"x" * (MAX_HANDSHAKE_MESSAGE_BYTES + 1))


def test_parser_rejects_duplicate_fields():
    _, _, offer, _, _ = _handshake_messages()
    encoded = offer.to_bytes()
    duplicate = encoded[:-1] + b',"v":1}'

    with pytest.raises(HandshakeError, match="duplicate handshake field: v"):
        HandshakeOffer.from_bytes(duplicate)


def test_parser_rejects_missing_and_unexpected_fields():
    _, _, offer, _, _ = _handshake_messages()
    payload = json.loads(offer.to_bytes())
    del payload["signature"]
    missing = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()

    with pytest.raises(HandshakeError, match="missing fields: signature"):
        HandshakeOffer.from_bytes(missing)

    payload = json.loads(offer.to_bytes())
    payload["extra"] = True
    unexpected = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()

    with pytest.raises(HandshakeError, match="unexpected fields: extra"):
        HandshakeOffer.from_bytes(unexpected)


def test_parser_rejects_wrong_message_kind_with_complete_schema():
    _, _, offer, _, _ = _handshake_messages()
    payload = json.loads(offer.to_bytes())
    payload["kind"] = "response"
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()

    with pytest.raises(HandshakeError, match="expected handshake message kind 'offer'"):
        HandshakeOffer.from_bytes(encoded)


@pytest.mark.parametrize(
    ("field", "value"),
    [
        ("v", True),
        ("v", 2),
        ("suite", "UNKNOWN"),
        ("suite", 7),
        ("initiator", ""),
        ("initiator", " alice"),
        ("initiator", "alice\nadmin"),
        ("initiator", "a" * (MAX_PARTICIPANT_NAME_BYTES + 1)),
        ("responder", "alice"),
    ],
)
def test_offer_parser_rejects_invalid_protocol_fields(field, value):
    _, _, offer, _, _ = _handshake_messages()
    payload = json.loads(offer.to_bytes())
    payload[field] = value
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")

    with pytest.raises(HandshakeError, match="invalid field values"):
        HandshakeOffer.from_bytes(encoded)


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("signature", 7, "encoding must be a string"),
        ("signature", "00", "encode exactly 64 bytes"),
        ("signature", "AA" * 64, "canonical lowercase hexadecimal"),
        (
            "initiator_ephemeral_public_key",
            "g0" * 32,
            "canonical lowercase hexadecimal",
        ),
        (
            "initiator_signing_public_key",
            "00" * 31,
            "encode exactly 32 bytes",
        ),
    ],
)
def test_offer_parser_rejects_invalid_binary_encodings(field, value, message):
    _, _, offer, _, _ = _handshake_messages()
    payload = json.loads(offer.to_bytes())
    payload[field] = value
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()

    with pytest.raises(HandshakeError, match=message):
        HandshakeOffer.from_bytes(encoded)


def test_parser_rejects_noncanonical_json():
    _, _, offer, _, _ = _handshake_messages()
    canonical = offer.to_bytes()
    noncanonical = canonical.replace(b'"v":1', b'"v": 1')

    with pytest.raises(HandshakeError, match="not canonically encoded"):
        HandshakeOffer.from_bytes(noncanonical)


def test_canonical_tampering_survives_parser_but_fails_signature_verification():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    pending_alice = SessionFactory.initiator(
        local_identity=alice,
        remote_name=bob.name,
        remote_signing_public_key=bob.ed25519_public_bytes(),
    )
    payload = json.loads(pending_alice.offer.to_bytes())
    payload["initiator_ephemeral_public_key"] = (b"x" * 32).hex()
    tampered_blob = json.dumps(
        payload,
        separators=(",", ":"),
        sort_keys=True,
    ).encode()
    tampered_offer = HandshakeOffer.from_bytes(tampered_blob)

    with pytest.raises(InvalidSignatureError, match="verification failed"):
        SessionFactory.responder(
            local_identity=bob,
            remote_signing_public_key=alice.ed25519_public_bytes(),
            offer=tampered_offer,
        )


def test_response_parser_rejects_reflected_ephemeral_key():
    _, _, _, response, _ = _handshake_messages()
    payload = json.loads(response.to_bytes())
    payload["responder_ephemeral_public_key"] = payload[
        "initiator_ephemeral_public_key"
    ]
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()

    with pytest.raises(HandshakeError, match="invalid field values"):
        HandshakeResponse.from_bytes(encoded)


def test_confirmation_parser_rejects_reflected_ephemeral_key():
    _, _, _, _, confirmation = _handshake_messages()
    payload = json.loads(confirmation.to_bytes())
    payload["responder_ephemeral_public_key"] = payload[
        "initiator_ephemeral_public_key"
    ]
    encoded = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode()

    with pytest.raises(HandshakeError, match="invalid field values"):
        HandshakeConfirmation.from_bytes(encoded)
