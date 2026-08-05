from dataclasses import replace
from hashlib import sha256

import pytest
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from cyphersyntax.errors import InvalidSignatureError, KeyConfirmationError
from cyphersyntax.handshake import (
    HandshakeConfirmation,
    HandshakeOffer,
    HandshakeResponse,
    handshake_transcript,
)
from cyphersyntax.identity import Identity
from cyphersyntax.kdf import derive_session_root
from cyphersyntax.protocol import PROTOCOL_VERSION
from cyphersyntax.session import AeadSuite, SessionFactory


def _start_authenticated_handshake(
    alice: Identity,
    bob: Identity,
    *,
    suite: AeadSuite = AeadSuite.AES_GCM_SIV,
    alice_secret: bytes = b"",
    bob_secret: bytes = b"",
):
    pending_alice = SessionFactory.initiator(
        local_identity=alice,
        remote_name=bob.name,
        remote_signing_public_key=bob.ed25519_public_bytes(),
        suite=suite,
        supplemental_secret=alice_secret,
    )
    response, pending_bob = SessionFactory.responder(
        local_identity=bob,
        remote_signing_public_key=alice.ed25519_public_bytes(),
        offer=pending_alice.offer,
        supplemental_secret=bob_secret,
    )
    return pending_alice, response, pending_bob


@pytest.mark.parametrize("suite", [AeadSuite.AES_GCM_SIV, AeadSuite.CHACHA20_POLY1305])
def test_authenticated_ephemeral_handshake_roundtrip(suite):
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    pending_alice, response, pending_bob = _start_authenticated_handshake(
        alice,
        bob,
        suite=suite,
    )

    confirmation, alice_session = pending_alice.complete(response)
    bob_session = pending_bob.complete(confirmation)

    assert pending_alice.completed is True
    assert pending_bob.completed is True
    assert alice_session.root_key == bob_session.root_key
    assert bob_session.decrypt(alice_session.encrypt(b"hello bob")) == b"hello bob"
    assert alice_session.decrypt(bob_session.encrypt(b"hello alice")) == b"hello alice"


def test_handshake_signatures_bind_trusted_identity_keys():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    pending_alice, response, pending_bob = _start_authenticated_handshake(alice, bob)

    assert (
        pending_alice.offer.initiator_signing_public_key
        == alice.ed25519_public_bytes()
    )
    assert response.responder_signing_public_key == bob.ed25519_public_bytes()

    Identity.verify_signature(
        pending_alice.offer.signature_payload(),
        pending_alice.offer.signature,
        alice.ed25519_public_bytes(),
    )
    Identity.verify_signature(
        response.signature_payload(pending_alice.offer),
        response.signature,
        bob.ed25519_public_bytes(),
    )

    confirmation, _ = pending_alice.complete(response)
    Identity.verify_signature(
        confirmation.signature_payload(pending_bob.offer, pending_bob.response),
        confirmation.signature,
        alice.ed25519_public_bytes(),
    )


def test_responder_uses_fresh_ephemeral_key_not_static_exchange_key():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    pending_alice, response, pending_bob = _start_authenticated_handshake(alice, bob)
    confirmation, alice_session = pending_alice.complete(response)
    bob_session = pending_bob.complete(confirmation)

    assert response.responder_ephemeral_public_key != bob.x25519_public_bytes()

    static_shared_secret = bob.exchange_private_key.exchange(
        X25519PublicKey.from_public_bytes(
            pending_alice.offer.initiator_ephemeral_public_key
        )
    )
    static_candidate_root = derive_session_root(
        shared_secret=static_shared_secret,
        transcript_hash=sha256(
            handshake_transcript(pending_alice.offer, response)
        ).digest(),
    )
    assert static_candidate_root != alice_session.root_key
    assert static_candidate_root != bob_session.root_key


def test_each_handshake_uses_new_ephemeral_keys_and_root():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")

    first_pending, first_response, first_pending_bob = (
        _start_authenticated_handshake(alice, bob)
    )
    first_confirmation, first_alice = first_pending.complete(first_response)
    first_bob = first_pending_bob.complete(first_confirmation)

    second_pending, second_response, second_pending_bob = (
        _start_authenticated_handshake(alice, bob)
    )
    second_confirmation, second_alice = second_pending.complete(second_response)
    second_bob = second_pending_bob.complete(second_confirmation)

    assert (
        first_pending.offer.initiator_ephemeral_public_key
        != second_pending.offer.initiator_ephemeral_public_key
    )
    assert (
        first_response.responder_ephemeral_public_key
        != second_response.responder_ephemeral_public_key
    )
    assert first_alice.root_key != second_alice.root_key
    assert first_bob.root_key != second_bob.root_key


def test_initiator_handshake_cannot_be_completed_twice():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    pending_alice, response, _ = _start_authenticated_handshake(alice, bob)

    pending_alice.complete(response)
    with pytest.raises(RuntimeError, match="already been completed"):
        pending_alice.complete(response)


def test_responder_handshake_cannot_be_completed_twice():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    pending_alice, response, pending_bob = _start_authenticated_handshake(alice, bob)
    confirmation, _ = pending_alice.complete(response)

    pending_bob.complete(confirmation)
    with pytest.raises(RuntimeError, match="already been completed"):
        pending_bob.complete(confirmation)


def test_responder_rejects_offer_for_different_local_identity():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    mallory = Identity.generate("mallory")
    pending_alice = SessionFactory.initiator(
        local_identity=alice,
        remote_name=bob.name,
        remote_signing_public_key=bob.ed25519_public_bytes(),
    )

    with pytest.raises(ValueError, match="does not match handshake responder"):
        SessionFactory.responder(
            local_identity=mallory,
            remote_signing_public_key=alice.ed25519_public_bytes(),
            offer=pending_alice.offer,
        )


def test_responder_rejects_untrusted_initiator_signing_key():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    mallory = Identity.generate("mallory")
    pending_alice = SessionFactory.initiator(
        local_identity=alice,
        remote_name=bob.name,
        remote_signing_public_key=bob.ed25519_public_bytes(),
    )

    with pytest.raises(InvalidSignatureError, match="trust anchor"):
        SessionFactory.responder(
            local_identity=bob,
            remote_signing_public_key=mallory.ed25519_public_bytes(),
            offer=pending_alice.offer,
        )


def test_responder_rejects_tampered_signed_offer():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    pending_alice = SessionFactory.initiator(
        local_identity=alice,
        remote_name=bob.name,
        remote_signing_public_key=bob.ed25519_public_bytes(),
    )
    tampered_offer = replace(
        pending_alice.offer,
        initiator_ephemeral_public_key=b"x" * 32,
    )

    with pytest.raises(InvalidSignatureError, match="verification failed"):
        SessionFactory.responder(
            local_identity=bob,
            remote_signing_public_key=alice.ed25519_public_bytes(),
            offer=tampered_offer,
        )


def test_initiator_rejects_untrusted_responder_signing_key():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    mallory = Identity.generate("mallory")
    pending_alice = SessionFactory.initiator(
        local_identity=alice,
        remote_name=bob.name,
        remote_signing_public_key=mallory.ed25519_public_bytes(),
    )
    response, _ = SessionFactory.responder(
        local_identity=bob,
        remote_signing_public_key=alice.ed25519_public_bytes(),
        offer=pending_alice.offer,
    )

    with pytest.raises(InvalidSignatureError, match="trust anchor"):
        pending_alice.complete(response)
    assert pending_alice.completed is False


def test_initiator_rejects_tampered_signed_response():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    pending_alice, response, _ = _start_authenticated_handshake(alice, bob)
    tampered_response = replace(
        response,
        responder_key_confirmation=b"x" * 32,
    )

    with pytest.raises(InvalidSignatureError, match="verification failed"):
        pending_alice.complete(tampered_response)
    assert pending_alice.completed is False


def test_supplemental_secret_mismatch_fails_responder_key_confirmation():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    pending_alice, response, _ = _start_authenticated_handshake(
        alice,
        bob,
        alice_secret=b"initiator secret",
        bob_secret=b"different responder secret",
    )

    with pytest.raises(KeyConfirmationError, match="responder key confirmation"):
        pending_alice.complete(response)
    assert pending_alice.completed is False


def test_responder_rejects_tampered_confirmation_signature():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    pending_alice, response, pending_bob = _start_authenticated_handshake(alice, bob)
    confirmation, _ = pending_alice.complete(response)
    tampered_signature = bytearray(confirmation.signature)
    tampered_signature[0] ^= 1
    forged_confirmation = replace(
        confirmation,
        signature=bytes(tampered_signature),
    )

    with pytest.raises(InvalidSignatureError, match="verification failed"):
        pending_bob.complete(forged_confirmation)
    assert pending_bob.completed is False


def test_responder_rejects_invalid_but_resigned_key_confirmation():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    pending_alice, response, pending_bob = _start_authenticated_handshake(alice, bob)
    confirmation, _ = pending_alice.complete(response)
    unsigned_forgery = replace(
        confirmation,
        initiator_key_confirmation=b"x" * 32,
        signature=b"\x00" * 64,
    )
    forged_confirmation = replace(
        unsigned_forgery,
        signature=alice.sign(
            unsigned_forgery.signature_payload(
                pending_bob.offer,
                pending_bob.response,
            )
        ),
    )

    with pytest.raises(KeyConfirmationError, match="initiator key confirmation"):
        pending_bob.complete(forged_confirmation)
    assert pending_bob.completed is False


def test_confirmation_must_match_response():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    pending_alice, response, pending_bob = _start_authenticated_handshake(alice, bob)
    confirmation, _ = pending_alice.complete(response)
    mismatched_confirmation = replace(confirmation, responder="mallory")

    with pytest.raises(ValueError, match="responder mismatch"):
        pending_bob.complete(mismatched_confirmation)


def test_response_must_match_original_offer():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    pending_alice, response, _ = _start_authenticated_handshake(alice, bob)
    mismatched_response = replace(response, responder="mallory")

    with pytest.raises(ValueError, match="responder mismatch"):
        pending_alice.complete(mismatched_response)
    assert pending_alice.completed is False


def test_handshake_offer_validation():
    with pytest.raises(ValueError, match="participants must be distinct"):
        HandshakeOffer(
            version=PROTOCOL_VERSION,
            suite=AeadSuite.AES_GCM_SIV.value,
            initiator="alice",
            responder="alice",
            initiator_ephemeral_public_key=b"a" * 32,
            initiator_signing_public_key=b"b" * 32,
            signature=b"c" * 64,
        )

    with pytest.raises(ValueError, match="exactly 32 bytes"):
        HandshakeOffer(
            version=PROTOCOL_VERSION,
            suite=AeadSuite.AES_GCM_SIV.value,
            initiator="alice",
            responder="bob",
            initiator_ephemeral_public_key=b"short",
            initiator_signing_public_key=b"b" * 32,
            signature=b"c" * 64,
        )


def test_handshake_rejects_non_integer_version():
    with pytest.raises(TypeError, match="version must be an integer"):
        HandshakeOffer(
            version=True,
            suite=AeadSuite.AES_GCM_SIV.value,
            initiator="alice",
            responder="bob",
            initiator_ephemeral_public_key=b"a" * 32,
            initiator_signing_public_key=b"b" * 32,
            signature=b"c" * 64,
        )


def test_handshake_response_rejects_reflected_ephemeral_key():
    offer = HandshakeOffer(
        version=PROTOCOL_VERSION,
        suite=AeadSuite.AES_GCM_SIV.value,
        initiator="alice",
        responder="bob",
        initiator_ephemeral_public_key=b"a" * 32,
        initiator_signing_public_key=b"b" * 32,
        signature=b"c" * 64,
    )

    with pytest.raises(ValueError, match="ephemeral public keys must be distinct"):
        HandshakeResponse.from_offer(
            offer,
            responder_ephemeral_public_key=offer.initiator_ephemeral_public_key,
            responder_signing_public_key=b"d" * 32,
            responder_key_confirmation=b"e" * 32,
            signature=b"f" * 64,
        )


def test_handshake_response_rejects_suite_substitution():
    offer = HandshakeOffer(
        version=PROTOCOL_VERSION,
        suite=AeadSuite.AES_GCM_SIV.value,
        initiator="alice",
        responder="bob",
        initiator_ephemeral_public_key=b"a" * 32,
        initiator_signing_public_key=b"b" * 32,
        signature=b"c" * 64,
    )
    response = HandshakeResponse(
        version=PROTOCOL_VERSION,
        suite=AeadSuite.CHACHA20_POLY1305.value,
        initiator="alice",
        responder="bob",
        initiator_ephemeral_public_key=b"a" * 32,
        initiator_signing_public_key=b"b" * 32,
        responder_ephemeral_public_key=b"d" * 32,
        responder_signing_public_key=b"e" * 32,
        responder_key_confirmation=b"f" * 32,
        signature=b"g" * 64,
    )

    with pytest.raises(ValueError, match="suite mismatch"):
        response.validate_for_offer(offer)


def test_confirmation_constructor_validates_signature_length():
    with pytest.raises(ValueError, match="exactly 64 bytes"):
        HandshakeConfirmation(
            version=PROTOCOL_VERSION,
            suite=AeadSuite.AES_GCM_SIV.value,
            initiator="alice",
            responder="bob",
            initiator_ephemeral_public_key=b"a" * 32,
            responder_ephemeral_public_key=b"b" * 32,
            initiator_key_confirmation=b"c" * 32,
            signature=b"short",
        )
