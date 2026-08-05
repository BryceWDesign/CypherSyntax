from hashlib import sha256

import pytest
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PublicKey

from cyphersyntax.handshake import (
    HandshakeOffer,
    HandshakeResponse,
    handshake_transcript,
)
from cyphersyntax.identity import Identity
from cyphersyntax.kdf import derive_session_root
from cyphersyntax.protocol import PROTOCOL_VERSION
from cyphersyntax.session import AeadSuite, SessionFactory


@pytest.mark.parametrize("suite", [AeadSuite.AES_GCM_SIV, AeadSuite.CHACHA20_POLY1305])
def test_public_ephemeral_handshake_roundtrip(suite):
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")

    pending_alice = SessionFactory.initiator(
        local_identity=alice,
        remote_name=bob.name,
        suite=suite,
    )
    response, bob_session = SessionFactory.responder(
        local_identity=bob,
        offer=pending_alice.offer,
    )
    alice_session = pending_alice.complete(response)

    assert pending_alice.completed is True
    assert alice_session.root_key == bob_session.root_key
    assert (
        alice_session.local_ephemeral_public_bytes
        == pending_alice.offer.initiator_ephemeral_public_key
    )
    assert (
        bob_session.local_ephemeral_public_bytes
        == response.responder_ephemeral_public_key
    )
    assert bob_session.decrypt(alice_session.encrypt(b"hello bob")) == b"hello bob"
    assert alice_session.decrypt(bob_session.encrypt(b"hello alice")) == b"hello alice"


def test_responder_uses_fresh_ephemeral_key_not_static_exchange_key():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    pending_alice = SessionFactory.initiator(
        local_identity=alice,
        remote_name=bob.name,
    )

    response, bob_session = SessionFactory.responder(
        local_identity=bob,
        offer=pending_alice.offer,
    )
    alice_session = pending_alice.complete(response)

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

    first_pending = SessionFactory.initiator(
        local_identity=alice,
        remote_name=bob.name,
    )
    first_response, first_bob = SessionFactory.responder(
        local_identity=bob,
        offer=first_pending.offer,
    )
    first_alice = first_pending.complete(first_response)

    second_pending = SessionFactory.initiator(
        local_identity=alice,
        remote_name=bob.name,
    )
    second_response, second_bob = SessionFactory.responder(
        local_identity=bob,
        offer=second_pending.offer,
    )
    second_alice = second_pending.complete(second_response)

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
    pending_alice = SessionFactory.initiator(
        local_identity=alice,
        remote_name=bob.name,
    )
    response, _ = SessionFactory.responder(
        local_identity=bob,
        offer=pending_alice.offer,
    )

    pending_alice.complete(response)
    with pytest.raises(RuntimeError, match="already been completed"):
        pending_alice.complete(response)


def test_responder_rejects_offer_for_different_identity():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    mallory = Identity.generate("mallory")
    pending_alice = SessionFactory.initiator(
        local_identity=alice,
        remote_name=bob.name,
    )

    with pytest.raises(ValueError, match="does not match handshake responder"):
        SessionFactory.responder(
            local_identity=mallory,
            offer=pending_alice.offer,
        )


def test_response_must_match_original_offer():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    pending_alice = SessionFactory.initiator(
        local_identity=alice,
        remote_name=bob.name,
    )
    response, _ = SessionFactory.responder(
        local_identity=bob,
        offer=pending_alice.offer,
    )
    mismatched_response = HandshakeResponse(
        version=response.version,
        suite=response.suite,
        initiator=response.initiator,
        responder="mallory",
        initiator_ephemeral_public_key=response.initiator_ephemeral_public_key,
        responder_ephemeral_public_key=response.responder_ephemeral_public_key,
    )

    with pytest.raises(ValueError, match="responder mismatch"):
        pending_alice.complete(mismatched_response)
    assert pending_alice.completed is False


def test_supplemental_secret_must_match():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    pending_alice = SessionFactory.initiator(
        local_identity=alice,
        remote_name=bob.name,
        supplemental_secret=b"initiator secret",
    )
    response, bob_session = SessionFactory.responder(
        local_identity=bob,
        offer=pending_alice.offer,
        supplemental_secret=b"different responder secret",
    )
    alice_session = pending_alice.complete(response)

    assert alice_session.root_key != bob_session.root_key
    with pytest.raises(InvalidTag):
        bob_session.decrypt(alice_session.encrypt(b"must not decrypt"))


def test_handshake_offer_validation():
    with pytest.raises(ValueError, match="participants must be distinct"):
        HandshakeOffer(
            version=PROTOCOL_VERSION,
            suite=AeadSuite.AES_GCM_SIV.value,
            initiator="alice",
            responder="alice",
            initiator_ephemeral_public_key=b"a" * 32,
        )

    with pytest.raises(ValueError, match="exactly 32 bytes"):
        HandshakeOffer(
            version=PROTOCOL_VERSION,
            suite=AeadSuite.AES_GCM_SIV.value,
            initiator="alice",
            responder="bob",
            initiator_ephemeral_public_key=b"short",
        )


def test_handshake_rejects_non_integer_version():
    with pytest.raises(TypeError, match="version must be an integer"):
        HandshakeOffer(
            version=True,
            suite=AeadSuite.AES_GCM_SIV.value,
            initiator="alice",
            responder="bob",
            initiator_ephemeral_public_key=b"a" * 32,
        )


def test_handshake_response_rejects_reflected_ephemeral_key():
    offer = HandshakeOffer(
        version=PROTOCOL_VERSION,
        suite=AeadSuite.AES_GCM_SIV.value,
        initiator="alice",
        responder="bob",
        initiator_ephemeral_public_key=b"a" * 32,
    )

    with pytest.raises(ValueError, match="ephemeral public keys must be distinct"):
        HandshakeResponse.from_offer(
            offer,
            responder_ephemeral_public_key=offer.initiator_ephemeral_public_key,
        )


def test_handshake_response_rejects_suite_substitution():
    offer = HandshakeOffer(
        version=PROTOCOL_VERSION,
        suite=AeadSuite.AES_GCM_SIV.value,
        initiator="alice",
        responder="bob",
        initiator_ephemeral_public_key=b"a" * 32,
    )
    response = HandshakeResponse(
        version=PROTOCOL_VERSION,
        suite=AeadSuite.CHACHA20_POLY1305.value,
        initiator="alice",
        responder="bob",
        initiator_ephemeral_public_key=b"a" * 32,
        responder_ephemeral_public_key=b"b" * 32,
    )

    with pytest.raises(ValueError, match="suite mismatch"):
        response.validate_for_offer(offer)
