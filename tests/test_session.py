import pytest
from cryptography.exceptions import InvalidTag

from cyphersyntax.errors import ReplayDetectedError
from cyphersyntax.identity import Identity
from cyphersyntax.kdf import derive_message_key
from cyphersyntax.protocol import MAX_MESSAGE_SEQUENCE
from cyphersyntax.session import AeadSuite, SessionFactory
from cyphersyntax.wire import MessageEnvelope


@pytest.mark.parametrize("suite", [AeadSuite.AES_GCM_SIV, AeadSuite.CHACHA20_POLY1305])
def test_roundtrip(suite):
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_session, bob_session = SessionFactory.pair_for_tests(
        alice=alice,
        bob=bob,
        suite=suite,
    )

    blob = alice_session.encrypt(b"hello bob")
    assert bob_session.decrypt(blob) == b"hello bob"


@pytest.mark.parametrize("suite", [AeadSuite.AES_GCM_SIV, AeadSuite.CHACHA20_POLY1305])
def test_first_message_key_material_is_separated_by_direction(suite):
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_session, bob_session = SessionFactory.pair_for_tests(
        alice=alice,
        bob=bob,
        suite=suite,
    )

    assert alice_session.root_key == bob_session.root_key

    alice_key, alice_nonce = derive_message_key(
        alice_session.root_key,
        0,
        suite.value,
        sender_public_key=alice_session.local_ephemeral_public_bytes,
        recipient_public_key=alice_session.remote_ephemeral_public_bytes,
    )
    bob_key, bob_nonce = derive_message_key(
        bob_session.root_key,
        0,
        suite.value,
        sender_public_key=bob_session.local_ephemeral_public_bytes,
        recipient_public_key=bob_session.remote_ephemeral_public_bytes,
    )

    assert alice_key != bob_key
    assert alice_nonce != bob_nonce


@pytest.mark.parametrize("suite", [AeadSuite.AES_GCM_SIV, AeadSuite.CHACHA20_POLY1305])
def test_bidirectional_first_messages_roundtrip(suite):
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_session, bob_session = SessionFactory.pair_for_tests(
        alice=alice,
        bob=bob,
        suite=suite,
    )

    alice_packet = alice_session.encrypt(b"hello bob")
    bob_packet = bob_session.encrypt(b"hello alice")

    assert bob_session.decrypt(alice_packet) == b"hello bob"
    assert alice_session.decrypt(bob_packet) == b"hello alice"


@pytest.mark.parametrize("suite", [AeadSuite.AES_GCM_SIV, AeadSuite.CHACHA20_POLY1305])
def test_public_factory_bidirectional_roundtrip(suite):
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_session = SessionFactory.initiator(
        local_identity=alice,
        remote_name=bob.name,
        remote_x25519_public_key=bob.x25519_public_bytes(),
        suite=suite,
    )
    bob_session = SessionFactory.responder(
        local_identity=bob,
        remote_name=alice.name,
        remote_x25519_public_key=alice.x25519_public_bytes(),
        peer_ephemeral_public_key=alice_session.local_ephemeral_public_bytes,
        suite=suite,
    )

    assert alice_session.root_key == bob_session.root_key

    alice_packet = alice_session.encrypt(b"public hello bob")
    bob_packet = bob_session.encrypt(b"public hello alice")

    assert bob_session.decrypt(alice_packet) == b"public hello bob"
    assert alice_session.decrypt(bob_packet) == b"public hello alice"


@pytest.mark.parametrize("suite", [AeadSuite.AES_GCM_SIV, AeadSuite.CHACHA20_POLY1305])
def test_tampered_ciphertext_does_not_consume_sequence_number(suite):
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_session, bob_session = SessionFactory.pair_for_tests(
        alice=alice,
        bob=bob,
        suite=suite,
    )

    legitimate_blob = alice_session.encrypt(b"do not alter")
    forged_envelope = MessageEnvelope.from_bytes(legitimate_blob)
    forged_ciphertext = bytearray(forged_envelope.ciphertext)
    forged_ciphertext[0] ^= 0x01
    forged_envelope.ciphertext = bytes(forged_ciphertext)

    with pytest.raises(InvalidTag):
        bob_session.decrypt(forged_envelope.to_bytes())

    assert bob_session.replay_window.highest_seen == -1
    assert bob_session.decrypt(legitimate_blob) == b"do not alter"


@pytest.mark.parametrize("suite", [AeadSuite.AES_GCM_SIV, AeadSuite.CHACHA20_POLY1305])
def test_forged_high_sequence_does_not_advance_replay_window(suite):
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_session, bob_session = SessionFactory.pair_for_tests(
        alice=alice,
        bob=bob,
        suite=suite,
    )

    legitimate_blob = alice_session.encrypt(b"sequence zero remains valid")
    forged_envelope = MessageEnvelope.from_bytes(legitimate_blob)
    forged_envelope.sequence = 10_000

    with pytest.raises(InvalidTag):
        bob_session.decrypt(forged_envelope.to_bytes())

    assert bob_session.replay_window.highest_seen == -1
    assert bob_session.replay_window.seen == set()
    assert bob_session.decrypt(legitimate_blob) == b"sequence zero remains valid"


def test_replay_detection():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_session, bob_session = SessionFactory.pair_for_tests(alice=alice, bob=bob)

    blob = alice_session.encrypt(b"once only")
    assert bob_session.decrypt(blob) == b"once only"
    with pytest.raises(ReplayDetectedError):
        bob_session.decrypt(blob)


def test_send_sequence_exhaustion_fails_before_key_or_nonce_reuse():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_session, _ = SessionFactory.pair_for_tests(alice=alice, bob=bob)
    alice_session.send_sequence = MAX_MESSAGE_SEQUENCE

    final_packet = MessageEnvelope.from_bytes(alice_session.encrypt(b"final sequence"))
    assert final_packet.sequence == MAX_MESSAGE_SEQUENCE
    assert alice_session.send_sequence == MAX_MESSAGE_SEQUENCE + 1

    with pytest.raises(OverflowError, match="message sequence exhausted"):
        alice_session.encrypt(b"must not encrypt")


def test_hybrid_ready_schedule_changes_root_key():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    a1, b1 = SessionFactory.pair_for_tests(
        alice=alice,
        bob=bob,
        supplemental_secret=b"",
    )
    a2, b2 = SessionFactory.pair_for_tests(
        alice=alice,
        bob=bob,
        supplemental_secret=b"pq-layer",
    )
    assert a1.root_key != a2.root_key
    assert b1.root_key != b2.root_key
