import pytest

from cyphersyntax.errors import ReplayDetectedError
from cyphersyntax.identity import Identity
from cyphersyntax.kdf import derive_message_key
from cyphersyntax.session import AeadSuite, SessionFactory


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


def test_tamper_detection():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_session, bob_session = SessionFactory.pair_for_tests(alice=alice, bob=bob)

    blob = bytearray(alice_session.encrypt(b"do not alter"))
    blob[-1] ^= 0x01
    with pytest.raises(Exception):
        bob_session.decrypt(bytes(blob))


def test_replay_detection():
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_session, bob_session = SessionFactory.pair_for_tests(alice=alice, bob=bob)

    blob = alice_session.encrypt(b"once only")
    assert bob_session.decrypt(blob) == b"once only"
    with pytest.raises(ReplayDetectedError):
        bob_session.decrypt(blob)


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
