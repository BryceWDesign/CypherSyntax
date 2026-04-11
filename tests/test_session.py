import pytest

from cyphersyntax.identity import Identity
from cyphersyntax.session import SessionFactory, AeadSuite
from cyphersyntax.errors import ReplayDetectedError


@pytest.mark.parametrize("suite", [AeadSuite.AES_GCM_SIV, AeadSuite.CHACHA20_POLY1305])
def test_roundtrip(suite):
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_session, bob_session = SessionFactory.pair_for_tests(alice=alice, bob=bob, suite=suite)

    blob = alice_session.encrypt(b"hello bob")
    assert bob_session.decrypt(blob) == b"hello bob"


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
    a1, b1 = SessionFactory.pair_for_tests(alice=alice, bob=bob, supplemental_secret=b"")
    a2, b2 = SessionFactory.pair_for_tests(alice=alice, bob=bob, supplemental_secret=b"pq-layer")
    assert a1.root_key != a2.root_key
    assert b1.root_key != b2.root_key
