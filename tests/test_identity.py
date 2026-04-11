from cyphersyntax.identity import Identity
from cyphersyntax.errors import InvalidSignatureError


def test_identity_sign_and_verify():
    alice = Identity.generate("alice")
    msg = b"integrity matters"
    sig = alice.sign(msg)
    alice.verify(msg, sig)


def test_identity_detects_tampering():
    alice = Identity.generate("alice")
    sig = alice.sign(b"good")
    try:
        alice.verify(b"bad", sig)
    except InvalidSignatureError:
        return
    raise AssertionError("tampered signature should fail")
