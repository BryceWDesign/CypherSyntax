from cyphersyntax.identity import Identity
from cyphersyntax.session import SessionFactory, AeadSuite


def main() -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")
    alice_session, bob_session = SessionFactory.pair_for_tests(
        alice=alice,
        bob=bob,
        suite=AeadSuite.AES_GCM_SIV,
        supplemental_secret=b"future-pq-kem-secret",
    )
    packet = alice_session.encrypt(b"CypherSyntax demo message")
    plaintext = bob_session.decrypt(packet)
    print(plaintext.decode("utf-8"))


if __name__ == "__main__":
    main()
