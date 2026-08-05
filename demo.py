from cyphersyntax.handshake import (
    HandshakeConfirmation,
    HandshakeOffer,
    HandshakeResponse,
)
from cyphersyntax.identity import Identity
from cyphersyntax.session import AeadSuite, SessionFactory


def main() -> None:
    alice = Identity.generate("alice")
    bob = Identity.generate("bob")

    pending_alice = SessionFactory.initiator(
        local_identity=alice,
        remote_name=bob.name,
        remote_signing_public_key=bob.ed25519_public_bytes(),
        suite=AeadSuite.AES_GCM_SIV,
        supplemental_secret=b"future-pq-kem-secret",
    )
    received_offer = HandshakeOffer.from_bytes(pending_alice.offer.to_bytes())
    response, pending_bob = SessionFactory.responder(
        local_identity=bob,
        remote_signing_public_key=alice.ed25519_public_bytes(),
        offer=received_offer,
        supplemental_secret=b"future-pq-kem-secret",
    )
    received_response = HandshakeResponse.from_bytes(response.to_bytes())
    confirmation, alice_session = pending_alice.complete(received_response)
    received_confirmation = HandshakeConfirmation.from_bytes(
        confirmation.to_bytes()
    )
    bob_session = pending_bob.complete(received_confirmation)

    packet = alice_session.encrypt(b"CypherSyntax demo message")
    plaintext = bob_session.decrypt(packet)
    print(plaintext.decode("utf-8"))


if __name__ == "__main__":
    main()
