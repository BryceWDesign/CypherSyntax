from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from hashlib import sha256

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from .handshake import HandshakeOffer, HandshakeResponse, handshake_transcript
from .identity import Identity
from .kdf import derive_message_key, derive_session_root
from .protocol import MAX_MESSAGE_SEQUENCE, PROTOCOL_VERSION, validate_message_sequence
from .replay import ReplayWindow
from .wire import MessageEnvelope


class AeadSuite(str, Enum):
    AES_GCM_SIV = "AES_GCM_SIV"
    CHACHA20_POLY1305 = "CHACHA20_POLY1305"


@dataclass(slots=True)
class SessionState:
    local_name: str
    remote_name: str
    suite: AeadSuite
    root_key: bytes
    local_ephemeral_public_bytes: bytes
    remote_ephemeral_public_bytes: bytes
    send_sequence: int = 0
    replay_window: ReplayWindow = field(default_factory=ReplayWindow)

    def _build_aead(self, key: bytes):
        if self.suite == AeadSuite.AES_GCM_SIV:
            return AESGCMSIV(key)
        if self.suite == AeadSuite.CHACHA20_POLY1305:
            return ChaCha20Poly1305(key)
        raise ValueError(f"unsupported suite: {self.suite}")

    def encrypt(self, plaintext: bytes) -> bytes:
        if self.send_sequence > MAX_MESSAGE_SEQUENCE:
            raise OverflowError("message sequence exhausted")
        validate_message_sequence(self.send_sequence)
        sequence = self.send_sequence
        envelope = MessageEnvelope(
            version=PROTOCOL_VERSION,
            suite=self.suite.value,
            sender=self.local_name,
            recipient=self.remote_name,
            sequence=sequence,
            ciphertext=b"",
        )
        key, nonce = derive_message_key(
            self.root_key,
            sequence,
            self.suite.value,
            sender_public_key=self.local_ephemeral_public_bytes,
            recipient_public_key=self.remote_ephemeral_public_bytes,
        )
        ciphertext = self._build_aead(key).encrypt(
            nonce,
            plaintext,
            envelope.associated_data(),
        )
        envelope.ciphertext = ciphertext
        self.send_sequence += 1
        return envelope.to_bytes()

    def decrypt(self, blob: bytes) -> bytes:
        envelope = MessageEnvelope.from_bytes(blob)
        if envelope.version != PROTOCOL_VERSION:
            raise ValueError(f"unsupported envelope version: {envelope.version}")
        if envelope.suite != self.suite.value:
            raise ValueError("AEAD suite mismatch")
        if envelope.recipient != self.local_name:
            raise ValueError("message recipient mismatch")
        if envelope.sender != self.remote_name:
            raise ValueError("message sender mismatch")

        def authenticate() -> bytes:
            key, nonce = derive_message_key(
                self.root_key,
                envelope.sequence,
                self.suite.value,
                sender_public_key=self.remote_ephemeral_public_bytes,
                recipient_public_key=self.local_ephemeral_public_bytes,
            )
            return self._build_aead(key).decrypt(
                nonce,
                envelope.ciphertext,
                envelope.associated_data(),
            )

        return self.replay_window.authenticate_and_record(
            envelope.sequence,
            authenticate,
        )


@dataclass(slots=True)
class InitiatorHandshake:
    local_identity: Identity = field(repr=False)
    offer: HandshakeOffer
    supplemental_secret: bytes = field(default=b"", repr=False)
    _ephemeral_private_key: X25519PrivateKey | None = field(
        default=None,
        repr=False,
    )

    @property
    def completed(self) -> bool:
        return self._ephemeral_private_key is None

    def complete(self, response: HandshakeResponse) -> SessionState:
        private_key = self._ephemeral_private_key
        if private_key is None:
            raise RuntimeError("initiator handshake has already been completed")

        response.validate_for_offer(self.offer)
        suite = AeadSuite(response.suite)
        remote_public_key = X25519PublicKey.from_public_bytes(
            response.responder_ephemeral_public_key
        )
        shared_secret = private_key.exchange(remote_public_key)
        transcript_hash = sha256(
            handshake_transcript(self.offer, response)
        ).digest()
        root_key = derive_session_root(
            shared_secret=shared_secret,
            transcript_hash=transcript_hash,
            supplemental_secret=self.supplemental_secret,
        )
        session = SessionState(
            local_name=self.offer.initiator,
            remote_name=self.offer.responder,
            suite=suite,
            root_key=root_key,
            local_ephemeral_public_bytes=self.offer.initiator_ephemeral_public_key,
            remote_ephemeral_public_bytes=response.responder_ephemeral_public_key,
        )
        self._ephemeral_private_key = None
        return session


class SessionFactory:
    @classmethod
    def initiator(
        cls,
        *,
        local_identity: Identity,
        remote_name: str,
        suite: AeadSuite = AeadSuite.AES_GCM_SIV,
        supplemental_secret: bytes = b"",
    ) -> InitiatorHandshake:
        local_ephemeral = X25519PrivateKey.generate()
        offer = HandshakeOffer(
            version=PROTOCOL_VERSION,
            suite=suite.value,
            initiator=local_identity.name,
            responder=remote_name,
            initiator_ephemeral_public_key=(
                local_ephemeral.public_key().public_bytes_raw()
            ),
        )
        return InitiatorHandshake(
            local_identity=local_identity,
            offer=offer,
            supplemental_secret=supplemental_secret,
            _ephemeral_private_key=local_ephemeral,
        )

    @classmethod
    def responder(
        cls,
        *,
        local_identity: Identity,
        offer: HandshakeOffer,
        supplemental_secret: bytes = b"",
    ) -> tuple[HandshakeResponse, SessionState]:
        if local_identity.name != offer.responder:
            raise ValueError("local identity does not match handshake responder")

        suite = AeadSuite(offer.suite)
        local_ephemeral = X25519PrivateKey.generate()
        local_ephemeral_public = local_ephemeral.public_key().public_bytes_raw()
        response = HandshakeResponse.from_offer(
            offer,
            responder_ephemeral_public_key=local_ephemeral_public,
        )
        remote_public_key = X25519PublicKey.from_public_bytes(
            offer.initiator_ephemeral_public_key
        )
        shared_secret = local_ephemeral.exchange(remote_public_key)
        transcript_hash = sha256(handshake_transcript(offer, response)).digest()
        root_key = derive_session_root(
            shared_secret=shared_secret,
            transcript_hash=transcript_hash,
            supplemental_secret=supplemental_secret,
        )
        session = SessionState(
            local_name=offer.responder,
            remote_name=offer.initiator,
            suite=suite,
            root_key=root_key,
            local_ephemeral_public_bytes=local_ephemeral_public,
            remote_ephemeral_public_bytes=offer.initiator_ephemeral_public_key,
        )
        return response, session

    @classmethod
    def pair_for_tests(
        cls,
        *,
        alice: Identity,
        bob: Identity,
        suite: AeadSuite = AeadSuite.AES_GCM_SIV,
        supplemental_secret: bytes = b"",
    ) -> tuple[SessionState, SessionState]:
        pending_alice = cls.initiator(
            local_identity=alice,
            remote_name=bob.name,
            suite=suite,
            supplemental_secret=supplemental_secret,
        )
        response, bob_session = cls.responder(
            local_identity=bob,
            offer=pending_alice.offer,
            supplemental_secret=supplemental_secret,
        )
        alice_session = pending_alice.complete(response)
        return alice_session, bob_session
