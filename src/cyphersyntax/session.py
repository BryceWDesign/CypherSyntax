from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
import hmac
from hashlib import sha256

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from .errors import InvalidSignatureError, KeyConfirmationError
from .handshake import (
    HandshakeConfirmation,
    HandshakeOffer,
    HandshakeResponse,
    handshake_transcript,
)
from .identity import Identity
from .kdf import derive_key_confirmation, derive_message_key, derive_session_root
from .protocol import (
    MAX_MESSAGE_SEQUENCE,
    MAX_PLAINTEXT_BYTES,
    PROTOCOL_VERSION,
    validate_message_sequence,
)
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
    root_key: bytes = field(repr=False)
    local_ephemeral_public_bytes: bytes
    remote_ephemeral_public_bytes: bytes
    send_sequence: int = 0
    replay_window: ReplayWindow = field(default_factory=ReplayWindow)

    def _build_aead(self, key: bytes) -> AESGCMSIV | ChaCha20Poly1305:
        if self.suite == AeadSuite.AES_GCM_SIV:
            return AESGCMSIV(key)
        if self.suite == AeadSuite.CHACHA20_POLY1305:
            return ChaCha20Poly1305(key)
        raise ValueError(f"unsupported suite: {self.suite}")

    def encrypt(self, plaintext: bytes) -> bytes:
        if type(plaintext) is not bytes:
            raise TypeError("plaintext must be bytes")
        if len(plaintext) > MAX_PLAINTEXT_BYTES:
            raise ValueError("plaintext exceeds the maximum message size")
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
    remote_signing_public_key: bytes = field(repr=False)
    offer: HandshakeOffer
    supplemental_secret: bytes = field(default=b"", repr=False)
    _ephemeral_private_key: X25519PrivateKey | None = field(
        default=None,
        repr=False,
    )

    @property
    def completed(self) -> bool:
        return self._ephemeral_private_key is None

    def complete(
        self,
        response: HandshakeResponse,
    ) -> tuple[HandshakeConfirmation, SessionState]:
        private_key = self._ephemeral_private_key
        if private_key is None:
            raise RuntimeError("initiator handshake has already been completed")

        response.validate_for_offer(self.offer)
        if response.responder_signing_public_key != self.remote_signing_public_key:
            raise InvalidSignatureError("responder signing key does not match trust anchor")
        Identity.verify_signature(
            response.signature_payload(self.offer),
            response.signature,
            self.remote_signing_public_key,
        )

        suite = AeadSuite(response.suite)
        remote_public_key = X25519PublicKey.from_public_bytes(
            response.responder_ephemeral_public_key
        )
        shared_secret = private_key.exchange(remote_public_key)
        transcript_hash = sha256(handshake_transcript(self.offer, response)).digest()
        root_key = derive_session_root(
            shared_secret=shared_secret,
            transcript_hash=transcript_hash,
            supplemental_secret=self.supplemental_secret,
        )
        expected_responder_confirmation = derive_key_confirmation(
            root_key,
            transcript_hash,
            role="responder",
        )
        if not hmac.compare_digest(
            response.responder_key_confirmation,
            expected_responder_confirmation,
        ):
            raise KeyConfirmationError("responder key confirmation failed")

        initiator_key_confirmation = derive_key_confirmation(
            root_key,
            transcript_hash,
            role="initiator",
        )
        unsigned_confirmation = HandshakeConfirmation(
            version=response.version,
            suite=response.suite,
            initiator=response.initiator,
            responder=response.responder,
            initiator_ephemeral_public_key=(
                response.initiator_ephemeral_public_key
            ),
            responder_ephemeral_public_key=(
                response.responder_ephemeral_public_key
            ),
            initiator_key_confirmation=initiator_key_confirmation,
            signature=b"\x00" * 64,
        )
        confirmation = HandshakeConfirmation(
            version=unsigned_confirmation.version,
            suite=unsigned_confirmation.suite,
            initiator=unsigned_confirmation.initiator,
            responder=unsigned_confirmation.responder,
            initiator_ephemeral_public_key=(
                unsigned_confirmation.initiator_ephemeral_public_key
            ),
            responder_ephemeral_public_key=(
                unsigned_confirmation.responder_ephemeral_public_key
            ),
            initiator_key_confirmation=(
                unsigned_confirmation.initiator_key_confirmation
            ),
            signature=self.local_identity.sign(
                unsigned_confirmation.signature_payload(self.offer, response)
            ),
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
        return confirmation, session


@dataclass(slots=True)
class ResponderHandshake:
    remote_signing_public_key: bytes = field(repr=False)
    offer: HandshakeOffer
    response: HandshakeResponse
    suite: AeadSuite
    _root_key: bytes | None = field(default=None, repr=False)

    @property
    def completed(self) -> bool:
        return self._root_key is None

    def complete(self, confirmation: HandshakeConfirmation) -> SessionState:
        root_key = self._root_key
        if root_key is None:
            raise RuntimeError("responder handshake has already been completed")

        confirmation.validate_for_response(self.response)
        Identity.verify_signature(
            confirmation.signature_payload(self.offer, self.response),
            confirmation.signature,
            self.remote_signing_public_key,
        )
        transcript_hash = sha256(
            handshake_transcript(self.offer, self.response)
        ).digest()
        expected_confirmation = derive_key_confirmation(
            root_key,
            transcript_hash,
            role="initiator",
        )
        if not hmac.compare_digest(
            confirmation.initiator_key_confirmation,
            expected_confirmation,
        ):
            raise KeyConfirmationError("initiator key confirmation failed")

        session = SessionState(
            local_name=self.offer.responder,
            remote_name=self.offer.initiator,
            suite=self.suite,
            root_key=root_key,
            local_ephemeral_public_bytes=(
                self.response.responder_ephemeral_public_key
            ),
            remote_ephemeral_public_bytes=(
                self.offer.initiator_ephemeral_public_key
            ),
        )
        self._root_key = None
        return session


class SessionFactory:
    @classmethod
    def initiator(
        cls,
        *,
        local_identity: Identity,
        remote_name: str,
        remote_signing_public_key: bytes,
        suite: AeadSuite = AeadSuite.AES_GCM_SIV,
        supplemental_secret: bytes = b"",
    ) -> InitiatorHandshake:
        local_ephemeral = X25519PrivateKey.generate()
        local_ephemeral_public = local_ephemeral.public_key().public_bytes_raw()
        local_signing_public = local_identity.ed25519_public_bytes()
        signature_payload = HandshakeOffer.signature_payload_for(
            version=PROTOCOL_VERSION,
            suite=suite.value,
            initiator=local_identity.name,
            responder=remote_name,
            initiator_ephemeral_public_key=local_ephemeral_public,
            initiator_signing_public_key=local_signing_public,
        )
        offer = HandshakeOffer(
            version=PROTOCOL_VERSION,
            suite=suite.value,
            initiator=local_identity.name,
            responder=remote_name,
            initiator_ephemeral_public_key=local_ephemeral_public,
            initiator_signing_public_key=local_signing_public,
            signature=local_identity.sign(signature_payload),
        )
        return InitiatorHandshake(
            local_identity=local_identity,
            remote_signing_public_key=remote_signing_public_key,
            offer=offer,
            supplemental_secret=supplemental_secret,
            _ephemeral_private_key=local_ephemeral,
        )

    @classmethod
    def responder(
        cls,
        *,
        local_identity: Identity,
        remote_signing_public_key: bytes,
        offer: HandshakeOffer,
        supplemental_secret: bytes = b"",
    ) -> tuple[HandshakeResponse, ResponderHandshake]:
        if local_identity.name != offer.responder:
            raise ValueError("local identity does not match handshake responder")
        if offer.initiator_signing_public_key != remote_signing_public_key:
            raise InvalidSignatureError("initiator signing key does not match trust anchor")
        Identity.verify_signature(
            offer.signature_payload(),
            offer.signature,
            remote_signing_public_key,
        )

        suite = AeadSuite(offer.suite)
        local_ephemeral = X25519PrivateKey.generate()
        local_ephemeral_public = local_ephemeral.public_key().public_bytes_raw()
        local_signing_public = local_identity.ed25519_public_bytes()
        remote_public_key = X25519PublicKey.from_public_bytes(
            offer.initiator_ephemeral_public_key
        )
        shared_secret = local_ephemeral.exchange(remote_public_key)

        provisional_response = HandshakeResponse.from_offer(
            offer,
            responder_ephemeral_public_key=local_ephemeral_public,
            responder_signing_public_key=local_signing_public,
            responder_key_confirmation=b"\x00" * 32,
            signature=b"\x00" * 64,
        )
        transcript_hash = sha256(
            handshake_transcript(offer, provisional_response)
        ).digest()
        root_key = derive_session_root(
            shared_secret=shared_secret,
            transcript_hash=transcript_hash,
            supplemental_secret=supplemental_secret,
        )
        responder_key_confirmation = derive_key_confirmation(
            root_key,
            transcript_hash,
            role="responder",
        )
        unsigned_response = HandshakeResponse.from_offer(
            offer,
            responder_ephemeral_public_key=local_ephemeral_public,
            responder_signing_public_key=local_signing_public,
            responder_key_confirmation=responder_key_confirmation,
            signature=b"\x00" * 64,
        )
        response = HandshakeResponse.from_offer(
            offer,
            responder_ephemeral_public_key=local_ephemeral_public,
            responder_signing_public_key=local_signing_public,
            responder_key_confirmation=responder_key_confirmation,
            signature=local_identity.sign(
                unsigned_response.signature_payload(offer)
            ),
        )
        pending = ResponderHandshake(
            remote_signing_public_key=remote_signing_public_key,
            offer=offer,
            response=response,
            suite=suite,
            _root_key=root_key,
        )
        return response, pending

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
            remote_signing_public_key=bob.ed25519_public_bytes(),
            suite=suite,
            supplemental_secret=supplemental_secret,
        )
        response, pending_bob = cls.responder(
            local_identity=bob,
            remote_signing_public_key=alice.ed25519_public_bytes(),
            offer=pending_alice.offer,
            supplemental_secret=supplemental_secret,
        )
        confirmation, alice_session = pending_alice.complete(response)
        bob_session = pending_bob.complete(confirmation)
        return alice_session, bob_session
