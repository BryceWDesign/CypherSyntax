from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from cryptography.hazmat.primitives.ciphers.aead import AESGCMSIV, ChaCha20Poly1305
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from .identity import Identity
from .kdf import derive_message_key, derive_session_root
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
        sequence = self.send_sequence
        self.send_sequence += 1
        envelope = MessageEnvelope(
            version=1,
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
        ciphertext = self._build_aead(key).encrypt(nonce, plaintext, envelope.associated_data())
        envelope.ciphertext = ciphertext
        return envelope.to_bytes()

    def decrypt(self, blob: bytes) -> bytes:
        envelope = MessageEnvelope.from_bytes(blob)
        if envelope.version != 1:
            raise ValueError(f"unsupported envelope version: {envelope.version}")
        if envelope.suite != self.suite.value:
            raise ValueError("AEAD suite mismatch")
        if envelope.recipient != self.local_name:
            raise ValueError("message recipient mismatch")
        if envelope.sender != self.remote_name:
            raise ValueError("message sender mismatch")
        self.replay_window.observe(envelope.sequence)
        key, nonce = derive_message_key(
            self.root_key,
            envelope.sequence,
            self.suite.value,
            sender_public_key=self.remote_ephemeral_public_bytes,
            recipient_public_key=self.local_ephemeral_public_bytes,
        )
        return self._build_aead(key).decrypt(nonce, envelope.ciphertext, envelope.associated_data())


class SessionFactory:
    @staticmethod
    def _canonical_transcript(public_a: bytes, public_b: bytes) -> bytes:
        first, second = sorted((public_a, public_b))
        return b"CypherSyntax/transcript/v1|" + first + b"|" + second

    @staticmethod
    def _make_root(
        *,
        local_private_key: X25519PrivateKey,
        remote_public_key_bytes: bytes,
        local_ephemeral_public_bytes: bytes,
        remote_ephemeral_public_bytes: bytes,
        supplemental_secret: bytes = b"",
    ) -> bytes:
        remote_public_key = X25519PublicKey.from_public_bytes(remote_public_key_bytes)
        shared_secret = local_private_key.exchange(remote_public_key)
        transcript_hash = SessionFactory._canonical_transcript(
            local_ephemeral_public_bytes,
            remote_ephemeral_public_bytes,
        )
        return derive_session_root(
            shared_secret=shared_secret,
            transcript_hash=transcript_hash,
            supplemental_secret=supplemental_secret,
        )

    @classmethod
    def initiator(
        cls,
        *,
        local_identity: Identity,
        remote_name: str,
        remote_x25519_public_key: bytes,
        suite: AeadSuite = AeadSuite.AES_GCM_SIV,
        supplemental_secret: bytes = b"",
    ) -> SessionState:
        local_ephemeral = X25519PrivateKey.generate()
        local_ephemeral_public_bytes = local_ephemeral.public_key().public_bytes_raw()
        root_key = cls._make_root(
            local_private_key=local_ephemeral,
            remote_public_key_bytes=remote_x25519_public_key,
            local_ephemeral_public_bytes=local_ephemeral_public_bytes,
            remote_ephemeral_public_bytes=remote_x25519_public_key,
            supplemental_secret=supplemental_secret,
        )
        return SessionState(
            local_name=local_identity.name,
            remote_name=remote_name,
            suite=suite,
            root_key=root_key,
            local_ephemeral_public_bytes=local_ephemeral_public_bytes,
            remote_ephemeral_public_bytes=remote_x25519_public_key,
        )

    @classmethod
    def responder(
        cls,
        *,
        local_identity: Identity,
        remote_name: str,
        remote_x25519_public_key: bytes,
        peer_ephemeral_public_key: bytes,
        suite: AeadSuite = AeadSuite.AES_GCM_SIV,
        supplemental_secret: bytes = b"",
    ) -> SessionState:
        root_key = cls._make_root(
            local_private_key=local_identity.exchange_private_key,
            remote_public_key_bytes=peer_ephemeral_public_key,
            local_ephemeral_public_bytes=local_identity.x25519_public_bytes(),
            remote_ephemeral_public_bytes=peer_ephemeral_public_key,
            supplemental_secret=supplemental_secret,
        )
        return SessionState(
            local_name=local_identity.name,
            remote_name=remote_name,
            suite=suite,
            root_key=root_key,
            local_ephemeral_public_bytes=local_identity.x25519_public_bytes(),
            remote_ephemeral_public_bytes=peer_ephemeral_public_key,
        )

    @classmethod
    def pair_for_tests(
        cls,
        *,
        alice: Identity,
        bob: Identity,
        suite: AeadSuite = AeadSuite.AES_GCM_SIV,
        supplemental_secret: bytes = b"",
    ) -> tuple[SessionState, SessionState]:
        alice_ephemeral = X25519PrivateKey.generate()
        bob_ephemeral = X25519PrivateKey.generate()
        alice_ephemeral_public = alice_ephemeral.public_key().public_bytes_raw()
        bob_ephemeral_public = bob_ephemeral.public_key().public_bytes_raw()

        alice_root = cls._make_root(
            local_private_key=alice_ephemeral,
            remote_public_key_bytes=bob_ephemeral_public,
            local_ephemeral_public_bytes=alice_ephemeral_public,
            remote_ephemeral_public_bytes=bob_ephemeral_public,
            supplemental_secret=supplemental_secret,
        )
        bob_root = cls._make_root(
            local_private_key=bob_ephemeral,
            remote_public_key_bytes=alice_ephemeral_public,
            local_ephemeral_public_bytes=bob_ephemeral_public,
            remote_ephemeral_public_bytes=alice_ephemeral_public,
            supplemental_secret=supplemental_secret,
        )
        alice_state = SessionState(
            local_name=alice.name,
            remote_name=bob.name,
            suite=suite,
            root_key=alice_root,
            local_ephemeral_public_bytes=alice_ephemeral_public,
            remote_ephemeral_public_bytes=bob_ephemeral_public,
        )
        bob_state = SessionState(
            local_name=bob.name,
            remote_name=alice.name,
            suite=suite,
            root_key=bob_root,
            local_ephemeral_public_bytes=bob_ephemeral_public,
            remote_ephemeral_public_bytes=alice_ephemeral_public,
        )
        return alice_state, bob_state
