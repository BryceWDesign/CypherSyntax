from __future__ import annotations

from dataclasses import dataclass

from .protocol import PROTOCOL_VERSION


X25519_PUBLIC_KEY_LENGTH = 32


def _validate_name(field_name: str, value: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not value:
        raise ValueError(f"{field_name} must not be empty")


def _validate_public_key(field_name: str, value: bytes) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{field_name} must be bytes")
    if len(value) != X25519_PUBLIC_KEY_LENGTH:
        raise ValueError(
            f"{field_name} must be exactly {X25519_PUBLIC_KEY_LENGTH} bytes"
        )


def _encode_field(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


@dataclass(frozen=True, slots=True)
class HandshakeOffer:
    version: int
    suite: str
    initiator: str
    responder: str
    initiator_ephemeral_public_key: bytes

    def __post_init__(self) -> None:
        if isinstance(self.version, bool) or not isinstance(self.version, int):
            raise TypeError("handshake version must be an integer")
        if self.version != PROTOCOL_VERSION:
            raise ValueError(f"unsupported handshake version: {self.version}")
        if not isinstance(self.suite, str):
            raise TypeError("handshake suite must be a string")
        if not self.suite:
            raise ValueError("handshake suite must not be empty")
        _validate_name("handshake initiator", self.initiator)
        _validate_name("handshake responder", self.responder)
        if self.initiator == self.responder:
            raise ValueError("handshake participants must be distinct")
        _validate_public_key(
            "initiator ephemeral public key",
            self.initiator_ephemeral_public_key,
        )


@dataclass(frozen=True, slots=True)
class HandshakeResponse:
    version: int
    suite: str
    initiator: str
    responder: str
    initiator_ephemeral_public_key: bytes
    responder_ephemeral_public_key: bytes

    def __post_init__(self) -> None:
        HandshakeOffer(
            version=self.version,
            suite=self.suite,
            initiator=self.initiator,
            responder=self.responder,
            initiator_ephemeral_public_key=self.initiator_ephemeral_public_key,
        )
        _validate_public_key(
            "responder ephemeral public key",
            self.responder_ephemeral_public_key,
        )
        if (
            self.responder_ephemeral_public_key
            == self.initiator_ephemeral_public_key
        ):
            raise ValueError("handshake ephemeral public keys must be distinct")

    @classmethod
    def from_offer(
        cls,
        offer: HandshakeOffer,
        *,
        responder_ephemeral_public_key: bytes,
    ) -> "HandshakeResponse":
        return cls(
            version=offer.version,
            suite=offer.suite,
            initiator=offer.initiator,
            responder=offer.responder,
            initiator_ephemeral_public_key=offer.initiator_ephemeral_public_key,
            responder_ephemeral_public_key=responder_ephemeral_public_key,
        )

    def validate_for_offer(self, offer: HandshakeOffer) -> None:
        if self.version != offer.version:
            raise ValueError("handshake response version mismatch")
        if self.suite != offer.suite:
            raise ValueError("handshake response suite mismatch")
        if self.initiator != offer.initiator:
            raise ValueError("handshake response initiator mismatch")
        if self.responder != offer.responder:
            raise ValueError("handshake response responder mismatch")
        if (
            self.initiator_ephemeral_public_key
            != offer.initiator_ephemeral_public_key
        ):
            raise ValueError("handshake response initiator key mismatch")


def handshake_transcript(
    offer: HandshakeOffer,
    response: HandshakeResponse,
) -> bytes:
    response.validate_for_offer(offer)
    return b"".join(
        (
            b"CypherSyntax/handshake-transcript/v1",
            _encode_field(str(offer.version).encode("ascii")),
            _encode_field(offer.suite.encode("utf-8")),
            _encode_field(offer.initiator.encode("utf-8")),
            _encode_field(offer.responder.encode("utf-8")),
            _encode_field(offer.initiator_ephemeral_public_key),
            _encode_field(response.responder_ephemeral_public_key),
        )
    )
