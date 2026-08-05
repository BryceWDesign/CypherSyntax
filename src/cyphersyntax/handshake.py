from __future__ import annotations

from dataclasses import dataclass

from .protocol import PROTOCOL_VERSION


X25519_PUBLIC_KEY_LENGTH = 32
ED25519_PUBLIC_KEY_LENGTH = 32
ED25519_SIGNATURE_LENGTH = 64
KEY_CONFIRMATION_LENGTH = 32


def _validate_name(field_name: str, value: str) -> None:
    if not isinstance(value, str):
        raise TypeError(f"{field_name} must be a string")
    if not value:
        raise ValueError(f"{field_name} must not be empty")


def _validate_bytes(field_name: str, value: bytes, expected_length: int) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{field_name} must be bytes")
    if len(value) != expected_length:
        raise ValueError(
            f"{field_name} must be exactly {expected_length} bytes"
        )


def _encode_field(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def _handshake_context(
    *,
    version: int,
    suite: str,
    initiator: str,
    responder: str,
    initiator_ephemeral_public_key: bytes,
    initiator_signing_public_key: bytes,
) -> bytes:
    return b"".join(
        (
            b"CypherSyntax/handshake-offer/v1",
            _encode_field(str(version).encode("ascii")),
            _encode_field(suite.encode("utf-8")),
            _encode_field(initiator.encode("utf-8")),
            _encode_field(responder.encode("utf-8")),
            _encode_field(initiator_ephemeral_public_key),
            _encode_field(initiator_signing_public_key),
        )
    )


@dataclass(frozen=True, slots=True)
class HandshakeOffer:
    version: int
    suite: str
    initiator: str
    responder: str
    initiator_ephemeral_public_key: bytes
    initiator_signing_public_key: bytes
    signature: bytes

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
        _validate_bytes(
            "initiator ephemeral public key",
            self.initiator_ephemeral_public_key,
            X25519_PUBLIC_KEY_LENGTH,
        )
        _validate_bytes(
            "initiator signing public key",
            self.initiator_signing_public_key,
            ED25519_PUBLIC_KEY_LENGTH,
        )
        _validate_bytes(
            "initiator handshake signature",
            self.signature,
            ED25519_SIGNATURE_LENGTH,
        )

    @staticmethod
    def signature_payload_for(
        *,
        version: int,
        suite: str,
        initiator: str,
        responder: str,
        initiator_ephemeral_public_key: bytes,
        initiator_signing_public_key: bytes,
    ) -> bytes:
        return _handshake_context(
            version=version,
            suite=suite,
            initiator=initiator,
            responder=responder,
            initiator_ephemeral_public_key=initiator_ephemeral_public_key,
            initiator_signing_public_key=initiator_signing_public_key,
        )

    def signature_payload(self) -> bytes:
        return self.signature_payload_for(
            version=self.version,
            suite=self.suite,
            initiator=self.initiator,
            responder=self.responder,
            initiator_ephemeral_public_key=self.initiator_ephemeral_public_key,
            initiator_signing_public_key=self.initiator_signing_public_key,
        )


@dataclass(frozen=True, slots=True)
class HandshakeResponse:
    version: int
    suite: str
    initiator: str
    responder: str
    initiator_ephemeral_public_key: bytes
    initiator_signing_public_key: bytes
    responder_ephemeral_public_key: bytes
    responder_signing_public_key: bytes
    responder_key_confirmation: bytes
    signature: bytes

    def __post_init__(self) -> None:
        _validate_offer_fields(
            version=self.version,
            suite=self.suite,
            initiator=self.initiator,
            responder=self.responder,
            initiator_ephemeral_public_key=self.initiator_ephemeral_public_key,
            initiator_signing_public_key=self.initiator_signing_public_key,
        )
        _validate_bytes(
            "responder ephemeral public key",
            self.responder_ephemeral_public_key,
            X25519_PUBLIC_KEY_LENGTH,
        )
        if (
            self.responder_ephemeral_public_key
            == self.initiator_ephemeral_public_key
        ):
            raise ValueError("handshake ephemeral public keys must be distinct")
        _validate_bytes(
            "responder signing public key",
            self.responder_signing_public_key,
            ED25519_PUBLIC_KEY_LENGTH,
        )
        _validate_bytes(
            "responder key confirmation",
            self.responder_key_confirmation,
            KEY_CONFIRMATION_LENGTH,
        )
        _validate_bytes(
            "responder handshake signature",
            self.signature,
            ED25519_SIGNATURE_LENGTH,
        )

    @classmethod
    def from_offer(
        cls,
        offer: HandshakeOffer,
        *,
        responder_ephemeral_public_key: bytes,
        responder_signing_public_key: bytes,
        responder_key_confirmation: bytes,
        signature: bytes,
    ) -> "HandshakeResponse":
        return cls(
            version=offer.version,
            suite=offer.suite,
            initiator=offer.initiator,
            responder=offer.responder,
            initiator_ephemeral_public_key=offer.initiator_ephemeral_public_key,
            initiator_signing_public_key=offer.initiator_signing_public_key,
            responder_ephemeral_public_key=responder_ephemeral_public_key,
            responder_signing_public_key=responder_signing_public_key,
            responder_key_confirmation=responder_key_confirmation,
            signature=signature,
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
        if self.initiator_signing_public_key != offer.initiator_signing_public_key:
            raise ValueError("handshake response initiator signing key mismatch")

    def signature_payload(self, offer: HandshakeOffer) -> bytes:
        transcript = handshake_transcript(offer, self)
        return b"".join(
            (
                b"CypherSyntax/handshake-response-signature/v1",
                _encode_field(transcript),
                _encode_field(self.responder_key_confirmation),
            )
        )


@dataclass(frozen=True, slots=True)
class HandshakeConfirmation:
    version: int
    suite: str
    initiator: str
    responder: str
    initiator_ephemeral_public_key: bytes
    responder_ephemeral_public_key: bytes
    initiator_key_confirmation: bytes
    signature: bytes

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
        _validate_bytes(
            "initiator ephemeral public key",
            self.initiator_ephemeral_public_key,
            X25519_PUBLIC_KEY_LENGTH,
        )
        _validate_bytes(
            "responder ephemeral public key",
            self.responder_ephemeral_public_key,
            X25519_PUBLIC_KEY_LENGTH,
        )
        _validate_bytes(
            "initiator key confirmation",
            self.initiator_key_confirmation,
            KEY_CONFIRMATION_LENGTH,
        )
        _validate_bytes(
            "initiator confirmation signature",
            self.signature,
            ED25519_SIGNATURE_LENGTH,
        )

    def validate_for_response(self, response: HandshakeResponse) -> None:
        if self.version != response.version:
            raise ValueError("handshake confirmation version mismatch")
        if self.suite != response.suite:
            raise ValueError("handshake confirmation suite mismatch")
        if self.initiator != response.initiator:
            raise ValueError("handshake confirmation initiator mismatch")
        if self.responder != response.responder:
            raise ValueError("handshake confirmation responder mismatch")
        if (
            self.initiator_ephemeral_public_key
            != response.initiator_ephemeral_public_key
        ):
            raise ValueError("handshake confirmation initiator key mismatch")
        if (
            self.responder_ephemeral_public_key
            != response.responder_ephemeral_public_key
        ):
            raise ValueError("handshake confirmation responder key mismatch")

    def signature_payload(
        self,
        offer: HandshakeOffer,
        response: HandshakeResponse,
    ) -> bytes:
        self.validate_for_response(response)
        transcript = handshake_transcript(offer, response)
        return b"".join(
            (
                b"CypherSyntax/handshake-confirmation-signature/v1",
                _encode_field(transcript),
                _encode_field(response.responder_key_confirmation),
                _encode_field(self.initiator_key_confirmation),
            )
        )


def _validate_offer_fields(
    *,
    version: int,
    suite: str,
    initiator: str,
    responder: str,
    initiator_ephemeral_public_key: bytes,
    initiator_signing_public_key: bytes,
) -> None:
    if isinstance(version, bool) or not isinstance(version, int):
        raise TypeError("handshake version must be an integer")
    if version != PROTOCOL_VERSION:
        raise ValueError(f"unsupported handshake version: {version}")
    if not isinstance(suite, str):
        raise TypeError("handshake suite must be a string")
    if not suite:
        raise ValueError("handshake suite must not be empty")
    _validate_name("handshake initiator", initiator)
    _validate_name("handshake responder", responder)
    if initiator == responder:
        raise ValueError("handshake participants must be distinct")
    _validate_bytes(
        "initiator ephemeral public key",
        initiator_ephemeral_public_key,
        X25519_PUBLIC_KEY_LENGTH,
    )
    _validate_bytes(
        "initiator signing public key",
        initiator_signing_public_key,
        ED25519_PUBLIC_KEY_LENGTH,
    )


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
            _encode_field(offer.initiator_signing_public_key),
            _encode_field(offer.signature),
            _encode_field(response.responder_ephemeral_public_key),
            _encode_field(response.responder_signing_public_key),
        )
    )
