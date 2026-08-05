from __future__ import annotations

from dataclasses import dataclass
import json
from typing import Any, ClassVar

from .errors import HandshakeError
from .protocol import MAX_PARTICIPANT_NAME_BYTES, PROTOCOL_VERSION


X25519_PUBLIC_KEY_LENGTH = 32
ED25519_PUBLIC_KEY_LENGTH = 32
ED25519_SIGNATURE_LENGTH = 64
KEY_CONFIRMATION_LENGTH = 32
MAX_HANDSHAKE_MESSAGE_BYTES = 4096
SUPPORTED_HANDSHAKE_SUITES = frozenset(
    {"AES_GCM_SIV", "CHACHA20_POLY1305"}
)

_OFFER_KIND = "offer"
_RESPONSE_KIND = "response"
_CONFIRMATION_KIND = "confirmation"
_COMMON_FIELDS = frozenset({"kind", "v", "suite", "initiator", "responder"})
_OFFER_FIELDS = _COMMON_FIELDS | frozenset(
    {
        "initiator_ephemeral_public_key",
        "initiator_signing_public_key",
        "signature",
    }
)
_RESPONSE_FIELDS = _OFFER_FIELDS | frozenset(
    {
        "responder_ephemeral_public_key",
        "responder_signing_public_key",
        "responder_key_confirmation",
    }
)
_CONFIRMATION_FIELDS = _COMMON_FIELDS | frozenset(
    {
        "initiator_ephemeral_public_key",
        "responder_ephemeral_public_key",
        "initiator_key_confirmation",
        "signature",
    }
)


def _validate_version(value: object) -> int:
    if type(value) is not int:
        raise TypeError("handshake version must be an integer")
    if value != PROTOCOL_VERSION:
        raise ValueError(f"unsupported handshake version: {value}")
    return value


def _validate_suite(value: object) -> str:
    if type(value) is not str:
        raise TypeError("handshake suite must be a string")
    if value not in SUPPORTED_HANDSHAKE_SUITES:
        raise ValueError(f"unsupported handshake suite: {value}")
    return value


def _validate_name(field_name: str, value: object) -> str:
    if type(value) is not str:
        raise TypeError(f"{field_name} must be a string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError(f"{field_name} must contain valid Unicode") from exc
    if not encoded or len(encoded) > MAX_PARTICIPANT_NAME_BYTES:
        raise ValueError(
            f"{field_name} must contain 1 to "
            f"{MAX_PARTICIPANT_NAME_BYTES} UTF-8 bytes"
        )
    if value != value.strip():
        raise ValueError(f"{field_name} must not contain surrounding whitespace")
    if not value.isprintable():
        raise ValueError(f"{field_name} must contain only printable characters")
    return value


def _validate_bytes(field_name: str, value: object, expected_length: int) -> bytes:
    if type(value) is not bytes:
        raise TypeError(f"{field_name} must be bytes")
    if len(value) != expected_length:
        raise ValueError(
            f"{field_name} must be exactly {expected_length} bytes"
        )
    return value


def _validate_participants(initiator: object, responder: object) -> tuple[str, str]:
    validated_initiator = _validate_name("handshake initiator", initiator)
    validated_responder = _validate_name("handshake responder", responder)
    if validated_initiator == validated_responder:
        raise ValueError("handshake participants must be distinct")
    return validated_initiator, validated_responder


def _encode_field(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def _encode_message(payload: dict[str, object]) -> bytes:
    encoded = json.dumps(
        payload,
        ensure_ascii=False,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(encoded) > MAX_HANDSHAKE_MESSAGE_BYTES:
        raise HandshakeError("encoded handshake message exceeds the maximum size")
    return encoded


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise HandshakeError(f"duplicate handshake field: {key}")
        result[key] = value
    return result


def _reject_nonfinite_number(value: str) -> None:
    raise HandshakeError(f"non-finite handshake number is not permitted: {value}")


def _parse_message(
    data: bytes,
    *,
    expected_kind: str,
    expected_fields: frozenset[str],
) -> dict[str, Any]:
    if type(data) is not bytes:
        raise HandshakeError("handshake message input must be bytes")
    if not data:
        raise HandshakeError("handshake message input must not be empty")
    if len(data) > MAX_HANDSHAKE_MESSAGE_BYTES:
        raise HandshakeError("handshake message input exceeds the maximum size")
    try:
        raw = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_nonfinite_number,
        )
    except HandshakeError:
        raise
    except (
        UnicodeDecodeError,
        json.JSONDecodeError,
        RecursionError,
        ValueError,
    ) as exc:
        raise HandshakeError("failed to parse handshake message") from exc

    if type(raw) is not dict:
        raise HandshakeError("handshake message must be a JSON object")

    if "kind" in raw and (
        type(raw["kind"]) is not str or raw["kind"] != expected_kind
    ):
        raise HandshakeError(
            f"expected handshake message kind {expected_kind!r}"
        )

    received_fields = frozenset(raw)
    missing_fields = sorted(expected_fields - received_fields)
    unexpected_fields = sorted(received_fields - expected_fields)
    if missing_fields:
        raise HandshakeError(
            f"handshake message is missing fields: {', '.join(missing_fields)}"
        )
    if unexpected_fields:
        raise HandshakeError(
            "handshake message contains unexpected fields: "
            f"{', '.join(unexpected_fields)}"
        )
    return raw


def _decode_hex(field_name: str, value: object, expected_length: int) -> bytes:
    if type(value) is not str:
        raise HandshakeError(f"handshake {field_name} encoding must be a string")
    if len(value) != expected_length * 2:
        raise HandshakeError(
            f"handshake {field_name} must encode exactly {expected_length} bytes"
        )
    if any(character not in "0123456789abcdef" for character in value):
        raise HandshakeError(
            f"handshake {field_name} must use canonical lowercase hexadecimal"
        )
    return bytes.fromhex(value)


def _construct_and_verify_canonical(
    data: bytes,
    constructor: type[_HandshakeMessage],
    values: dict[str, object],
) -> _HandshakeMessage:
    try:
        message = constructor(**values)
    except (TypeError, ValueError) as exc:
        raise HandshakeError("handshake message contains invalid field values") from exc
    if message.to_bytes() != data:
        raise HandshakeError("handshake message is not canonically encoded")
    return message


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


class _HandshakeMessage:
    _kind: ClassVar[str]

    def to_bytes(self) -> bytes:
        raise NotImplementedError


@dataclass(frozen=True, slots=True)
class HandshakeOffer(_HandshakeMessage):
    version: int
    suite: str
    initiator: str
    responder: str
    initiator_ephemeral_public_key: bytes
    initiator_signing_public_key: bytes
    signature: bytes

    _kind: ClassVar[str] = _OFFER_KIND

    def __post_init__(self) -> None:
        _validate_version(self.version)
        _validate_suite(self.suite)
        _validate_participants(self.initiator, self.responder)
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
        _validate_offer_fields(
            version=version,
            suite=suite,
            initiator=initiator,
            responder=responder,
            initiator_ephemeral_public_key=initiator_ephemeral_public_key,
            initiator_signing_public_key=initiator_signing_public_key,
        )
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

    def to_bytes(self) -> bytes:
        return _encode_message(
            {
                "kind": self._kind,
                "v": self.version,
                "suite": self.suite,
                "initiator": self.initiator,
                "responder": self.responder,
                "initiator_ephemeral_public_key": (
                    self.initiator_ephemeral_public_key.hex()
                ),
                "initiator_signing_public_key": (
                    self.initiator_signing_public_key.hex()
                ),
                "signature": self.signature.hex(),
            }
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> HandshakeOffer:
        raw = _parse_message(
            data,
            expected_kind=cls._kind,
            expected_fields=_OFFER_FIELDS,
        )
        message = _construct_and_verify_canonical(
            data,
            cls,
            {
                "version": raw["v"],
                "suite": raw["suite"],
                "initiator": raw["initiator"],
                "responder": raw["responder"],
                "initiator_ephemeral_public_key": _decode_hex(
                    "initiator ephemeral public key",
                    raw["initiator_ephemeral_public_key"],
                    X25519_PUBLIC_KEY_LENGTH,
                ),
                "initiator_signing_public_key": _decode_hex(
                    "initiator signing public key",
                    raw["initiator_signing_public_key"],
                    ED25519_PUBLIC_KEY_LENGTH,
                ),
                "signature": _decode_hex(
                    "initiator handshake signature",
                    raw["signature"],
                    ED25519_SIGNATURE_LENGTH,
                ),
            },
        )
        if not isinstance(message, cls):
            raise AssertionError("unexpected handshake message type")
        return message


@dataclass(frozen=True, slots=True)
class HandshakeResponse(_HandshakeMessage):
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

    _kind: ClassVar[str] = _RESPONSE_KIND

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
        if self.responder_ephemeral_public_key == self.initiator_ephemeral_public_key:
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
    ) -> HandshakeResponse:
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
        if self.initiator_ephemeral_public_key != offer.initiator_ephemeral_public_key:
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

    def to_bytes(self) -> bytes:
        return _encode_message(
            {
                "kind": self._kind,
                "v": self.version,
                "suite": self.suite,
                "initiator": self.initiator,
                "responder": self.responder,
                "initiator_ephemeral_public_key": (
                    self.initiator_ephemeral_public_key.hex()
                ),
                "initiator_signing_public_key": (
                    self.initiator_signing_public_key.hex()
                ),
                "responder_ephemeral_public_key": (
                    self.responder_ephemeral_public_key.hex()
                ),
                "responder_signing_public_key": (
                    self.responder_signing_public_key.hex()
                ),
                "responder_key_confirmation": (
                    self.responder_key_confirmation.hex()
                ),
                "signature": self.signature.hex(),
            }
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> HandshakeResponse:
        raw = _parse_message(
            data,
            expected_kind=cls._kind,
            expected_fields=_RESPONSE_FIELDS,
        )
        message = _construct_and_verify_canonical(
            data,
            cls,
            {
                "version": raw["v"],
                "suite": raw["suite"],
                "initiator": raw["initiator"],
                "responder": raw["responder"],
                "initiator_ephemeral_public_key": _decode_hex(
                    "initiator ephemeral public key",
                    raw["initiator_ephemeral_public_key"],
                    X25519_PUBLIC_KEY_LENGTH,
                ),
                "initiator_signing_public_key": _decode_hex(
                    "initiator signing public key",
                    raw["initiator_signing_public_key"],
                    ED25519_PUBLIC_KEY_LENGTH,
                ),
                "responder_ephemeral_public_key": _decode_hex(
                    "responder ephemeral public key",
                    raw["responder_ephemeral_public_key"],
                    X25519_PUBLIC_KEY_LENGTH,
                ),
                "responder_signing_public_key": _decode_hex(
                    "responder signing public key",
                    raw["responder_signing_public_key"],
                    ED25519_PUBLIC_KEY_LENGTH,
                ),
                "responder_key_confirmation": _decode_hex(
                    "responder key confirmation",
                    raw["responder_key_confirmation"],
                    KEY_CONFIRMATION_LENGTH,
                ),
                "signature": _decode_hex(
                    "responder handshake signature",
                    raw["signature"],
                    ED25519_SIGNATURE_LENGTH,
                ),
            },
        )
        if not isinstance(message, cls):
            raise AssertionError("unexpected handshake message type")
        return message


@dataclass(frozen=True, slots=True)
class HandshakeConfirmation(_HandshakeMessage):
    version: int
    suite: str
    initiator: str
    responder: str
    initiator_ephemeral_public_key: bytes
    responder_ephemeral_public_key: bytes
    initiator_key_confirmation: bytes
    signature: bytes

    _kind: ClassVar[str] = _CONFIRMATION_KIND

    def __post_init__(self) -> None:
        _validate_version(self.version)
        _validate_suite(self.suite)
        _validate_participants(self.initiator, self.responder)
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
        if self.responder_ephemeral_public_key == self.initiator_ephemeral_public_key:
            raise ValueError("handshake ephemeral public keys must be distinct")
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
        if self.initiator_ephemeral_public_key != response.initiator_ephemeral_public_key:
            raise ValueError("handshake confirmation initiator key mismatch")
        if self.responder_ephemeral_public_key != response.responder_ephemeral_public_key:
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

    def to_bytes(self) -> bytes:
        return _encode_message(
            {
                "kind": self._kind,
                "v": self.version,
                "suite": self.suite,
                "initiator": self.initiator,
                "responder": self.responder,
                "initiator_ephemeral_public_key": (
                    self.initiator_ephemeral_public_key.hex()
                ),
                "responder_ephemeral_public_key": (
                    self.responder_ephemeral_public_key.hex()
                ),
                "initiator_key_confirmation": (
                    self.initiator_key_confirmation.hex()
                ),
                "signature": self.signature.hex(),
            }
        )

    @classmethod
    def from_bytes(cls, data: bytes) -> HandshakeConfirmation:
        raw = _parse_message(
            data,
            expected_kind=cls._kind,
            expected_fields=_CONFIRMATION_FIELDS,
        )
        message = _construct_and_verify_canonical(
            data,
            cls,
            {
                "version": raw["v"],
                "suite": raw["suite"],
                "initiator": raw["initiator"],
                "responder": raw["responder"],
                "initiator_ephemeral_public_key": _decode_hex(
                    "initiator ephemeral public key",
                    raw["initiator_ephemeral_public_key"],
                    X25519_PUBLIC_KEY_LENGTH,
                ),
                "responder_ephemeral_public_key": _decode_hex(
                    "responder ephemeral public key",
                    raw["responder_ephemeral_public_key"],
                    X25519_PUBLIC_KEY_LENGTH,
                ),
                "initiator_key_confirmation": _decode_hex(
                    "initiator key confirmation",
                    raw["initiator_key_confirmation"],
                    KEY_CONFIRMATION_LENGTH,
                ),
                "signature": _decode_hex(
                    "initiator confirmation signature",
                    raw["signature"],
                    ED25519_SIGNATURE_LENGTH,
                ),
            },
        )
        if not isinstance(message, cls):
            raise AssertionError("unexpected handshake message type")
        return message


def _validate_offer_fields(
    *,
    version: int,
    suite: str,
    initiator: str,
    responder: str,
    initiator_ephemeral_public_key: bytes,
    initiator_signing_public_key: bytes,
) -> None:
    _validate_version(version)
    _validate_suite(suite)
    _validate_participants(initiator, responder)
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
