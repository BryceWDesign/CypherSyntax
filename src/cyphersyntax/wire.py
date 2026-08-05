from __future__ import annotations

from dataclasses import dataclass
import json
import re
from typing import Any

from .errors import EnvelopeError
from .protocol import (
    AEAD_TAG_BYTES,
    MAX_CIPHERTEXT_BYTES,
    MAX_ENVELOPE_BYTES,
    MAX_PARTICIPANT_NAME_BYTES,
    MAX_PROTOCOL_VERSION,
    MAX_SUITE_NAME_BYTES,
    validate_message_sequence,
)


_ENVELOPE_FIELDS = frozenset(
    {"v", "suite", "sender", "recipient", "sequence", "ciphertext"}
)
_SUITE_PATTERN = re.compile(r"[A-Z][A-Z0-9_]*\Z")
_HEX_PATTERN = re.compile(r"[0-9a-f]+\Z")


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise EnvelopeError(f"duplicate envelope field: {key}")
        result[key] = value
    return result


def _validate_protocol_version(version: object) -> int:
    if type(version) is not int:
        raise EnvelopeError("envelope version must be an integer")
    if not 1 <= version <= MAX_PROTOCOL_VERSION:
        raise EnvelopeError("envelope version is outside the supported wire range")
    return version


def _validate_suite_name(suite: object) -> str:
    if type(suite) is not str:
        raise EnvelopeError("envelope suite must be a string")
    try:
        encoded = suite.encode("ascii")
    except UnicodeEncodeError as exc:
        raise EnvelopeError("envelope suite must contain only ASCII characters") from exc
    if not encoded or len(encoded) > MAX_SUITE_NAME_BYTES:
        raise EnvelopeError(
            f"envelope suite must contain 1 to {MAX_SUITE_NAME_BYTES} bytes"
        )
    if _SUITE_PATTERN.fullmatch(suite) is None:
        raise EnvelopeError("envelope suite contains invalid characters")
    return suite


def _validate_participant_name(field_name: str, value: object) -> str:
    if type(value) is not str:
        raise EnvelopeError(f"envelope {field_name} must be a string")
    try:
        encoded = value.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise EnvelopeError(
            f"envelope {field_name} must contain valid Unicode"
        ) from exc
    if not encoded or len(encoded) > MAX_PARTICIPANT_NAME_BYTES:
        raise EnvelopeError(
            f"envelope {field_name} must contain 1 to "
            f"{MAX_PARTICIPANT_NAME_BYTES} UTF-8 bytes"
        )
    if value != value.strip():
        raise EnvelopeError(
            f"envelope {field_name} must not contain surrounding whitespace"
        )
    if not value.isprintable():
        raise EnvelopeError(
            f"envelope {field_name} must contain only printable characters"
        )
    return value


def _validate_ciphertext(ciphertext: object) -> bytes:
    if type(ciphertext) is not bytes:
        raise EnvelopeError("envelope ciphertext must be bytes")
    if len(ciphertext) < AEAD_TAG_BYTES:
        raise EnvelopeError("envelope ciphertext is shorter than the AEAD tag")
    if len(ciphertext) > MAX_CIPHERTEXT_BYTES:
        raise EnvelopeError("envelope ciphertext exceeds the maximum size")
    return ciphertext


def _decode_ciphertext(value: object) -> bytes:
    if type(value) is not str:
        raise EnvelopeError("envelope ciphertext encoding must be a string")
    if len(value) % 2 != 0:
        raise EnvelopeError("envelope ciphertext must contain an even number of hex digits")
    if _HEX_PATTERN.fullmatch(value) is None:
        raise EnvelopeError("envelope ciphertext must use canonical lowercase hexadecimal")
    try:
        return bytes.fromhex(value)
    except ValueError as exc:
        raise EnvelopeError("envelope ciphertext is not valid hexadecimal") from exc


@dataclass(slots=True)
class MessageEnvelope:
    version: int
    suite: str
    sender: str
    recipient: str
    sequence: int
    ciphertext: bytes

    def _validate_metadata(self) -> None:
        _validate_protocol_version(self.version)
        _validate_suite_name(self.suite)
        sender = _validate_participant_name("sender", self.sender)
        recipient = _validate_participant_name("recipient", self.recipient)
        if sender == recipient:
            raise EnvelopeError("envelope sender and recipient must be distinct")
        try:
            validate_message_sequence(self.sequence)
        except (TypeError, ValueError) as exc:
            raise EnvelopeError(str(exc)) from exc

    def _validate_complete(self) -> None:
        self._validate_metadata()
        _validate_ciphertext(self.ciphertext)

    def associated_data(self) -> bytes:
        self._validate_metadata()
        return json.dumps(
            {
                "v": self.version,
                "suite": self.suite,
                "sender": self.sender,
                "recipient": self.recipient,
                "sequence": self.sequence,
            },
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

    def to_bytes(self) -> bytes:
        self._validate_complete()
        payload = {
            "v": self.version,
            "suite": self.suite,
            "sender": self.sender,
            "recipient": self.recipient,
            "sequence": self.sequence,
            "ciphertext": self.ciphertext.hex(),
        }
        encoded = json.dumps(
            payload,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        if len(encoded) > MAX_ENVELOPE_BYTES:
            raise EnvelopeError("encoded message envelope exceeds the maximum size")
        return encoded

    @classmethod
    def from_bytes(cls, data: bytes) -> "MessageEnvelope":
        if type(data) is not bytes:
            raise EnvelopeError("message envelope input must be bytes")
        if not data:
            raise EnvelopeError("message envelope input must not be empty")
        if len(data) > MAX_ENVELOPE_BYTES:
            raise EnvelopeError("message envelope input exceeds the maximum size")

        try:
            raw = json.loads(
                data.decode("utf-8"),
                object_pairs_hook=_reject_duplicate_keys,
            )
        except EnvelopeError:
            raise
        except (
            UnicodeDecodeError,
            json.JSONDecodeError,
            RecursionError,
            ValueError,
        ) as exc:
            raise EnvelopeError("failed to parse message envelope") from exc

        if type(raw) is not dict:
            raise EnvelopeError("message envelope must be a JSON object")

        received_fields = frozenset(raw)
        missing_fields = sorted(_ENVELOPE_FIELDS - received_fields)
        unexpected_fields = sorted(received_fields - _ENVELOPE_FIELDS)
        if missing_fields:
            raise EnvelopeError(
                f"message envelope is missing fields: {', '.join(missing_fields)}"
            )
        if unexpected_fields:
            raise EnvelopeError(
                f"message envelope contains unexpected fields: "
                f"{', '.join(unexpected_fields)}"
            )

        envelope = cls(
            version=_validate_protocol_version(raw["v"]),
            suite=_validate_suite_name(raw["suite"]),
            sender=_validate_participant_name("sender", raw["sender"]),
            recipient=_validate_participant_name("recipient", raw["recipient"]),
            sequence=raw["sequence"],
            ciphertext=_decode_ciphertext(raw["ciphertext"]),
        )
        envelope._validate_complete()
        if envelope.to_bytes() != data:
            raise EnvelopeError("message envelope is not canonically encoded")
        return envelope
