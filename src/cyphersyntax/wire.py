from __future__ import annotations

from dataclasses import dataclass
import json

from .errors import EnvelopeError


@dataclass(slots=True)
class MessageEnvelope:
    version: int
    suite: str
    sender: str
    recipient: str
    sequence: int
    ciphertext: bytes

    def associated_data(self) -> bytes:
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
        payload = {
            "v": self.version,
            "suite": self.suite,
            "sender": self.sender,
            "recipient": self.recipient,
            "sequence": self.sequence,
            "ciphertext": self.ciphertext.hex(),
        }
        return json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")

    @classmethod
    def from_bytes(cls, data: bytes) -> "MessageEnvelope":
        try:
            raw = json.loads(data.decode("utf-8"))
            return cls(
                version=int(raw["v"]),
                suite=str(raw["suite"]),
                sender=str(raw["sender"]),
                recipient=str(raw["recipient"]),
                sequence=int(raw["sequence"]),
                ciphertext=bytes.fromhex(raw["ciphertext"]),
            )
        except Exception as exc:
            raise EnvelopeError("failed to parse message envelope") from exc
