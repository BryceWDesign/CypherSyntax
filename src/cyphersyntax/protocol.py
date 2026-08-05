from __future__ import annotations


PROTOCOL_VERSION = 1
MAX_MESSAGE_SEQUENCE = (1 << 64) - 1


def validate_message_sequence(sequence: int) -> None:
    if isinstance(sequence, bool) or not isinstance(sequence, int):
        raise TypeError("message sequence must be an integer")
    if not 0 <= sequence <= MAX_MESSAGE_SEQUENCE:
        raise ValueError("message sequence must fit in an unsigned 64-bit integer")
