from __future__ import annotations


PROTOCOL_VERSION = 1
MAX_MESSAGE_SEQUENCE = (1 << 64) - 1
MAX_PROTOCOL_VERSION = (1 << 16) - 1
MAX_PARTICIPANT_NAME_BYTES = 255
MAX_SUITE_NAME_BYTES = 64
MAX_PLAINTEXT_BYTES = 1_048_576
AEAD_TAG_BYTES = 16
MAX_CIPHERTEXT_BYTES = MAX_PLAINTEXT_BYTES + AEAD_TAG_BYTES
MAX_ENVELOPE_BYTES = (MAX_CIPHERTEXT_BYTES * 2) + 4096


def validate_message_sequence(sequence: int) -> None:
    if type(sequence) is not int:
        raise TypeError("message sequence must be an integer")
    if not 0 <= sequence <= MAX_MESSAGE_SEQUENCE:
        raise ValueError("message sequence must fit in an unsigned 64-bit integer")
