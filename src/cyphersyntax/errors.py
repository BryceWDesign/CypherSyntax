"""Exception hierarchy for CypherSyntax."""

from __future__ import annotations


class CypherSyntaxError(Exception):
    """Base error for the package."""


class InvalidSignatureError(CypherSyntaxError):
    """Raised when signature verification fails."""


class KeyConfirmationError(CypherSyntaxError):
    """Raised when handshake key confirmation fails."""


class ReplayDetectedError(CypherSyntaxError):
    """Raised when a message sequence number is replayed."""


class EnvelopeError(CypherSyntaxError):
    """Raised when an envelope cannot be parsed or validated."""


class HandshakeError(CypherSyntaxError):
    """Raised when a handshake message cannot be parsed or validated."""


class PersistenceError(CypherSyntaxError):
    """Base error for durable local persistence failures."""


class StoreError(PersistenceError):
    """Raised when an encrypted store cannot be saved or loaded safely."""


class IdentityError(PersistenceError):
    """Raised when persisted identity material is invalid or inaccessible."""
