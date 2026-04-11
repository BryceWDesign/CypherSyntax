class CypherSyntaxError(Exception):
    """Base error for the package."""


class InvalidSignatureError(CypherSyntaxError):
    """Raised when signature verification fails."""


class ReplayDetectedError(CypherSyntaxError):
    """Raised when a message sequence number is replayed."""


class EnvelopeError(CypherSyntaxError):
    """Raised when an envelope cannot be parsed or validated."""
