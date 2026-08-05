"""Authenticated secure-messaging primitives for CypherSyntax."""

from .errors import (
    CypherSyntaxError,
    EnvelopeError,
    HandshakeError,
    IdentityError,
    InvalidSignatureError,
    KeyConfirmationError,
    PersistenceError,
    ReplayDetectedError,
    StoreError,
)
from .handshake import HandshakeConfirmation, HandshakeOffer, HandshakeResponse
from .identity import Identity
from .session import (
    AeadSuite,
    InitiatorHandshake,
    ResponderHandshake,
    SessionFactory,
    SessionState,
)
from .store import EncryptedStore

__version__ = "0.1.0"

__all__ = [
    "AeadSuite",
    "CypherSyntaxError",
    "EncryptedStore",
    "EnvelopeError",
    "HandshakeConfirmation",
    "HandshakeError",
    "HandshakeOffer",
    "HandshakeResponse",
    "Identity",
    "IdentityError",
    "InitiatorHandshake",
    "InvalidSignatureError",
    "KeyConfirmationError",
    "PersistenceError",
    "ReplayDetectedError",
    "ResponderHandshake",
    "SessionFactory",
    "SessionState",
    "StoreError",
    "__version__",
]
