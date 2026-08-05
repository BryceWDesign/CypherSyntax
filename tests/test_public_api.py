from __future__ import annotations

from importlib import resources

import cyphersyntax
from cyphersyntax import (
    AeadSuite,
    EncryptedStore,
    HandshakeConfirmation,
    HandshakeOffer,
    HandshakeResponse,
    Identity,
    SessionFactory,
    SessionState,
)


def test_public_api_exports_are_explicit_and_resolvable():
    expected = {
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
    }

    assert set(cyphersyntax.__all__) == expected
    for name in cyphersyntax.__all__:
        assert hasattr(cyphersyntax, name)


def test_public_api_symbols_are_the_expected_objects():
    assert AeadSuite is cyphersyntax.AeadSuite
    assert EncryptedStore is cyphersyntax.EncryptedStore
    assert HandshakeConfirmation is cyphersyntax.HandshakeConfirmation
    assert HandshakeOffer is cyphersyntax.HandshakeOffer
    assert HandshakeResponse is cyphersyntax.HandshakeResponse
    assert Identity is cyphersyntax.Identity
    assert SessionFactory is cyphersyntax.SessionFactory
    assert SessionState is cyphersyntax.SessionState


def test_version_matches_package_release():
    assert cyphersyntax.__version__ == "0.1.0"


def test_pep561_marker_is_packaged_as_a_resource():
    marker = resources.files("cyphersyntax").joinpath("py.typed")

    assert marker.is_file()
    assert "PEP 561" in marker.read_text(encoding="utf-8")
