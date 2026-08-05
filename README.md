# CypherSyntax

CypherSyntax is a compact authenticated secure-messaging core for Python. It provides a
canonical three-message handshake, identity authentication, bidirectional session
protection, replay defense, encrypted local persistence, and a reproducible repository
green gate.

It is intentionally a focused cryptographic library rather than a finished messenger,
network transport, anonymity system, or collection of loosely connected algorithms.

## Security status

CypherSyntax is a **security-focused proof of concept**. It has extensive automated
assurance, but it has **not** received an independent cryptographic audit and is
**not production certified**. Do not use it as the sole protection for high-value operational
communications.

See [SECURITY_NOTES.md](SECURITY_NOTES.md) for the threat model, trust requirements, and
explicit limitations. See [AUDIT_REPORT.md](AUDIT_REPORT.md) for the original findings and
completed remediation.

## Implemented capabilities

- Fresh two-sided ephemeral X25519 session establishment.
- Ed25519 authentication of the initiator offer, responder response, and initiator
  confirmation.
- Explicit mutual key confirmation before the responder establishes a session.
- HKDF-SHA256 session, directional-traffic, and per-message key derivation.
- Separate keys and nonces for each direction and message sequence.
- Synchronized send counters to prevent concurrent nonce reuse.
- AES-GCM-SIV by default, with ChaCha20-Poly1305 as an alternative.
- Canonical bounded handshake and message serialization.
- Replay tracking that commits state only after successful authentication.
- Scrypt plus AES-GCM-SIV encrypted local stores and identity bundles.
- Atomic persistence replacement and path-safe identity filenames.
- Explicit installed-package API with a PEP 561 `py.typed` marker.
- Python 3.10 through 3.14 GitHub Actions matrix.
- Branch-aware tests, source assurance, wheel verification, isolated installation, and
  installed-package smoke testing through one green command.

## Requirements

- Python 3.10 or newer.
- `cryptography>=46.0.0`.

## Installation

Install the runtime package from the repository:

```
python -m pip install .
```

For development and repository validation:

```
python -m pip install -e ".[dev]"
python check_green.py
```

`GREEN CHECK PASSED` is the only successful repository result. The command fails if
compilation, source assurance, tests, the 90 percent branch-coverage floor, demo execution,
wheel validation, isolated installation, or the installed-wheel smoke test fails.

## Authenticated handshake and message round trip

The peer Ed25519 public keys in this example are trust anchors. A real application must
obtain and verify them through an authenticated out-of-band process before starting the
handshake.

```
from cyphersyntax import (
    AeadSuite,
    HandshakeConfirmation,
    HandshakeOffer,
    HandshakeResponse,
    Identity,
    SessionFactory,
)

alice = Identity.generate("alice")
bob = Identity.generate("bob")

pending_alice = SessionFactory.initiator(
    local_identity=alice,
    remote_name=bob.name,
    remote_signing_public_key=bob.ed25519_public_bytes(),
    suite=AeadSuite.AES_GCM_SIV,
)

# Transport the canonical offer bytes to Bob.
received_offer = HandshakeOffer.from_bytes(pending_alice.offer.to_bytes())
response, pending_bob = SessionFactory.responder(
    local_identity=bob,
    remote_signing_public_key=alice.ed25519_public_bytes(),
    offer=received_offer,
)

# Transport the canonical response bytes to Alice.
received_response = HandshakeResponse.from_bytes(response.to_bytes())
confirmation, alice_session = pending_alice.complete(received_response)

# Transport the canonical confirmation bytes to Bob.
received_confirmation = HandshakeConfirmation.from_bytes(
    confirmation.to_bytes()
)
bob_session = pending_bob.complete(received_confirmation)

packet = alice_session.encrypt(b"hello bob")
assert bob_session.decrypt(packet) == b"hello bob"

reply = bob_session.encrypt(b"hello alice")
assert alice_session.decrypt(reply) == b"hello alice"
```

## Optional supplemental secret

Both handshake parties may supply the same additional high-entropy secret through the
`supplemental_secret` argument. The value is mixed into the session-root derivation and
verified by key confirmation.

This is an extension point, not a post-quantum claim. The session is post-quantum only if
the supplemental secret is produced by a separately reviewed post-quantum protocol with
correct authentication, encapsulation, validation, and lifecycle handling.

## Identity persistence

```
from cyphersyntax import Identity

passphrase = b"a passphrase containing at least sixteen bytes"
alice = Identity.generate("alice")
alice.save("private-identities", passphrase)

restored = Identity.load("alice", "private-identities", passphrase)
assert restored.ed25519_public_bytes() == alice.ed25519_public_bytes()
```

Identity files contain one encrypted authenticated bundle. Filenames are derived from a
hash of the validated identity name rather than embedding the name directly.

## Encrypted local store

```
from cyphersyntax import EncryptedStore

store = EncryptedStore(
    "private-state.bin",
    b"a passphrase containing at least sixteen bytes",
)
store.save({"counter": 7, "enabled": True})
assert store.load() == {"counter": 7, "enabled": True}
```

The store accepts canonical JSON-compatible dictionaries. It does not serialize arbitrary
Python objects.

## Protocol boundaries

CypherSyntax deliberately does not implement:

- a network transport;
- a double ratchet or post-compromise recovery;
- metadata hiding or traffic-analysis resistance;
- anonymous routing;
- group messaging;
- certificate or key-transparency infrastructure;
- post-quantum security by default;
- guaranteed secure memory erasure;
- protection after endpoint or live-session compromise.

Applications are responsible for trusted peer-key distribution, transport availability,
authorization, rate limiting, application framing, key rotation policy, error handling,
and operational secret management.

## Repository structure

```
.github/workflows/ci.yml       GitHub Actions green matrix
check_green.py                 complete local and CI green gate
check_source_quality.py        repository-native static assurance
src/cyphersyntax/              installable package
tests/                         protocol, persistence, parser, and gate tests
demo.py                        serialized authenticated round trip
AUDIT_REPORT.md                source-repository findings and remediation
SECURITY_NOTES.md              security model and limitations
```

## License

CypherSyntax is licensed under the GNU Affero General Public License, version 3 only. See
[LICENSE](LICENSE).
