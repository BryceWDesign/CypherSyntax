# CypherSyntax

CypherSyntax is a defensive, hybrid-ready secure messaging core built after auditing two incomplete repositories that mixed solid intentions with broken packaging, mocked cryptography, and protocol claims that exceeded what the code actually delivered.

This repository does **not** try to combine every encryption scheme on earth. That would be bad engineering.
Instead, it provides a clean baseline built around:

- X25519 for ephemeral key agreement
- Ed25519 for identity signing
- HKDF-SHA256 for key derivation
- AES-GCM-SIV or ChaCha20-Poly1305 for authenticated encryption
- Versioned message envelopes with associated data binding
- Replay protection using monotonic sequence numbers and a sliding replay window
- Passphrase-based encrypted local storage using Scrypt + AES-GCM-SIV
- A hybrid-ready key schedule that can absorb an optional supplemental secret later (for example from a post-quantum KEM integration)

## What was kept in spirit

From BlackVault:
- session-oriented design
- transport/message framing mindset
- modular separation between key exchange, session state, and encryption

From IX-GhostProtocol:
- stronger move toward X25519 and Ed25519
- identity management concept
- storage abstraction
- explicit wire packet structure

## What was deliberately rejected

- fake or mocked post-quantum cryptography presented as real
- “self-defending encryption” claims that were not backed by protocol mechanics
- kitchen-sink crypto layering without a threat-model reason
- anonymity transports and Tor hooks merged blindly into a core crypto library
- test suites that referenced packages and APIs that did not exist

## Threat model

CypherSyntax is a **cryptographic core**, not a finished messenger and not an anonymity network.
It aims to provide:

- confidentiality and integrity for messages
- sender authentication when signatures are used
- forward secrecy for a session established via ephemeral X25519
- replay detection within a bounded window
- disciplined serialization and envelope versioning

It does **not** claim:

- full metadata resistance
- production-ready double ratchet semantics
- post-quantum security by default
- transport anonymity
- resistance to endpoint compromise

## Quick start

```python
from cyphersyntax.identity import Identity
from cyphersyntax.session import SessionFactory, AeadSuite

alice = Identity.generate("alice")
bob = Identity.generate("bob")

alice_session = SessionFactory.initiator(
    local_identity=alice,
    remote_name="bob",
    remote_x25519_public_key=bob.x25519_public_bytes(),
    suite=AeadSuite.AES_GCM_SIV,
)

bob_session = SessionFactory.responder(
    local_identity=bob,
    remote_name="alice",
    remote_x25519_public_key=alice_session.local_ephemeral_public_bytes,
    peer_ephemeral_public_key=alice_session.local_ephemeral_public_bytes,
    suite=AeadSuite.AES_GCM_SIV,
)

```

See tests for end-to-end usage.

**Status**

This is a serious cleaned-up proof of concept...
