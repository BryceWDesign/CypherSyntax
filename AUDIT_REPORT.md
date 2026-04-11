# Audit Report: BlackVault + IX-GhostProtocol -> CypherSyntax

## High-confidence failures found in the source repos

### 1) Packaging and import model was broken
- BlackVault tests import `core.*` and `network.*`, but the repository uses a `src/` layout without packaging metadata or import path configuration.
- IX-GhostProtocol tests import `ix_ghostprotocol.*`, but no such package exists in the repository.

### 2) Tests and implementation did not match
- BlackVault tests reference `create_session_key()` and `remove_session_key()` methods that do not exist in the session manager.
- IX-GhostProtocol tests reference `generate_keypair()`, `encrypt_message()`, `NetworkNode`, and `Peer`, none of which exist in the implementation.

### 3) Dangerous or incomplete cryptographic design choices
- Mocked “Kyber” code returned hard-coded bytes and therefore could not provide any post-quantum security.
- Shared secrets were truncated directly instead of always being processed through a disciplined KDF.
- Some code paths rotated symmetric keys locally without a protocol for synchronizing the peer, which would break decryption.
- The padding strategy in one engine appended zero bytes and stripped them with `rstrip(b"\x00")`, which can destroy legitimate plaintext suffix bytes.
- Nonce management and protocol state were underspecified.

### 4) Claims exceeded the code
- README claims around stable core protocol, metadata resistance, and advanced transports were not matched by the repository state.
- “Self-defending encryption” was described conceptually but not implemented as a credible protocol feature.

## What CypherSyntax does instead
- chooses a small set of modern primitives
- makes the key schedule explicit
- removes fake PQ claims while leaving a safe extension point
- introduces replay tracking and versioned envelopes
- fixes packaging and testability
- narrows scope to a defensible cryptographic core
