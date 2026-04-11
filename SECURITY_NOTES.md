# Security Notes

## Why this repository does not implement “everything”

A secure system gets worse when it accumulates unnecessary primitives, partial protocol layers, or mocked cryptography.
CypherSyntax intentionally keeps the core tight.

## Current defaults

- Key agreement: X25519
- Signatures: Ed25519
- KDF: HKDF-SHA256
- AEAD default: AES-GCM-SIV
- Alternate AEAD: ChaCha20-Poly1305
- Local secret storage: Scrypt + AES-GCM-SIV

## Hybrid-ready, not fake-PQ

The key schedule accepts an optional supplemental secret.
That makes it straightforward to integrate a real ML-KEM or HPKE-based input later without lying about post-quantum security today.

## Deliberate omissions

- no mocked Kyber
- no “self-defending” kill-switch marketing
- no Tor adapter
- no claim of metadata resistance
- no claim of production-grade double ratchet
