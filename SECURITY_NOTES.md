# Security Notes

## Security status

CypherSyntax is a security-focused proof of concept. It is not independently audited and
must not be treated as a production messenger or as protection for high-value operational
communications.

## Implemented design

### Identity authentication

Each identity has an Ed25519 signing key. The initiator offer, responder response, and
initiator confirmation are signed and bound to participant names, the selected suite,
protocol version, and both ephemeral X25519 public keys.

The caller must already possess the expected peer Ed25519 public key. CypherSyntax does
not solve trust-anchor distribution, certificate validation, key transparency, or human
identity verification.

### Session establishment

Both parties generate fresh ephemeral X25519 keys. HKDF-SHA256 derives the session root
from the X25519 shared secret, the authenticated transcript hash, and an optional
supplemental secret. Both parties prove possession of the same root through role-specific
key confirmation before the responder creates an established session.

The optional supplemental secret is only an extension point. It does not provide
post-quantum security unless it comes from a separately implemented and correctly
validated post-quantum mechanism.

### Message protection

The session derives separate directional traffic secrets. Each message sequence derives
a fresh 256-bit AEAD key and 96-bit nonce. Supported suites are:

- AES-GCM-SIV, the default;
- ChaCha20-Poly1305.

Message metadata is authenticated as associated data. Send-sequence allocation is locked
so concurrent callers cannot reuse a sequence, key, or nonce. The unsigned 64-bit send
space fails closed on exhaustion.

### Replay handling

The receiver validates whether a sequence is eligible, authenticates the ciphertext, and
records the sequence only after successful authentication. Forged packets therefore
cannot consume sequence numbers or advance the replay window.

### Serialization boundaries

Handshake messages and encrypted envelopes use canonical JSON. Parsers reject duplicate,
missing, unexpected, malformed, noncanonical, oversized, and out-of-range fields before
cryptographic processing continues.

### Local persistence

Identity bundles and generic local state use Scrypt-derived AES-GCM-SIV encryption.
Writes use a same-directory temporary file, file synchronization, and atomic replacement.
Passphrases must contain 16 to 1024 bytes.

## Explicit non-goals and limitations

CypherSyntax does not currently provide:

- independent security certification;
- a double ratchet or post-compromise recovery;
- group-session semantics;
- message deletion or guaranteed secure memory erasure;
- metadata hiding or traffic-analysis resistance;
- anonymous routing or transport security;
- remote identity discovery or trust-on-first-use policy;
- certificate, transparency-log, or revocation infrastructure;
- post-quantum security by default;
- protection after endpoint or live-session compromise.

The library also does not supply a network transport. Applications must frame and deliver
handshake and message bytes without altering them and must apply their own availability,
rate-limiting, authorization, logging, and key-lifecycle policies.

## Operational requirements

- Obtain peer Ed25519 public keys through an authenticated channel.
- Use a new handshake for every new session.
- Never reuse a `SessionState` with a different peer or trust anchor.
- Do not persist session root keys unless a separate reviewed design requires it.
- Treat authentication, key-confirmation, replay, parsing, and persistence errors as hard
  failures.
- Do not log private keys, session roots, supplemental secrets, plaintext, or passphrases.
- Run `python check_green.py` after every security-relevant change.

## Reporting security defects

Do not include live secrets, private keys, passphrases, or sensitive message content in a
public report. Use a private repository security-reporting channel when one is available.
A report should include the affected version, reproduction steps, impact, and whether the
issue has already been disclosed elsewhere.
