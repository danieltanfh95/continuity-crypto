# Security policy

## Disclosure

Report security issues privately to **danieltanfh95@gmail.com** before opening a public issue or PR. Please include:

- A description of the issue and the affected namespace or function.
- Steps to reproduce or a minimal failing REPL snippet.
- Your assessment of impact.

Expect an acknowledgement within 7 days. Fix timelines depend on severity and on whether a coordinated change across downstream consumers (fingerprint-lock, continuity-witness) is required.

GPG-encrypted reports are welcome. Request a public key over the same email.

## Supported versions

v0.1 is the only released line. Fixes land on `main`. No long-term support branches exist.

## Scope

The library commits to the following at the code level:

- Secret-key bytes are never logged.
- Secret-key bytes are never included in error messages or stack traces.
- Keystore-managed files are created atomically at 0600. The loader refuses to proceed if the perm restriction did not succeed on a POSIX filesystem.
- No network egress and no telemetry in library code.
- Ed25519 is the default and preferred signature algorithm. 32-byte raw pubkeys, 64-byte raw signatures, base64url-unpadded wire encoding.
- `SHA-256(canonical_pubkey_bytes)` is the stable thumbprint pattern.

In-scope for a security report:

- Secret-material leakage through logs, exceptions, or returned values.
- Keystore perm-restriction bypass.
- Signature verification that accepts a malformed or wrong-root-pubkey token.
- Canonical-signing length-prefix or size-limit violations that admit ambiguous encodings.
- Supply-chain concerns in the pinned `org.biscuitsec/biscuit` version.

Out of scope for this library (belongs to the calling primitive):

- Replay-cache storage and lookup.
- Audience and scope semantics.
- Revocation authority and key-rotation ceremony.
- Hardware-key custody. The loader reads raw 32-byte seeds from env, config, or disk only.
- Encrypted-at-rest keyfiles. Disk encryption of the containing filesystem is the caller's responsibility.

## Non-goals

- A bug-bounty program.
- Timely fixes for issues reachable only by code that bypasses the documented API.
- Backward-compatible shims for pre-release behavior. The library is v0.1 and the API is additive but not yet frozen.
