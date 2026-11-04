# continuity-crypto — architecture

continuity-crypto is a small Clojure-JVM `deps.edn` library. It is loaded in-process by each consuming primitive (continuity-auth / fingerprint-lock, continuity-witness, future lab primitives). It does not ship a CLI, a server, a binary, or a network protocol of its own.

## namespaces (v0.1)

```
continuity-crypto.envelope   base64url-unpadded codec + byte-array primitives
continuity-crypto.keystore   parameterized 32-byte Ed25519 seed loader
                             (env → config → keyfile → autogen, 0600 perms)
continuity-crypto.biscuit    biscuit-java wrappers: KeyPair construction,
                             root-public-key export, pubkey thumbprint,
                             token verify / attenuate / serialize round-trip
continuity-crypto.canonical  length-prefixed binary canonicalization machinery
                             (version-tag prefix + uint32-BE length-prefixed
                             fields; caller supplies tag and field tuples)
```

## what is NOT in the library

- Domain-specific minting. Each calling primitive writes its own `mint` with its own claim vocabulary (fingerprint-lock has identity / tier / audience facts; witness will have action-class / scope / audience facts). The library offers the cryptographic operations, not the fact vocabulary.
- Canonical-signing version tags. The library knows the *machinery* for length-prefixed binary canonicalization; each caller supplies its own `FPL2\n` / `CWL1\n` / future tags. The library does not own any tag.
- HTTP / handlers / datastore / domain code. Fingerprint-lock's server-product shape and witness's CLI+warm-server shape stay with each primitive.
- A Unix-socket protocol of its own. v0.1 is in-process library only. If a future use case wants out-of-process consumption of these primitives, a continuity-crypto-server sibling can be added then — separately from this library.

## dependencies

- `org.clojure/clojure` 1.12.0 (JVM stdlib).
- `org.biscuitsec/biscuit` 2.3.1 (biscuit-java; package: `com.clevercloud.biscuit.*`).

No transitive cryptography dependencies introduced beyond what biscuit-java pulls. No BouncyCastle direct dep (fingerprint-lock pulls BC for separate non-substrate purposes; not needed here). No network egress, no telemetry.

## threat-model commitments

The library is a primitive. Its job is to do its cryptographic operations correctly and surface error states cleanly. Higher-level threat-modeling (replay scope, audience binding, revocation authority) belongs to the calling primitive.

Commitments the library makes:

- Secret-key bytes are never logged.
- Secret-key bytes are never included in error messages or stack traces.
- 0600 permissions on any keystore-loader-managed file. The loader creates the file atomically at those perms and refuses to read a file it just wrote if the perm restriction did not succeed.
- Test fixtures carrying secret-shaped bytes are marked `THIS IS A TEST KEY DO NOT USE`.
- Ed25519 is the default and preferred algorithm. 32-byte raw pubkeys, 64-byte raw signatures, base64url-unpadded encoding on the wire.
- `SHA-256(canonical_pubkey_bytes)` as the thumbprint pattern for stable identity references in ledger and grant fields.
- No network egress in library code. No telemetry.

Out of scope:

- Hardware-key custody. The keystore loader reads raw 32-byte seeds from env, config, or disk only.
- Encrypted-at-rest keyfiles. The caller is responsible for disk encryption of the containing filesystem.
- Key escrow and rotation workflow. The library offers load and autogen; rotation ceremony is the caller's.
- Replay-cache storage. Callers that need replay protection own the cache.

For disclosure channels see [`../SECURITY.md`](../SECURITY.md).
