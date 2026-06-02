# continuity-crypto

Shared substrate library for the continuity-* family of identity / capability / accountability primitives. Library only: no CLI, no server, no user-facing surface. Each calling primitive (continuity-auth / fingerprint-lock, continuity-witness, future lab primitives) consumes it in-process via deps.edn.

The library contains base64url envelope encoding, a parameterized Ed25519 seed-keystore loader, biscuit-java wrappers, and the length-prefixed binary canonicalization machinery used by both `FPL2\n` (fingerprint-lock's ledger format) and `CWL1\n` (continuity-witness's ledger format). Domain semantics — which facts to mint into a biscuit, which fields go into a canonical entry, what an audience means — stay with the calling primitive.

See [docs/architecture.md](docs/architecture.md) for the namespace map and [docs/api.md](docs/api.md) for per-namespace function signatures. The full rationale and extraction sequencing live in [.internal/seed.md](.internal/seed.md).
