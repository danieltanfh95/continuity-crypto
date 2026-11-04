# continuity-crypto

Shared substrate library for the continuity-* family of identity, capability, and accountability primitives. Clojure-JVM, library only. Ships no CLI, no server, no network protocol of its own. Each calling primitive (fingerprint-lock, continuity-witness, future lab primitives) loads it in-process via `deps.edn`.

## namespaces

- `continuity-crypto.envelope` — base64url-unpadded codec and the byte-array primitives the rest of the library composes over.
- `continuity-crypto.keystore` — parameterized 32-byte Ed25519 seed loader. Precedence env → config → keyfile → autogen, with atomic 0600 file creation.
- `continuity-crypto.biscuit` — biscuit-java wrappers. KeyPair construction, root-pubkey export (hex, raw, SHA-256 thumbprint), token verify / attenuate / serialize.
- `continuity-crypto.canonical` — length-prefixed binary canonicalization machinery for signing. Caller supplies the version tag and the `[type max-size value]` field tuples. Powers both `FPL2\n` (fingerprint-lock) and `CWL1\n` (continuity-witness).

Domain vocabulary stays with the caller. The library offers cryptographic operations, not the fact set, not the ledger field ordering, not the audience vocabulary.

## install

Git-dep in `deps.edn`.

```clojure
{:deps
 {io.github.danieltanfh95/continuity-crypto
  {:git/sha "da8bb4fd8e7e2ff31d35b751a45044f510594f38"}}}
```

Clojars publishing is deferred until a downstream consumer requires a Maven coord.

## quickstart

```clojure
(require '[continuity-crypto.keystore  :as keystore]
         '[continuity-crypto.biscuit   :as biscuit]
         '[continuity-crypto.envelope  :as env]
         '[continuity-crypto.canonical :as canonical])

(def seed
  (keystore/load-or-create-seed!
    {:env-var-name-raw      "MYAPP_ROOT_KEY"
     :env-var-name-key-path "MYAPP_ROOT_KEY_PATH"
     :default-path          "/var/lib/myapp/root.key"
     :seed-bytes            32
     :label                 "myapp root"}
    {}))

(def kp              (biscuit/keypair-from-seed seed))
(def root-pub        (biscuit/root-public-key kp))
(def pub-hex         (biscuit/root-public-key-hex kp))
(def thumbprint-bs   (biscuit/pubkey-thumbprint root-pub))  ; 32 bytes
(def thumbprint-b64  (env/b64url-encode thumbprint-bs))

;; canonical-sign a two-field record under version tag "MYAPP1\n"
(def payload
  (canonical/write "MYAPP1\n"
                   [[:utf8  64 "actor-123"]
                    [:bytes 32 thumbprint-bs]]))
```

See [`docs/api.md`](docs/api.md) for the full per-namespace signatures.

## development

```
clojure -M:test          # kaocha, 28 tests
clojure -M:lint          # clj-kondo
clojure -M:dev           # nREPL + cider
```

## docs

- [`docs/architecture.md`](docs/architecture.md) — namespace map, dependency pins, threat-model commitments.
- [`docs/api.md`](docs/api.md) — per-namespace function signatures and error shapes.
- [`SECURITY.md`](SECURITY.md) — disclosure channel and library-level crypto hygiene commitments.

## status

v0.1. API stable for the two in-tree consumers. Expect additive changes before v1. Bumping the pinned `org.biscuitsec/biscuit` version is a coordinated change across continuity-crypto and every consuming primitive.

## license

MIT. See [`LICENSE`](LICENSE).
