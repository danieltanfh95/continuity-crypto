# continuity-crypto — api

Per-namespace function signatures, behavior, error shapes. v0.1.

## `continuity-crypto.envelope`

Pure base64url codec, plus the small byte-array primitives the rest of the library composes over.

```clojure
(b64url-encode ^bytes bs) => ^String
;; URL-safe, *unpadded*. Empty input → empty string.

(b64url-decode ^String s) => ^bytes
;; Strict decoder. Rejects non-URL-safe alphabet or unexpected padding.
;; Throws java.lang.IllegalArgumentException on malformed input.

(utf8-encode ^String s) => ^bytes
;; UTF-8 byte representation. nil input → nil.

(byte-array-of n) => ^bytes
;; JVM byte array of length n.

(ba-length ba) => long
(ba-get   ba i) => int           ; unsigned 0..255
(ba-set!  ba i v) => nil
(ba-copy! src s-off dst d-off n) => nil

(uint32-be! dst off n) => nil
;; Write unsigned 32-bit integer n at dst[off..off+4) in big-endian.
;; Throws ex-info {:n n} if n is negative or > 2^32-1.

(uint32-be-read src off) => long
;; Read big-endian uint32 from src[off..off+4).

(concat-bytes [^bytes ...]) => ^bytes
;; Concatenate a sequence of byte arrays into a single byte array.
```

## `continuity-crypto.keystore`

Parameterized 32-byte secret loader. Same precedence chain across all callers: env-raw → env-b64 → config-b64 → keyfile → autogen.

```clojure
(load-or-create-seed! opts config) => ^bytes
;; opts = {:env-var-name-raw      "CONTINUITY_AUTH_BISCUIT_ROOT_KEY"
;;         :env-var-name-key-path "CONTINUITY_AUTH_BISCUIT_ROOT_KEY_PATH"
;;         :default-path          "/var/lib/continuity-auth/biscuit-root.key"
;;         :seed-bytes            32
;;         :label                 "biscuit root"}
;; config = {:key-b64  <optional-b64-string>
;;           :key-path <optional-path-override>}
;;
;; Returns 32-byte array on success. Throws ex-info with :label / :expected /
;; :got on wrong-length input. Writes 0600 keyfile on autogen branch; refuses
;; to silently proceed on POSIX-perm failure (warns to *err* on non-POSIX FS).
```

## `continuity-crypto.biscuit`

biscuit-java wrappers plus the thumbprint primitive. All operations that
delegate to biscuit-java normalize the per-method Java exception contract
into `ex-info` with `{:op <op-key> :cause <message>}` so callers handle one
exception shape.

```clojure
(keypair-from-seed ^bytes seed) => ^KeyPair
;; Construct the (immutable, thread-safe) biscuit-java KeyPair from a
;; 32-byte Ed25519 seed.

(root-public-key ^KeyPair kp) => ^PublicKey
;; Return the biscuit PublicKey. Pass this into `verify`.

(root-public-key-hex ^KeyPair kp) => ^String
;; Uppercase hex of the root Ed25519 public key, in the form hosts pin to
;; verify tokens offline.

(pubkey-bytes ^PublicKey pk) => ^bytes
;; Raw 32-byte canonical Ed25519 pubkey bytes. The form that goes into a
;; thumbprint, a wire payload, or a registry.

(pubkey-thumbprint ^PublicKey pk) => ^bytes
;; SHA-256(canonical_pubkey_bytes). 32 bytes. The stable identifier
;; pattern both fingerprint-lock and continuity-witness use to reference
;; a principal, lineage, or actor in ledger and grant fields. Callers
;; wanting a string form should b64url-encode (or hex-encode) the result
;; themselves.

(serialize ^Biscuit token) => ^String
;; Base64url-unpadded serialization of the token. Throws ex-info
;; {:op :serialize :cause ...} on biscuit-java error.

(verify ^String b64-token ^PublicKey root-pubkey) => ^Biscuit
;; Parse and verify the base64url-encoded biscuit token against an explicit
;; root PublicKey. Returns the verified Biscuit on success. Throws ex-info
;; {:op :verify :cause ...} on signature failure, malformed input, or any
;; biscuit-java error. The caller's host-pinning contract lives here —
;; supply the pubkey you trust, not one read off the token.

(attenuate ^Biscuit token ^Block block) => ^Biscuit
;; Append an attenuation block, returning a new biscuit. The caller
;; constructs the block via biscuit-java's builder (typically
;; `(.create_block token)` followed by `.add_check` / `.add_fact`); the
;; substrate signs and appends. Throws ex-info {:op :attenuate :cause ...}
;; on biscuit-java error. The original token is immutable.
```

## `continuity-crypto.canonical`

Length-prefixed binary canonicalization machinery. Caller supplies a version tag and a sequence of `[type max-size value]` tuples; the library writes them deterministically.

```clojure
(write ^String version-tag fields) => ^bytes
;; fields = [[:utf8  max-bytes ^String value]
;;           [:bytes max-bytes ^bytes  value]
;;           ...]
;; Output layout (binary):
;;   version-tag UTF-8 bytes
;;   for each field: uint32-BE(byte-len) || raw bytes
;;
;; :utf8  — value must be a string; UTF-8-encoded length must be ≤ max-bytes.
;; :bytes — value must be a byte array of length exactly max-bytes.
;; Any other field-type keyword → ex-info "unsupported canonical field type"
;; with {:field-index :type}.
;; Length-overrun on :utf8 → ex-info with {:field-index :type :max :actual}.
;; Length-mismatch on :bytes → ex-info with {:field-index :type :expected :actual}.
```

Both `FPL2\n` (fingerprint-lock's request envelope) and `CWL1\n` (continuity-witness's ledger entry) are callers of `write` with their own tag and their own field tuples; neither field vocabulary lives in this library.
