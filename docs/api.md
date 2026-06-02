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

biscuit-java wrappers + the thumbprint primitive.

```clojure
(keypair-from-seed ^bytes seed) => ^KeyPair
;; Construct the (immutable, thread-safe) biscuit-java KeyPair from a
;; 32-byte Ed25519 seed.

(root-public-key-hex ^KeyPair kp) => ^String
;; Uppercase hex of the root Ed25519 public key, suitable for hosts to
;; pin and verify tokens offline.

(pubkey-thumbprint ^KeyPair kp) => ^bytes
;; SHA-256(canonical_pubkey_bytes). 32 bytes. Used wherever a principal,
;; lineage, or actor needs a stable identifier in a ledger or grant field.
;; Callers wanting a string form should b64url-encode the result themselves.

(serialize ^Biscuit token) => ^String
;; Base64url-unpadded serialization of the token.

(deserialize ^String b64-token ^PublicKey root-pubkey) => ^Biscuit
;; Verify root signature with the explicit root pubkey, then return the
;; parsed Biscuit. Throws on signature failure or malformed input.

(verify ^String b64-token ^PublicKey root-pubkey) => ^Biscuit
;; Alias for deserialize. Reads as "verify the root signature" at the
;; caller's callsite without committing to a single name.

(attenuate ^Biscuit token ^Block block) => ^Biscuit
;; Append-only block attenuation. Returns a new token; the original is
;; immutable.
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
;; Any other field-type keyword → ex-info "unsupported canonical field type".
;; Length-overrun on :utf8 or length-mismatch on :bytes → ex-info with
;; {:field-index :type :max :actual} keys.
```

Both `FPL2\n` (fingerprint-lock's request envelope) and `CWL1\n` (continuity-witness's ledger entry) are callers of `write` with their own tag and their own field tuples; neither field vocabulary lives in this library.
