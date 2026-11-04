(ns continuity-crypto.biscuit
  "biscuit-java wrappers plus the Ed25519 pubkey thumbprint primitive.
  Cryptographic operations only. KeyPair construction from a 32-byte
  Ed25519 seed, root-pubkey export (hex, raw bytes, SHA-256 thumbprint),
  and the three biscuit-token primitives both consuming primitives need
  at the wire level — serialize, verify (parse + signature check against
  an explicit root pubkey), and attenuate (append-block).

  Domain semantics — which facts to mint, which checks to add, what an
  audience means — stay with the caller. The caller builds the
  authority-block or attenuation-block via biscuit-java's builder API
  directly (`com.clevercloud.biscuit.token.builder.*`); the substrate
  signs/verifies/serializes the result.

  All wrappers normalize biscuit-java's checked Java exceptions into
  `ex-info` with `:op` and `:cause` keys so callers handle one exception
  shape rather than the per-method Java contract. Package:
  `com.clevercloud.biscuit.*`."
  (:import
   (com.clevercloud.biscuit.crypto KeyPair PublicKey)
   (com.clevercloud.biscuit.token Biscuit)
   (com.clevercloud.biscuit.token.builder Block)
   (java.security MessageDigest)))

(defn keypair-from-seed
  "Construct the (immutable, thread-safe) biscuit-java `KeyPair` from a
  32-byte Ed25519 seed."
  ^KeyPair [^bytes seed]
  (KeyPair. seed))

(defn root-public-key
  "Return the biscuit `PublicKey` of the given KeyPair. Useful for callers
  that need to pass the pubkey into `verify`."
  ^PublicKey [^KeyPair kp]
  (.public_key kp))

(defn root-public-key-hex
  "Uppercase hex of the root Ed25519 public key. The form hosts pin to
  verify tokens offline."
  ^String [^KeyPair kp]
  (.toHex (.public_key kp)))

(defn pubkey-bytes
  "Raw 32-byte canonical Ed25519 pubkey bytes. The form that goes into a
  thumbprint, a wire payload, or a registry."
  ^bytes [^PublicKey pk]
  (.toBytes pk))

(defn pubkey-thumbprint
  "`SHA-256(canonical_pubkey_bytes)`. 32 bytes. The stable identifier
  pattern both fingerprint-lock and continuity-witness use to reference
  a principal / lineage / actor in ledger and grant fields. Callers
  wanting a string form should `b64url-encode` (or hex-encode) the
  result themselves."
  ^bytes [^PublicKey pk]
  (let [md (MessageDigest/getInstance "SHA-256")]
    (.digest md (.toBytes pk))))

(defn serialize
  "Serialize a `Biscuit` token to base64url-unpadded form."
  ^String [^Biscuit token]
  (try
    (.serialize_b64url token)
    (catch Exception e
      (throw (ex-info "biscuit serialize failed"
                      {:op :serialize :cause (.getMessage e)} e)))))

(defn verify
  "Parse and verify a base64url-encoded biscuit token against an explicit
  root `PublicKey`. Returns the verified `Biscuit` on success; throws
  `ex-info` with `{:op :verify :cause <message>}` on signature failure,
  malformed input, or any biscuit-java error. The caller's host-pinning
  contract lives here — supply the pubkey you trust, not one read off the
  token."
  ^Biscuit [^String b64-token ^PublicKey root-pubkey]
  (try
    (Biscuit/from_b64url b64-token root-pubkey)
    (catch Exception e
      (throw (ex-info "biscuit verify failed"
                      {:op :verify :cause (.getMessage e)} e)))))

(defn attenuate
  "Append an attenuation block to `token`, returning a new biscuit. The
  caller constructs the block via biscuit-java's builder (typically
  `(.create_block token)` followed by `.add_check` / `.add_fact` calls);
  the substrate signs and appends.

  Throws `ex-info` with `{:op :attenuate :cause <message>}` on biscuit-java
  error. The original token is immutable."
  ^Biscuit [^Biscuit token ^Block block]
  (try
    (.attenuate token block)
    (catch Exception e
      (throw (ex-info "biscuit attenuate failed"
                      {:op :attenuate :cause (.getMessage e)} e)))))
