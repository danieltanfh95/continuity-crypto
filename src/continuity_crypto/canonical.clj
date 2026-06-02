(ns continuity-crypto.canonical
  "Length-prefixed binary canonicalization machinery.

  Output layout:
    <version-tag UTF-8 bytes>
    for each field:
      uint32-BE(byte-len) || raw bytes

  Each caller supplies its own version-tag literal (e.g. continuity-auth's
  `FPL2\\n` request-envelope tag, continuity-witness's `CWL1\\n` ledger-entry
  tag) and its own ordered field tuples. The library knows the machinery;
  the library does not know which fields exist or what they mean.

  No JSON canonicalization. No schema-as-data DSL. No Malli dep. Caller
  passes inline `[type max-size value]` tuples and accepts the small price
  of repeating the schema at each callsite in exchange for a substrate that
  introduces no new vocabulary.

  Supported types in v0.1:
    :utf8  — string value; UTF-8-encoded byte length must be ≤ max-size.
    :bytes — byte-array value; byte length must equal max-size exactly.

  Source: continuity-auth's `envelope/canonical-bytes` (the FPL2 producer);
  carved out behind the caller-parameterized API."
  (:require
   [continuity-crypto.envelope :as envelope]))

(defn- prefixed
  "Return [4-byte uint32-BE length prefix, the bytes themselves]."
  [bs]
  (let [len    (envelope/ba-length bs)
        prefix (envelope/byte-array-of 4)]
    (envelope/uint32-be! prefix 0 len)
    [prefix bs]))

(defn- encode-utf8! [field-index max-size ^String value]
  (let [bs (envelope/utf8-encode value)
        n  (envelope/ba-length bs)]
    (when (> n max-size)
      (throw (ex-info "canonical :utf8 field exceeds maximum byte length"
                      {:field-index field-index
                       :type        :utf8
                       :max         max-size
                       :actual      n})))
    bs))

(defn- check-bytes-len! [field-index expected ^bytes value]
  (let [n (envelope/ba-length value)]
    (when-not (= n expected)
      (throw (ex-info "canonical :bytes field has wrong length"
                      {:field-index field-index
                       :type        :bytes
                       :expected    expected
                       :actual      n})))
    value))

(defn- encode-field [field-index [type max-size value]]
  (case type
    :utf8  (encode-utf8! field-index max-size value)
    :bytes (check-bytes-len! field-index max-size value)
    (throw (ex-info "unsupported canonical field type"
                    {:field-index field-index
                     :type        type}))))

(defn write
  "Build the canonical signing-input byte array.

    version-tag  literal string written verbatim at the head (e.g. \"FPL2\\n\").
    fields       sequence of [type max-size value] tuples in fixed order.

  Returns ^bytes."
  ^bytes [^String version-tag fields]
  (let [tag-bytes (envelope/utf8-encode version-tag)
        encoded   (map-indexed encode-field fields)]
    (envelope/concat-bytes
     (cons tag-bytes
           (mapcat prefixed encoded)))))
