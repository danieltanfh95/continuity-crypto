(ns continuity-crypto.envelope
  "Base64url-unpadded codec plus the byte-array primitives the rest of
  the library composes over. No domain knowledge, no envelope schema, no
  version tags. Each caller layers its own canonical-signing version tag
  (see `continuity-crypto.canonical`) on top.")

(defn utf8-encode
  "Encode a Clojure string to a byte array using UTF-8. nil input → nil."
  ^bytes [^String s]
  (when (some? s)
    (.getBytes s "UTF-8")))

(defn byte-array-of
  "Allocate a JVM byte array of the given length."
  ^bytes [n]
  (byte-array n))

(defn ba-length
  "Length of a byte array."
  [ba]
  (alength ^bytes ba))

(defn ba-get
  "Read byte at index as unsigned int (0..255)."
  [ba i]
  (bit-and 0xff (aget ^bytes ba i)))

(defn ba-set!
  "Set byte at index. v must be in 0..255."
  [ba i v]
  (aset-byte ^bytes ba i (unchecked-byte v)))

(defn ba-copy!
  "Copy src[s-off..s-off+n) into dst[d-off..)."
  [src s-off dst d-off n]
  (System/arraycopy ^bytes src (int s-off) ^bytes dst (int d-off) (int n)))

(defn uint32-be!
  "Write the unsigned 32-bit integer n at dst[off..off+4) in big-endian order."
  [dst off n]
  (when (or (neg? n) (> n 4294967295))
    (throw (ex-info "uint32-be! out of range" {:n n})))
  (ba-set! dst (+ off 0) (bit-and 0xff (bit-shift-right n 24)))
  (ba-set! dst (+ off 1) (bit-and 0xff (bit-shift-right n 16)))
  (ba-set! dst (+ off 2) (bit-and 0xff (bit-shift-right n 8)))
  (ba-set! dst (+ off 3) (bit-and 0xff n)))

(defn uint32-be-read
  "Read a big-endian unsigned 32-bit integer from src starting at off."
  [src off]
  (+ (bit-shift-left (ba-get src off) 24)
     (bit-shift-left (ba-get src (+ off 1)) 16)
     (bit-shift-left (ba-get src (+ off 2)) 8)
     (ba-get src (+ off 3))))

(defn concat-bytes
  "Concatenate a sequence of byte arrays into a single byte array."
  ^bytes [byte-arrays]
  (let [total (reduce + 0 (map ba-length byte-arrays))
        out   (byte-array-of total)]
    (loop [arrs   byte-arrays
           offset 0]
      (if-let [a (first arrs)]
        (let [n (ba-length a)]
          (ba-copy! a 0 out offset n)
          (recur (rest arrs) (+ offset n)))
        out))))

(defn b64url-encode
  "Base64url-unpadded encoding. Empty input → empty string."
  ^String [^bytes bs]
  (.encodeToString (.withoutPadding (java.util.Base64/getUrlEncoder)) bs))

(defn b64url-decode
  "Strict base64url decoder. Rejects unexpected padding or non-URL-safe alphabet."
  ^bytes [^String s]
  (.decode (java.util.Base64/getUrlDecoder) s))
