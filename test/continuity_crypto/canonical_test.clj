(ns continuity-crypto.canonical-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [continuity-crypto.canonical :as canonical]
   [continuity-crypto.envelope :as env]))

(defn- ba= [^bytes a ^bytes b]
  (and (= (alength a) (alength b))
       (every? true? (map = (seq a) (seq b)))))

(defn- bytes-of [& xs] (byte-array (map unchecked-byte xs)))

;; -- basic shape -----------------------------------------------------------

(deftest write-emits-version-tag-then-length-prefixed-fields
  (testing "single :bytes field produces [tag, len-BE-4, value]"
    (let [tag    "TAG1\n"
          value  (bytes-of 0xaa 0xbb 0xcc 0xdd)
          out    (canonical/write tag [[:bytes 4 value]])
          tag-bs (env/utf8-encode tag)]
      (is (= (+ (alength tag-bs) 4 4) (alength ^bytes out)))
      (is (ba= tag-bs (java.util.Arrays/copyOfRange ^bytes out 0 (alength tag-bs))))
      (is (= 4 (env/uint32-be-read out (alength tag-bs))))
      (is (ba= value (java.util.Arrays/copyOfRange ^bytes out
                                                   (+ (alength tag-bs) 4)
                                                   (alength ^bytes out)))))))

(deftest write-preserves-field-order
  (testing "two fields are written in supplied order"
    (let [tag "T\n"
          a   (bytes-of 1 2)
          b   (bytes-of 3 4 5)
          out (canonical/write tag [[:bytes 2 a] [:bytes 3 b]])
          tag-bs (env/utf8-encode tag)
          o   (alength tag-bs)]
      ;; layout: tag, len(2)=2, a, len(4)=3, b
      (is (= 2 (env/uint32-be-read out o)))
      (is (ba= a (java.util.Arrays/copyOfRange ^bytes out (+ o 4) (+ o 4 2))))
      (is (= 3 (env/uint32-be-read out (+ o 4 2))))
      (is (ba= b (java.util.Arrays/copyOfRange ^bytes out
                                               (+ o 4 2 4) (+ o 4 2 4 3)))))))

;; -- type behavior ---------------------------------------------------------

(deftest utf8-field-encoded-as-utf8
  (let [out    (canonical/write "T\n" [[:utf8 32 "héllo"]])
        tag-bs (env/utf8-encode "T\n")
        o      (alength tag-bs)
        len    (env/uint32-be-read out o)
        expect (env/utf8-encode "héllo")]
    (is (= (alength ^bytes expect) len))
    (is (ba= expect (java.util.Arrays/copyOfRange ^bytes out
                                                  (+ o 4) (+ o 4 len))))))

(deftest utf8-overrun-rejected
  (testing "string longer than max-bytes (post-UTF-8) throws ex-info"
    (let [thrown (try
                   (canonical/write "T\n" [[:utf8 3 "abcd"]])
                   nil
                   (catch clojure.lang.ExceptionInfo e e))]
      (is (some? thrown))
      (is (= :utf8 (:type (ex-data thrown))))
      (is (= 3 (:max (ex-data thrown))))
      (is (= 4 (:actual (ex-data thrown)))))))

(deftest bytes-wrong-length-rejected
  (testing ":bytes value not matching declared length throws ex-info"
    (let [thrown (try
                   (canonical/write "T\n" [[:bytes 4 (bytes-of 1 2 3)]])
                   nil
                   (catch clojure.lang.ExceptionInfo e e))]
      (is (some? thrown))
      (is (= :bytes (:type (ex-data thrown))))
      (is (= 4 (:expected (ex-data thrown))))
      (is (= 3 (:actual (ex-data thrown)))))))

(deftest unknown-type-rejected
  (testing "unsupported field type → ex-info with :type and :field-index"
    (let [thrown (try
                   (canonical/write "T\n" [[:int 4 42]])
                   nil
                   (catch clojure.lang.ExceptionInfo e e))]
      (is (some? thrown))
      (is (= :int (:type (ex-data thrown))))
      (is (= 0 (:field-index (ex-data thrown)))))))

;; -- FPL2 byte-for-byte parity --------------------------------------------
;;
;; Goal: prove `canonical/write` with FPL2 inputs produces the exact bytes
;; that continuity-auth's `envelope/canonical-bytes` produces today. This is
;; the regression guard for the fingerprint-lock refactor.
;;
;; We reproduce continuity-auth's expected output manually with the same
;; encode primitives the library exposes, then assert equality.

(defn- fpl2-canonical-expected
  "Replicate continuity-auth.envelope/canonical-bytes layout for the FPL2
  request envelope, using continuity-crypto.envelope primitives directly."
  ^bytes [{:keys [method path body-sha256 ts nonce fp-digest host-user-id key-id]}]
  (let [tag       (env/utf8-encode "FPL2\n")
        method-b  (env/utf8-encode method)
        path-b    (env/utf8-encode path)
        ts-b      (env/utf8-encode ts)
        host-b    (env/utf8-encode (or host-user-id ""))
        prefix    (fn [^bytes bs]
                    (let [p (byte-array 4)]
                      (env/uint32-be! p 0 (alength bs))
                      [p bs]))]
    (env/concat-bytes
     (concat [tag]
             (prefix method-b)
             (prefix path-b)
             (prefix body-sha256)
             (prefix ts-b)
             (prefix nonce)
             (prefix fp-digest)
             (prefix host-b)
             (prefix key-id)))))

(deftest fpl2-parity
  (testing "canonical/write FPL2 spec matches the hand-rolled FPL2 layout"
    (let [body-sha256 (byte-array (map unchecked-byte (range 32)))
          nonce       (byte-array (map (fn [i] (unchecked-byte (+ i 100))) (range 16)))
          fp-digest   (byte-array (map (fn [i] (unchecked-byte (+ i 200))) (range 32)))
          key-id      (byte-array (map (fn [i] (unchecked-byte (+ i 50))) (range 32)))
          fields      {:method       "POST"
                       :path         "/v1/api/example?query=value"
                       :body-sha256  body-sha256
                       :ts           "2026-06-02T12:34:56.789Z"
                       :nonce        nonce
                       :fp-digest    fp-digest
                       :host-user-id "host-user-abc"
                       :key-id       key-id}
          expected (fpl2-canonical-expected fields)
          actual   (canonical/write
                    "FPL2\n"
                    [[:utf8  16    (:method fields)]
                     [:utf8  4096  (:path fields)]
                     [:bytes 32    (:body-sha256 fields)]
                     [:utf8  40    (:ts fields)]
                     [:bytes 16    (:nonce fields)]
                     [:bytes 32    (:fp-digest fields)]
                     [:utf8  256   (:host-user-id fields)]
                     [:bytes 32    (:key-id fields)]])]
      (is (ba= expected actual)))))

(deftest fpl2-parity-empty-host-user-id
  (testing "empty host-user-id (FPL2 allows len=0) produces matching bytes"
    (let [body-sha256 (byte-array 32)
          nonce       (byte-array 16)
          fp-digest   (byte-array 32)
          key-id      (byte-array 32)
          fields      {:method       "GET"
                       :path         "/health"
                       :body-sha256  body-sha256
                       :ts           "2026-06-02T00:00:00.000Z"
                       :nonce        nonce
                       :fp-digest    fp-digest
                       :host-user-id ""
                       :key-id       key-id}
          expected (fpl2-canonical-expected fields)
          actual   (canonical/write
                    "FPL2\n"
                    [[:utf8  16    (:method fields)]
                     [:utf8  4096  (:path fields)]
                     [:bytes 32    (:body-sha256 fields)]
                     [:utf8  40    (:ts fields)]
                     [:bytes 16    (:nonce fields)]
                     [:bytes 32    (:fp-digest fields)]
                     [:utf8  256   (:host-user-id fields)]
                     [:bytes 32    (:key-id fields)]])]
      (is (ba= expected actual)))))
