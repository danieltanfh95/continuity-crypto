(ns continuity-crypto.envelope-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [continuity-crypto.envelope :as env]))

(defn- ba= [^bytes a ^bytes b]
  (and (= (alength a) (alength b))
       (every? true? (map = (seq a) (seq b)))))

(defn- bytes-of [& xs] (byte-array (map unchecked-byte xs)))

(deftest b64url-roundtrip-test
  (testing "encode/decode round-trips arbitrary bytes"
    (doseq [in [(byte-array 0)
                (bytes-of 0)
                (bytes-of 0 1 2 3 4 5 6 7 8 9)
                (bytes-of 0xff 0xfe 0xfd)
                (bytes-of 0x3e 0x3f 0x40)]] ; the + and / boundary
      (let [s (env/b64url-encode in)
            out (env/b64url-decode s)]
        (is (ba= in out)))))

  (testing "encoding is URL-safe and unpadded (no + / = chars)"
    (let [s (env/b64url-encode (bytes-of 0xfb 0xff 0xff 0xfe))]
      (is (not (re-find #"[+/=]" s))))))

(deftest utf8-encode-test
  (testing "encodes ASCII to single-byte UTF-8"
    (is (ba= (bytes-of 0x61 0x62 0x63) (env/utf8-encode "abc"))))
  (testing "encodes non-ASCII to multi-byte UTF-8"
    ;; "é" is U+00E9 → 0xC3 0xA9
    (is (ba= (bytes-of 0xc3 0xa9) (env/utf8-encode "é"))))
  (testing "nil input → nil"
    (is (nil? (env/utf8-encode nil)))))

(deftest uint32-be-roundtrip-test
  (testing "write and read round-trip"
    (doseq [n [0 1 255 256 65535 65536 16777215 16777216 4294967295]]
      (let [buf (byte-array 4)]
        (env/uint32-be! buf 0 n)
        (is (= n (env/uint32-be-read buf 0))
            (str "n=" n)))))
  (testing "out-of-range write throws"
    (let [buf (byte-array 4)]
      (is (thrown? clojure.lang.ExceptionInfo
                   (env/uint32-be! buf 0 -1)))
      (is (thrown? clojure.lang.ExceptionInfo
                   (env/uint32-be! buf 0 4294967296))))))

(deftest concat-bytes-test
  (testing "concatenates in order"
    (is (ba= (bytes-of 1 2 3 4 5 6)
             (env/concat-bytes [(bytes-of 1 2 3) (bytes-of 4 5 6)]))))
  (testing "empty input → empty output"
    (is (zero? (alength ^bytes (env/concat-bytes [])))))
  (testing "single arr → identity-like"
    (is (ba= (bytes-of 7 8 9)
             (env/concat-bytes [(bytes-of 7 8 9)])))))
