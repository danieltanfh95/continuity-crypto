(ns continuity-crypto.biscuit-test
  (:require
   [clojure.test :refer [deftest is testing]]
   [continuity-crypto.biscuit :as cc-biscuit])
  (:import
   (com.clevercloud.biscuit.crypto KeyPair)
   (com.clevercloud.biscuit.token Biscuit)))

;; THIS IS A TEST KEY DO NOT USE
(defn- fixed-seed ^bytes []
  (byte-array (map unchecked-byte (range 32))))

(defn- distinct-seed ^bytes []
  (byte-array (map (fn [i] (unchecked-byte (+ i 64))) (range 32))))

(defn- ba= [^bytes a ^bytes b]
  (and (= (alength a) (alength b))
       (every? true? (map = (seq a) (seq b)))))

(defn- mint-trivial
  "Mint a minimal biscuit with one authority fact, signed by `kp`.
  We use biscuit-java's builder directly — minting domain facts is the
  caller's job, not the substrate's. This helper exists for round-trip
  tests only."
  ^Biscuit [^KeyPair kp]
  (-> (Biscuit/builder kp)
      (.add_authority_fact "principal(\"test\")")
      (.build)))

;; -- keypair / pubkey ------------------------------------------------------

(deftest keypair-from-seed-is-deterministic
  (testing "same seed → same root pubkey; different seeds → different pubkeys"
    (let [a (cc-biscuit/root-public-key-hex (cc-biscuit/keypair-from-seed (fixed-seed)))
          b (cc-biscuit/root-public-key-hex (cc-biscuit/keypair-from-seed (fixed-seed)))
          c (cc-biscuit/root-public-key-hex (cc-biscuit/keypair-from-seed (distinct-seed)))]
      (is (= a b))
      (is (not= a c))
      (is (= 64 (count a)) "Ed25519 pubkey is 32 bytes = 64 hex chars"))))

(deftest pubkey-bytes-is-32
  (let [kp (cc-biscuit/keypair-from-seed (fixed-seed))
        bs (cc-biscuit/pubkey-bytes (cc-biscuit/root-public-key kp))]
    (is (= 32 (alength ^bytes bs)))))

;; -- pubkey-thumbprint -----------------------------------------------------

(deftest pubkey-thumbprint-is-32-and-stable
  (let [kp1 (cc-biscuit/keypair-from-seed (fixed-seed))
        kp2 (cc-biscuit/keypair-from-seed (fixed-seed))
        kp3 (cc-biscuit/keypair-from-seed (distinct-seed))
        t1  (cc-biscuit/pubkey-thumbprint (cc-biscuit/root-public-key kp1))
        t2  (cc-biscuit/pubkey-thumbprint (cc-biscuit/root-public-key kp2))
        t3  (cc-biscuit/pubkey-thumbprint (cc-biscuit/root-public-key kp3))]
    (testing "thumbprint is exactly 32 bytes (SHA-256)"
      (is (= 32 (alength ^bytes t1))))
    (testing "same pubkey → same thumbprint"
      (is (ba= t1 t2)))
    (testing "different pubkey → different thumbprint"
      (is (not (ba= t1 t3))))))

(deftest pubkey-thumbprint-matches-sha256-of-pubkey-bytes
  (testing "thumbprint is SHA-256 of canonical pubkey bytes — caller-verifiable"
    (let [kp     (cc-biscuit/keypair-from-seed (fixed-seed))
          pk     (cc-biscuit/root-public-key kp)
          pk-bs  (cc-biscuit/pubkey-bytes pk)
          md     (java.security.MessageDigest/getInstance "SHA-256")
          expect (.digest md pk-bs)
          actual (cc-biscuit/pubkey-thumbprint pk)]
      (is (ba= expect actual)))))

;; -- serialize / verify round-trip -----------------------------------------

(deftest serialize-and-verify-round-trip
  (testing "a minted token serializes to base64url and verifies back to a Biscuit"
    (let [kp     (cc-biscuit/keypair-from-seed (fixed-seed))
          token  (mint-trivial kp)
          b64    (cc-biscuit/serialize token)
          parsed (cc-biscuit/verify b64 (cc-biscuit/root-public-key kp))]
      (is (string? b64))
      (is (instance? Biscuit parsed)))))

(deftest verify-wrong-pubkey-rejected
  (testing "a token minted under one root key does not verify under another"
    (let [kp    (cc-biscuit/keypair-from-seed (fixed-seed))
          other (cc-biscuit/keypair-from-seed (distinct-seed))
          token (mint-trivial kp)
          b64   (cc-biscuit/serialize token)
          thrown (try
                   (cc-biscuit/verify b64 (cc-biscuit/root-public-key other))
                   nil
                   (catch clojure.lang.ExceptionInfo e e))]
      (is (some? thrown))
      (is (= :verify (:op (ex-data thrown)))))))

(deftest verify-malformed-token-rejected
  (testing "garbage input throws ex-info with :op :verify"
    (let [kp     (cc-biscuit/keypair-from-seed (fixed-seed))
          thrown (try
                   (cc-biscuit/verify "not-a-real-token" (cc-biscuit/root-public-key kp))
                   nil
                   (catch clojure.lang.ExceptionInfo e e))]
      (is (some? thrown))
      (is (= :verify (:op (ex-data thrown)))))))

;; -- attenuate -------------------------------------------------------------

(deftest attenuate-appends-block-and-still-verifies
  (testing "attenuation produces a new biscuit that still verifies under the
            original root pubkey; the original is unchanged"
    (let [kp        (cc-biscuit/keypair-from-seed (fixed-seed))
          base      (mint-trivial kp)
          block     (-> (.create_block base)
                        (.add_check "check if principal(\"test\")"))
          attn      (cc-biscuit/attenuate base block)
          b64-attn  (cc-biscuit/serialize attn)
          parsed    (cc-biscuit/verify b64-attn (cc-biscuit/root-public-key kp))
          b64-base  (cc-biscuit/serialize base)]
      (is (instance? Biscuit attn))
      (is (instance? Biscuit parsed))
      (testing "attenuated token's serialization differs from the original"
        (is (not= b64-base b64-attn))))))
