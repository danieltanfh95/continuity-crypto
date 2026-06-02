(ns continuity-crypto.keystore
  "Parameterized fixed-length secret-byte loader. Each caller supplies the
  env-var names, the default keyfile path, the expected byte-length, and a
  short label for error messages; the loader resolves the secret with the
  same precedence every consumer wants:

    1. Env var `<env-var-name-raw>`            (base64url-unpadded literal)
    2. Config map `:key-b64`                   (base64url-unpadded literal)
    3. Keyfile at the resolved path            (EDN `{:secret-b64 \"...\"}`)
    4. Auto-generate a fresh secret, write a 0600 keyfile, return the bytes.

  The keyfile path is itself resolved with:
    1. Env var `<env-var-name-key-path>`
    2. Config map `:key-path`
    3. The supplied `:default-path`.

  The library refuses to read secret bytes of any length other than the
  caller-supplied `:seed-bytes` and throws `ex-info` with `{:expected :got}`
  so callers can pattern on the shape rather than the message string.

  Source pattern: continuity-auth's `biscuit-token/load-or-create-seed!` and
  the sibling `ip-hmac/load-or-create-key!` (both lifted into one function).
  Secret-key bytes are never logged anywhere; never included in error
  messages or stack traces."
  (:require
   [clojure.edn :as edn]
   [clojure.java.io :as io]
   [continuity-crypto.envelope :as envelope])
  (:import
   (java.nio.file Files)
   (java.nio.file.attribute PosixFilePermissions)
   (java.security SecureRandom)))

(defn- blank? [^String s]
  (or (nil? s) (.isBlank s)))

(defn- getenv [^String name] (System/getenv name))

(defn- read-keyfile
  ^bytes [^String label ^String path seed-bytes]
  (let [{:keys [secret-b64]} (edn/read-string (slurp path))
        bs (envelope/b64url-decode secret-b64)]
    (when-not (= seed-bytes (alength bs))
      (throw (ex-info (str label " keyfile: wrong length")
                      {:path path :expected seed-bytes :got (alength bs)})))
    bs))

(defn- generate-secret ^bytes [seed-bytes]
  (let [bs (byte-array seed-bytes)]
    (.nextBytes (SecureRandom.) bs)
    bs))

(defn- restrict-perms! [path]
  (try
    (Files/setPosixFilePermissions
     path (PosixFilePermissions/fromString "rw-------"))
    (catch UnsupportedOperationException _
      (binding [*out* *err*]
        (println (str "WARN: cannot set POSIX perms on " path
                      " — non-POSIX filesystem"))))))

(defn- write-new-keyfile! ^bytes [^String path seed-bytes]
  (let [seed (generate-secret seed-bytes)
        f    (io/file path)]
    (when-let [parent (.getParentFile f)]
      (.mkdirs parent))
    (spit f (pr-str {:secret-b64 (envelope/b64url-encode seed)}))
    (restrict-perms! (.toPath f))
    seed))

(defn resolve-key-path
  "Resolve the keyfile path. Env var overrides config; config overrides
  the supplied default."
  ^String [{:keys [env-var-name-key-path default-path]}
           {:keys [key-path]}]
  (let [from-env (getenv env-var-name-key-path)]
    (cond
      (not (blank? from-env)) from-env
      (not (blank? key-path)) key-path
      :else                   default-path)))

(defn load-or-create-seed!
  "Resolve a fixed-length secret. Precedence (highest first):
    env-var-name-raw → :key-b64 → keyfile → auto-generate-and-persist.

  `opts`:
    {:env-var-name-raw      \"<NAME>\"   ; base64url-unpadded literal
     :env-var-name-key-path \"<NAME>\"   ; keyfile path override
     :default-path          \"<path>\"
     :seed-bytes            <int>        ; e.g. 32
     :label                 \"<short>\"} ; for error messages

  `config`:
    {:key-b64  \"<optional-b64-literal>\"
     :key-path \"<optional-path-override>\"}

  Returns ^bytes of length :seed-bytes. Throws ex-info with `:expected`/`:got`
  on wrong-length input. Writes a 0600 keyfile on the auto-generate branch
  (warns to *err* on non-POSIX filesystems where perm restriction fails)."
  ^bytes [{:keys [env-var-name-raw seed-bytes label] :as opts}
          {:keys [key-b64] :as config}]
  (let [from-env-raw (getenv env-var-name-raw)]
    (cond
      (not (blank? from-env-raw))
      (let [bs (envelope/b64url-decode from-env-raw)]
        (when-not (= seed-bytes (alength bs))
          (throw (ex-info (str env-var-name-raw ": wrong length")
                          {:expected seed-bytes :got (alength bs)})))
        bs)

      (not (blank? key-b64))
      (let [bs (envelope/b64url-decode key-b64)]
        (when-not (= seed-bytes (alength bs))
          (throw (ex-info (str label " :key-b64: wrong length")
                          {:expected seed-bytes :got (alength bs)})))
        bs)

      :else
      (let [path (resolve-key-path opts config)]
        (if (.exists (io/file path))
          (read-keyfile label path seed-bytes)
          (write-new-keyfile! path seed-bytes))))))
