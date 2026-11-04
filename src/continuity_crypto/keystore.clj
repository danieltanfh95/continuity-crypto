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
   (java.nio.file FileSystems Files StandardOpenOption)
   (java.nio.file.attribute FileAttribute PosixFilePermissions)
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

(defn- posix-supported? []
  (-> (FileSystems/getDefault)
      .supportedFileAttributeViews
      (.contains "posix")))

(defn- write-new-keyfile!
  "Create the keyfile atomically with 0600 permissions on POSIX
  filesystems. Prior shape wrote via `spit` (default umask, typically
  0644) then chmodded to 0600 as a second step, which opened a race
  window a local attacker could use to read the key between the two
  operations. The NIO path here combines `CREATE_NEW` with
  `PosixFilePermissions/asFileAttribute` so the file never exists on
  disk with any perms other than 0600.

  Non-POSIX filesystems fall back to the spit path with a warning;
  callers that need hardened perms on Windows must supply the key
  via `env-var-name-raw` or `:key-b64`."
  ^bytes [^String path seed-bytes]
  (let [seed       (generate-secret seed-bytes)
        f          (io/file path)
        payload    (.getBytes (pr-str {:secret-b64 (envelope/b64url-encode seed)})
                              "UTF-8")]
    (when-let [parent (.getParentFile f)]
      (.mkdirs parent))
    (if (posix-supported?)
      (let [p    (.toPath f)
            attr (PosixFilePermissions/asFileAttribute
                  (PosixFilePermissions/fromString "rw-------"))]
        ;; Two-step atomic 0600 creation. `createFile` creates the empty
        ;; file with the perms attribute in one syscall (throws
        ;; FileAlreadyExistsException if the path already exists — the
        ;; caller gate `(.exists f) read vs. write` keeps us on the write
        ;; branch only when the path is free). The subsequent `write`
        ;; writes the payload into the already-0600 file; perms are
        ;; untouched.
        (Files/createFile p (into-array FileAttribute [attr]))
        (Files/write p payload (into-array StandardOpenOption
                                           [StandardOpenOption/WRITE
                                            StandardOpenOption/TRUNCATE_EXISTING])))
      (do
        (spit f (String. payload "UTF-8"))
        (binding [*out* *err*]
          (println (str "WARN: cannot set POSIX perms on " path
                        " — non-POSIX filesystem")))))
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
