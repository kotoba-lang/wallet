(ns wallet.siwe
  "Real SIWE (EIP-4361) sign-in: unlike kotoba-lang/cacao (which mints an
  Ed25519-did:key-signed CAIP-122 token for internal actor auth), this signs
  the EIP-4361 plaintext with the wallet's actual secp256k1 Ethereum account
  key via the standard `personal_sign` scheme
  (\"\\x19Ethereum Signed Message:\\n\" + byte-length + message -> keccak256
  -> ECDSA), so the resulting signature is verifiable by real Ethereum
  tooling (siwe.js / viem / ethers) via `ecrecover` — this is what makes a
  wallet MetaMask/Coinbase-Wallet-compatible for dApp login, not just
  SIWE-shaped."
  (:require [clojure.string :as str]
            [eth-crypto.core :as eth]))

(defn message
  "The EIP-4361 plaintext to sign. `address` is the EIP-55 checksummed 0x…
  address (from `wallet.chain/account`'s :address)."
  ^String [{:keys [domain address statement uri version chain-id nonce issued-at
                   expiration-time not-before request-id resources]
            :or {version "1"}}]
  (let [lines (cond-> [(str domain " wants you to sign in with your Ethereum account:")
                       address ""]
                statement (conj statement "")
                :always (into [(str "URI: " uri)
                              (str "Version: " version)
                              (str "Chain ID: " chain-id)
                              (str "Nonce: " nonce)
                              (str "Issued At: " issued-at)])
                expiration-time (conj (str "Expiration Time: " expiration-time))
                not-before (conj (str "Not Before: " not-before))
                request-id (conj (str "Request ID: " request-id))
                (seq resources) (conj "Resources:")
                (seq resources) (into (map #(str "- " %) resources)))]
    (str/join "\n" lines)))

;; ─── personal_sign (EIP-191 \x19 prefix) ─────────────────────────────────

(defn- concat-bytes ^bytes [arrays]
  (let [total (reduce (fn [^long n ^bytes a] (+ n (alength a))) 0 arrays)
        out (byte-array total)]
    (loop [off 0 as arrays]
      (if (seq as)
        (let [^bytes a (first as)]
          (System/arraycopy a 0 out off (alength a))
          (recur (+ off (alength a)) (rest as)))
        out))))

(defn personal-sign-digest
  "The keccak256 digest actually signed by MetaMask's `personal_sign` /
  `eth_sign` for a UTF-8 `message` string: keccak256(\"\\x19Ethereum Signed
  Message:\\n\" + utf8-byte-length + message)."
  ^bytes [^String msg]
  (let [msg-bytes (eth/utf8 msg)
        prefix (eth/utf8 (str "Ethereum Signed Message:\n" (alength msg-bytes)))]
    (eth/keccak256 (concat-bytes [prefix msg-bytes]))))

(defn sign-message
  "Sign `msg` with a 32-byte `privkey`, personal_sign-style. Returns the
  0x… 65-byte (r‖s‖v, v∈{27,28}) hex signature."
  ^String [^String msg ^bytes privkey]
  (let [digest (personal-sign-digest msg)
        {:keys [r s recovery-id]} (eth/secp256k1-sign privkey digest)
        v (+ 27 recovery-id)
        r32 (let [^bytes b (.toByteArray ^java.math.BigInteger r) n (alength b) out (byte-array 32)]
              (if (<= n 32) (do (System/arraycopy b 0 out (- 32 n) n) out)
                  (java.util.Arrays/copyOfRange b (- n 32) n)))
        s32 (let [^bytes b (.toByteArray ^java.math.BigInteger s) n (alength b) out (byte-array 32)]
              (if (<= n 32) (do (System/arraycopy b 0 out (- 32 n) n) out)
                  (java.util.Arrays/copyOfRange b (- n 32) n)))]
    (str "0x" (eth/bytes->hex (concat-bytes [r32 s32 (byte-array [(unchecked-byte v)])])) )))

(defn verify-message
  "Recover the signer address from `msg` + `sig-hex` (0x… 65-byte) and check
  it matches `expected-address` (case-insensitive — both are EIP-55
  checksummed, but compare loosely in case a caller passes lowercase)."
  [^String msg ^String sig-hex ^String expected-address]
  (let [digest (personal-sign-digest msg)
        sig (eth/hex->bytes sig-hex)
        recovered (eth/ecrecover-checksum digest sig)]
    (= (str/lower-case recovered) (str/lower-case expected-address))))

;; ─── convenience: sign-in / verify a full SIWE flow ──────────────────────

(defn sign-in
  "Build the EIP-4361 message for `opts` (see `message`) and personal_sign it
  with `privkey`. Returns {:message :signature :address}."
  [opts ^bytes privkey]
  (let [msg (message opts)]
    {:message msg
     :signature (sign-message msg privkey)
     :address (:address opts)}))

(defn verify-sign-in
  "Verify a `sign-in` result: the signature recovers to :address."
  [{:keys [message signature address]}]
  (verify-message message signature address))
