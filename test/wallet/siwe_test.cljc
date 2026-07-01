(ns wallet.siwe-test
  "Verifies the real (secp256k1, personal_sign-based) SIWE flow: sign then
  verify round-trips, and tampering (message or address) is rejected via
  ecrecover — the same check real Ethereum tooling (siwe.js/viem/ethers)
  would perform."
  (:require [clojure.test :refer [deftest is]]
            [btc-crypto.bip32 :as bip32]
            [btc-crypto.bip39 :as bip39]
            [wallet.chain :as w]
            [wallet.siwe :as siwe]))

(def ^:private seed
  (bip39/mnemonic->seed
   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"))
(def ^:private acct (w/account (bip32/seed->master seed) :eth))

(def ^:private opts
  {:domain "kotobase.net" :address (:address acct) :statement "Sign in to kotobase."
   :uri "https://kotobase.net" :version "1" :chain-id 1 :nonce "abcd1234"
   :issued-at "2026-07-01T00:00:00Z"})

(deftest message-contains-expected-lines
  (let [msg (siwe/message opts)]
    (is (re-find #"^kotobase\.net wants you to sign in with your Ethereum account:\n" msg))
    (is (re-find (re-pattern (:address acct)) msg))
    (is (re-find #"Chain ID: 1" msg))
    (is (re-find #"Nonce: abcd1234" msg))))

(deftest sign-in-verifies
  (let [result (siwe/sign-in opts (:private-key acct))]
    (is (true? (siwe/verify-sign-in result)))))

(deftest tampered-message-fails-verification
  (let [result (siwe/sign-in opts (:private-key acct))]
    (is (false? (siwe/verify-message (str (:message result) "x") (:signature result) (:address acct))))))

(deftest wrong-address-fails-verification
  (let [result (siwe/sign-in opts (:private-key acct))]
    (is (false? (siwe/verify-message (:message result) (:signature result)
                                      "0x0000000000000000000000000000000000000000")))))
