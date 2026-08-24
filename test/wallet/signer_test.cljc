(ns wallet.signer-test
  "The signer seam is kept honest by a PARITY ORACLE: the signer-backed path
  must produce byte-identical output to the legacy in-process private-key
  path (which is verified in eth-crypto/btc-crypto's own repos). A refactor
  that changes tx assembly, digesting, or signature layout shows up as a
  byte mismatch here, not as a plausible-looking signature the network
  rejects. Refusals pin their :reason literal (repo rule: a check must have
  refused for the reason it names)."
  (:require [clojure.test :refer [deftest is]]
            [clojure.string :as str]
            [btc-crypto.bip32 :as bip32]
            [btc-crypto.bip39 :as bip39]
            [wallet.chain :as w]
            [wallet.chains :as chains]
            [wallet.signer :as signer]
            [wallet.siwe :as siwe]))

(def ^:private seed
  (bip39/mnemonic->seed
   "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"))
(def ^:private master (bip32/seed->master seed))
(def ^:private sgnr (signer/seed-signer master))

(defn- refusal-reason [thunk]
  (try (thunk) ::no-throw
       (catch #?(:clj clojure.lang.ExceptionInfo :cljs :default) e
         (:reason (ex-data e)))))

;; ─── signer-backed accounts carry no key, match privkey derivation ───────

(deftest signer-account-carries-no-private-key-and-matches
  (let [acct (w/account-with sgnr :eth)]
    (is (= "m/44'/60'/0'/0/0" (:path acct)))
    (is (nil? (:private-key acct)))
    (is (= (dissoc (w/account master :eth) :private-key) acct))))

(deftest utxo-pubkey-derivation-matches-privkey-derivation
  (doseq [chain [:btc :ltc :doge :bch]]
    (is (= (dissoc (w/account master chain) :private-key)
           (w/account-with sgnr chain))
        (str chain))))

;; ─── multi-chain: EVM shares one address, UTXO forks have their own ──────

(deftest evm-chains-share-one-address-and-differ-in-chain-id
  (let [eth (w/account-with sgnr :eth)
        bnb (w/account-with sgnr :bnb)
        base (w/account-with sgnr :base)]
    (is (= (:address eth) (:address bnb) (:address base)))
    (is (= [1 56 8453] [(:chain-id eth) (:chain-id bnb) (:chain-id base)]))))

(deftest utxo-forks-derive-their-own-versioned-addresses
  (let [ltc (w/account-with sgnr :ltc)
        doge (w/account-with sgnr :doge)
        bch (w/account-with sgnr :bch)]
    (is (= "m/44'/2'/0'/0/0" (:path ltc)))
    (is (str/starts-with? (:p2pkh ltc) "L"))
    (is (str/starts-with? (:p2wpkh ltc) "ltc1"))
    (is (str/starts-with? (:p2pkh doge) "D"))
    (is (nil? (:p2wpkh doge)))             ; Dogecoin has no SegWit — no fabricated form
    (is (some? (:cashaddr bch)))
    (is (nil? (:p2pkh bch)))))             ; BCH answers in CashAddr, not base58

;; ─── tx parity: signer path == privkey path, byte for byte ───────────────

(deftest legacy-tx-parity-signer-vs-privkey
  (let [tx {:nonce 9 :gas-price 20000000000 :gas 21000
            :to "0x3535353535353535353535353535353535353535"
            :value 1000000000000000000 :data "0x" :chain-id 1}]
    (is (= (w/sign-tx (w/account master :eth) tx)
           (w/sign-tx-with sgnr (w/account-with sgnr :eth) tx)))))

(deftest eip1559-tx-parity-and-chain-id-injection
  ;; the signer path gets NO :chain-id — the registry injects 8453; parity
  ;; with the explicit-chain-id privkey path proves the injection is right.
  (let [tx {:nonce 0 :max-priority-fee-per-gas 1000000000
            :max-fee-per-gas 30000000000 :gas 21000
            :to "0x3535353535353535353535353535353535353535"
            :value 0 :data "0x"}]
    (is (= (w/sign-tx (w/account master :base) (assoc tx :chain-id 8453))
           (w/sign-tx-with sgnr (w/account-with sgnr :base) tx)))))

(deftest parity-oracle-discriminates
  ;; two DIFFERENT accounts must not sign identically — proves the equality
  ;; assertions above compare real signatures, not two constants.
  (is (not= (siwe/sign-message-with "m" sgnr "m/44'/60'/0'/0/0")
            (siwe/sign-message-with "m" sgnr "m/44'/60'/0'/0/1"))))

;; ─── SIWE through the signer: the self-custody attach flow ───────────────

(deftest siwe-signer-parity-and-verify
  (let [acct (w/account master :eth)
        opts {:domain "example.com" :address (:address acct)
              :uri "https://example.com" :chain-id 1
              :nonce "32891756" :issued-at "2026-08-24T00:00:00Z"}
        via-key (siwe/sign-in opts (:private-key acct))
        via-signer (siwe/sign-in-with opts sgnr (:path acct))]
    (is (= (:signature via-key) (:signature via-signer)))
    (is (:ok? (siwe/verify-sign-in via-signer {:expected-domain "example.com"})))
    (is (= :domain-mismatch
           (:reason (siwe/verify-sign-in via-signer {:expected-domain "evil.example"}))))))

;; ─── refusals: staged chains, wrong network, receive-only ────────────────

(deftest staged-chain-refused-not-fabricated
  (is (= :wallet.chains/staged   (refusal-reason #(w/account-with sgnr :sol))))
  (is (= :wallet.chains/staged   (refusal-reason #(w/account master :ada))))
  (is (= :wallet.chains/external (refusal-reason #(chains/entry :atom))))
  (is (= :wallet.chains/unknown  (refusal-reason #(chains/entry :not-a-chain)))))

(deftest chain-id-mismatch-refused
  (let [tx {:nonce 0 :gas-price 1 :gas 21000
            :to "0x3535353535353535353535353535353535353535"
            :value 0 :data "0x" :chain-id 1}]
    (is (= :wallet.chain/chain-id-mismatch
           (refusal-reason #(w/sign-tx-with sgnr (w/account-with sgnr :bnb) tx))))))

(deftest bch-signing-refused-as-receive-only
  (is (= :wallet.chain/receive-only
         (refusal-reason #(w/sign-tx (w/account master :bch) {})))))

(deftest utxo-signer-tx-refused-honestly
  ;; UTXO tx signing through the seam is follow-up work, not silently absent.
  (is (= :wallet.chain/signer-family-unsupported
         (refusal-reason #(w/sign-tx-with sgnr (w/account-with sgnr :btc) {})))))

;; ─── registry sanity: every entry is either derivable or explains itself ─

(deftest registry-entries-are-complete
  (doseq [[k e] chains/chains]
    (case (:status e)
      nil (case (:family e)
            :evm (is (and (:chain-id e) (:coin-type e)) (str k))
            :utxo (is (and (:network e) (:coin-type e)) (str k)))
      :planned (is (string? (:needs e)) (str k " must name what it is waiting on"))
      :external (is (string? (:owner e)) (str k " must name its owner")))))
