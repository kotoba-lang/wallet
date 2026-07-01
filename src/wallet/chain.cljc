(ns wallet.chain
  "Non-custodial multi-chain wallet core: one BIP-32/39/44 seed, one
  ChainDriver protocol, a registry of drivers ({:eth :btc} shipped here).
  HD derivation is chain-agnostic secp256k1 math shared via
  btc-crypto.bip32 (Ethereum and Bitcoin both derive on the same curve —
  only the address encoding and tx format differ, which is what a
  ChainDriver captures). Private keys never leave this process/library
  boundary; callers get back {:private-key ...} and are responsible for
  keystore encryption (see wallet.keystore) if persisting it."
  (:require [btc-crypto.bip32 :as bip32]
            [btc-crypto.core :as btc]
            [btc-crypto.tx :as btc-tx]
            [eth-crypto.core :as eth]))

(defprotocol ChainDriver
  (bip44-path [driver account change index]
    "The BIP-44 derivation path string for account/change/index on this chain.")
  (address-of [driver privkey]
    "Chain address(es) for a 32-byte private key.")
  (sign-tx* [driver privkey tx]
    "Chain-specific signed transaction for `tx` (shape is chain-specific —
    see each driver's docstring)."))

;; ─── :eth driver (BIP-44 coin type 60') ──────────────────────────────────

(def eth-driver
  (reify ChainDriver
    (bip44-path [_ account change index] (str "m/44'/60'/" account "'/" change "/" index))
    (address-of [_ privkey] {:address (eth/address-of-privkey privkey)})
    (sign-tx* [_ privkey tx] (eth/sign-tx-legacy tx privkey))))

;; ─── :btc driver (BIP-44 coin type 0' for legacy P2PKH, BIP-84 84' for
;;     native segwit P2WPKH — `bip44-path` always returns the 44' path;
;;     P2WPKH-preferring callers should derive under \"m/84'/0'/...\"
;;     directly, both work with the same driver since address-of/sign-tx*
;;     only need the raw private key) ─────────────────────────────────────

(def btc-driver
  (reify ChainDriver
    (bip44-path [_ account change index] (str "m/44'/0'/" account "'/" change "/" index))
    (address-of [_ privkey] (btc/address-of-privkey privkey))
    (sign-tx* [_ privkey {:keys [script-type] :as tx :or {script-type :p2wpkh}}]
      (case script-type
        :p2wpkh (btc-tx/sign-p2wpkh (:tx tx) (:input-index tx) (:amount tx) privkey)
        :p2pkh (btc-tx/sign-legacy-p2pkh (:tx tx) (:input-index tx) privkey)))))

(def drivers {:eth eth-driver :btc btc-driver})

;; ─── account derivation ──────────────────────────────────────────────────

(defn account
  "Derive account/change/index for `chain` (:eth or :btc) from `master`
  (a btc-crypto.bip32 seed->master node). Returns {:chain :path
  :private-key :address(es)}."
  ([master chain] (account master chain 0 0 0))
  ([master chain account-index] (account master chain account-index 0 0))
  ([master chain account-index change index]
   (let [driver (get drivers chain)
         path (bip44-path driver account-index change index)
         node (bip32/derive-path master path)
         privkey (:private-key node)]
     (merge {:chain chain :path path :private-key privkey}
            (address-of driver privkey)))))

(defn sign-tx
  "Sign `tx` (chain-specific shape — see each driver's `sign-tx*`) with the
  private key of a derived `account`."
  [{:keys [chain private-key]} tx]
  (sign-tx* (get drivers chain) private-key tx))
