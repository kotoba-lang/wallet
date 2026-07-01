# wallet (non-custodial マルチチェーン wallet)

MetaMask / Coinbase Wallet 型の non-custodial マルチチェーン wallet を portable
Clojure (`.cljc`) で。単一の BIP-32/39/44 seed から `ChainDriver` レジストリ
（`:eth`/`:btc` を同梱、拡張可能）でアカウントを導出し、**本物の
SIWE (EIP-4361)** — `cacao`（Ed25519 did:key の actor 内部認証専用）とは別に、
secp256k1 の `personal_sign` で署名し `ecrecover` で検証する、siwe.js/viem/
ethers 等の実 Ethereum tooling がそのまま検証できるフロー — を提供する。
ADR: `90-docs/adr/2607012200-kotoba-lang-btc-mining-wallet-substrate.md`。

秘密鍵は wallet の外に一切出さない（non-custodial）。
[kotoba-lang/btc-crypto](https://github.com/kotoba-lang/btc-crypto)（共有
secp256k1 HD tree・BTC アドレス/tx）と
[kotoba-lang/eth-crypto](https://github.com/kotoba-lang/eth-crypto)（ETH
アドレス/tx/keccak）に依存。

## Namespaces

- `wallet.chain` — `ChainDriver` プロトコル + `:eth`/`:btc` driver +
  `account`（BIP-44 パス導出）+ `sign-tx`。HD 導出は secp256k1 で
  チェーン非依存なので `btc-crypto.bip32` を両チェーンで共有する
  （Ethereum も Bitcoin と同じ曲線）
- `wallet.siwe` — 本物の SIWE (EIP-4361): `message`（正準テキスト構築）、
  `sign-message`/`verify-message`（`personal_sign` + `ecrecover`）、
  `sign-in`/`verify-sign-in`
- `wallet.keystore` — ローカル暗号化キーストア。`kotoba.lang.crypto` の
  `IAEAD` data contract 上に JVM 向けの実 AES-256-GCM 実装
  （`kc/mock-aead` はテスト専用、と `crypto` 自身がドキュメント化している）+
  PBKDF2-HMAC-SHA256 によるパスフレーズ鍵導出を同梱

## Quick start

```clojure
(require '[btc-crypto.bip32 :as bip32]
         '[btc-crypto.bip39 :as bip39]
         '[wallet.chain :as wallet]
         '[wallet.siwe :as siwe]
         '[clojure.java.io :as io])

(def seed (bip39/mnemonic->seed "<12/24-word mnemonic>" "<optional passphrase>"))
(def master (bip32/seed->master seed))

(def eth (wallet/account master :eth))   ;=> {:chain :eth :path "m/44'/60'/0'/0/0" :address "0x..."}
(def btc (wallet/account master :btc))   ;=> {:chain :btc :path "m/44'/0'/0'/0/0" :p2pkh "1..." :p2wpkh "bc1..."}

(def signed (siwe/sign-in {:domain "example.com" :address (:address eth)
                           :uri "https://example.com" :chain-id 1
                           :nonce "..." :issued-at "2026-07-01T00:00:00Z"}
                          (:private-key eth)))
(siwe/verify-sign-in signed) ;=> true
```

## Test

```
clojure -M:test
```
