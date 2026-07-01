(ns wallet.keystore-test
  (:require [clojure.test :refer [deftest is]]
            [wallet.keystore :as ks]))

(def ^:private privkey (byte-array (range 32)))

(deftest round-trip
  (let [encrypted (ks/encrypt-keystore privkey "correct horse battery staple" 1000)
        decrypted (ks/decrypt-keystore encrypted "correct horse battery staple")]
    (is (= (seq privkey) (seq decrypted)))))

(deftest wrong-passphrase-rejected
  (let [encrypted (ks/encrypt-keystore privkey "correct horse battery staple" 1000)]
    (is (thrown? #?(:clj Exception :cljs js/Error) (ks/decrypt-keystore encrypted "wrong passphrase")))))

(deftest tampered-ciphertext-rejected
  (let [encrypted (ks/encrypt-keystore privkey "correct horse battery staple" 1000)
        tampered (update encrypted :ciphertext (fn [^bytes ct]
                                                  (let [c (aclone ct)]
                                                    (aset-byte c 0 (unchecked-byte (bit-xor (aget c 0) 1)))
                                                    c)))]
    (is (thrown? #?(:clj Exception :cljs js/Error) (ks/decrypt-keystore tampered "correct horse battery staple")))))

(deftest each-encryption-uses-a-fresh-nonce-and-salt
  (let [a (ks/encrypt-keystore privkey "pw" 1000)
        b (ks/encrypt-keystore privkey "pw" 1000)]
    (is (not= (seq (:nonce a)) (seq (:nonce b))))
    (is (not= (seq (:salt a)) (seq (:salt b))))))
