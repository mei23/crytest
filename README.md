# crytest

ActivityPubのHTTP Signatureの実験コード集

### keypair.ts

各種鍵生成 (RSA, ECDSA, ed25519, ed448)
`genRsaKeyPair`, `genEcKeyPair`, `genEd25519KeyPair`, `genEd448KeyPair`

### signed-request.ts

APアプリから使うもの

`createSignedPost`, `createSignedGet`, `genDigestHeader`

### http-signature.ts

実装

### portable/

Misskeyにrsa-sha256専用で送った元ソース

### tools/bench.ts

ベンチ用
