# Development oracle

Pinned `@scure/bip32` 2.4.0 with npm integrity hashes for every dependency.
Run `npm ci --ignore-scripts`, then `node vectors.mjs` to regenerate
`../../bip32/test/scure.tsv`. The 64 cases cover 16/32/48/64-byte seeds,
root nodes, hardened and public derivation, and unsigned index boundaries.
No JavaScript or ScriptC is used by the production packages.

The official fixture alongside it is the 17 raw extended-key pairs from
BIP32 vectors 1–4, independently decoded from Base58Check in Bitcoin's
`test/vectors/bip32-test-vectors.json`. BIP32 specification (BSD-2-Clause):
https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki

Impossible HMAC outcomes are tested through the private OCaml functor;
scure's automatic retry policy is intentionally not adopted.
