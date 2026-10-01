# Independent vectors

- `rust-vectors.tsv`: 128 records from `typed-io/rust-ed25519-bip32`, pinned at
  `2066bbfa011d26a5ea18cf4558240e9299bd0668` (MIT/Apache-2.0). Regenerate from
  the repository root with:

  ```sh
  cargo run --locked --release --manifest-path tests/rust-ed25519-bip32/Cargo.toml > ed25519-bip32/test/rust-vectors.tsv
  ```

- `cardano-vectors.tsv`: the five unprotected V2/PBKDF records in Cardano's
  wallet goldens at `ac2e12a471b735ad80949bcbf0f6f634e5dbef77` (MIT). The stored
  cached public key is removed from 128-byte xprv values to obtain CIP-16's 96
  bytes. These cover the root and four derivation paths. Records for V1 and
  legacy root generation are intentionally outside this backend's scope.
- `icarus-vectors.tsv`: Python `hashlib.pbkdf2_hmac`, 17 entropy lengths times
  five passphrase lengths, including 128, 129 and 257-byte HMAC key boundaries.
- `master-vectors.tsv`: Python `hashlib` paper-style SHA512/SHA256 masters,
  including the forbidden-bit failures, for 256 seed lengths.

Regenerate the latter three with a clean Cardano checkout at the pinned commit:

```sh
python3 tools/generate-ed25519-bip32-fixtures.py --cardano-source /path/to/cardano-crypto
```

Rust, Python, OpenSSL (used internally by some Python builds), the legacy
OCaml comparison and their dependencies are only development oracles. The
standalone runtime and its ordinary OCaml tests do not depend on them.
