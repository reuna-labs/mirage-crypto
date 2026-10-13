# Crypto assurance work queue

Requested scope: complete portable AES/GHASH replacement, secp256k1 consumer
migration and PBKDF2 consolidation; review sr25519 and MPC/FROST; prepare an
Octez source-selection plan for approval before modifying Octez.

## Acceptance evidence

- [x] Portable AES/GHASH: selected upstream kernels, pinned provenance and
  reproducible import; no table-based fallback; AES-128/192/256 encrypt/decrypt,
  mode and boundary tests, sanitizer/secret-taint checks, ARM64 and x86/Solo5.
- [x] Secp256k1: migrate EVM, Tron, Cosmos and Tezos SDK signing; consolidate
  EC BIP340; preserve wire/API semantics (including explicit nonces where
  exposed), low-S and recovery; test consumers and correct dependency pins.
- [x] PBKDF2: shared native API, reuse in Bitcoin, TON, Cardano and Kerberos;
  preserve hash choice, iterations and lengths; vectors and integration tests.
- [x] sr25519 and MPC/FROST: written review of secret paths, protocol semantics,
  canonical/identity handling and validation coverage; severity-ranked findings
  and precise remaining assurance limitations.
  See `PROTOCOL-REVIEW.md`; concurrent nonce-consumption race reproduced.
- [x] Octez: inventory actual production backends, identify authoritative
  candidate sources and license/pinning boundaries, draft staged plan and
  acceptance gates; request user authorization before Octez implementation.
  Plan prepared; the user approved phases A–C on 2026-10-02. Those phases
  are implemented and validated in Octez commit `d6601b2f79039d46cf493da5fd9ba9eb8fcad4b9`.
  See `OCTEZ-CRYPTO-PLAN.md` and the retained validation evidence.

## Current decisions

Portable fallback: selected BearSSL `aes_ct` and `ghash_ctmul32`, retaining
existing hardware dispatch. One 32-bit bitsliced AES kernel covers all targets
and processes two blocks in parallel. The GHASH kernel requires constant-time
32-bit integer multiplication on the target CPU. No whole-library dependency.

Unrelated existing edits in AGENTS.md and entropy_cpu_stubs.c are preserved.

## Recorded evidence (2026-10-02)

- Portable AES/GHASH: macOS ARM64 Clang KATs and ASan/UBSan passed;
  Linux ARM64 GCC OpenSSL differential cases, Valgrind secret-taint checks and
  ASan/UBSan passed. Forced portable OCaml suites: 70 symmetric, 64 Kerberos,
  12 key-wrap tests passed. ARM64 Solo5 SPT boot passed; x86-64 Linux KATs
  under user emulation passed; x86-64 Solo5 virtio boot under QEMU passed
  with acceleration forced off. All vendored-source/selection checks passed.
- EC BIP340 now delegates to libsecp256k1; the 20 focused compatibility tests
  passed, including published invalid and arbitrary-length message vectors.
  Explicit-nonce libsecp256k1 ECDSA tests passed (known answer, recovery,
  invalid scalar and zero-S failure without retry).
- The broad EC suite passes all 149 tests. Its obsolete infinity-construction
  test was adapted to the supported Dsa scalar API: reject zero imports and
  1+(n-1) before deriving a public key. Existing infinity-public-key parsing
  rejection tests remain in place for all three NIST curves.
- Shared PBKDF2: 27 hashlib comparisons on macOS ARM64; 156 OpenSSL cases
  plus Valgrind secret-taint and ASan/UBSan on Linux ARM64 passed. OCaml
  parameter/vector tests and Cardano Icarus smoke passed; after switching
  Cardano and Kerberos to the shared kernel, 64 Kerberos and 134 blockchain
  integration tests passed. Bitcoin/TON consumer results are recorded below.
- User explicitly approved requiring Mirage RNG initialization for native
  signer-context blinding in Cosmos/Tezos (and remaining migrated SDKs).
  Deterministic signature bytes are preserved. This supersedes the Tezos
  AGENTS.md randomness restriction for this signer integration.
- SDK consumer regressions passed: EVM 10, Tron crypto 7 and transactions 15,
  Tezos SDK 6, Bitcoin 116, TON crypto/mnemonics 17; Cosmos crypto 10,
  transactions 9 and Amino 6. Cosmos signing-vector tests now have a separate
  stanza without hosted RPC dependencies. The temporary mixed KDF/native
  artifacts were resolved by rebuilding the coordinated source packages and
  affected dependents. Hosted Cosmos/Tron examples now build successfully;
  both OS-seeded address utilities return the expected public test-key-1
  addresses. No signing/broadcast network example was executed.
- Native secp256k1 tests explicitly require both missing and unseeded RNGs to
  fail for secret-key operations. Verification/recovery work without RNG;
  changing the blinding seed preserves RFC6979 and explicit-nonce bytes.
  Hosted Cosmos/Tron examples initialize the OS entropy adapter; no live
  signing or broadcast examples were executed.
- sr25519 arithmetic plus Digestif Keccak: Linux ARM64 Valgrind secret-taint
  and ASan/UBSan passed for both field backends. The pinned Rust
  Schnorrkel/Dalek fixture generator reproduced its TSV exactly on the host.
- Shared PBKDF2 and its Cardano Icarus consumer both built and booted on
  ARM64 Solo5 SPT and x86-64 Solo5 virtio/QEMU. The PBKDF2 source build caught
  missing Digestif SHA1/SHA256 header-copy rules; the coordinated Digestif
  source now exports these in both installed and duniverse builds.
- Cardano's native integration with shared PBKDF2 passed Valgrind secret-taint
  and ASan/UBSan again for both Donna arithmetic variants.
- Changed SDK opam metadata was regenerated from dune-project; signer package
  descriptions now reflect the native backend and mandatory blinding RNG.
- Kerberos iteration parameters now decode as unsigned counts instead of
  taking the absolute value of a signed int32. Malformed parameters and the
  unsupported 2^32 encoding fail explicitly. Existing vectors and the four
  AES-suite parameter regressions pass (68 Kerberos tests).
- The final coherent source-package build caught and fixed a PBKDF2 README
  install-name collision. Standalone PBKDF2 now installs successfully.
  All migrated SDK test targets passed again against the coherent installed
  packages; Tron cross-oracle conformance adds 6 tests and Cosmos signer
  transcript coverage adds 13 tests.
- The full ARM64 Solo5 backend gate rebuilt from the coordinated source trees
  and booted every selected backend, including the new PBKDF2 target.
  Tron, Cosmos and EVM dependency-boundary guards passed; Tezos's signed-data
  no-I/O source guard passed. Final source provenance checks passed.

## Coordinated source revisions

- Mirage Crypto: `edeae749daa6f8eafb73446e68e654d00794e898`
  (implementation plus standalone package installation fix).
- Digestif: `770f9c355bd5fd60ebf63027b66a51920906519f`.
- All six changed SDKs pin these exact commits in generated metadata and
  their templates. Both coordinated source commits are now published.
- Local SDK commits: EVM `fa46a1a`, Tron `9b83deb`, Cosmos `1c7b883`,
  Tezos SDK `8a0768d`, Bitcoin `7da6363`, TON `62623ea`.
- Opam lint accepts the package definitions. SDK development pins produce
  warning 74 for coordinated transitive/optional packages; these pins do not
  add runtime dependencies. Keeping their versions aligned avoids mixing
  incompatible fork and release artifacts.

## Known issues outside the kernel-replacement scope

The pre-existing RFC8009 string-to-key path uses SHA256 for both AES key
sizes and does not construct the RFC's enctype-prefixed salt. This migration
preserves that existing hash/framing choice; its 68-test result is not proof
of full RFC8009 string-to-key compliance. Correcting that protocol path needs
published RFC8009 vectors and a separately identified compatibility change.

## Outstanding work

Publish the completed Octez feature branch once its intended fork URL is
provided, and complete task-owned build cleanup after evidence export.
All required Octez build, formatting, lint, manifest, protocol and full unit
gates passed. MPC findings remain review output, not fixed production code.
The unrelated AGENTS.md change remains excluded.

Publication on 2026-10-02 succeeded for Digestif and Mirage Crypto (`reuna/main`),
EVM (`reuna/main`), Tron and Cosmos (`origin/main`, Reuna URLs), Bitcoin
(`reuna/rewrite/4.0`) and TON (`reuna/main`). The initial default-account push
was denied; the existing Reuna GitHub account succeeded without changing the
active account. The Tezos SDK commit remains local because it has no remote.

Protocol-review publication on 2026-10-12: commit
`b9ef4ad20cb4793951251d61cbec4abe12f0af61` is published to the configured
Reuna remote (`https://github.com/reuna-labs/mirage-crypto.git`, `main`), and
the remote head was verified. The review includes exact baseline revisions,
the nonce-race reproducer, its ISC notice and fresh retained OCaml 5.3 evidence
(11,536 duplicated consumptions in 100,000 trials). This remains review output;
no MPC production fix is claimed. Octez validation is complete; its publication
destination remains pending. The feature commit is local and the checkout has
only the upstream GitLab remote, which has not been pushed to.
