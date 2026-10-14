# Octez crypto implementation: approved phases A–C

Inventory date: 2026-10-02. Checkout: `~/reuna/web3/tezos`, commit
`34a13eb8750c3f8458b57a6573e0dba86434e0ae`. This is full Octez, separate from
the `ocaml-tezos` SDK migrated in the current work. No Octez files have been
changed at inventory time. The user approved publication and implementation
of phases A–C on 2026-10-02.

## Findings from the existing build

| Surface | Existing implementation | Proposed action |
| --- | --- | --- |
| secp256k1 in `src/lib_crypto/secp256k1.ml` | `secp256k1-internal`; context randomized with `Hacl.Rand` | Keep the established native algorithm; compare its exact API/encoding behavior with our minimal libsecp256k1 adapter before replacing bindings. |
| Ed25519, P256, hashes, MACs in `src/lib_hacl` | `hacl-star` and `hacl-star-raw`; lock selects 0.7.2 | Select matching generated HACL C kernels and write small C stubs where reducing the binding closure is useful. Preserve existing verified kernels' properties. |
| BLS12-381 | BLST plus local `blst_extended.c`, field/group wrappers and polynomial code | Separate upstream kernel provenance from local extensions. Port only signature operations that match our native API; classify extensions individually. |
| Sapling | Local Rust FFI over Zcash crates, with ctypes binding generation | Retain protocol-compatible Rust cryptography initially. First inventory exports, proof parameters and build-only versus runtime binding dependencies. |
| ML-DSA-44 | `src/rust_libcrux`, libcrux-ml-dsa 0.0.5, native Rust/OCaml bridge | Retain this kernel initially. Evaluate a small native ABI or generated C only against the exact crate revision and parameter set. |
| KZG, PLONK and polynomial protocols | Local higher-level protocols over field/group kernels | Review secret versus public scalar paths and transcripts independently. A BLST swap cannot validate these protocols. |

Existing sources already include established cryptographic kernels. The work
should focus on unsupported local arithmetic, binding closure and secret-path
assurance. A generic algorithm-name match is insufficient for consensus or
historical signature-verification compatibility.

## Authoritative sources and pin boundaries

1. **Bitcoin Core libsecp256k1** — [upstream](https://github.com/bitcoin-core/secp256k1),
   MIT. Reuse our selected commit
   `6e2c8bc4ecdc6e71dbe7a368f360d8d453ce435d` as a comparison candidate. Upstream
   documents constant-time signing/key generation, recovery and embedded use.
   Keep RNG context blinding and preserve Octez's digest, watermark, compact
   signature, low-S and recovery semantics. Do not route all Octez curves
   through this secp-only implementation.

2. **HACL*** — [upstream](https://github.com/hacl-star/hacl-star). Its generated
   C is also available under MIT; retain the exact selected files' license
   notices. Resolve the currently locked 0.7.2 package to the underlying
   generated-source revision before importing. Record source commit, file
   hashes, extraction/compiler provenance and the verified algorithm/variant.
   Start with byte-compatible Ed25519/P256 and hashes currently used by Hacl;
   avoid a blanket claim that every wrapper is covered by the kernel proofs.

3. **BLST** — [upstream](https://github.com/supranational/blst), Apache-2.0.
   Octez's `src/lib_bls12_381/update_blst.sh` selects
   `ab335a9a5e5b691ffb919813e7115809584474dd`; our native package selects
   `54e6e55674722fc2797ebb4bbb71b26d881eb4b8`. Compare these revisions before
   choosing one. Preserve MinPk/MinSig choices, domain tags, aggregation and
   subgroup/identity rejection. Upstream audit/formal-verification work does
   not automatically cover Octez's appended extension C or proving code.

4. **Zcash sources** — [librustzcash](https://github.com/zcash/librustzcash)
   and the precise dependencies locked by Octez's `src/rustzcash_deps`.
   Local FFI metadata declares MIT OR Apache-2.0. Inventory licenses per crate
   and parameter-file provenance separately. Do not replace Sapling with a
   general BLS library: the proof system, Jubjub operations and transaction
   semantics require their own matching implementation.

5. **libcrux** — [upstream](https://github.com/celabshq/libcrux), currently
   redirected from cryspen/libcrux; Apache-2.0/MIT notices must follow selected
   files. Use Octez's locked 0.0.5 source as the compatibility baseline.
   Determine which ML-DSA-44 paths and generated artifacts have what assurance
   before proposing a different build route. No Rust-to-C translation is
   presumed to inherit verification without that evidence.

The first implementation phase must resolve outstanding source revisions from
the lockfiles/archive checksums; no floating `main` imports or guessed pins.

## Approved phases

### Phase A: inventory and compatibility harness

- Build a reachable-operation map from signer APIs, protocol verification and
  proof APIs, separating secret signing/proving from public verification.
- Preserve an Octez baseline oracle and exported fixtures before edits.
- Record imported kernels, local extensions, generated bindings, RNG sources,
  allocation/runtime requirements and exact source/license manifests.
- Inventory frozen protocol compatibility and reject any change that alters
  historical acceptance behavior without a separately authorized decision.

### Phase B: bounded signer integration

- Introduce minimal native adapters for the selected secp256k1 and HACL signer
  subset, preserving the public Octez OCaml interfaces.
- Use caller/platform entropy for secret-key context blinding. Initialization
  failures must be explicit; deterministic signature bytes stay deterministic.
- Extract a small signer closure suitable for Solo5. Do not require the full
  Octez node, prover or Rust dependency tree to become an enclave library.
- Retain only required kernel translation units, with reproducible selectors
  and tiny C stubs. Measure transitive package and linked-symbol changes.

### Phase C: BLS signature boundary

- Compare the two pinned BLST revisions and Octez signature semantics.
- Reuse the established native signature kernel where compatibility is proven.
- Inventory every local extension operation used by polynomial/proof code and
  its secret/public inputs. Do not delete an extension based only on a similar
  upstream function name.

### Separate later proposals

Sapling bindings, ML-DSA integration changes, timelock/bignum work and
KZG/PLONK/prover hardening each need a focused source-selection and compatibility
plan. They are inventoried in this queue but not included in the proposed
initial signer replacement authorization.

## Acceptance gates for each changed primitive

- Existing Octez tests plus differential tests against the preserved baseline
  and upstream vectors; include malformed, boundary, subgroup and identity
  encodings, watermark/domain-tag handling and deterministic byte outputs.
- Native sanitizer and secret-taint checks, allocation/GC and concurrency tests
  at the OCaml boundary, failure behavior when RNG is unavailable.
- Fixed-versus-random secret timing populations for complete exposed secret
  operations, with limitations reported separately from kernel guarantees.
- ARM64 and x86-64 native validation; actual Solo5 boots for the extracted
  signer subset, with closure/symbol checks and code-size measurements.
- Edit Octez's manifest sources and regenerate dune/opam metadata; do not hand
  edit generated files. Run the repository's formatting, manifest consistency,
  build and relevant protocol gates before any commit.

Approved scope: Phases A–C, with each primitive gated by compatibility
evidence. The separate later proposals remain outside this implementation scope.

## Implementation checkpoint (2026-10-03)

Publication of the coordinated Digestif/Mirage Crypto and five SDK commits is
complete; remote heads were verified. Tezos SDK remains local because no remote
is configured. Octez phases A–C are approved and implementation is ongoing.

- Two standalone native adapters are integrated: HACL Ed25519/P256 and
  libsecp256k1, with isolated native symbols and no binding/runtime dependencies
  beyond OCaml. Secp secret operations require explicit blinding entropy.
- Full Octez crypto and both signer backends compile on OCaml 5.3, including
  the optional Ledger implementation. Existing HACL 40, crypto 61, BLS 356,
  BLS-signature 196 and polynomial/SRS 107 tests pass.
- HACL 820 and secp 501 baseline records match. The secp parser differential
  adds 25,000 malformed cases and 1,024 ordering comparisons. Standalone
  runners were corrected to honor the caller-selected compiler and rerun on 5.3.
- BLST is updated to Reuna pin 54e6e55674722fc2797ebb4bbb71b26d881eb4b8 after
  2,402 kernel comparison records and old/new Octez tests. All seven local
  extension exports remain. Five identical sizeof helpers now come upstream.
- HACL/secp FFI sanitizer, GC/concurrency, RNG failure and seed-wipe checks
  pass. BLST sanitizer and four-domain/GC checks pass. Signing/public-derivation
  kernel taint checks pass; BLST keygen's zero-scalar retry is an explicitly
  reproduced pre-existing secret-dependent branch, not included in that pass.
- Eight complete HACL/secp operation timing populations (50,000/class) on
  OCaml 5.3 have max absolute t 1.661 after removing a harness input-buffer bias.
  Eleven BLS populations (50,000/class) have max absolute t 1.938; no blanket
  CT claim. Another 36 HACL facade buffer acceptance/output cases match.
- ARM64 SPT and x86-64 virtio/QEMU Solo5 boots pass with Mirage RNG. Symbol
  gates detect no Zarith/GMP, ctypes, Unix, HACL OS RNG or Rust in the extracted
  images. Native x86 kernel binaries pass under user emulation; not bare-metal
  x86 timing evidence.
- Sapling/ML-DSA source/license inventory covers 25 checksum-verified selected
  crates, all wrapper exports, parameter hashes and all local BLST extension
  callers. The old Orchard 0.1.0 crate declares LICENSE-BOSL; libcrux 0.0.5
  kernels declare Apache-2.0. These distinctions are retained in the report.

Authoritative detailed evidence and remaining gates are in
`~/reuna/web3/tezos/scripts/crypto/README.md` and `NON-SIGNER-INVENTORY.md`.
Full lint and formatting pass; manifest consistency passes in a clean disposable
validation snapshot. Both standalone packages install with their license files,
and their recursive findlib closure contains only the two adapter packages.
The 36 HACL, 74 secp and 172 BLST selected source files match pinned inputs.

Full applicable build/protocol gates and feature-branch publication remain.
All 39 protocol-environment tests pass. The missing RSS, RISC-V Rust target and
libclang prerequisites are installed. After storage was freed, the full build
exposed an independently reproduced pre-existing ML-DSA bytecode-link failure.
The pinned OCaml Rust binding's no-caml-startup feature fixes it without changing
kernel/wrapper sources or Cargo.lock. The isolated bytecode test and the complete
dune build -j 4 now pass. Full make test-unit is running; protocol compilation
and final consistency checks remain. Standalone runner commands now preserve
the shared workspace profile/cache rather than using Dune package mode.

The user authorized finishing validation and cleaning up task-owned Docker
artifacts afterward. Preserve evidence before removing mc-native-backends;
its large writable layer contains the temporary builds. It has no Docker
volumes. Other Kubernetes containers/volumes are outside this cleanup.
Sources and logs are preserved, including a host log archive at
/tmp/octez-validation-logs.tar.gz. The host feature branch is
reuna@native-crypto-signers. No Octez implementation commit has been made; only
its upstream GitLab remote is configured. Publication destination is pending.

## External-drive resume (2026-10-10)

The user requires the remaining Octez build to run on the external drive.
The previous `mc-native-backends` container and its image are no longer present;
there is no surviving validation process to resume. Host source changes and
`tests/review/octez-2026-10-04/evidence.tar.gz` survive. The last full unit
retry's outcome is unavailable and must not be counted as a pass.

The replacement container is `octez-native-external`. Its `/work` is a bind
mount of `/Volumes/Seagate Expansion Drive/reuna/builds/octez-native-signers-20261010`.
The source snapshot, `_build`, opam root, Rust toolchains, Cargo cache, formatter,
logs, home and temporary directories all live there. `/tmp` and `/var/tmp` are
also external bind mounts. The Linux system-tooling layer is the only new
container storage on the internal disk. Source staging excludes generated
build artifacts and records per-file hashes in `source-manifest.json`.

The external runner checks these mount/environment paths and stops if external
free space falls below 20 GiB or internal free space falls below 8 GiB.
It also requires a read-only container root, so build writes must use the
external mounts. The initial shared-storage growth check was replaced because
it also counted unrelated Docker activity. The pinned OCaml 5.3 / Rust 1.88
environment, locked dependencies and validation tools have been recreated
successfully. A Docker runtime restart stopped the containers after dependency
installation; the external state survived and the read-only container was
restarted. The completed setup container was removed. The full repository build
passed in `/work/src` (`GATE EXIT: 0`), with log
`/work/logs/repository-build.log` copied into the host evidence directory.
DAL fixture installation and checksum verification passed. Final formatting
passed without source changes on October 11. Full lint and manifest consistency
also passed. The sequential final-gate runner is executing the full serial unit
suite, then both protocol compilation aliases and final whole-operation signer
timing; it stops on failure. Logs for completed gates are copied to the host
evidence directory.

The previous run found and fixed the secp public-key heap representation: a
canonical x coordinate and parity bit now preserve the frozen 72-byte model.
Both affected protocol size tests, the adapter's boundary/differential tests,
and rebuilt ARM/x86 Solo5 boots passed before interruption. The broad unit run
also encountered a worker-callback failure and concurrent Snoop temporary-file
warnings; isolated reruns passed. Full-suite completion remains unverified.

## Native test filesystem correction (2026-10-12)

The first external full-unit run stopped at the internal 8 GiB safety cutoff.
It also exposed two environment failures: missing `/etc/services` and RocksDB
checkpoint hard-link failures on the shared external filesystem. Debian
netbase files fix the connection-pool suite (all three tests pass). The exact
shrunk NDS counterexample fails twice on the shared filesystem, passes twice
on tmpfs, and passes on an ext4 image stored on the external drive.

The replacement container preserves the completed build/cache and mounts that
8 GiB ext4 image for temporary test storage. Its root remains read-only. The
original property seed is being rerun before resuming the full gates. No NDS,
frozen protocol or crypto source was changed for this environment correction.
The protocol review and retained nonce-race evidence are committed separately
as b9ef4ad; the Octez implementation remains uncommitted.

## Storage interruption (2026-10-13)

The original-seed snapshot property passed on external ext4. The subsequent
full unit run reached a retained checkpoint of 63/139 NDS cases, then stopped
at 2026-10-12 21:29:42 UTC when internal Docker free space fell below 8 GiB.
This is not a full unit pass. The completed build and external workspace
survive. The next day, internal Docker space remained about 6.2 GiB, with
555 GiB free externally. Tests have not restarted under that cutoff.

The task containers each have only 238,719 writable bytes; their shared system
image is about 1.16 GB. A separate request asks permission to remove Docker's
12.83 GB of unused shared build cache. No unrelated images, containers or
volumes have been removed. Full unit/protocol/timing gates, commit, publication
and final cleanup remain outstanding.

Further inspection confirmed that the runner's own 8 GiB internal reserve was
unnecessarily stopping external-only builds: the container root is read-only,
all writable build/temporary mounts are external, and its writable layer stayed
at 238,719 bytes. The reserve is now 2 GiB for Docker metadata, with the 20 GiB
external reserve and mount checks unchanged. Storage preflight passed and the
remaining protocol/timing/unit sequence resumed. No shared cache was deleted;
the cache-cleanup request is no longer needed to resume. The new supervisor
checkpoints buffered NDS output so interruptions cannot discard all progress
evidence. Test scope and sample counts are unchanged.

Both complete protocol aliases (`@runtest_compile_protocol` and
`@runtest_out_of_opam`) passed on October 13. Final HACL/secp timing after the
public-key heap-layout correction completed all eight populations at 50,000
samples per class, with max absolute Welch t 1.9575. Raw logs and a parsed
summary are retained; this is virtualized timing evidence, not a CT proof.
The full unit retry is running with persistent NDS output checkpoints.

## Temporary I/O correction (2026-10-13, 17:13 UTC)

After eight hours the ext4 retry remained at 63/139 NDS tests, with only four
minutes of CPU and repeated journal-commit waits. An unchanged full NDS
executable, with identical alias arguments and sample counts, passed all 139
tests in 109.748 seconds using a bounded `noswap` tmpfs directory. The live
ext4 attempt was preserved during that comparison, then deliberately stopped
with SIGINT (gate result -2, supervisor exit 254); its full and partial logs
are retained. It is not a passed unit gate.

The complete `make test-unit` gate is now running with a 4 GiB non-swappable
RAM temporary filesystem, a 1.5 GiB available-memory reserve, and unchanged
disk-space reserves. Source, build, caches, toolchains and logs remain on the
external drive. No test or crypto source, filters or sample counts changed.
See `tests/review/octez-2026-10-10/temporary-storage-decision.md` and the
retained probe plus `run-unit-ram.py`. The complete unit result is pending.

## Final implementation and validation (2026-10-13)

Octez commit `d6601b2f79039d46cf493da5fd9ba9eb8fcad4b9` on
`reuna@native-crypto-signers` implements the approved phases A–C.
All 350 implementation files match the tested external snapshot; the sole
additional difference is the final validation README. Frozen protocol sources
are unchanged. The source comparison and exact file hashes are retained.

All required gates pass: full build, formatting, lint, clean manifest check,
both protocol compilation aliases and the complete `make test-unit` command.
The final unit log records success for non-protocol, protocol and other unit
stages, ending in `GATE EXIT: 0`. The protocol stage took 1:08:12.5967.
The initial RAM attempt's environment failures were corrected by regenerating
archived stale Snoop outputs and extracting matching Debian Python shared
libraries into the external workspace; no test expectation was changed.

`tests/review/octez-2026-10-10/external-validation-logs.tar.gz` retains 56
logs/manifests with a verified hash index, in addition to the earlier evidence
archive. Timing and prior Solo5 artifact limitations remain as recorded.
Publication needs the intended Octez fork URL; only upstream GitLab is
configured. Task-owned cleanup follows evidence export. The separate later
crypto proposals remain outside this completed implementation scope.

Task-owned cleanup is complete: the 67.6 GiB external build workspace, both
validation containers and their image were removed after evidence publication
in Mirage Crypto `9acc54f89a3fbbc6767f98b216b9fa276b1a2c94`. The task loop
device was verified detached. Source checkouts and retained evidence are
preserved; shared caches and unrelated volumes were not pruned. The exact
cleanup receipt is `tests/review/octez-2026-10-10/cleanup.json`.

## Publication complete

The user authorized creating Reuna repositories matching the other web3
repositories. Octez is published at https://github.com/reuna-labs/tezos on
`reuna@native-crypto-signers`; its remote head is exactly
`d6601b2f79039d46cf493da5fd9ba9eb8fcad4b9`. The Tezos SDK is published at
https://github.com/reuna-labs/ocaml-tezos on `main`, with remote head
`8a0768d4506f2cadb571ed06742902cb5a15915a`. Both are public. Commit history
was preserved and the upstream Octez GitLab remote was left unchanged.
The publication blocker is resolved; all approved phases and cleanup are done.
