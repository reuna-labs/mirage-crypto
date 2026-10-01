# Native Cardano migration validation

Validated on macOS ARM64 (OCaml 5.2) and isolated Linux ARM64 (OCaml 5.5).
Digestif C code/header: `4c33049713a1449ab5066ebe286a9c6f763d32b6`.
Source provenance and limitations are in `../BACKENDS.md` and vendor manifests.

- Standalone package build and tests with `dune -p mirage-crypto-ed25519-bip32`.
- Native/bytecode vectors and GC stress; four concurrent OCaml domains.
- 128 pinned Rust records, 5 Cardano C goldens, 85 independent PBKDF2 records,
  and 256 paper master records, including error results.
- Strict key imports, raw-verifier legacy edge matrix, S=L/S+L, maximal
  indices and derived scalar overflow. Existing blockchain suite: 134 tests.
- Native Valgrind taint + ASan/UBSan in both Donna arithmetic variants;
  deliberately unaligned keys, points, messages and result buffers included.
- OCaml C-stub integration suite under ASan/UBSan.
- Downstream Cardano: 76 tests, including added strict-import coverage.
- ARM64 SPT and x86-64 virtio/QEMU boots for both the standalone package and
  Cardano's public Key pipeline. No RNG initialization. Dependency and symbol
  checks exclude RNG, Unix, Zarith, GMP and ctypes from the signing image.

## Empirical timing sample

Linux ARM64, portable C, `-O2`, fixed versus random secrets with controlled
public inputs. A deterministic PRNG randomizes class order; 1,000 warm-up
samples per operation are discarded. Command: `sh tools/check-ed25519-bip32-timing.sh`.

| Operation | Fixed / random samples | Mean ns, fixed / random | Welch t |
| --- | --- | --- | --- |
| Public key | 19906 / 20094 | 8725 / 8732 | -0.459 |
| Signature | 20105 / 19895 | 18652 / 18670 | -0.562 |
| Soft child | 19989 / 20011 | 15093 / 14664 | 1.914 |
| Hardened child | 20000 / 20000 | 3294 / 3281 | 1.651 |
| Icarus | 4921 / 5079 | 5095354 / 5093458 | 0.167 |

This run found no strong class-dependent timing signal. It is a small empirical
regression check on a virtualized host, not a formal verification or a claim
that all compilers, CPUs, secret distributions and protocol paths are constant-time.
