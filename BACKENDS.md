# Vendored blockchain backends

The production kernels are selected upstream C sources with small OCaml C
stubs. Each package can be installed independently. None depends on ctypes,
Zarith, GMP, Rust, a system crypto library, or a Unix RNG provider.
`mirage-crypto-secp256k1`, `mirage-crypto-bls12-381`, and
`mirage-crypto-sr25519` depend on the portable
Mirage RNG; applications supply and seed it in their own environment.

| Package | Upstream pin | License |
| --- | --- | --- |
| `mirage-crypto-secp256k1` | [libsecp256k1 v0.8.0](https://github.com/bitcoin-core/secp256k1/tree/6e2c8bc4ecdc6e71dbe7a368f360d8d453ce435d) | MIT |
| `mirage-crypto-bls12-381` | [BLST v0.3.17](https://github.com/supranational/blst/tree/54e6e55674722fc2797ebb4bbb71b26d881eb4b8) | Apache-2.0 |
| `mirage-crypto-blake3` | [BLAKE3 1.8.7](https://github.com/BLAKE3-team/BLAKE3/tree/f3149ec5bb5449af877ba20377a11008ff499fa2) | CC0 or Apache-2.0 alternatives; see vendored licenses |
| `mirage-crypto-sr25519` | [libsodium 1.0.22-RELEASE](https://github.com/jedisct1/libsodium/tree/77e1ce5d6dee871c49ef211222ba18ef0c486bda) | ISC |
| `mirage-crypto-poseidon` | [CryptoExperts Poseidon](https://github.com/CryptoExperts/poseidon/tree/68a88df9cb894fe1e0ee8b1b1b5825602c83635a) | Apache-2.0 |

The binding code is ISC. Each `vendor/manifest.json` records the commit and
SHA-256 of every imported file; upstream sources are unmodified. Licenses and
manifests are installed with each package. Run `tools/check-backend-vendor.py`
before reviewing or upgrading an import. Re-run the checks below after changes
to the compiler, build flags, upstream revision, or bindings.

## Scope and compatibility

`Mirage_crypto_blockchain` delegates ECDSA/recovery, BIP340, BLS12-381, BLAKE3,
Poseidon, and sr25519 to these packages. Its secp256k1 point/scalar and Poseidon APIs
retain their existing Zarith representations. **Those conversions are variable
time.** Use the separate fixed-width APIs for secret inputs. BLS opaque values
now use native representations; its public `p` and `r` constants remain `Z.t`
in the compatibility module. Serialized wire formats are preserved; marshaled
internal values are not a persistence format.

The existing `mirage-crypto-ec` and `mirage-crypto-blockchain-core` production
dependency closures are unchanged. In particular, the EC secp256k1 group and
scalar primitives used by FROST remain available and independent. The legacy
blockchain secp256k1 group adapter uses those primitives. Stark ECDSA,
Ed25519-BIP32, and unrelated primitives retain their existing implementations
and timing caveats.

Behavior worth checking at migration boundaries:

* ECDSA signing is RFC6979 deterministic and produces low-S signatures.
  Verification accepts high-S by normalizing a temporary; compact parsing
  preserves S and recovery parity. DER parsing is strict, including trailing
  bytes and integer encodings. Digests must be 32 bytes.
* Every secp256k1 private operation creates and randomizes its own context,
  wipes it, and frees it before returning. Even deterministic signing and
  public-key derivation need an initialized RNG. Optional `g` parameters on
  the standalone API permit a separate generator per domain.
* Standalone BIP340 accepts arbitrary message lengths and defaults to fresh
  auxiliary randomness. The compatibility adapter retains its zero auxiliary
  default. Explicit auxiliary values must be 32 bytes.
* BLS uses the Basic scheme with G1 public keys, G2 signatures, and the
  `BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_` domain. Parsing checks subgroup
  membership. Verification rejects identity keys/signatures; aggregate
  verification rejects empty sets and duplicate messages. Zero remains a
  group scalar, but public derivation and signing reject it as a private key.
  Invalid point encodings can now produce a broader `Not_on_curve` error.
* BLAKE3 supports keyed hashing, derive-key, and arbitrary positive XOF output
  sizes. Derive-key contexts are length-aware, including embedded NUL bytes.
* Poseidon uses StarkWare's width-3, rate-2 parameters and pair/single/sponge
  domain separation. The fixed-width API requires canonical field elements;
  the legacy adapter reduces arbitrary signed `Z.t` inputs modulo the prime.

## Build choices and assurance

libsecp256k1 includes only the base kernel and recovery, extrakeys, and
schnorrsig modules. `ECMULT_WINDOW_SIZE=8`, `COMB_BLOCKS=2`, and `COMB_TEETH=5`
select upstream's small precomputed tables. Secret signing/key generation uses
upstream constant-time routines; public decoding and verification can be
variable time.

BLST uses its upstream assembly on x86_64 and ARM64 with `__BLST_PORTABLE__`.
Other architectures select its C fallback, but are not validated here. BLST's
published audits and formal-verification work concern specific routines and
revisions; they do not constitute a proof of this complete binding.

BLAKE3 uses only the official portable C compression code. SIMD paths and x86
CPU probing are disabled. A binding-side population-count helper for public
chunk lengths avoids a freestanding `__popcountdi2` dependency, without
requiring the x86 POPCNT instruction.

Poseidon selects `ISO_C`, with binding-side symbol namespacing. Adoption was
gated on independent differential tests, sanitizer checks, inspection, and a
secret-taint run of the selected kernel. These checks passed on the tested
builds. No formal-verification or independent-audit claim is made for it.

### sr25519 and shared Keccak

The existing OCaml Schnorrkel/Merlin/STROBE sequencing is retained. Roughly
300 lines of production OCaml field/group/scalar arithmetic and Keccak code
are removed. No sr25519-donna code is used. The C boundary passes only
canonical 32-byte Ristretto encodings and reduced little-endian scalars.
Secret reduction, addition, multiplication and point multiplication use
libsodium. Zero scalars and identity points are handled by masked substitution
and selection around libsodium's identity-rejecting multiplication API;
there is no retry loop. Invalid public points are rejected before secret work.

The import includes unchanged upstream ref10 arithmetic, both field backends,
and small selected public API/utility functions. `tools/select-sr25519-sodium.py`
extracts those functions verbatim from the pinned sources and generates symbol
namespacing. `--check` verifies the checked-in result; Python is not needed to
build or use the package. No libsodium initialization, OS entropy provider,
allocator, CPU dispatch, dynamic libsodium linkage, or OCaml binding package
is introduced. The upstream 51-bit field backend is used with `__int128`;
other compilers use the upstream 25.5-bit backend.

**Build requirement:** pin the sibling Reuna Digestif checkout with the new
`digestif.keccak-f1600` sublibrary. An upstream Digestif package lacking that
sublibrary is insufficient, even if it satisfies the numeric opam constraint.
The sublibrary selects Digestif C and exposes an in-place 200-byte, 24-round
permutation. It reuses the existing SHA3 permutation, with an aligned temporary
and the same host-endian conversion. STROBE retains its own framing and padding.
Digestif's ordinary hash APIs and their padding are unchanged.

Mini-secret expansion, custom contexts, the signature marker, legacy signature
verification, and the existing **malleable VRF pre-output** are preserved.
There is no new HDKD, DLEQ proof, or VRF output-expansion API. The malleable
pre-output is not a complete VRF and should not be used as the non-malleable
Schnorrkel VRF with soft HDKD.

**Assurance:** secret scalar and Ristretto arithmetic is delegated to libsodium.
The sr25519 protocol and Merlin/STROBE integration have not independently been
verified constant-time. C kernel taint checks do not cover the entire OCaml
runtime/protocol. Statistical full-protocol timing analysis and independent
review remain further assurance work; no whole-signer constant-time claim is
made. Witness-state buffers are cleared after use, including RNG exceptions,
but this does not guarantee erasure of other OCaml heap copies.

All stubs validate lengths before accessing buffers, keep OCaml values rooted
across allocations, and copy opaque BLST values into aligned local structures.
They hold the OCaml runtime lock while using heap pointers. There is no shared
mutable signing context. C secret temporaries are wiped where held by the
bindings, but erasure of GC-managed OCaml strings and their copies is not
guaranteed. Timing claims concern secret contents, not public input lengths.

## Validation

From a configured development switch:

```sh
tools/check-backend-vendor.py
dune exec tests/test_native_backends.exe
dune exec tests/test_blockchain_runner.exe
dune exec tests/test_backend_domains.exe # OCaml 5
dune build tests/test_native_backends.bc
dune exec tests/test_native_backends.bc
dune runtest secp256k1/test bls12-381/test blake3/test poseidon/test
dune build mirage-crypto-secp256k1.install mirage-crypto-bls12-381.install \
  mirage-crypto-blake3.install mirage-crypto-poseidon.install
dune build --build-dir _build-sanitize --profile backend-sanitize \
  tests/test_native_backends.exe
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 \
  _build-sanitize/default/tests/test_native_backends.exe
tools/check-backend-ct.sh # Linux, C compiler and Valgrind
tools/check-backend-stack.sh # GCC local C stack-frame report
```

`tests/reference` preserves independent, test-only implementations; it is not
installed. Tests include 380 Wycheproof valid/invalid ECDSA cases, all 19
BIP340 vectors, 35 BLAKE3 input lengths in all modes including XOF, five
RFC9380 G2 vectors, deterministic differential checks, recovery/high-S/DER,
subgroup and identity rejection, malformed encodings, repeated GC/compaction,
legacy adapters, and four concurrent OCaml domains. Wycheproof `acceptable`
cases are excluded because they deliberately permit different policies.
Valgrind checks upstream secp256k1's `ctime_tests.c` and selected BLST secret
operations, keyed BLAKE3, and Poseidon. Taint tests are evidence for the
exercised compiled paths, not proofs or exhaustive side-channel tests.

Vector provenance (`tests/native_vectors.ml` contains extracted fixtures):

| Input | SHA-256 of source file |
| --- | --- |
| `tests/ecdsa_secp256k1_sha256_test.json`; SHA-256 messages before verification | `1f579e2da5f6d954b0881e25c6090ffd5f3e160b07ac76ab8b341e6838afd97b` |
| [BIP340 test-vectors.csv](https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv) | `34c9d1d9c3a88d524bc80778540dc43f8306ec249a7485293063c376db851c2d` |
| BLAKE3 pinned tree, `test_vectors/test_vectors.json` | `dcb91ea8accc77e6d6e632af7cdc1a99a9f3ae78cf648da595c7d064db32f624` |
| BLST pinned tree, `bindings/vectors/hash_to_curve/BLS12381G2_XMD_SHA-256_SSWU_RO_.json` | `7ff2010d99cd886ab8e951ae1ed657b57e6b95fe6029fa4a0f519ea5ca29f126` |

The broad pre-existing `test_ec` suite has an unrelated compile blocker:
its infinity-encoding tests reference `Dsa.Primitive` through `Dh_dsa`, whose
public signature does not expose that module. The new focused regression
checks exercise the retained P256k1 group and scalar API without changing
the production EC interface or removing those existing tests.

## Solo5 and footprint

In a Linux switch with `ocaml-solo5`, Solo5, eqaf, logs, and the sibling
digestif sources:

```sh
DIGESTIF_SOURCE=../digestif tools/check-backend-solo5.sh
# Alternative cross-toolchain; build for a VM and boot with its launcher:
SOLO5_TOOLCHAIN=solo5x86 MODE=virtio RUN=0 tools/check-backend-solo5.sh
qemu-system-x86_64 -accel tcg -m 128 -display none -serial stdio -no-reboot \
  -kernel /path/printed/by/script/smoke_secp256k1.exe
```

The script stages a separate workspace, rebuilds dependencies for the target,
and rejects GMP, Zarith, ctypes, and Unix symbols in each linked executable.
Its test-only Dune stanzas require 2.8; the packages retain Dune 2.7 support.
All five applications booted successfully on ARM64 Solo5 SPT and x86_64
Solo5 virtio under QEMU TCG with OCaml 5.5.1. Host vector/regression tests ran
on macOS ARM64 OCaml 5.2 and Linux ARM64 OCaml 5.5.1; ASan/UBSan ran on macOS,
and Valgrind secret-taint checks ran on Linux ARM64.
The backend package-only install/test builds passed, as did a separate installed
BLST consumer in both native and bytecode modes.

Initial `size` totals in bytes, including OCaml runtime, RNG when needed,
test code, and Solo5 bindings (`text + data + bss`, not kernel-only size):

| Smoke application | ARM64 SPT | x86_64 virtio |
| --- | ---: | ---: |
| secp256k1 | 1,889,812 | 1,939,601 |
| BLS12-381 | 1,907,692 | 1,966,225 |
| BLAKE3 | 768,428 | 864,689 |
| Poseidon | 777,596 | 872,401 |
| sr25519 | 1,830,140 | 1,871,889 |

An initial macOS ARM64 run of `dune exec bench/bench_backends.exe` measured:

| Operation | Microseconds/op | OCaml allocated bytes/op |
| --- | ---: | ---: |
| ECDSA sign, including context blinding | 45.57 | 792 |
| ECDSA verify | 20.12 | 0 |
| BIP340 sign | 45.73 | 1,296 |
| BLS sign | 238.90 | 608 |
| BLS verify | 801.80 | 1,488 |
| BLAKE3, 1 KiB | 1.46 | 48 |
| Poseidon pair | 16.85 | 128 |

These are indicative host measurements, not enclave performance guarantees.
OCaml allocation counts exclude native context allocation and C stack space.
The GCC 12 ARM64 `-O2 -fstack-usage` report's largest C frame is BLST's
`POINTonE2_mult_gls` at 18,576 bytes. The BLAKE3 binding frame is 2,160 bytes.
The sr25519 kernel's largest reported frame is `ge25519_scalarmult` at
4,208 bytes. The report excludes assembly and cumulative call depth; it is not a bound
on total stack use. Size stack budgets with those additional costs in mind.

### sr25519 regression commands

```sh
python3 tools/select-sr25519-sodium.py --check
dune exec tests/test_sr25519.exe -- tests/sr25519_vectors.tsv
dune runtest sr25519/test
dune build mirage-crypto-sr25519.install
tools/check-sr25519-vectors.sh # developer oracle; needs Rust and crates.io/cache
DIGESTIF_SOURCE=../digestif tools/check-sr25519-kernel.sh # ASan/UBSan
MODE=ct DIGESTIF_SOURCE=../digestif tools/check-sr25519-kernel.sh # Linux Valgrind
dune build --build-dir _build-sanitize --profile backend-sanitize tests/test_sr25519.exe
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 \
  _build-sanitize/default/tests/test_sr25519.exe tests/sr25519_vectors.tsv
```

The locked Rust oracle uses Schnorrkel 0.11.5, Merlin 3.0.0 and Dalek 4.1.3.
The 194 checked-in cases contain 66 exact key/signature/VRF comparisons,
64 group/scalar cases, and 64 point-parsing cases. Entropy is controlled only
in tests; production signing still requires a properly seeded Mirage RNG.
Tests also cover scalar L/L±1, zero/identity results, invalid FFI lengths,
GC compaction, old protocol compatibility, and 128 whole-state Keccak
comparisons. All 726 Digestif C regression tests pass as well. The regular suite does not require Rust or network access.
Both field backends and the actual Digestif permutation pass ASan/UBSan and
Linux ARM64 Valgrind taint checks. Native/bytecode and four-domain tests pass;
ARM64 SPT and x86_64 virtio Solo5 smoke applications boot successfully without
Zarith, GMP, ctypes or Unix symbols.
