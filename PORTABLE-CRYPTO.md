# Portable AES and GHASH

The generic AES and GHASH backends select BearSSL sources at commit
`7bea48e5e850ab4cafbe68d3765cdaba13a86d6f`, from
<https://www.bearssl.org/git/BearSSL>. The unmodified source files, MIT license,
and SHA-256 import manifest live in `src/native/portable/vendor`.

Only `aes_ct.c`, `aes_ct_enc.c`, `aes_ct_dec.c` and `ghash_ctmul32.c` are
compiled. `tools/select-portable-crypto.py` reproduces the private header's
byte-order helpers verbatim from upstream `inner.h` and namespaces all external
kernel symbols. There is no BearSSL package, TLS code, ctypes, OS service or
allocator dependency. Python is needed only to reproduce/check the selection.

AES uses the 32-bit bitsliced implementation on every portable target. It
supports 128-, 192- and 256-bit keys and two simultaneous blocks. This keeps a
single portable implementation and avoids secret-indexed S-box tables. The
small adapter packs/unpacks blocks, handles unaligned OCaml buffers and wipes
its own temporary schedules. This is not a guarantee that every upstream stack
temporary or GC-managed copy is erased. Existing AES-NI dispatch is retained.

GHASH uses `ghash_ctmul32` on every portable target, with a 16-byte key instead
of the former 64-bit fallback's 65,536-byte table. Existing PCLMUL dispatch is
retained. The previous separately adapted 32-bit GHASH copy is removed.

## Assurance scope

BearSSL describes the bitsliced AES design and the multiplication-based GHASH
design at <https://www.bearssl.org/constanttime.html>. GHASH's constant-time
property requires constant-time 32-bit multiplication on the target CPU;
<https://www.bearssl.org/ctmul.html> discusses hardware exceptions. These are
upstream constant-time implementations, not a formal verification claim for
the complete Mirage API or compiler output. Generic AES is expected to be
slower than the old table implementation; hardware acceleration remains the
default where supported.

Set `MIRAGE_CRYPTO_ACCELERATE=false` at build time to force the portable
backend; `auto` is the default. Dune tracks the setting. This is a build-time
choice: key schedules never change representation while a process is running.

## Reproducible checks

- `python3 tools/select-portable-crypto.py --check`: provenance and selection.
- `sh tools/check-portable-crypto.sh`: AES known answers and OpenSSL differential
  checks for all key sizes, odd/even/empty block counts, unaligned and in-place
  buffers; GHASH differential checks for lengths 0 through 257; secret-taint
  checks and ASan/UBSan. OpenSSL and Valgrind are test-only dependencies.
- Build/run `tests/test_symmetric_runner.exe`, `tests/test_kerberos_runner.exe`
  and `tests/test_kw_runner.exe` with acceleration forced off. These exercise
  the public API and existing mode/profile vectors.
- `tests/solo5/smoke_portable_crypto.ml` checks AES and GCM in the freestanding
  runtime; the backend Solo5 script includes it.

Record actual validation results in ASSURANCE-WORK.md; these commands alone
are not evidence that a target/compiler configuration has passed.
