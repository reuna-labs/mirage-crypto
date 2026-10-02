# Shared native PBKDF2

`Mirage_crypto_pbkdf2` provides PBKDF2-HMAC-SHA1, SHA256 and SHA512 through
small OCaml C stubs. Bitcoin BIP39 and TON use SHA512; Cardano Icarus calls
the same C entry point with its own framing and clamp; Kerberos uses the
hash selected by its existing suite implementation.

```
Mirage_crypto_pbkdf2.sha512
  ~password ~salt ~iterations:2048 ~length:64
```

The package uses the Crypton fast-pbkdf2 selection at
`bb8a805ced29a935103a9e121ddb9d9fd0d732bf`, with Digestif's existing C hash
kernels. No additional SHA implementation or system crypto library is linked.
It has no RNG, Unix, ctypes, Zarith or GMP requirement.

The coordinated Reuna Digestif checkout must expose `digestif_sha1.h`,
`digestif_sha256.h` and `digestif_sha512.h`, both as installed headers and
through its source-tree dune rules. A generic Digestif version number alone
does not guarantee these C interfaces. Source headers must match the linked
Digestif C implementation.

## Bounds and assurance

Iterations are public and must be in 1..2^32-1, within OCaml's integer range.
Output length is public, nonnegative and bounded by both 2^32-64 and
`Sys.max_string_length`. Length zero returns an empty string. Applications
must bound caller-controlled work; these representation limits are not
practical resource limits.

Selection preserves the upstream PBKDF2 algorithm and adds explicit native
temporary wiping. Password/salt lengths are observable. Native wiping does
not erase all immutable OCaml copies or prove compiler-level zeroization.
This selected implementation has not been formally verified by this work.

Reproduce provenance with `python3 tools/select-pbkdf2.py --check`.
`tools/check-pbkdf2-native.sh` compares 156 hash/length/iteration cases against
OpenSSL and runs secret-taint and sanitizer checks. OCaml vector/boundary tests
are in `test/smoke.ml`; the same test boots under ARM64 and x86-64 Solo5.
OpenSSL and Valgrind are validation tools, not production dependencies.

## Notices

The fast-pbkdf2 algorithm source is dedicated under CC0-1.0 by Joseph
Birr-Pixton and Nicolas Di Prima. Crypton supporting headers retain Vincent
Hanquez's BSD notices: the two-clause notice is in the installed
`crypton_bitfn.h`, and the repository license is in `LICENSE`. The Reuna
adapter follows this repository's ISC license. Originals and their checksums
are retained in `vendor/`; the selection tool verifies generated adaptations.
