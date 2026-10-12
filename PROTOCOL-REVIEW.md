# sr25519 and MPC/FROST review — 2026-10-02

Scope: source review of the secret arithmetic boundary, transcripts, nonce
lifecycle and protocol framing. This is not an independent security audit or
an assertion of whole-program constant-time behavior. No MPC production code
was changed by this review.

MPC baseline: `ocaml-mpc` commit
`7b78792ce64f9190b67491230931761af71cf737`. Mirage baseline:
`edeae749daa6f8eafb73446e68e654d00794e898`; native source revisions are recorded
in `BACKENDS.md` and the vendor manifests.

Rechecked on 2026-10-11: MPC HEAD `5d76e81078da816bfed8c133b489961d8726966e`
leaves the reviewed signing, secret-cell and scalar-adapter source unchanged.
Its guard edits are shell formatting and preserve the file-level limitation.
Mirage HEAD `2dca1e4fd8f70ac26984785c8af6d2bd8fee63f9` adds only PBKDF2
repository metadata and an unrelated entropy CPU-target fix relative to the
reviewed baseline; it does not change the reviewed sr25519 implementation.

## Findings, in priority order

### High, conditional on concurrent use: nonce consumption is not atomic

`ocaml-mpc/lib/frost/sign.ml:117` calls `Mpc.Secret.get` and then
`Mpc.Secret.wipe`. `lib/mpc/secret.ml:7` checks a mutable Boolean before copying
the bytes. There is no lock or atomic ownership transfer. Two domains can both
copy the original nonce before either wipes it. Retaining an old session value
is sufficient to share the same cell. Sequential replay protection does not
establish protection for concurrent calls, and the public interface does not
state an exclusive-domain ownership requirement.

Reproduction: `tests/review/mpc_nonce_race.ml` embeds the reviewed Secret
implementation (ISC notice in `tests/review/LICENSE-MPC.md`) and the exact get/wipe sequence, before scalar parsing. Linux
ARM64, OCaml 5.5, two domains, 100,000 synchronized trials: **9,162 cells returned
the original 64-byte value to both domains**. Counts depend on scheduling.

The original raw race log is not in the preserved evidence archive. A fresh
Linux ARM64 / OCaml 5.3.0 run on 2026-10-11 reproduced the race: **11,536 of 100,000 cells returned the
original value to both domains**. The raw output is preserved in
`tests/review/mpc-nonce-race-20261011.log`; its source/log hashes are in
`tests/review/mpc-nonce-race-20261011.json`. No production MPC code was changed.

```
ocamlfind ocamlopt -package eqaf -linkpkg tests/review/mpc_nonce_race.ml -o /tmp/mpc_nonce_race
/tmp/mpc_nonce_race
```

This reproduces the consumption race, not a full malicious-coordinator attack
or secret-share extraction. It invalidates the claim in the source comment that
no execution can consume a commitment twice. Repeated use across suitable
distinct signing packages can compromise signing shares. The documentation's
blanket claim that two signatures always recover the share is too strong for
FROST's two-nonce equation; coefficients and unknowns matter.

Recommended fix: implement an atomic consume operation that transfers ownership
of the nonce buffer once, and serialize consumption against wiping. Ensure
failure/exception paths erase the owned buffer. Add full session tests with
concurrent distinct packages, retained states and cancellation. Until fixed,
serialize all access to a signing session and its retained versions.

### Medium: a participant does not enforce its configured signing set

`lib/frost/sign.ml:204` validates the message, the canonical commitment list,
presence of its own identifier and equality of its own commitment. It does not
compare the other identifiers with `cfg.signers` mapped through `id_of_peer`.
The coordinator's own `build_package` checks list length, but a malicious
coordinator can construct messages without using that function.

This is a signer-policy binding gap: a participant can release a share for a
different set than its local configuration selected. It does not by itself
demonstrate a below-threshold forgery. Require an exact configured identifier
set, validated for uniqueness and nonzero identifiers when creating the
session. Add a negative test that changes another participant while preserving
the victim's commitment. Finding is based on source inspection; no end-to-end
malicious-coordinator test was run in this review.

### Medium portability gap: canonical scalar parsing assumes 64-bit OCaml

`lib/ed25519/mpc_ed25519.ml:44` and
`lib/secp256k1/mpc_secp256k1.ml:38` extract the subtraction borrow using
`lsr 62`. Their comments explicitly assume a 63-bit OCaml integer. That is
not portable to a 31-bit integer runtime. Current ARM64/x86-64 validation does
not establish behavior on 32-bit OCaml.

Use a portable fixed-width comparison or an explicit supported-architecture
restriction, and test 0, L-1, L, L+1 and maximal encodings on each supported
word size. No 32-bit runtime reproduction was performed here.

### Assurance gap: variable-time call guard operates at file granularity

`test/scalar_mul_guard.sh` allows entire files and selected textual receiver
names. Its reported count is files, not individual call sites. A new secret
use inside an already permitted file would pass. Reviewed current uses in
Shamir/VSS, FROST aggregation and DKG verification use public identifiers,
binding factors, challenges or Lagrange coefficients.

Strengthen the boundary with explicit public-scalar types or a narrower API;
at minimum make the guard enumerate actual expressions and review changes to
them. Do not treat the existing grep guard as a data-flow proof.

### Assurance limits: zero handling and secret erasure

The secp256k1 group adapter branches on a zero scalar in
`Element.scalar_mul_base` (`lib/secp256k1/mpc_secp256k1.ml:216`). Thus its
execution is not uniform across every scalar including zero. A resulting
public identity already discloses zero in commitment contexts; this observation
does not establish additional exploitable leakage. Specify this domain clearly
before making blanket constant-time claims.

`Secret.wipe` cannot erase immutable copies, OCaml GC copies or every native
temporary. This limitation is already documented. Repeated `Start` events also
deserve a lifecycle regression: `start` can replace a live committed nonce
without wiping the older retained cell. These observations are not evidence of
a remotely demonstrated key compromise.

## sr25519

The current implementation keeps Schnorrkel/Merlin/STROBE sequencing in OCaml.
Scalar arithmetic, reduction and Ristretto group operations use the selected
libsodium C substrate; the Keccak-f[1600] permutation uses Digestif. These
remain distinct assurance boundaries.

Inspected STROBE absorb/overwrite/squeeze loops depend on lengths, positions
and operation flags. Secret bytes are absorbed as values, not used as array
indices. The witness transcript copy is wiped by `Fun.protect`, including
exceptional exits. Immutable nonce, scalar and random-byte copies remain
subject to the OCaml memory-erasure limitation. Source inspection is not a
proof about every compiler-generated instruction or GC behavior.

Validation completed during this work:

- Native scalar/Ristretto plus actual Digestif Keccak: Valgrind secret-taint
  checks and ASan/UBSan on Linux ARM64, both selected field backends.
- `tools/check-sr25519-vectors.sh`: the locked Rust Schnorrkel/Dalek generator
  reproduced the committed TSV exactly on the host.
- Existing boundary coverage includes zero/identity compatibility and
  canonical parsing; native selection/provenance checks also pass.

These results cover the kernels and checked operations. They do not establish
whole-protocol constant-time behavior. No new whole-OCaml dudect campaign was
run as part of this review. Keep the interface warning that the protocol and
Merlin/STROBE integration have not independently been verified constant-time.

`vrf_output` is deliberately only Schnorrkel's malleable VRF **pre-output**.
It does not implement the DLEQ proof or `VRFResult` output derivation. There is
no HDKD API here. Therefore neither full VRF proving nor secret-child
derivation can be claimed as covered by the sr25519 checks.

## Protocol review limits and next gates

FROST signing requires fresh nonce pairs and secret-dependent operations need
side-channel protection. The RFC distinguishes signing from distributed key
generation; its signing vectors cannot validate this repository's DKG extension.
See [RFC 9591, sections 7.1 and 7.3](https://www.rfc-editor.org/rfc/rfc9591.html)
and the [Merlin witness RNG design](https://merlin.cool/transcript/rng.html).

The DKG proof challenge intentionally follows the upstream FROST framing;
session binding is checked in the message envelope instead. Authenticating
that envelope and providing confidential share transport, replay protection
and durable lifecycle policy remain caller obligations. This review does not
certify those deployment mechanisms.

Next work: fix atomic consumption first, enforce the configured signing set,
then run the complete MPC vectors/interop and adversarial session suite against
the corrected implementation. Whole-protocol timing tests must cover complete
secret-to-public-key/signature paths with controlled public inputs, not only
arithmetic kernels. The existing unaudited status must remain.
