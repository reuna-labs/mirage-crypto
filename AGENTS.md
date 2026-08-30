# mirage-crypto

mirage-crypto fork carrying the Reuna EC, blockchain and key-wrap work: a constant-time secp256k1 group API, Ed25519 `*_into` scalar primitives and Ed25519<->X25519 conversion, BIP-340 Schnorr, Brainpool curves, bignum-free blockchain primitives, and `mirage-crypto-kw` (AES Key Wrap, RFC 3394 and RFC 5649). The Nitrokey `nethsm-mirage-crypto` EC rework is merged in on the `nethsm-integration` line, which is why this sits in `ports/ocaml` and is shared by the web3 stack and nethsm/SCR.

## Where this repo sits

`~/reuna/ports/ocaml/mirage-crypto` — inside the `ocaml` container in the `ports/` group
(Solo5 enclave core, language runtime ports and samples). The container is a plain
directory, not a repository: this checkout and its sibling are the repositories.

The tree was reorganised into effort groups; peer repositories are **no longer siblings**
at `../`. The full layout:

- `~/reuna/web3/` — OCaml/Mirage web3 protocol libraries
- `~/reuna/ports/` — Solo5 enclave core, language runtime ports and samples
- `~/reuna/ha/` — Reuna HA components
- `~/reuna/trust/` — Reuna trust components and the signed wire contracts
- `~/reuna/platform/` — RTP and the Kubernetes admission/runtime surface
- `~/reuna/research/` — reference checkouts, studied not built
- `~/reuna/vault/Reuna/` — the Obsidian design vault (Strategy, HLD, `SDD/`). Reachable from any group as `../vault/Reuna/` via a symlink.
- root also holds `infra/`, `release/`, `knowledge-bundle/`, `demo-app/`, `drivers/`, `attic/`

## Direct peers

Paths are relative to this repository's root.

| Peer | Path from here | Why |
|---|---|---|
| `digestif` | `../digestif` | the other patched crypto library in this container; pinned together in the same opam switch |

## Design docs

- `../../vault/Reuna/SDD/` — component design documents
- `../../vault/Reuna/Platryx HLD.md` — how the components fit together

## Helper toolkits — `~/gilbahat`

Peer repositories used as tooling live **outside** `~/reuna`, in `~/gilbahat`. They are not
checked out here and are referenced by absolute path:

- `~/gilbahat/qemu` — patched QEMU (the tree the enclave/emulation scripts invoke)
- `~/gilbahat/qemurb`, `~/gilbahat/vhost-device`, `~/gilbahat/vsock-emulation-layer` — virtio/vsock plumbing for macOS-hosted guests
- `~/gilbahat/confidential-computing.sgx` — patched SGX emulation
- `~/gilbahat/ms-tpm-20-ref` — TPM simulator; `tpm2-tss`, `tpm2-tools`, `tpm2-pkcs11`, `tpm2-abrmd`, `tpm2-pytss` — mac-friendly TPM library builds
- `~/gilbahat/ocaml-tpm2` — OCaml ESAPI bindings (`OCAML_TPM2_DIR`)
- `~/gilbahat/elfuse` — ELF/FUSE tooling
- `~/gilbahat/alloy`, `~/gilbahat/opentelemetry-collector` — telemetry
- `~/gilbahat/aws-nitro-enclaves-cli` — Nitro tooling
- `~/gilbahat/karpenter`, `karpenter-provider-{aws,azure,oci}` — cluster autoscaling
- `~/gilbahat/ding-libs`, `~/gilbahat/libverto` — gssproxy build dependencies

Prefer the existing env-var knobs where a script defines one (`SGX_PATCHED_SOURCE`,
`VSOCK_EMULATION_LAYER`, `OCAML_TPM2_DIR`, `SIM`) rather than hardcoding a new path.
