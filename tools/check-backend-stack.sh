#!/bin/sh
# GCC -fstack-usage reports local static frames, not cumulative call depth.
set -eu
cd "$(dirname "$0")/.."
CC=${CC:-cc}
OUT=${OUT:-_build/backend-stack}
OCAML_INCLUDE=${OCAML_INCLUDE:-$(ocamlc -where)}
mkdir -p "$OUT"
for source in secp256k1/k1_kernel.c secp256k1/k1_stubs.c \
  bls12-381/blst_kernel.c bls12-381/blst_stubs.c \
  blake3/b3_kernel.c blake3/b3_dispatch.c blake3/b3_portable.c blake3/b3_stubs.c \
  poseidon/poseidon_field.c poseidon/poseidon_kernel.c \
  poseidon/poseidon_constants.c poseidon/poseidon_stubs.c \
  sr25519/sodium_kernel.c sr25519/ristretto_adapter.c sr25519/sr_stubs.c; do
  base=$(basename "$source" .c)
  "$CC" -O2 -std=c99 -fstack-usage -I"$OCAML_INCLUDE" \
    -Isr25519/vendor/src/libsodium/include/sodium -DISO_C \
    -D__BLST_PORTABLE__ -DBLAKE3_NO_SSE2 -DBLAKE3_NO_SSE41 \
    -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512 -DBLAKE3_USE_NEON=0 \
    -DENABLE_MODULE_RECOVERY -DENABLE_MODULE_EXTRAKEYS -DENABLE_MODULE_SCHNORRSIG \
    -DECMULT_WINDOW_SIZE=8 -DCOMB_BLOCKS=2 -DCOMB_TEETH=5 \
    -c "$source" -o "$OUT/$base.o"
done
echo 'Largest C frames (bytes); excludes assembly and cumulative call depth:'
sort -k2,2nr "$OUT"/*.su | head -20
