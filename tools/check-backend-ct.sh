#!/bin/sh
# Linux: upstream secp256k1 checks and selected secret-processing kernels.
set -eu
cd "$(dirname "$0")/.."
CC=${CC:-cc}
OUT=${OUT:-_build/backend-ct}
mkdir -p "$OUT"
"$CC" -O2 -g -DVALGRIND -DENABLE_MODULE_RECOVERY -DENABLE_MODULE_EXTRAKEYS \
  -DENABLE_MODULE_SCHNORRSIG -DECMULT_WINDOW_SIZE=8 -DCOMB_BLOCKS=2 -DCOMB_TEETH=5 \
  secp256k1/vendor/src/ctime_tests.c secp256k1/k1_kernel.c \
  secp256k1/k1_precomputed.c secp256k1/k1_precomputed_gen.c -o "$OUT/secp-ct"
valgrind --quiet --error-exitcode=1 "$OUT/secp-ct"
"$CC" -O2 -g -I. -DISO_C -D__BLST_PORTABLE__ -DBLAKE3_NO_SSE2 \
  -DBLAKE3_NO_SSE41 -DBLAKE3_NO_AVX2 -DBLAKE3_NO_AVX512 -DBLAKE3_USE_NEON=0 \
  tests/ct/kernels.c bls12-381/blst_kernel.c bls12-381/vendor/build/assembly.S \
  blake3/b3_kernel.c blake3/b3_dispatch.c blake3/b3_portable.c \
  poseidon/poseidon_field.c poseidon/poseidon_kernel.c poseidon/poseidon_constants.c \
  -o "$OUT/kernels-ct"
valgrind --quiet --error-exitcode=1 "$OUT/kernels-ct"
echo 'Backend secret-taint checks passed.'
