#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
DIGESTIF_SOURCE=${DIGESTIF_SOURCE:-../digestif}
OUT=${OUT:-_build/ed25519-bip32-timing}
CC=${CC:-cc}
mkdir -p "$OUT"
cp "$DIGESTIF_SOURCE/src-c/native/sha512.h" "$OUT/digestif_sha512.h"
"$CC" -O2 -I. -Ied25519-bip32 -I"$OUT" \
 -Ied25519-bip32/vendor/cardano/cbits/ed25519 -Ied25519-bip32/vendor/crypton/cbits \
 tests/ct/ed25519_bip32_timing.c ed25519-bip32/cardano_kernel.c \
 ed25519-bip32/pbkdf2_kernel.c "$DIGESTIF_SOURCE/src-c/native/sha512.c" \
 -lm -o "$OUT/timing"
"$OUT/timing"
