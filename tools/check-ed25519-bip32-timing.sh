#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
DIGESTIF_SOURCE=${DIGESTIF_SOURCE:-../digestif}
OUT=${OUT:-_build/ed25519-bip32-timing}
CC=${CC:-cc}
mkdir -p "$OUT"
for hash in sha1 sha256 sha512; do
  cp "$DIGESTIF_SOURCE/src-c/native/$hash.h" "$OUT/digestif_$hash.h"
done
"$CC" -O2 -I. -Ied25519-bip32 -I"$OUT" \
 -Ied25519-bip32/vendor/cardano/cbits/ed25519 -Ipbkdf2 -Ipbkdf2/vendor/cbits \
 tests/ct/ed25519_bip32_timing.c ed25519-bip32/cardano_kernel.c \
 ed25519-bip32/pbkdf2_kernel.c pbkdf2/pbkdf2_kernel.c "$DIGESTIF_SOURCE/src-c/native/sha512.c" "$DIGESTIF_SOURCE/src-c/native/sha1.c" "$DIGESTIF_SOURCE/src-c/native/sha256.c" \
 -lm -o "$OUT/timing"
"$OUT/timing"
