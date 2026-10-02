#!/bin/sh
# Linux standalone boundary checks. Digestif must be the matching pinned source.
set -eu
cd "$(dirname "$0")/.."
DIGESTIF_SOURCE=${DIGESTIF_SOURCE:-../digestif}
OUT=${OUT:-_build/ed25519-bip32-native}
CC=${CC:-cc}
mkdir -p "$OUT"
for hash in sha1 sha256 sha512; do
  cp "$DIGESTIF_SOURCE/src-c/native/$hash.h" "$OUT/digestif_$hash.h"
done
# MC_EDB32_CTGRIND declassifies only the returned private-key validity bit.
FLAGS="-O2 -g -I. -Ied25519-bip32 -I$OUT -Ied25519-bip32/vendor/cardano/cbits/ed25519 -Ipbkdf2 -Ipbkdf2/vendor/cbits"
SRC="tests/ct/ed25519_bip32.c ed25519-bip32/cardano_kernel.c ed25519-bip32/pbkdf2_kernel.c pbkdf2/pbkdf2_kernel.c $DIGESTIF_SOURCE/src-c/native/sha512.c $DIGESTIF_SOURCE/src-c/native/sha1.c $DIGESTIF_SOURCE/src-c/native/sha256.c"
$CC $FLAGS -DCTGRIND -DMC_EDB32_CTGRIND $SRC -o "$OUT/taint"
valgrind --quiet --error-exitcode=1 "$OUT/taint"
$CC $FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer $SRC -o "$OUT/sanitize"
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 "$OUT/sanitize"
$CC $FLAGS -DED25519_FORCE_32BIT -DCTGRIND -DMC_EDB32_CTGRIND $SRC -o "$OUT/taint32"
valgrind --quiet --error-exitcode=1 "$OUT/taint32"
$CC $FLAGS -DED25519_FORCE_32BIT -fsanitize=address,undefined -fno-omit-frame-pointer $SRC -o "$OUT/sanitize32"
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 "$OUT/sanitize32"
echo 'Ed25519-BIP32 native taint and sanitizer checks passed.'
