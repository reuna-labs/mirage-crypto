#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
DIGESTIF_SOURCE=${DIGESTIF_SOURCE:-../digestif}
CC=${CC:-cc}
OUT=${OUT:-_build/pbkdf2-native}
mkdir -p "$OUT"
for hash in sha1 sha256 sha512; do
  cp "$DIGESTIF_SOURCE/src-c/native/$hash.h" "$OUT/digestif_$hash.h"
done
python3 tools/select-pbkdf2.py --check
FLAGS="-O2 -g -Wall -Wextra -Werror -Wno-sign-compare -I. -Ipbkdf2 -Ipbkdf2/vendor/cbits -I$OUT"
SRC="tests/ct/pbkdf2.c pbkdf2/pbkdf2_kernel.c $DIGESTIF_SOURCE/src-c/native/sha1.c $DIGESTIF_SOURCE/src-c/native/sha256.c $DIGESTIF_SOURCE/src-c/native/sha512.c"
$CC $FLAGS $SRC -lcrypto -o "$OUT/differential"
"$OUT/differential"
$CC $FLAGS -DCTGRIND $SRC -lcrypto -o "$OUT/taint"
valgrind --quiet --error-exitcode=1 "$OUT/taint"
$CC $FLAGS -fsanitize=address,undefined -fno-omit-frame-pointer $SRC -lcrypto -o "$OUT/sanitize"
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 "$OUT/sanitize"
