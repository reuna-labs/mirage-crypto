#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
CC=${CC:-cc}
OUT=${OUT:-_build/portable-crypto}
mkdir -p "$OUT"
python3 tools/select-portable-crypto.py --check
SRC="tests/ct/portable_crypto.c src/native/portable_crypto.c src/native/bear_aes_ct.c src/native/bear_aes_ct_enc.c src/native/bear_aes_ct_dec.c src/native/bear_ghash.c"
FLAGS="-O3 -g -Wall -Wextra -Werror -I. -Isrc/native/portable"
$CC $FLAGS -DHAVE_OPENSSL $SRC -lcrypto -o "$OUT/differential"
"$OUT/differential"
$CC $FLAGS -DHAVE_OPENSSL -DCTGRIND $SRC -lcrypto -o "$OUT/taint"
valgrind --quiet --error-exitcode=1 "$OUT/taint"
$CC $FLAGS -DHAVE_OPENSSL -fsanitize=address,undefined -fno-omit-frame-pointer $SRC -lcrypto -o "$OUT/sanitize"
ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 "$OUT/sanitize"
