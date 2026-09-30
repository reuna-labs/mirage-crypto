#!/bin/sh
# Selected arithmetic plus the actual Digestif Keccak permutation.
set -eu
cd "$(dirname "$0")/.."
DIGESTIF_SOURCE=${DIGESTIF_SOURCE:-../digestif}
CC=${CC:-cc}
MODE=${MODE:-sanitize}
OUT=${OUT:-_build/sr25519-kernel}
mkdir -p "$OUT"
case "$MODE" in
  sanitize) FLAGS='-fsanitize=address,undefined -fno-omit-frame-pointer' ;;
  ct) FLAGS='-DCTGRIND' ;;
  *) echo 'MODE must be sanitize or ct' >&2; exit 1 ;;
esac
# Both upstream field backends are included and checked.
for bits in 64 32; do
  EXTRA=''
  if [ "$bits" = 32 ]; then EXTRA='-DMC_SR_FORCE_32BIT'; fi
  # FLAGS and EXTRA deliberately contain separate compiler arguments.
  "$CC" -std=c99 -O2 -g $FLAGS $EXTRA -I. \
    -Isr25519/vendor/src/libsodium/include/sodium \
    -I"$DIGESTIF_SOURCE/src-c/native" tests/ct/sr25519.c \
    sr25519/sodium_kernel.c sr25519/ristretto_adapter.c \
    "$DIGESTIF_SOURCE/src-c/native/sha3.c" -o "$OUT/check-$bits"
  if [ "$MODE" = ct ]; then
    valgrind --quiet --error-exitcode=1 "$OUT/check-$bits"
  else
    ASAN_OPTIONS=detect_leaks=0 UBSAN_OPTIONS=halt_on_error=1 "$OUT/check-$bits"
  fi
done
echo "sr25519 + Keccak $MODE checks passed (both field backends)."
