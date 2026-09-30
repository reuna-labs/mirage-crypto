#include <stdint.h>
/* BLAKE3 uses popcount only for public tree/chunk lengths. Avoid a libgcc
 * __popcountdi2 dependency on freestanding x86 without assuming POPCNT. */
static inline unsigned mc_b3_popcount(uint64_t x) {
  x -= (x >> 1) & UINT64_C(0x5555555555555555);
  x = (x & UINT64_C(0x3333333333333333)) + ((x >> 2) & UINT64_C(0x3333333333333333));
  x = (x + (x >> 4)) & UINT64_C(0x0f0f0f0f0f0f0f0f);
  return (unsigned)((x * UINT64_C(0x0101010101010101)) >> 56);
}
#define __builtin_popcountll(x) mc_b3_popcount(x)
#include "vendor/c/blake3.c"
