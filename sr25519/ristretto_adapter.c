/* ISC. Group semantics around libsodium's identity-result rejection. */
#include <string.h>
#include "sodium_config.h"
#include "crypto_core_ristretto255.h"
#include "crypto_scalarmult_ristretto255.h"
#include "utils.h"
#include "ristretto_adapter.h"

static const unsigned char base[32] = {
  0xe2,0xf2,0xae,0x0a,0x6a,0xbc,0x4e,0x71,0xa8,0x84,0xa9,0x61,0xc5,0x00,0x51,0x5f,
  0x58,0xe3,0x0b,0x6a,0xa5,0x82,0xdd,0x8d,0xb6,0xa6,0x59,0x45,0xe0,0x8d,0x2d,0x76
};

/* Volatile masks stop the compiler recognizing these selections as branches
 * or conditional memory operations. Inspect the compiled adapter on upgrades. */
static unsigned char substitute_scalar(unsigned char k[32], const unsigned char s[32]) {
  unsigned char zero = (unsigned char) sodium_is_zero(s, 32);
  volatile unsigned char mask = (unsigned char)(0u - zero);
  for (unsigned i = 0; i < 32; i++) k[i] = s[i] & (unsigned char)~mask;
  k[0] |= mask & 1u;
  return zero;
}
static void select_identity(unsigned char out[32], unsigned char zero) {
  volatile unsigned char mask = (unsigned char)(zero - 1u);
  for (unsigned i = 0; i < 32; i++) out[i] &= mask;
}
void mc_sr_mul_base(unsigned char out[32], const unsigned char scalar[32]) {
  unsigned char k[32];
  unsigned char zero = substitute_scalar(k, scalar);
  /* k is nonzero and canonical, so the upstream operation cannot fail. */
  (void) crypto_scalarmult_ristretto255_base(out, k);
  select_identity(out, zero);
  sodium_memzero(k, sizeof k);
}
int mc_sr_mul(unsigned char out[32], const unsigned char scalar[32], const unsigned char point[32]) {
  if (!crypto_core_ristretto255_is_valid_point(point)) return -1;
  unsigned char k[32], p[32];
  unsigned char zero = substitute_scalar(k, scalar);
  unsigned char identity = (unsigned char) sodium_is_zero(point, 32);
  volatile unsigned char mask = (unsigned char)(0u - identity);
  for (unsigned i = 0; i < 32; i++) p[i] = (point[i] & (unsigned char)~mask) | (base[i] & mask);
  /* Both substituted operands are nonzero in a prime-order group. */
  int status = crypto_scalarmult_ristretto255(out, k, p);
  (void) status; /* Guaranteed success for substituted operands. */
  select_identity(out, zero | identity);
  sodium_memzero(k, sizeof k);
  sodium_memzero(p, sizeof p);
  return 0;
}
