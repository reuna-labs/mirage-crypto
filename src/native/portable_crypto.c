/* ISC; selected BearSSL kernels are MIT, see portable/vendor/LICENSE.txt. */
#include "portable_crypto.h"
#include "portable/inner.h"

static void wipe(void *p, size_t n)
{
  volatile unsigned char *b = p;
  while (n--) *b++ = 0;
}

void mc_aes_ct_derive(const void *key, void *schedule, unsigned rounds)
{
  uint32_t comp[60];
  br_aes_ct_keysched(comp, key, (rounds - 6) * 4);
  memcpy(schedule, comp, (rounds + 1) * 16);
  wipe(comp, sizeof comp);
}

void mc_aes_ct_blocks(const void *src0, void *dst0, const void *schedule,
                      unsigned rounds, size_t blocks, int decrypt)
{
  const unsigned char *src = src0;
  unsigned char *dst = dst0;
  uint32_t comp[60], expanded[120], q[8];
  memcpy(comp, schedule, (rounds + 1) * 16);
  br_aes_ct_skey_expand(expanded, rounds, comp);
  while (blocks) {
    size_t count = blocks >= 2 ? 2 : 1;
    memset(q, 0, sizeof q);
    for (size_t b = 0; b < count; b++)
      for (size_t w = 0; w < 4; w++)
        q[2 * w + b] = br_dec32le(src + 16 * b + 4 * w);
    br_aes_ct_ortho(q);
    if (decrypt) br_aes_ct_bitslice_decrypt(rounds, expanded, q);
    else br_aes_ct_bitslice_encrypt(rounds, expanded, q);
    br_aes_ct_ortho(q);
    for (size_t b = 0; b < count; b++)
      for (size_t w = 0; w < 4; w++)
        br_enc32le(dst + 16 * b + 4 * w, q[2 * w + b]);
    src += 16 * count;
    dst += 16 * count;
    blocks -= count;
  }
  wipe(comp, sizeof comp);
  wipe(expanded, sizeof expanded);
  wipe(q, sizeof q);
}

void mc_ghash_ct(void *hash, const void *key, const void *src, size_t len)
{
  br_ghash_ctmul32(hash, key, src, len);
}
