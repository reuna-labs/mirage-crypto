/* Private, allocation-free portable kernel adapter. Key lengths/rounds and
 * block counts are validated by the OCaml API; buffers may be unaligned.
 * AES buffers may be disjoint or exactly in place. */
#ifndef MC_PORTABLE_CRYPTO_H
#define MC_PORTABLE_CRYPTO_H
#include <stddef.h>
#include <stdint.h>
void mc_aes_ct_derive(const void *key, void *schedule, unsigned rounds);
void mc_aes_ct_blocks(const void *src, void *dst, const void *schedule,
                      unsigned rounds, size_t blocks, int decrypt);
void mc_ghash_ct(void *hash, const void *key, const void *src, size_t len);
#endif
