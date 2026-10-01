/* ISC. Fixed-width native boundary. No internal curve structs escape. */
#ifndef MC_EDB32_H
#define MC_EDB32_H
#include <stdint.h>
#include <stddef.h>
int mc_edb32_private_valid(const uint8_t key[96]);
int mc_edb32_public_valid(const uint8_t key[32]);
int mc_edb32_root(const uint8_t hash[64],const uint8_t cc[32],uint8_t out[96]);
void mc_edb32_public(const uint8_t key[96],uint8_t out[64]);
int mc_edb32_derive_private(const uint8_t key[96],uint32_t index,uint8_t out[96]);
int mc_edb32_derive_public(const uint8_t key[64],uint32_t index,uint8_t out[64]);
void mc_edb32_sign(const uint8_t key[96],const uint8_t *msg,size_t len,uint8_t out[64]);
int mc_edb32_verify(const uint8_t key[32],const uint8_t sig[64],const uint8_t *msg,size_t len);
void mc_edb32_icarus(const uint8_t *entropy,size_t elen,const uint8_t *pass,size_t plen,uint8_t out[96]);
#endif
