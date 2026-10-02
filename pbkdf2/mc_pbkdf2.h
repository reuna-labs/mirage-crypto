#ifndef MC_PBKDF2_H
#define MC_PBKDF2_H
#include <stddef.h>
#include <stdint.h>
/* iterations >= 1; 1 <= nout <= UINT32_MAX - 63. Inputs may be unaligned.
 * Output must not alias input. The OCaml interface enforces these bounds. */
void mc_pbkdf2_sha1(const uint8_t *,size_t,const uint8_t *,size_t,uint32_t,uint8_t *,size_t);
void mc_pbkdf2_sha256(const uint8_t *,size_t,const uint8_t *,size_t,uint32_t,uint8_t *,size_t);
void mc_pbkdf2_sha512(const uint8_t *,size_t,const uint8_t *,size_t,uint32_t,uint8_t *,size_t);
#endif
