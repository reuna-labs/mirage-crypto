/* Selected upstream fast-PBKDF2 SHA512, linked to Digestif's hash kernel. */
#include "edb32.h"
#include "wipe.h"
#define NO_INLINE_ASM
#define crypton_sha512_transform mc_edb32_sha512_transform
#define crypton_fastpbkdf2_hmac_sha512 mc_edb32_pbkdf2_sha512
#include "pbkdf2_sha512.inc"
void mc_edb32_icarus(const uint8_t *entropy,size_t elen,const uint8_t *pass,size_t plen,uint8_t out[96]) {
  mc_edb32_pbkdf2_sha512(pass,plen,entropy,elen,4096,out,96);
  out[0]&=248; out[31]=(out[31]&31)|64;
}
