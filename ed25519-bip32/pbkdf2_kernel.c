/* Icarus framing over the shared native PBKDF2 kernel. */
#include "edb32.h"
#include <mc_pbkdf2.h>
void mc_edb32_icarus(const uint8_t *entropy,size_t elen,const uint8_t *pass,size_t plen,uint8_t out[96]) {
  mc_pbkdf2_sha512(pass,plen,entropy,elen,4096,out,96);
  out[0]&=248; out[31]=(out[31]&31)|64;
}
