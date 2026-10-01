/* Standalone kernel checks: -DCTGRIND taints secrets; otherwise sanitizer smoke. */
#include <assert.h>
#include <string.h>
#include "ed25519-bip32/edb32.h"
#ifdef CTGRIND
#include <valgrind/memcheck.h>
#define SECRET(p,n) VALGRIND_MAKE_MEM_UNDEFINED((p),(n))
#define PUBLIC(p,n) VALGRIND_MAKE_MEM_DEFINED((p),(n))
#else
#define SECRET(p,n) ((void)0)
#define PUBLIC(p,n) ((void)0)
#endif
int main(void) {
 uint8_t key[96],pub[64],child[96],sig[64],entropy[32],pass[129];
 const uint8_t msg[]="native Cardano secret-flow check";
 for(unsigned n=0;n<16;n++) {
  for(unsigned i=0;i<96;i++) key[i]=(uint8_t)(i*13+n*37);
  key[0]&=248;key[31]=(key[31]&31)|64;
  SECRET(key,sizeof key);
  mc_edb32_public(key,pub); PUBLIC(pub,sizeof pub);
  assert(mc_edb32_public_valid(pub));
  assert(mc_edb32_derive_private(key,n,child));
  assert(mc_edb32_derive_private(key,UINT32_C(0x80000000)+n,child));
  mc_edb32_sign(key,msg,sizeof msg,sig); PUBLIC(sig,sizeof sig);
  assert(mc_edb32_verify(pub,sig,msg,sizeof msg));
  PUBLIC(key,sizeof key);PUBLIC(child,sizeof child);
 }
 memset(entropy,42,sizeof entropy);memset(pass,37,sizeof pass);
 SECRET(entropy,sizeof entropy);SECRET(pass,sizeof pass);
 mc_edb32_icarus(entropy,sizeof entropy,pass,sizeof pass,key);
 PUBLIC(key,sizeof key);PUBLIC(entropy,sizeof entropy);PUBLIC(pass,sizeof pass);
 assert(mc_edb32_private_valid(key));
 /* Offset every caller-owned buffer, including a message longer than a
  * SHA512 block, to exercise the portable SHA512 marshalling boundary. */
 uint8_t kb[97],pb[65],sb[65],mb[258],eb[33],pw[130];
 memcpy(kb+1,key,96);memset(mb,17,sizeof mb);memset(eb,19,sizeof eb);memset(pw,23,sizeof pw);
 mc_edb32_public(kb+1,pb+1);
 mc_edb32_sign(kb+1,mb+1,257,sb+1);
 assert(mc_edb32_verify(pb+1,sb+1,mb+1,257));
 mc_edb32_icarus(eb+1,32,pw+1,129,kb+1);
 assert(mc_edb32_private_valid(kb+1));
 return 0;
}
