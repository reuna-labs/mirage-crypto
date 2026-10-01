/* ISC adapter; curve and scalar formulas are selected upstream reference code. */
#include <string.h>
#include "edb32.h"
#include "wipe.h"
#ifdef MC_EDB32_CTGRIND
#include <valgrind/memcheck.h>
#define DECLASSIFY(p,n) VALGRIND_MAKE_MEM_DEFINED((p),(n))
#else
#define DECLASSIFY(p,n) ((void)0)
#endif
#define ED25519_NO_INLINE_ASM
#define cardano_crypto_ed25519_publickey mc_edb32_ed25519_publickey
#define cardano_crypto_ed25519_sign mc_edb32_ed25519_sign
#define cardano_crypto_ed25519_sign_open mc_edb32_ed25519_sign_open
#define cardano_crypto_ed25519_scalar_add mc_edb32_ed25519_scalar_add
#define cardano_crypto_ed25519_point_add mc_edb32_ed25519_point_add
#define cardano_crypto_ed25519_extend mc_edb32_ed25519_extend
/* Only public sliding-window digits (-15..15) reach this helper. Solo5's
 * minimal libc need not export abs(). */
static int mc_edb32_public_abs(int x) { return x < 0 ? -x : x; }
#define abs mc_edb32_public_abs
#include "cardano_curve.inc"
#undef abs
#include "cardano_arithmetic.inc"
#include "cardano_hmac.inc"
DECL_HMAC(sha512,SHA512_BLOCK_SIZE,SHA512_DIGEST_SIZE,struct sha512_ctx,
          crypton_sha512_init,crypton_sha512_update,crypton_sha512_finalize);

static const uint8_t order[32]={0xed,0xd3,0xf5,0x5c,0x1a,0x63,0x12,0x58,
  0xd6,0x9c,0xf7,0xa2,0xde,0xf9,0xde,0x14,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0x10};
static const uint8_t identity[32]={1};
static const uint8_t zero[32]={0};
/* Public encodings only: comparison and point decoding may be variable-time. */
static int scalar_canonical(const uint8_t s[32]) {
  for(int i=31;i>=0;i--) { if(s[i]<order[i]) return 1; if(s[i]>order[i]) return 0; }
  return 0;
}
int mc_edb32_private_valid(const uint8_t key[96]) {
  return ((key[0]&7)==0) & ((key[31]&0xc0)==0x40);
}
int mc_edb32_public_valid(const uint8_t key[32]) {
  ge25519 p,q; bignum256modm l,z; uint8_t encoded[32],x[32];
  if(!ge25519_unpack_negative_vartime(&p,key)) return 0;
  /* Decoder returns -P. Re-encode y and the input sign, checking negative zero. */
  ge25519_pack(encoded,&p);
  curve25519_contract(x,p.x);
  if(memcmp(x,zero,32)==0 && (key[31]&0x80)) return 0;
  encoded[31]=(encoded[31]&0x7f)|(key[31]&0x80);
  if(memcmp(encoded,key,32)!=0 || memcmp(key,identity,32)==0) return 0;
  /* Load L without reducing it. [L]P=0 rejects mixed-order as well as torsion. */
  expand_raw256_modm(l,order); expand_raw256_modm(z,zero);
  ge25519_double_scalarmult_vartime(&q,&p,l,z); ge25519_pack(encoded,&q);
  return memcmp(encoded,identity,32)==0;
}
int mc_edb32_root(const uint8_t hash[64],const uint8_t cc[32],uint8_t out[96]) {
  if(hash[31]&0x20) return 0;
  memcpy(out,hash,64); out[0]&=248; out[31]=(out[31]&127)|64;
  memcpy(out+64,cc,32); return 1;
}
void mc_edb32_public(const uint8_t key[96],uint8_t out[64]) {
  cardano_crypto_ed25519_publickey(key,out); memcpy(out+32,key+64,32);
}
static void index_le(uint8_t out[4],uint32_t i) {
  out[0]=(uint8_t)i; out[1]=(uint8_t)(i>>8); out[2]=(uint8_t)(i>>16); out[3]=(uint8_t)(i>>24);
}
/* V2 domain separation and HMAC sequencing from encrypted_sign.c, without
 * encrypted storage or a cached public key. Inputs/outputs use CIP-16 bytes. */
int mc_edb32_derive_private(const uint8_t key[96],uint32_t index,uint8_t out[96]) {
  uint8_t pub[32],idx[4],z[64],cc[64],zl8[64]={0},priv[64];
  HMAC_sha512_ctx ctx; int hard=(index & UINT32_C(0x80000000))!=0;
  const uint8_t ztag=hard?0:2, ctag=hard?1:3;
  memcpy(priv,key,64); index_le(idx,index);
  if(!hard) cardano_crypto_ed25519_publickey(priv,pub);
  HMAC_sha512_init(&ctx,key+64,32); HMAC_sha512_update(&ctx,&ztag,1);
  HMAC_sha512_update(&ctx,hard?priv:pub,hard?64:32); HMAC_sha512_update(&ctx,idx,4);
  HMAC_sha512_final(&ctx,z);
  multiply8_v2(zl8,z,28); scalar_add_no_overflow(zl8,priv,out);
  add_256bits_v2(out+32,z+32,priv+32);
  HMAC_sha512_init(&ctx,key+64,32); HMAC_sha512_update(&ctx,&ctag,1);
  HMAC_sha512_update(&ctx,hard?priv:pub,hard?64:32); HMAC_sha512_update(&ctx,idx,4);
  HMAC_sha512_final(&ctx,cc); memcpy(out+64,cc+32,32);
  int valid=mc_edb32_private_valid(out);
  DECLASSIFY(&valid,sizeof valid); /* Explicitly returned validity status. */
  mc_edb32_wipe(priv,sizeof priv); mc_edb32_wipe(z,sizeof z); mc_edb32_wipe(zl8,sizeof zl8);
  mc_edb32_wipe(cc,sizeof cc); mc_edb32_wipe(&ctx,sizeof ctx);
  if(!valid) mc_edb32_wipe(out,96);
  return valid;
}
int mc_edb32_derive_public(const uint8_t key[64],uint32_t index,uint8_t out[64]) {
  if(index & UINT32_C(0x80000000)) return 0;
  uint8_t idx[4],z[64],cc[64],zl8[64]={0},tweak[32]; HMAC_sha512_ctx ctx;
  const uint8_t ztag=2,ctag=3; index_le(idx,index);
  HMAC_sha512_init(&ctx,key+32,32); HMAC_sha512_update(&ctx,&ztag,1);
  HMAC_sha512_update(&ctx,key,32); HMAC_sha512_update(&ctx,idx,4); HMAC_sha512_final(&ctx,z);
  multiply8_v2(zl8,z,28); cardano_crypto_ed25519_publickey(zl8,tweak);
  int valid=cardano_crypto_ed25519_point_add(tweak,key,out)==0;
  HMAC_sha512_init(&ctx,key+32,32); HMAC_sha512_update(&ctx,&ctag,1);
  HMAC_sha512_update(&ctx,key,32); HMAC_sha512_update(&ctx,idx,4); HMAC_sha512_final(&ctx,cc);
  memcpy(out+32,cc+32,32);
  valid=valid && mc_edb32_public_valid(out);
  mc_edb32_wipe(z,sizeof z); mc_edb32_wipe(zl8,sizeof zl8); mc_edb32_wipe(cc,sizeof cc);
  mc_edb32_wipe(&ctx,sizeof ctx); if(!valid) mc_edb32_wipe(out,64);
  return valid;
}
void mc_edb32_sign(const uint8_t key[96],const uint8_t *msg,size_t len,uint8_t out[64]) {
  uint8_t pk[32]; cardano_crypto_ed25519_publickey(key,pk);
  cardano_crypto_ed25519_sign(msg,len,NULL,0,key,pk,out);
}
int mc_edb32_verify(const uint8_t key[32],const uint8_t sig[64],const uint8_t *msg,size_t len) {
  /* Preserve the existing raw verifier, including canonical S. Wallet public
   * keys are validated separately; raw verification has no new subgroup gate. */
  return scalar_canonical(sig+32) && cardano_crypto_ed25519_sign_open(msg,len,key,sig)==0;
}
