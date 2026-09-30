/* ISC. Only public libsecp256k1 interfaces are used here. */
#include <stdlib.h>
#include <string.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include "vendor/include/secp256k1.h"
#include "vendor/include/secp256k1_preallocated.h"
#include "vendor/include/secp256k1_recovery.h"
#include "vendor/include/secp256k1_extrakeys.h"
#include "vendor/include/secp256k1_schnorrsig.h"

#define CTX secp256k1_context_static
#define IN(v) ((const unsigned char *)String_val(v))
static void wipe(void *p, size_t n) { volatile unsigned char *q=p; while(n--) *q++=0; }
static void length(value v, size_t n) {
  if (caml_string_length(v)!=n) caml_invalid_argument("secp256k1: length");
}
static secp256k1_context *context(value seed, void **mem, size_t *size) {
  length(seed,32);
  *size=secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE);
  *mem=malloc(*size); if (!*mem) caml_raise_out_of_memory();
  secp256k1_context *ctx=secp256k1_context_preallocated_create(*mem,SECP256K1_CONTEXT_NONE);
  int ok=secp256k1_context_randomize(ctx,IN(seed));
  if (!ok) { secp256k1_context_preallocated_destroy(ctx); wipe(*mem,*size); free(*mem); caml_failwith("secp256k1: context"); }
  return ctx;
}
static void destroy(secp256k1_context *ctx,void *mem,size_t n) {
  secp256k1_context_preallocated_destroy(ctx); wipe(mem,n); free(mem);
}
static value serialize_pub(const secp256k1_pubkey *pk) {
  unsigned char out[65]; size_t len=65;
  secp256k1_ec_pubkey_serialize(CTX,out,&len,pk,SECP256K1_EC_UNCOMPRESSED);
  return caml_alloc_initialized_string(len,(const char *)out);
}
CAMLprim value mc_k1_valid(value sk) {
  length(sk,32); return Val_bool(secp256k1_ec_seckey_verify(CTX,IN(sk)));
}
/* Scalar-only operations need no generator context or randomization. Allocate
 * before copying secrets to the stack, and wipe the copy on both outcomes. */
CAMLprim value mc_k1_priv_add_tweak(value sk,value tweak) {
  CAMLparam2(sk,tweak); CAMLlocal1(out);
  length(sk,32); length(tweak,32); out=caml_alloc_string(32);
  unsigned char key[32]; memcpy(key,IN(sk),32);
  int ok=secp256k1_ec_seckey_tweak_add(CTX,key,IN(tweak));
  if(ok) memcpy(Bytes_val(out),key,32);
  wipe(key,sizeof key);
  if(!ok) CAMLreturn(caml_copy_string(""));
  CAMLreturn(out);
}
CAMLprim value mc_k1_priv_negate(value sk) {
  CAMLparam1(sk); CAMLlocal1(out); length(sk,32); out=caml_alloc_string(32);
  unsigned char key[32]; memcpy(key,IN(sk),32);
  int ok=secp256k1_ec_seckey_negate(CTX,key);
  if(ok) memcpy(Bytes_val(out),key,32);
  wipe(key,sizeof key);
  if(!ok) caml_invalid_argument("secp256k1: secret key");
  CAMLreturn(out);
}
CAMLprim value mc_k1_pub_add_tweak(value input,value tweak) {
  CAMLparam2(input,tweak); length(tweak,32); secp256k1_pubkey pk;
  if(!secp256k1_ec_pubkey_parse(CTX,&pk,IN(input),caml_string_length(input)) ||
     !secp256k1_ec_pubkey_tweak_add(CTX,&pk,IN(tweak)))
    CAMLreturn(caml_copy_string(""));
  CAMLreturn(serialize_pub(&pk));
}
CAMLprim value mc_k1_pub_add(value a,value b) {
  CAMLparam2(a,b); secp256k1_pubkey pa,pb,out;
  const secp256k1_pubkey *points[2]={&pa,&pb};
  if(!secp256k1_ec_pubkey_parse(CTX,&pa,IN(a),caml_string_length(a)) ||
     !secp256k1_ec_pubkey_parse(CTX,&pb,IN(b),caml_string_length(b)) ||
     !secp256k1_ec_pubkey_combine(CTX,&out,points,2))
    CAMLreturn(caml_copy_string(""));
  CAMLreturn(serialize_pub(&out));
}
CAMLprim value mc_k1_pub_negate(value input) {
  CAMLparam1(input); secp256k1_pubkey pk;
  if(!secp256k1_ec_pubkey_parse(CTX,&pk,IN(input),caml_string_length(input)))
    caml_invalid_argument("secp256k1: public key");
  int ok=secp256k1_ec_pubkey_negate(CTX,&pk);
  (void)ok;
  CAMLreturn(serialize_pub(&pk));
}
CAMLprim value mc_k1_parse_pub(value s) {
  CAMLparam1(s); secp256k1_pubkey pk;
  if (!secp256k1_ec_pubkey_parse(CTX,&pk,IN(s),caml_string_length(s))) CAMLreturn(caml_copy_string(""));
  CAMLreturn(serialize_pub(&pk));
}
CAMLprim value mc_k1_pub(value sk,value seed) {
  CAMLparam2(sk,seed); length(sk,32);
  void *mem; size_t n; secp256k1_pubkey pk;
  secp256k1_context *ctx=context(seed,&mem,&n);
  int ok=secp256k1_ec_pubkey_create(ctx,&pk,IN(sk)); destroy(ctx,mem,n);
  if(!ok) caml_invalid_argument("secp256k1: secret key");
  CAMLreturn(serialize_pub(&pk));
}
CAMLprim value mc_k1_sign(value sk,value msg,value seed) {
  CAMLparam3(sk,msg,seed); length(sk,32); length(msg,32);
  secp256k1_ecdsa_recoverable_signature sig; unsigned char out[65]; int recid=0;
  void *mem; size_t n; secp256k1_context *ctx=context(seed,&mem,&n);
  int ok=secp256k1_ecdsa_sign_recoverable(ctx,&sig,IN(msg),IN(sk),NULL,NULL);
  if(ok) secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx,out,&recid,&sig);
  destroy(ctx,mem,n); wipe(&sig,sizeof sig);
  if(!ok) caml_invalid_argument("secp256k1: signing failed");
  out[64]=(unsigned char)recid;
  CAMLreturn(caml_alloc_initialized_string(65,(const char *)out));
}
CAMLprim value mc_k1_parse_sig(value input,value compact) {
  CAMLparam2(input,compact); secp256k1_ecdsa_signature sig; unsigned char out[64];
  int ok;
  if(Bool_val(compact)) { length(input,64); ok=secp256k1_ecdsa_signature_parse_compact(CTX,&sig,IN(input)); }
  else ok=secp256k1_ecdsa_signature_parse_der(CTX,&sig,IN(input),caml_string_length(input));
  if(!ok) CAMLreturn(caml_copy_string(""));
  secp256k1_ecdsa_signature_serialize_compact(CTX,out,&sig);
  CAMLreturn(caml_alloc_initialized_string(64,(const char *)out));
}
CAMLprim value mc_k1_der(value input) {
  CAMLparam1(input); length(input,64); secp256k1_ecdsa_signature sig;
  unsigned char out[72]; size_t n=sizeof out;
  if(!secp256k1_ecdsa_signature_parse_compact(CTX,&sig,IN(input))) caml_invalid_argument("secp256k1: signature");
  secp256k1_ecdsa_signature_serialize_der(CTX,out,&n,&sig);
  CAMLreturn(caml_alloc_initialized_string(n,(const char *)out));
}
CAMLprim value mc_k1_verify(value pk,value sig,value msg) {
  length(sig,64); length(msg,32); secp256k1_pubkey p; secp256k1_ecdsa_signature s;
  if(!secp256k1_ec_pubkey_parse(CTX,&p,IN(pk),caml_string_length(pk)) ||
     !secp256k1_ecdsa_signature_parse_compact(CTX,&s,IN(sig))) return Val_false;
  secp256k1_ecdsa_signature_normalize(CTX,&s,&s);
  return Val_bool(secp256k1_ecdsa_verify(CTX,&s,IN(msg),&p));
}
CAMLprim value mc_k1_recover(value sig,value msg,value id) {
  CAMLparam3(sig,msg,id); length(sig,64); length(msg,32);
  secp256k1_ecdsa_recoverable_signature s; secp256k1_pubkey pk; int i=Int_val(id);
  if(i<0 || i>3 || !secp256k1_ecdsa_recoverable_signature_parse_compact(CTX,&s,IN(sig),i) ||
     !secp256k1_ecdsa_recover(CTX,&pk,&s,IN(msg))) CAMLreturn(caml_copy_string(""));
  CAMLreturn(serialize_pub(&pk));
}
CAMLprim value mc_k1_xvalid(value input) {
  length(input,32); secp256k1_xonly_pubkey p;
  return Val_bool(secp256k1_xonly_pubkey_parse(CTX,&p,IN(input)));
}
CAMLprim value mc_k1_schnorr_sign(value sk,value msg,value aux,value seed) {
  CAMLparam4(sk,msg,aux,seed); length(sk,32); length(aux,32);
  secp256k1_keypair kp; unsigned char out[64]; void *mem; size_t n;
  secp256k1_context *ctx=context(seed,&mem,&n);
  secp256k1_schnorrsig_extraparams params=SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
  params.ndata=(void *)IN(aux);
  int ok=secp256k1_keypair_create(ctx,&kp,IN(sk));
  if(ok) ok=secp256k1_schnorrsig_sign_custom(ctx,out,IN(msg),caml_string_length(msg),&kp,&params);
  wipe(&kp,sizeof kp); destroy(ctx,mem,n);
  if(!ok) caml_invalid_argument("secp256k1: Schnorr signing failed");
  CAMLreturn(caml_alloc_initialized_string(64,(const char *)out));
}
CAMLprim value mc_k1_schnorr_verify(value pk,value sig,value msg) {
  length(pk,32); length(sig,64); secp256k1_xonly_pubkey p;
  if(!secp256k1_xonly_pubkey_parse(CTX,&p,IN(pk))) return Val_false;
  return Val_bool(secp256k1_schnorrsig_verify(CTX,IN(sig),IN(msg),caml_string_length(msg),&p));
}
