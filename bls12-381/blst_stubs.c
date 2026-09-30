/* ISC. Aligned C locals isolate upstream structures from OCaml's heap.
 * No OCaml allocation or runtime-lock release while heap pointers are in use. */
#include <string.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include "vendor/bindings/blst.h"
#define IN(v) ((const unsigned char *)String_val(v))
static void length(value v,size_t n) { if(caml_string_length(v)!=n) caml_invalid_argument("BLST: length"); }
static void wipe(void *p,size_t n) { volatile unsigned char *q=p; while(n--) *q++=0; }
static void load(void *p,size_t n,value v) { length(v,n); memcpy(p,String_val(v),n); }
static value save(const void *p,size_t n) { return caml_alloc_initialized_string(n,p); }
CAMLprim value mc_bls_scalar_valid(value s) {
  length(s,32); blst_scalar k; blst_scalar_from_bendian(&k,IN(s));
  int ok=blst_scalar_fr_check(&k); wipe(&k,sizeof k); return Val_bool(ok);
}
CAMLprim value mc_bls_secret_valid(value s) {
  length(s,32); blst_scalar k; blst_scalar_from_bendian(&k,IN(s));
  int ok=blst_sk_check(&k); wipe(&k,sizeof k); return Val_bool(ok);
}

CAMLprim value mc_bls_g1_parse(value s) {
  CAMLparam1(s); blst_p1_affine a; blst_p1 p; size_t n=caml_string_length(s);
  BLST_ERROR e;
  if(n==48) e=blst_p1_uncompress(&a,IN(s));
  else if(n==96) e=blst_p1_deserialize(&a,IN(s));
  else caml_invalid_argument("BLST: point length");
  if(e!=BLST_SUCCESS || !blst_p1_affine_in_g1(&a)) CAMLreturn(caml_copy_string(""));
  blst_p1_from_affine(&p,&a); CAMLreturn(save(&p,sizeof p));
}
CAMLprim value mc_bls_g1_serialize(value s,value compressed) {
  CAMLparam2(s,compressed); blst_p1 p; unsigned char out[96]; load(&p,sizeof p,s);
  if(Bool_val(compressed)) blst_p1_compress(out,&p); else blst_p1_serialize(out,&p);
  CAMLreturn(save(out,Bool_val(compressed)?48:96));
}
CAMLprim value mc_bls_g1_generator(value unit) {
  (void)unit; return save(blst_p1_generator(),sizeof(blst_p1));
}
CAMLprim value mc_bls_g1_check(value s,value which) {
  blst_p1 p; load(&p,sizeof p,s);
  switch(Int_val(which)) {
    case 0: return Val_bool(blst_p1_is_inf(&p));
    case 1: return Val_bool(blst_p1_on_curve(&p));
    default: return Val_bool(blst_p1_in_g1(&p));
  }
}
CAMLprim value mc_bls_g1_equal(value s,value t) {
  blst_p1 p,q; load(&p,sizeof p,s); load(&q,sizeof q,t);
  return Val_bool(blst_p1_is_equal(&p,&q));
}
CAMLprim value mc_bls_g1_add(value s,value t) {
  CAMLparam2(s,t); blst_p1 p,q,r; load(&p,sizeof p,s); load(&q,sizeof q,t);
  blst_p1_add_or_double(&r,&p,&q); CAMLreturn(save(&r,sizeof r));
}
CAMLprim value mc_bls_g1_neg(value s) {
  CAMLparam1(s); blst_p1 p; load(&p,sizeof p,s); blst_p1_cneg(&p,1);
  CAMLreturn(save(&p,sizeof p));
}
CAMLprim value mc_bls_g1_mult(value s,value scalar) {
  CAMLparam2(s,scalar); CAMLlocal1(out);
  length(scalar,32); out=caml_alloc_string(sizeof(blst_p1));
  blst_p1 p,r; blst_scalar k; load(&p,sizeof p,s); blst_scalar_from_bendian(&k,IN(scalar));
  blst_p1_mult(&r,&p,k.b,255); memcpy(Bytes_val(out),&r,sizeof r);
  wipe(&k,sizeof k); wipe(&r,sizeof r); CAMLreturn(out);
}

CAMLprim value mc_bls_g2_parse(value s) {
  CAMLparam1(s); blst_p2_affine a; blst_p2 p; size_t n=caml_string_length(s);
  BLST_ERROR e;
  if(n==96) e=blst_p2_uncompress(&a,IN(s));
  else if(n==192) e=blst_p2_deserialize(&a,IN(s));
  else caml_invalid_argument("BLST: point length");
  if(e!=BLST_SUCCESS || !blst_p2_affine_in_g2(&a)) CAMLreturn(caml_copy_string(""));
  blst_p2_from_affine(&p,&a); CAMLreturn(save(&p,sizeof p));
}
CAMLprim value mc_bls_g2_serialize(value s,value compressed) {
  CAMLparam2(s,compressed); blst_p2 p; unsigned char out[192]; load(&p,sizeof p,s);
  if(Bool_val(compressed)) blst_p2_compress(out,&p); else blst_p2_serialize(out,&p);
  CAMLreturn(save(out,Bool_val(compressed)?96:192));
}
CAMLprim value mc_bls_g2_generator(value unit) {
  (void)unit; return save(blst_p2_generator(),sizeof(blst_p2));
}
CAMLprim value mc_bls_g2_check(value s,value which) {
  blst_p2 p; load(&p,sizeof p,s);
  switch(Int_val(which)) {
    case 0: return Val_bool(blst_p2_is_inf(&p));
    case 1: return Val_bool(blst_p2_on_curve(&p));
    default: return Val_bool(blst_p2_in_g2(&p));
  }
}
CAMLprim value mc_bls_g2_equal(value s,value t) {
  blst_p2 p,q; load(&p,sizeof p,s); load(&q,sizeof q,t);
  return Val_bool(blst_p2_is_equal(&p,&q));
}
CAMLprim value mc_bls_g2_add(value s,value t) {
  CAMLparam2(s,t); blst_p2 p,q,r; load(&p,sizeof p,s); load(&q,sizeof q,t);
  blst_p2_add_or_double(&r,&p,&q); CAMLreturn(save(&r,sizeof r));
}
CAMLprim value mc_bls_g2_neg(value s) {
  CAMLparam1(s); blst_p2 p; load(&p,sizeof p,s); blst_p2_cneg(&p,1);
  CAMLreturn(save(&p,sizeof p));
}
CAMLprim value mc_bls_g2_mult(value s,value scalar) {
  CAMLparam2(s,scalar); CAMLlocal1(out);
  length(scalar,32); out=caml_alloc_string(sizeof(blst_p2));
  blst_p2 p,r; blst_scalar k; load(&p,sizeof p,s); blst_scalar_from_bendian(&k,IN(scalar));
  blst_p2_mult(&r,&p,k.b,255); memcpy(Bytes_val(out),&r,sizeof r);
  wipe(&k,sizeof k); wipe(&r,sizeof r); CAMLreturn(out);
}

CAMLprim value mc_bls_hash(value dst,value msg) {
  CAMLparam2(dst,msg); blst_p2 p;
  blst_hash_to_g2(&p,IN(msg),caml_string_length(msg),IN(dst),caml_string_length(dst),NULL,0);
  CAMLreturn(save(&p,sizeof p));
}
CAMLprim value mc_bls_pub(value scalar) {
  CAMLparam1(scalar); CAMLlocal1(out); length(scalar,32);
  out=caml_alloc_string(sizeof(blst_p1)); blst_scalar k; blst_p1 p;
  blst_scalar_from_bendian(&k,IN(scalar));
  if(!blst_sk_check(&k)) { wipe(&k,sizeof k); caml_invalid_argument("BLST: zero private key"); }
  blst_sk_to_pk_in_g1(&p,&k);
  memcpy(Bytes_val(out),&p,sizeof p); wipe(&k,sizeof k); CAMLreturn(out);
}
CAMLprim value mc_bls_sign(value scalar,value hash) {
  CAMLparam2(scalar,hash); CAMLlocal1(out); length(scalar,32);
  out=caml_alloc_string(sizeof(blst_p2)); blst_scalar k; blst_p2 p,h;
  load(&h,sizeof h,hash); blst_scalar_from_bendian(&k,IN(scalar));
  if(!blst_sk_check(&k)) { wipe(&k,sizeof k); caml_invalid_argument("BLST: zero private key"); }
  blst_sign_pk_in_g1(&p,&h,&k); memcpy(Bytes_val(out),&p,sizeof p);
  wipe(&k,sizeof k); CAMLreturn(out);
}
CAMLprim value mc_bls_miller(value q,value p) {
  CAMLparam2(q,p); blst_p1 x; blst_p2 y; blst_p1_affine a; blst_p2_affine b; blst_fp12 r;
  load(&x,sizeof x,p); load(&y,sizeof y,q);
  if(blst_p1_is_inf(&x) || blst_p2_is_inf(&y)) r=*blst_fp12_one();
  else { blst_p1_to_affine(&a,&x); blst_p2_to_affine(&b,&y); blst_miller_loop(&r,&b,&a); }
  CAMLreturn(save(&r,sizeof r));
}
CAMLprim value mc_bls_final(value v) {
  CAMLparam1(v); blst_fp12 p,r; load(&p,sizeof p,v); blst_final_exp(&r,&p); CAMLreturn(save(&r,sizeof r));
}
CAMLprim value mc_bls_gt_mul(value v,value w) {
  CAMLparam2(v,w); blst_fp12 p,q,r; load(&p,sizeof p,v); load(&q,sizeof q,w);
  blst_fp12_mul(&r,&p,&q); CAMLreturn(save(&r,sizeof r));
}
CAMLprim value mc_bls_gt_equal(value v,value w) {
  blst_fp12 p,q; load(&p,sizeof p,v); load(&q,sizeof q,w); return Val_bool(blst_fp12_is_equal(&p,&q));
}
CAMLprim value mc_bls_final_verify(value v,value w) {
  blst_fp12 p,q; load(&p,sizeof p,v); load(&q,sizeof q,w); return Val_bool(blst_fp12_finalverify(&p,&q));
}
