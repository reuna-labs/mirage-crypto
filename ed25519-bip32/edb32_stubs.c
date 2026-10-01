#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include "edb32.h"
#define IN(v) ((const uint8_t *)String_val(v))
#define OUT(v) ((uint8_t *)Bytes_val(v))
static void length(value v,size_t n) { if(caml_string_length(v)!=n) caml_invalid_argument("Ed25519_bip32: length"); }
CAMLprim value mc_edb32_priv_valid_stub(value key) { length(key,96); return Val_bool(mc_edb32_private_valid(IN(key))); }
CAMLprim value mc_edb32_pub_valid_stub(value key) { length(key,32); return Val_bool(mc_edb32_public_valid(IN(key))); }
CAMLprim value mc_edb32_root_stub(value hash,value cc) {
  CAMLparam2(hash,cc); CAMLlocal1(out); length(hash,64); length(cc,32); out=caml_alloc_string(96);
  if(!mc_edb32_root(IN(hash),IN(cc),OUT(out))) CAMLreturn(caml_copy_string("")); CAMLreturn(out);
}
CAMLprim value mc_edb32_public_stub(value key) {
  CAMLparam1(key); CAMLlocal1(out); length(key,96); out=caml_alloc_string(64);
  mc_edb32_public(IN(key),OUT(out)); CAMLreturn(out);
}
CAMLprim value mc_edb32_derive_priv_stub(value key,value index) {
  CAMLparam2(key,index); CAMLlocal1(out); length(key,96); out=caml_alloc_string(96);
  if(!mc_edb32_derive_private(IN(key),(uint32_t)Int32_val(index),OUT(out))) CAMLreturn(caml_copy_string("")); CAMLreturn(out);
}
CAMLprim value mc_edb32_derive_pub_stub(value key,value index) {
  CAMLparam2(key,index); CAMLlocal1(out); length(key,64); out=caml_alloc_string(64);
  if(!mc_edb32_derive_public(IN(key),(uint32_t)Int32_val(index),OUT(out))) CAMLreturn(caml_copy_string("")); CAMLreturn(out);
}
CAMLprim value mc_edb32_sign_stub(value key,value msg) {
  CAMLparam2(key,msg); CAMLlocal1(out); length(key,96); out=caml_alloc_string(64);
  mc_edb32_sign(IN(key),IN(msg),caml_string_length(msg),OUT(out)); CAMLreturn(out);
}
CAMLprim value mc_edb32_verify_stub(value key,value sig,value msg) {
  length(key,32); length(sig,64);
  return Val_bool(mc_edb32_verify(IN(key),IN(sig),IN(msg),caml_string_length(msg)));
}
CAMLprim value mc_edb32_icarus_stub(value entropy,value pass) {
  CAMLparam2(entropy,pass); CAMLlocal1(out); out=caml_alloc_string(96);
  mc_edb32_icarus(IN(entropy),caml_string_length(entropy),IN(pass),caml_string_length(pass),OUT(out)); CAMLreturn(out);
}
