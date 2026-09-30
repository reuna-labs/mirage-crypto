/* ISC. Allocate before borrowing OCaml pointers; hold the runtime lock. */
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include "sodium_config.h"
#include "crypto_core_ristretto255.h"
#include "private/ed25519_ref10.h"
#include "utils.h"
#include "ristretto_adapter.h"
#define IN(v) ((const unsigned char *)String_val(v))
#define OUT(v) ((unsigned char *)Bytes_val(v))
static void length(value v, size_t n) {
  if (caml_string_length(v) != n) caml_invalid_argument("Sr25519: buffer length");
}
CAMLprim value mc_sr_scalar_valid(value s) {
  length(s,32); return Val_bool(sc25519_is_canonical(IN(s)));
}
CAMLprim value mc_sr_scalar_reduce(value wide) {
  CAMLparam1(wide); CAMLlocal1(out); length(wide,64); out=caml_alloc_string(32);
  crypto_core_ristretto255_scalar_reduce(OUT(out),IN(wide)); CAMLreturn(out);
}
CAMLprim value mc_sr_scalar_add(value a, value b) {
  CAMLparam2(a,b); CAMLlocal1(out); length(a,32); length(b,32); out=caml_alloc_string(32);
  crypto_core_ristretto255_scalar_add(OUT(out),IN(a),IN(b)); CAMLreturn(out);
}
CAMLprim value mc_sr_scalar_mul(value a, value b) {
  CAMLparam2(a,b); CAMLlocal1(out); length(a,32); length(b,32); out=caml_alloc_string(32);
  crypto_core_ristretto255_scalar_mul(OUT(out),IN(a),IN(b)); CAMLreturn(out);
}
CAMLprim value mc_sr_point_valid(value p) {
  length(p,32); return Val_bool(crypto_core_ristretto255_is_valid_point(IN(p)));
}
CAMLprim value mc_sr_from_uniform(value wide) {
  CAMLparam1(wide); CAMLlocal1(out); length(wide,64); out=caml_alloc_string(32);
  crypto_core_ristretto255_from_hash(OUT(out),IN(wide)); CAMLreturn(out);
}
CAMLprim value mc_sr_point_base(value s) {
  CAMLparam1(s); CAMLlocal1(out); length(s,32); out=caml_alloc_string(32);
  mc_sr_mul_base(OUT(out),IN(s)); CAMLreturn(out);
}
CAMLprim value mc_sr_point_mul(value s,value p) {
  CAMLparam2(s,p); CAMLlocal1(out); length(s,32); length(p,32); out=caml_alloc_string(32);
  if (mc_sr_mul(OUT(out),IN(s),IN(p))) caml_invalid_argument("Sr25519: invalid point");
  CAMLreturn(out);
}
CAMLprim value mc_sr_point_sub(value p,value q) {
  CAMLparam2(p,q); CAMLlocal1(out); length(p,32); length(q,32); out=caml_alloc_string(32);
  if (crypto_core_ristretto255_sub(OUT(out),IN(p),IN(q))) caml_invalid_argument("Sr25519: invalid point");
  CAMLreturn(out);
}
