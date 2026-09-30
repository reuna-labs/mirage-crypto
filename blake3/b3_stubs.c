#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include "vendor/c/blake3.h"

/* ISC. Allocation precedes taking pointers into OCaml values. */
CAMLprim value mc_blake3(value mode,value param,value msg,value len) {
  CAMLparam4(mode,param,msg,len); CAMLlocal1(out);
  intnat n=Long_val(len); int m=Int_val(mode);
  if(n<1 || m<0 || m>2) caml_invalid_argument("Blake3: invalid argument");
  if(m==1 && caml_string_length(param)!=32) caml_invalid_argument("Blake3: key length");
  out=caml_alloc_string(n);
  blake3_hasher h;
  if(m==0) blake3_hasher_init(&h);
  else if(m==1) blake3_hasher_init_keyed(&h,(const uint8_t *)String_val(param));
  else blake3_hasher_init_derive_key_raw(&h,String_val(param),caml_string_length(param));
  blake3_hasher_update(&h,String_val(msg),caml_string_length(msg));
  blake3_hasher_finalize(&h,(uint8_t *)Bytes_val(out),n);
  volatile unsigned char *p=(volatile unsigned char *)&h;
  for(size_t i=0;i<sizeof h;i++) p[i]=0;
  CAMLreturn(out);
}
