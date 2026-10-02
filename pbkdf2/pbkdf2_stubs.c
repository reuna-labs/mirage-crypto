#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include "mc_pbkdf2.h"

CAMLprim value mc_pbkdf2_derive(value hash,value password,value salt,
                               value iterations,value size) {
  CAMLparam5(hash,password,salt,iterations,size);
  CAMLlocal1(out);
  intnat count=Long_val(iterations), len=Long_val(size), which=Long_val(hash);
  if(count < 1 || (uint64_t)count > UINT32_MAX)
    caml_invalid_argument("PBKDF2: iterations must be in [1, 2^32-1]");
  if(len < 0 || (uint64_t)len > UINT32_MAX-63 || (uintnat)len > Bsize_wsize(Max_wosize)-1)
    caml_invalid_argument("PBKDF2: output length out of range");
  if(which < 0 || which > 2) caml_invalid_argument("PBKDF2: hash");
  out=caml_alloc_string(len);
  if(len) {
    void (*derive)(const uint8_t *,size_t,const uint8_t *,size_t,uint32_t,uint8_t *,size_t)
      = which == 0 ? mc_pbkdf2_sha1 : which == 1 ? mc_pbkdf2_sha256 : mc_pbkdf2_sha512;
    derive((const uint8_t *)String_val(password),caml_string_length(password),
           (const uint8_t *)String_val(salt),caml_string_length(salt),(uint32_t)count,
           (uint8_t *)Bytes_val(out),(size_t)len);
  }
  CAMLreturn(out);
}
