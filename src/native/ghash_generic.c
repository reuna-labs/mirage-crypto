/* ISC; table-free GHASH on every portable target. */
#include "mirage_crypto.h"
#include "portable_crypto.h"

CAMLprim value mc_ghash_key_size_generic(__unit()) {
  return Val_int(16);
}

CAMLprim value mc_ghash_init_key_generic(value key, value m) {
  memcpy(_bp_uint8(m), _st_uint8(key), 16);
  return Val_unit;
}

CAMLprim value mc_ghash_generic(value m, value hash, value src, value off, value len) {
  mc_ghash_ct(_bp_uint8(hash), _st_uint8(m), _st_uint8_off(src, off), Int_val(len));
  return Val_unit;
}
