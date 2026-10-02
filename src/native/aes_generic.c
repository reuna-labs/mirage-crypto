/* ISC; portable AES uses the selected BearSSL bitsliced kernel. */
#include "mirage_crypto.h"
#include "portable_crypto.h"

CAMLprim value mc_aes_rk_size_generic(value rounds) {
  return Val_int((Int_val(rounds) + 1) * 16);
}

CAMLprim value mc_aes_derive_e_key_generic(value key, value rk, value rounds) {
  mc_aes_ct_derive(_st_uint8(key), _bp_uint8(rk), Int_val(rounds));
  return Val_unit;
}

CAMLprim value mc_aes_derive_d_key_generic(value key, value kr, value rounds, value rk) {
  /* BearSSL encryption and decryption use the same compressed schedule. */
  if (Is_block(rk))
    memcpy(_bp_uint8(kr), _st_uint8(Field(rk, 0)), (Int_val(rounds) + 1) * 16);
  else
    mc_aes_ct_derive(_st_uint8(key), _bp_uint8(kr), Int_val(rounds));
  return Val_unit;
}

CAMLprim value mc_aes_enc_generic(value src, value off1, value dst, value off2,
                                 value rk, value rounds, value blocks) {
  mc_aes_ct_blocks(_st_uint8_off(src, off1), _bp_uint8_off(dst, off2),
                  _st_uint8(rk), Int_val(rounds), Int_val(blocks), 0);
  return Val_unit;
}

CAMLprim value mc_aes_dec_generic(value src, value off1, value dst, value off2,
                                 value rk, value rounds, value blocks) {
  mc_aes_ct_blocks(_st_uint8_off(src, off1), _bp_uint8_off(dst, off2),
                  _st_uint8(rk), Int_val(rounds), Int_val(blocks), 1);
  return Val_unit;
}
