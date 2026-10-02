/* Portable fallback KATs, differential and secret-taint boundary checks.
 * OpenSSL is a test-only oracle; production has no OpenSSL dependency. */
#include <assert.h>
#include <stdio.h>
#include <string.h>
#include "src/native/portable_crypto.h"
#ifdef CTGRIND
#include <valgrind/memcheck.h>
#define SECRET(p,n) VALGRIND_MAKE_MEM_UNDEFINED(p,n)
#define PUBLIC(p,n) VALGRIND_MAKE_MEM_DEFINED(p,n)
#else
#define SECRET(p,n) ((void)0)
#define PUBLIC(p,n) ((void)0)
#endif
#ifdef HAVE_OPENSSL
#include <openssl/evp.h>
static void reference_aes(const unsigned char *key, int bits,
                          const unsigned char *in, unsigned char *out, int len) {
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  const EVP_CIPHER *cipher = bits == 128 ? EVP_aes_128_ecb() :
                            bits == 192 ? EVP_aes_192_ecb() : EVP_aes_256_ecb();
  int written, tail;
  assert(ctx && EVP_EncryptInit_ex(ctx, cipher, NULL, key, NULL));
  assert(EVP_CIPHER_CTX_set_padding(ctx, 0));
  assert(EVP_EncryptUpdate(ctx, out, &written, in, len));
  assert(EVP_EncryptFinal_ex(ctx, out + written, &tail));
  assert(written + tail == len);
  EVP_CIPHER_CTX_free(ctx);
}
#endif

/* Intentionally simple, variable-time bitwise GHASH oracle, test-only. */
static void reference_ghash(unsigned char y[16], const unsigned char h[16],
                            const unsigned char *data, size_t len) {
  while (len) {
    size_t n = len > 16 ? 16 : len;
    unsigned char v[16], z[16] = {0};
    for (size_t i = 0; i < n; i++) y[i] ^= data[i];
    memcpy(v, h, 16);
    for (unsigned bit = 0; bit < 128; bit++) {
      if ((y[bit / 8] >> (7 - bit % 8)) & 1)
        for (unsigned j = 0; j < 16; j++) z[j] ^= v[j];
      unsigned carry = v[15] & 1;
      for (unsigned j = 15; j > 0; j--) v[j] = (v[j] >> 1) | (v[j-1] << 7);
      v[0] >>= 1;
      if (carry) v[0] ^= 0xe1;
    }
    memcpy(y, z, 16);
    data += n; len -= n;
  }
}

int main(void) {
  static const unsigned char plaintext[16] = {
    0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,0x88,0x99,0xaa,0xbb,0xcc,0xdd,0xee,0xff};
  static const unsigned char ciphertext[3][16] = {
    {0x69,0xc4,0xe0,0xd8,0x6a,0x7b,0x04,0x30,0xd8,0xcd,0xb7,0x80,0x70,0xb4,0xc5,0x5a},
    {0xdd,0xa9,0x7c,0xa4,0x86,0x4c,0xdf,0xe0,0x6e,0xaf,0x70,0xa0,0xec,0x0d,0x71,0x91},
    {0x8e,0xa2,0xb7,0xca,0x51,0x67,0x45,0xbf,0xea,0xfc,0x49,0x90,0x4b,0x49,0x60,0x89}};
  unsigned char key[33], schedule[241], input[16*33+2], output[16*33+2], ref[16*33+2];
  for (unsigned k = 0; k < 3; k++) {
    for (unsigned i = 0; i < 32; i++) key[i+1] = i;
    SECRET(key+1, 16+8*k);
    mc_aes_ct_derive(key+1, schedule+1, 10+2*k);
    mc_aes_ct_blocks(plaintext, output, schedule+1, 10+2*k, 1, 0);
    PUBLIC(output,16);
    assert(!memcmp(output,ciphertext[k],16));
    mc_aes_ct_blocks(ciphertext[k], output, schedule+1, 10+2*k, 1, 1);
    PUBLIC(output,16);
    assert(!memcmp(output,plaintext,16));
    PUBLIC(key,sizeof key); PUBLIC(schedule,sizeof schedule);
    for (unsigned n = 0; n <= 33; n++) {
      size_t len = 16*n;
      for (unsigned i = 0; i < 32; i++) key[i+1] = i*17+n*31+k;
      for (size_t i = 0; i < len; i++) input[i+1] = i*11+n;
#ifdef HAVE_OPENSSL
      reference_aes(key+1,128+64*k,input+1,ref+1,(int)len);
#endif
      memset(output,0xa5,sizeof output);
      SECRET(key+1,16+8*k); SECRET(input+1,len);
      mc_aes_ct_derive(key+1,schedule+1,10+2*k);
      mc_aes_ct_blocks(input+1,output+1,schedule+1,10+2*k,n,0);
      PUBLIC(output,sizeof output);
      assert(output[0]==0xa5 && output[len+1]==0xa5);
#ifdef HAVE_OPENSSL
      assert(!memcmp(output+1,ref+1,len));
#endif
      SECRET(output+1,len);
      mc_aes_ct_blocks(output+1,output+1,schedule+1,10+2*k,n,1);
      PUBLIC(output,sizeof output); PUBLIC(input,sizeof input);
      assert(!memcmp(output+1,input+1,len));
      assert(output[0]==0xa5 && output[len+1]==0xa5);
      PUBLIC(key,sizeof key); PUBLIC(schedule,sizeof schedule);
    }
  }
  for (size_t len = 0; len <= 257; len++) {
    for (unsigned i=0;i<16;i++) { key[i+1]=i*7+len; output[i+1]=ref[i+1]=i*23; }
    for (size_t i=0;i<len;i++) input[i+1]=i*13+len;
    reference_ghash(ref+1,key+1,input+1,len);
    SECRET(key+1,16); SECRET(output+1,16); SECRET(input+1,len);
    mc_ghash_ct(output+1,key+1,input+1,len);
    PUBLIC(output,sizeof output);
    assert(!memcmp(output+1,ref+1,16));
    PUBLIC(key,sizeof key); PUBLIC(input,sizeof input);
  }
  puts("Portable AES/GHASH vectors, boundaries and differential checks passed.");
  return 0;
}
