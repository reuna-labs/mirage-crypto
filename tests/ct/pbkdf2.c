#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include "pbkdf2/mc_pbkdf2.h"
#ifdef CTGRIND
#include <valgrind/memcheck.h>
#define SECRET(p,n) VALGRIND_MAKE_MEM_UNDEFINED(p,n)
#define PUBLIC(p,n) VALGRIND_MAKE_MEM_DEFINED(p,n)
#else
#define SECRET(p,n) ((void)0)
#define PUBLIC(p,n) ((void)0)
#endif
int main(void) {
  typedef void (*derive)(const uint8_t *,size_t,const uint8_t *,size_t,uint32_t,uint8_t *,size_t);
  derive functions[] = {mc_pbkdf2_sha1,mc_pbkdf2_sha256,mc_pbkdf2_sha512};
  const EVP_MD *hashes[] = {EVP_sha1(),EVP_sha256(),EVP_sha512()};
  const size_t lengths[] = {0,1,19,20,31,32,63,64,65,127,128,129,255};
  const unsigned rounds[] = {1,2,17,2048};
  unsigned char password[257], salt[257], out[258], ref[258];
  for (unsigned h=0;h<3;h++)
    for (unsigned p=0;p<sizeof lengths/sizeof *lengths;p++)
      for (unsigned r=0;r<sizeof rounds/sizeof *rounds;r++) {
        size_t plen=lengths[p], slen=lengths[(p+3)%13], olen=lengths[(p+7)%13]+1;
        for(size_t i=0;i<plen;i++) password[i+1]=(unsigned char)(i*31+r);
        for(size_t i=0;i<slen;i++) salt[i+1]=(unsigned char)(i*17+p);
        assert(PKCS5_PBKDF2_HMAC((const char *)password+1,(int)plen,salt+1,(int)slen,
                                 rounds[r],hashes[h],(int)olen,ref+1));
        memset(out,0xa5,sizeof out);
        SECRET(password+1,plen);
        functions[h](password+1,plen,salt+1,slen,rounds[r],out+1,olen);
        PUBLIC(password,sizeof password); PUBLIC(out,sizeof out);
        assert(out[0]==0xa5 && out[olen+1]==0xa5);
        assert(!memcmp(out+1,ref+1,olen));
      }
  puts("PBKDF2 SHA1/SHA256/SHA512: 156 OpenSSL differential cases passed.");
}
