/* ISC. Dynamic secret-taint checks; run under Valgrind, not a timing proof. */
#include <string.h>
#include <valgrind/memcheck.h>
#include "bls12-381/vendor/bindings/blst.h"
#include "blake3/vendor/c/blake3.h"
#include "poseidon/poseidon_namespace.h"
#include "poseidon/vendor/sources/poseidon.h"
int main(void) {
  if (!RUNNING_ON_VALGRIND) return 77;
  unsigned char key[32]={1}, msg[64]={2}, out[131];
  blst_scalar sk; blst_p1 pk; blst_p2 h,sig;
  static const unsigned char dst[]="BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
  blst_hash_to_g2(&h,msg,sizeof msg,dst,sizeof(dst)-1,NULL,0);
  VALGRIND_MAKE_MEM_UNDEFINED(key,sizeof key);
  blst_scalar_from_bendian(&sk,key);
  blst_sk_to_pk_in_g1(&pk,&sk);
  blst_sign_pk_in_g1(&sig,&h,&sk);
  VALGRIND_MAKE_MEM_DEFINED(&pk,sizeof pk);
  VALGRIND_MAKE_MEM_DEFINED(&sig,sizeof sig);
  blake3_hasher b;
  VALGRIND_MAKE_MEM_UNDEFINED(msg,sizeof msg);
  blake3_hasher_init_keyed(&b,key);
  blake3_hasher_update(&b,msg,sizeof msg);
  blake3_hasher_finalize(&b,out,sizeof out);
  VALGRIND_MAKE_MEM_DEFINED(out,sizeof out);
  felt_t state[3]={{1},{2},{2}};
  VALGRIND_MAKE_MEM_UNDEFINED(state,sizeof state);
  permutation_3(state);
  VALGRIND_MAKE_MEM_DEFINED(state,sizeof state);
  return 0;
}
