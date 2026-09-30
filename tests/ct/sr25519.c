/* Compile with -DCTGRIND for Valgrind secret-flow checks, or sanitizers. */
#include <assert.h>
#include <string.h>
#ifdef CTGRIND
#include <valgrind/memcheck.h>
#define SECRET(p,n) VALGRIND_MAKE_MEM_UNDEFINED((p),(n))
#define PUBLIC(p,n) VALGRIND_MAKE_MEM_DEFINED((p),(n))
#else
#define SECRET(p,n) ((void)0)
#define PUBLIC(p,n) ((void)0)
#endif
#include "sr25519/sodium_config.h"
#include "crypto_core_ristretto255.h"
#include "utils.h"
#include "sr25519/ristretto_adapter.h"
#include "sha3.h"
int main(void) {
  unsigned char wide[64], s[32], t[32], q[32], p[32], out[32], state[200];
  for (unsigned round=0; round<16; round++) {
    for (unsigned i=0; i<64; i++) wide[i]=(unsigned char)(round*37+i*13);
    crypto_core_ristretto255_from_hash(p,wide); /* Public input point. */
    for (unsigned i=0; i<200; i++) state[i]=(unsigned char)(round+i);
    SECRET(state,200);
    digestif_sha3_permute(state);
    PUBLIC(state,200);
    SECRET(wide,64);
    crypto_core_ristretto255_scalar_reduce(s,wide);
    crypto_core_ristretto255_scalar_mul(t,s,s);
    crypto_core_ristretto255_scalar_add(q,t,s);
    mc_sr_mul_base(out,q);
    assert(mc_sr_mul(out,q,p)==0);
    memset(p,0,32); /* Identity is public. */
    assert(mc_sr_mul(out,q,p)==0);
    PUBLIC(out,32);
    assert(sodium_is_zero(out,32));
    memset(s,0,32);
    SECRET(s,32); /* Exercise zero selection without declassifying the scalar. */
    mc_sr_mul_base(out,s);
    assert(mc_sr_mul(out,s,p)==0);
    PUBLIC(out,32);
    assert(sodium_is_zero(out,32));
    PUBLIC(wide,64); PUBLIC(s,32); PUBLIC(t,32); PUBLIC(q,32);
  }
  memset(p,255,32); memset(out,42,32);
  assert(mc_sr_mul(out,s,p)==-1);
  for(unsigned i=0;i<32;i++) assert(out[i]==42);
  return 0;
}
