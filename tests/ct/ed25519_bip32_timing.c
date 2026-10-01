/* Empirical fixed-vs-random Welch timing check, not a constant-time proof.
 * Public message, index and input lengths are identical between classes. */
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <math.h>
#include <time.h>
#include "ed25519-bip32/edb32.h"
static uint64_t state=UINT64_C(0x5487261a92d358bc);
static uint64_t random_word(void) { state^=state<<13;state^=state>>7;state^=state<<17;return state; }
static double now(void) { struct timespec t;clock_gettime(CLOCK_MONOTONIC,&t);return t.tv_sec*1e9+t.tv_nsec; }
struct stats {double mean,m2;unsigned n;};
static void add(struct stats *s,double x) { s->n++;double d=x-s->mean;s->mean+=d/s->n;s->m2+=d*(x-s->mean); }
int main(void) {
 const uint8_t msg[32]={0};uint8_t key[96],out[96];
 for(unsigned operation=0;operation<5;operation++) {
  struct stats s[2]={{0}};
  const unsigned count=operation==4?10000:40000;
  for(unsigned n=0;n<count+1000;n++) {
   unsigned cls=random_word()&1;
   for(unsigned i=0;i<96;i++) key[i]=cls?(uint8_t)random_word():(uint8_t)(i*13);
   key[0]&=248;key[31]=(key[31]&31)|64;
   double start=now();
   switch(operation) {
    case 0:mc_edb32_public(key,out);break;
    case 1:mc_edb32_sign(key,msg,sizeof msg,out);break;
    case 2:(void)mc_edb32_derive_private(key,7,out);break;
    case 3:(void)mc_edb32_derive_private(key,UINT32_C(0x80000007),out);break;
    case 4:mc_edb32_icarus(key,32,key+32,32,out);break;
   }
   double elapsed=now()-start;if(n>=1000)add(&s[cls],elapsed);
  }
  double t=(s[0].mean-s[1].mean)/sqrt(s[0].m2/(s[0].n-1)/s[0].n+s[1].m2/(s[1].n-1)/s[1].n);
  printf("%s: n=%u/%u mean_ns=%.0f/%.0f Welch_t=%.3f\n",
   (const char*[]){"public","sign","soft child","hard child","Icarus"}[operation],s[0].n,s[1].n,s[0].mean,s[1].mean,t);fflush(stdout);
 }
 return 0;
}
