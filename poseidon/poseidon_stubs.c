/* ISC. StarkWare width-3 sponge over the upstream ISO C permutation. */
#include <string.h>
#include <caml/mlvalues.h>
#include <caml/memory.h>
#include <caml/alloc.h>
#include <caml/fail.h>
#include "poseidon_namespace.h"
#include "vendor/sources/poseidon.h"
static void decode(felt_t f,const unsigned char *s) {
  for(int i=0;i<4;i++) { uint64_t x=0; for(int j=0;j<8;j++) x=(x<<8)|s[(3-i)*8+j]; f[i]=x; }
}
static void encode(unsigned char *s,const felt_t f) {
  for(int i=0;i<4;i++) for(int j=0;j<8;j++) s[31-i*8-j]=(unsigned char)(f[i]>>(8*j));
}
CAMLprim value mc_poseidon_valid(value input) {
  if(caml_string_length(input)!=32) caml_invalid_argument("Poseidon: field length");
  static const unsigned char p[32]={8,0,0,0,0,0,0,17,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1};
  const unsigned char *s=(const unsigned char *)String_val(input); unsigned borrow=0;
  for(int i=31;i>=0;i--) { unsigned t=256u+s[i]-p[i]-borrow; borrow=1u-(t>>8); }
  return Val_bool(borrow);
}
CAMLprim value mc_poseidon_hash(value mode,value input) {
  CAMLparam2(mode,input); CAMLlocal1(out);
  size_t len=caml_string_length(input); int m=Int_val(mode);
  if((m==1 && len!=32) || (m==2 && len!=64) || (m==0 && len%32!=0) || m<0 || m>2)
    caml_invalid_argument("Poseidon: input length");
  out=caml_alloc_string(32);
  const unsigned char *s=(const unsigned char *)String_val(input);
  felt_t state[3]={{0}}, x={0};
  if(m!=0) {
    decode(state[0],s); if(m==2) decode(state[1],s+32);
    state[2][0]=(uint64_t)m; permutation_3(state);
  } else {
    size_t count=len/32, i=0;
    for(;i+1<count;i+=2) {
      decode(x,s+i*32); f251_add(state[0],state[0],x);
      decode(x,s+(i+1)*32); f251_add(state[1],state[1],x);
      permutation_3(state);
    }
    if(i<count) { decode(x,s+i*32); f251_add(state[0],state[0],x); }
    memset(x,0,sizeof x); x[0]=1;
    f251_add(state[i<count?1:0],state[i<count?1:0],x);
    permutation_3(state);
  }
  encode((unsigned char *)Bytes_val(out),state[0]);
  volatile unsigned char *p=(volatile unsigned char *)state;
  for(size_t i=0;i<sizeof state;i++) p[i]=0;
  p=(volatile unsigned char *)x; for(size_t i=0;i<sizeof x;i++) p[i]=0;
  CAMLreturn(out);
}
