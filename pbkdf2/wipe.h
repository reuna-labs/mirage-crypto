#ifndef MC_PBKDF2_WIPE_H
#define MC_PBKDF2_WIPE_H
#include <stddef.h>
static void mc_pbkdf2_wipe(void *p,size_t n) {
  volatile unsigned char *q=p; while(n--) *q++=0;
}
#endif
