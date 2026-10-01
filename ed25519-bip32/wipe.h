#ifndef MC_EDB32_WIPE_H
#define MC_EDB32_WIPE_H
#include <stddef.h>
static void mc_edb32_wipe(void *p,size_t n) {
  volatile unsigned char *q=p; while(n--) *q++=0;
}
#endif
