/* Fixed portable configuration for this selected, namespaced source build.
 * No RNG, CPU dispatch, allocator, weak-symbol helpers, or OS support. */
#define CONFIGURED 1
#define SODIUM_STATIC 1
#if defined(__SIZEOF_INT128__) && !defined(MC_SR_FORCE_32BIT)
#define HAVE_TI_MODE 1
#endif
#include "sodium_namespace.h"

/* Solo5 maps malloc to its allocator with a macro. Keep that macro out of
 * upstream's unused __attribute__((malloc)) declarations, then restore it. */
#ifdef malloc
#pragma push_macro("malloc")
#undef malloc
#include "utils.h"
#pragma pop_macro("malloc")
#endif
