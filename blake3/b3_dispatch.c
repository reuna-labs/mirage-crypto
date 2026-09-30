#include "vendor/c/blake3_impl.h"
/* Every SIMD backend is disabled. Suppress the upstream x86 feature probe
 * as well: portable Solo5 builds must not execute CPUID/XGETBV. */
#undef IS_X86
#include "vendor/c/blake3_dispatch.c"
