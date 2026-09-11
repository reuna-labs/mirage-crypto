/*
 * Copyright (c) 2015-2016 David Kaloper Meršinjak
 */

#define _POSIX_C_SOURCE 199309L

#include <caml/mlvalues.h>

#include "mirage_crypto.h"

#if defined (__i386__) || defined (__x86_64__)
#include <x86intrin.h>

#if defined (__x86_64__)
#define random_t unsigned long long
#define _rdseed_step _rdseed64_step
#define _rdrand_step _rdrand64_step
#define fill_bytes(buf, bufsz, off, data) memcpy(_bp_uint8_off(buf, off), data, 8)

#elif defined (__i386__)
#define random_t unsigned int
#define _rdseed_step _rdseed32_step
#define _rdrand_step _rdrand32_step
#define fill_bytes(buf, bufsz, off, data) memcpy(_bp_uint8_off(buf, off), data, 4)

#endif
#endif /* __i386__ || __x86_64__ */

/* mc_cycle_counter specification and requirements

   Below the function mc_cycle_counter is defined (with different
   implementations on different platforms. Its lower 32 bits are used for
   entropy collection on every entry to the main event loop.

   The requirement for this function is that every call to it (from OCaml)
   should lead to a different output (in the lower 32 bits), and it should be
   unpredictable (since the timestamp / cpu cycle counter is fine-grained
   enough).

   The executable test/test_entropy.ml tests parts of the requirements by
   calling mc_cycle_counter 10 times and comparing the output to the previous
   output.
*/

#if defined (_MSC_VER)
#include <immintrin.h>
#include <memory.h>

#if defined (_WIN64)
#define random_t unsigned long long
#define _rdseed_step _rdseed64_step
#define _rdrand_step _rdrand64_step
#define fill_bytes(buf, bufsz, off, data) memcpy_s(_bp_uint8_off(buf, off), bufsz, data, 8)

#elif defined (_WIN32)
#define random_t unsigned int
#define _rdseed_step _rdseed32_step
#define _rdrand_step _rdrand32_step
#define fill_bytes(buf, bufsz, off, data) memcpy_s(_bp_uint8_off(buf, off), bufsz, data, 4)
#endif

#endif /* _MSC_VER */

#if defined (__arm__)
/*
 * The ideal timing source on ARM are the performance counters, but these are
 * presently masked by Xen.
 * It would work like this:

#if defined (__ARM_ARCH_7A__)
  // Disable counter overflow interrupts.
  __asm__ __volatile__ ("mcr p15, 0, %0, c9, c14, 2" :: "r"(0x8000000f));
  // Program the PMU control register.
  __asm__ __volatile__ ("mcr p15, 0, %0, c9, c12, 0" :: "r"(1 | 16));
  // Enable all counters.
  __asm__ __volatile__ ("mcr p15, 0, %0, c9, c12, 1" :: "r"(0x8000000f));

  // Read:
  unsigned int res;
  __asm__ __volatile__ ("mrc p15, 0, %0, c9, c13, 0": "=r" (res));
*/
#if defined(__ocaml_freestanding__) || defined(__ocaml_solo5__)
static inline uint32_t read_virtual_count (void)
{
  uint32_t c_lo, c_hi;
  __asm__ __volatile__("mrrc p15, 1, %0, %1, c14":"=r"(c_lo), "=r"(c_hi));
  return c_lo;
}
#else
/* see https://github.com/mirage/mirage-crypto/issues/113 and
https://chromium.googlesource.com/external/gperftools/+/master/src/base/cycleclock.h
   The performance counters are only available in kernel mode (or if enabled via
   a kernel module also in user mode). Use clock_gettime as fallback.
 */
#include <time.h>
static inline uint32_t read_virtual_count (void)
{
  uint32_t pmccntr;
  uint32_t pmuseren;
  uint32_t pmcntenset;
  // Read the user mode perf monitor counter access permissions.
  __asm__ __volatile__ ("mrc p15, 0, %0, c9, c14, 0" : "=r" (pmuseren));
  if (pmuseren & 1) {  // Allows reading perfmon counters for user mode code.
    __asm__ __volatile__ ("mrc p15, 0, %0, c9, c12, 1" : "=r" (pmcntenset));
    if (pmcntenset & 0x80000000ul) {  // Is it counting?
      __asm__ __volatile__ ("mrc p15, 0, %0, c9, c13, 0" : "=r" (pmccntr));
      // The counter is set up to count every 64th cycle
      return pmccntr;
    }
  }
  struct timespec now;
  clock_gettime (CLOCK_MONOTONIC, &now);
  return now.tv_nsec;
}
#endif /* __ocaml_freestanding__ || __ocaml_solo5__ */
#endif /* arm */

#if defined (__aarch64__)
#define	isb() __asm__ __volatile__("isb" : : : "memory")
static inline uint64_t read_virtual_count(void)
{
  uint64_t c;
  isb();
  __asm__ __volatile__("mrs %0, cntvct_el0":"=r"(c));
  return c;
}
#endif /* aarch64 */

#if defined (__powerpc64__) || defined(__POWERPC__)
/* from clang's builtin version and gperftools at
https://chromium.googlesource.com/external/gperftools/+/master/src/base/cycleclock.h
*/
static inline uint64_t read_cycle_counter(void)
{
  uint64_t rval;
  __asm__ __volatile__ ("mfspr %0, 268":"=r" (rval));
  return rval;
}
#endif

#if defined (__riscv) && (64 == __riscv_xlen)
//since rdcycle is a privileged instruction since linux 6.6, we use rdtime when in user-space
static inline uint64_t cycle_count(void)
{
  uint64_t rval;
#if defined(__ocaml_freestanding__) || defined(__ocaml_solo5__)
  __asm__ __volatile__ ("rdcycle %0" : "=r" (rval));
#else
  __asm__ __volatile__ ("rdtime %0" : "=r" (rval));
#endif /* __ocaml_freestanding__ || __ocaml_solo5__ */
  return rval;
}
#endif

#if defined (__s390x__)
static inline uint64_t getticks(void)
{
  uint64_t rval;
  __asm__ __volatile__ ("stck %0" : "=Q" (rval) : : "cc");
  return rval;
}
#endif

#if defined (__mips__)
static inline unsigned long get_count(void) {
  unsigned long count;
  __asm__ __volatile__ ("rdhwr %[rt], $2" : [rt] "=d" (count));
  return count;
}
#endif

#if defined (__loongarch_lp64)
static inline unsigned long get_count(void) {
  unsigned long count;
  __asm__ __volatile__ ("rdtime.d %0, $zero\n" : "=r" (count));

  return count;
}
#endif

static inline uint64_t mc_read_counter (void) {
#if defined (__i386__) || defined (__x86_64__) || defined (_MSC_VER)
  return __rdtsc ();
#elif defined (__arm__) || defined (__aarch64__)
  return read_virtual_count ();
#elif defined(__powerpc64__) || defined(__POWERPC__)
  return read_cycle_counter ();
#elif defined(__riscv) && (64 == __riscv_xlen)
  return cycle_count ();
#elif defined (__s390x__)
  return getticks ();
#elif defined(__mips__)
  return get_count();
#elif defined(__loongarch_lp64)
  return get_count();
#else
#error ("No known cycle-counting instruction.")
#endif
}

/* MC_COUNTER_SPINS bounds the wait for the counter to advance. See
   mc_cycle_counter below for why there is a wait at all.

   It has to cover one tick of the coarsest counter we are willing to call
   working. A read costs on the order of 20ns (an isb plus an mrs on aarch64),
   so 1024 covers a tick of roughly 20us, i.e. a counter down to ~50kHz. Well
   under that and the source is not a timing source; the loop gives up, returns
   a repeated value, and rng/entropy_test.ml says so. Bounding it is the point:
   a counter that is genuinely stuck must still terminate. */
#define MC_COUNTER_SPINS 1024

CAMLprim value mc_cycle_counter (value __unused(unit)) {
  /* Return a value the PREVIOUS call cannot have returned.
     
     The contract stated at the top of this file is that every call yields a
     different result in the low 32 bits. On x86 that is free: __rdtsc has
     single-cycle resolution and two back-to-back reads always differ. On
     aarch64 it is not. read_virtual_count reads CNTVCT_EL0, which is the
     GENERIC TIMER and not a cycle counter, and on Apple silicon that counter
     advances in steps of ~41.7ns while CNTFRQ_EL0 reports 1GHz -- a 24MHz
     counter scaled by 1e9/24e6 = 41.67. Measured on an M-series host, three
     reads in four return the value their predecessor did.

     The visible effect was a MirageOS unikernel dying at boot, in the self-test
     that exists to catch exactly this:

         Fatal error: exception Failure("same data from timer at 3 with: ...")

     at an index that moved between runs, because whether a given iteration
     straddled a tick boundary was a race with the OCaml allocation in
     Entropy.interrupt_hook. Common arm64 server parts run the same timer at
     24 or 25MHz, so this is not specific to Apple or to Solo5; it is specific
     to using the generic timer as if it were a cycle counter.

     So: remember what was returned, and wait only when the counter has not
     moved since. That distinction matters. The self-test calls this in a tight
     loop and does need to wait; real use calls it once per entry to the event
     loop, which on a busy unikernel is far more often than once per 41.7ns
     tick, and there it must not. Waiting unconditionally -- two reads and a
     spin until they differ -- is simpler and needs no state, but it costs a
     full tick on EVERY call: measured at 46.6ns against ~20ns for a bare read,
     which a loop entered a million times a second would feel.

     mc_last is deliberately unsynchronised. It is read and written without a
     lock, and [@@noalloc] means OCaml domains can be in here at once. An
     aligned 64-bit load or store does not tear on any target this builds for,
     so the worst a race costs is one spin that was not needed or one repeated
     value in an entropy pool -- neither of which is worth an atomic on a path
     this hot. The self-test runs at boot in one domain and is unaffected. */
  static uint64_t mc_last;
  uint64_t c = mc_read_counter ();
  for (int i = 0; c == mc_last && i < MC_COUNTER_SPINS; i++)
    c = mc_read_counter ();
  mc_last = c;
  return Val_long (c);
}

/* end of mc_cycle_counter */

enum cpu_rng_t {
  RNG_NONE   = 0,
  RNG_RDRAND = 1,
  RNG_RDSEED = 2,
};

static int __cpu_rng = RNG_NONE;

static void detect (void) {
#ifdef __mc_ENTROPY__
  random_t r = 0;

  if (mc_detected_cpu_features.rdrand)
    /* AMD Ryzen 3000 bug where RDRAND always returns -1
       https://arstechnica.com/gadgets/2019/10/how-a-months-old-amd-microcode-bug-destroyed-my-weekend/ */
    for (int i = 0; i < 10; i++)
      if (_rdrand_step(&r) == 1 && r != (random_t) (-1)) {
        __cpu_rng = RNG_RDRAND;
        break;
      }

  if (mc_detected_cpu_features.rdseed)
    /* RDSEED could return -1, thus we test it here
       https://www.reddit.com/r/Amd/comments/cmza34/agesa_1003_abb_fixes_rdrandrdseed/ */
    for (int i = 0; i < 100; i++)
      if (_rdseed_step(&r) == 1 && r != (random_t) (-1)) {
        __cpu_rng |= RNG_RDSEED;
        break;
      }
#endif
}

CAMLprim value mc_cpu_rdseed (value buf, value off) {
#ifdef __mc_ENTROPY__
  random_t r = 0;
  int ok = 0;
  int i = 100;
  do { ok = _rdseed_step (&r); _mm_pause (); } while ( !(ok | !--i) );
  fill_bytes(buf, sizeof(r), off, &r);
  return Val_bool (ok);
#else
  /* ARM: CPU-assisted randomness here. */
  (void)buf;
  (void)off;
  return Val_false;
#endif
}

CAMLprim value mc_cpu_rdrand (value buf, value off) {
#ifdef __mc_ENTROPY__
  random_t r = 0;
  int ok = 0;
  int i = 10;
  do { ok = _rdrand_step (&r); } while ( !(ok | !--i) );
  fill_bytes(buf, sizeof(r), off, &r);
  return Val_bool (ok);
#else
  /* ARM: CPU-assisted randomness here. */
  (void)buf;
  (void)off;
  return Val_false;
#endif
}

CAMLprim value mc_cpu_rng_type (value __unused(unit)) {
  return Val_int (__cpu_rng);
}

CAMLprim value mc_entropy_detect (value __unused(unit)) {
  detect ();
  return Val_unit;
}
