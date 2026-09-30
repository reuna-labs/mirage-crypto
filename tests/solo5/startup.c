/* ISC. Same startup sequence as ocaml-solo5's example. */
#include <solo5.h>
#define CAML_NAME_SPACE
#include <caml/callback.h>
void _nolibc_init(uintptr_t, size_t);
int solo5_app_main(const struct solo5_start_info *si) {
  char *argv[] = { "backend-smoke", NULL };
  _nolibc_init(si->heap_start, si->heap_size);
  caml_startup(argv);
  return 0;
}
