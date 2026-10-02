/* ISC. Adapt the selected reference code to the installed Digestif C API.
 * Link digestif.c from the exact release that supplies this header. */
#ifndef MC_PBKDF2_SHA512_ADAPTER_H
#define MC_PBKDF2_SHA512_ADAPTER_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "wipe.h"
#include <digestif_sha512.h>
#define SHA512_BLOCK_SIZE 128
static inline void crypton_sha512_init(struct sha512_ctx *ctx) {
  digestif_sha512_init(ctx);
}
static inline void crypton_sha512_update(struct sha512_ctx *ctx, const void *input, size_t len) {
  const uint8_t *p = input;
  uint64_t block[SHA512_BLOCK_SIZE / sizeof(uint64_t)];
  /* Digestif's kernel accesses uint64_t words. A single aligned block per
   * update is safe even when a preceding update left a partial context block.
   * It also keeps every size_t -> uint32_t conversion bounded, without any
   * dependence on the caller's alignment (including 32-bit OCaml heaps). */
  while (len) {
    uint32_t n = len > sizeof block ? sizeof block : (uint32_t)len;
    memcpy(block, p, n);
    digestif_sha512_update(ctx, (uint8_t *)block, n);
    p += n; len -= n;
  }
  mc_pbkdf2_wipe(block, sizeof block);
}
static inline void crypton_sha512_finalize(struct sha512_ctx *ctx, uint8_t *out) {
  uint64_t digest[SHA512_DIGEST_SIZE / sizeof(uint64_t)];
  digestif_sha512_finalize(ctx, (uint8_t *)digest);
  memcpy(out, digest, sizeof digest);
  mc_pbkdf2_wipe(digest, sizeof digest);
}
#endif
