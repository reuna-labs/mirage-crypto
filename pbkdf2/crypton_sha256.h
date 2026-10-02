/* ISC. Adapt the selected reference code to the installed Digestif C API.
 * Link digestif.c from the exact release that supplies this header. */
#ifndef MC_PBKDF2_SHA256_ADAPTER_H
#define MC_PBKDF2_SHA256_ADAPTER_H
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "wipe.h"
#include <digestif_sha256.h>
#define SHA256_BLOCK_SIZE 64
static inline void crypton_sha256_init(struct sha256_ctx *ctx) {
  digestif_sha256_init(ctx);
}
static inline void crypton_sha256_update(struct sha256_ctx *ctx, const void *input, size_t len) {
  const uint8_t *p = input;
  uint32_t block[SHA256_BLOCK_SIZE / sizeof(uint32_t)];
  /* Digestif's kernel accesses uint32_t words. A single aligned block per
   * update is safe even when a preceding update left a partial context block.
   * It also keeps every size_t -> uint32_t conversion bounded, without any
   * dependence on the caller's alignment (including 32-bit OCaml heaps). */
  while (len) {
    uint32_t n = len > sizeof block ? sizeof block : (uint32_t)len;
    memcpy(block, p, n);
    digestif_sha256_update(ctx, (uint8_t *)block, n);
    p += n; len -= n;
  }
  mc_pbkdf2_wipe(block, sizeof block);
}
static inline void crypton_sha256_finalize(struct sha256_ctx *ctx, uint8_t *out) {
  uint32_t digest[SHA256_DIGEST_SIZE / sizeof(uint32_t)];
  digestif_sha256_finalize(ctx, (uint8_t *)digest);
  memcpy(out, digest, sizeof digest);
  mc_pbkdf2_wipe(digest, sizeof digest);
}
#endif
