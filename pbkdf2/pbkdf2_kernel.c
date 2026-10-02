/* Selected Crypton fast-PBKDF2, sharing Digestif's C hash kernels. */
#include "mc_pbkdf2.h"
#include "wipe.h"
#define NO_INLINE_ASM
#define crypton_sha1_transform mc_pbkdf2_sha1_transform
#define crypton_sha256_transform mc_pbkdf2_sha256_transform
#define crypton_sha512_transform mc_pbkdf2_sha512_transform
#define crypton_fastpbkdf2_hmac_sha1 mc_pbkdf2_sha1
#define crypton_fastpbkdf2_hmac_sha256 mc_pbkdf2_sha256
#define crypton_fastpbkdf2_hmac_sha512 mc_pbkdf2_sha512
#include "pbkdf2.inc"
