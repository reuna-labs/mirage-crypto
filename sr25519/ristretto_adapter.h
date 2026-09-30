#ifndef MC_SR_RISTRETTO_ADAPTER_H
#define MC_SR_RISTRETTO_ADAPTER_H
/* Canonical 32-byte LE scalars, canonical encoded Ristretto elements only.
 * Total group multiplication: zero scalar / identity point produce identity.
 * Point validation failure is public and returns -1 without an output. */
void mc_sr_mul_base(unsigned char out[32], const unsigned char scalar[32]);
int mc_sr_mul(unsigned char out[32], const unsigned char scalar[32], const unsigned char point[32]);
#endif
