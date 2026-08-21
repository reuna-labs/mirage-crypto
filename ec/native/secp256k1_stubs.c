#include "mirage_crypto.h"
#include "secp256k1_kiila.h"
#include <caml/memory.h>

CAMLprim value mc_secp256k1_sub(value out, value a, value b)
{
	CAMLparam3(out, a, b);
	fiat_secp256k1_sub((limb_t*)Bytes_val(out), (const limb_t*)String_val(a), (const limb_t*)String_val(b));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_secp256k1_add(value out, value a, value b)
{
	CAMLparam3(out, a, b);
	fiat_secp256k1_add((limb_t*)Bytes_val(out), (const limb_t*)String_val(a), (const limb_t*)String_val(b));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_secp256k1_mul(value out, value a, value b)
{
	CAMLparam3(out, a, b);
	fiat_secp256k1_mul((limb_t*)Bytes_val(out), (const limb_t*)String_val(a), (const limb_t*)String_val(b));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_secp256k1_from_bytes(value out, value in)
{
	CAMLparam2(out, in);
	fiat_secp256k1_from_bytes((limb_t*)Bytes_val(out), _st_uint8(in));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_secp256k1_to_bytes(value out, value in)
{
	CAMLparam2(out, in);
	fiat_secp256k1_to_bytes(Bytes_val(out), (const limb_t*)String_val(in));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_secp256k1_sqr(value out, value in)
{
	CAMLparam2(out, in);
	fiat_secp256k1_square((limb_t*)Bytes_val(out), (const limb_t*)String_val(in));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_secp256k1_from_montgomery(value out, value in)
{
	CAMLparam2(out, in);
	fiat_secp256k1_from_montgomery((limb_t*)Bytes_val(out), (const limb_t*)String_val(in));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_secp256k1_to_montgomery(value out, value in)
{
	CAMLparam2(out, in);
	fiat_secp256k1_to_montgomery((limb_t*)Bytes_val(out), (const limb_t*)String_val(in));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_secp256k1_nz(value x)
{
	CAMLparam1(x);
	limb_t ret;
	fiat_secp256k1_nonzero(&ret, (const limb_t*)String_val(x));
	CAMLreturn(Val_bool(ret));
}

CAMLprim value mc_secp256k1_set_one(value x)
{
	CAMLparam1(x);
    fiat_secp256k1_set_one((limb_t*)Bytes_val(x));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_secp256k1_inv(value out, value in)
{
	CAMLparam2(out, in);
	fiat_secp256k1_inv((limb_t*)Bytes_val(out), (const limb_t*)String_val(in));
	CAMLreturn(Val_unit);
}

CAMLprim value mc_secp256k1_select(value out, value bit, value t, value f)
{
	CAMLparam4(out, bit, t, f);
	fiat_secp256k1_selectznz(
		(limb_t*)Bytes_val(out),
		!!Bool_val(bit),
		(const limb_t*)String_val(f),
		(const limb_t*)String_val(t)
	);
	CAMLreturn(Val_unit);
}

#define PT(v) ((const pt_aff_t*) (String_val(v)))
#define PT_OUT(v) ((pt_aff_t*) (Bytes_val(v)))

CAMLprim value mc_secp256k1_scalar_mult_base(value out, value s)
{
	CAMLparam2(out, s);
	fixed_smul_cmb(PT_OUT(out), _st_uint8(s));
    CAMLreturn(Val_unit);
}

CAMLprim value mc_secp256k1_scalar_mult(value out, value s, value p)
{
    CAMLparam3(out, s, p);
	var_smul_rwnaf(PT_OUT(out), _st_uint8(s), PT(p));
    CAMLreturn(Val_unit);
}

CAMLprim value mc_secp256k1_scalar_mult_add(value out, value a, value b, value p)
{
	CAMLparam4(out, a, b, p);
    var_smul_wnaf_two(PT_OUT(out), _st_uint8(a), _st_uint8(b), PT(p));
    CAMLreturn(Val_unit);
}

/* out := p + q, on the affine Montgomery-form representation the OCaml layer
 * uses for points, where Y = 0 encodes the point at infinity (no finite
 * secp256k1 point has y = 0).
 *
 * Each input is lifted to projective coordinates with constant-time selects:
 * the identity to (0 : 1 : 0), any other point to (X : Y : 1).  The sum is
 * computed by the existing point_add_proj, ECCKiila's complete addition
 * (https://eprint.iacr.org/2015/1060 Alg 7, a = 0), which is valid for all
 * inputs including doubling and the identity.  Conversion back to affine is
 * the same inv/mul tail the var_smul/fixed_smul routines above use; it maps
 * a projective identity result (Z = 0) back to (0, 0) because the
 * Bernstein-Yang fiat_secp256k1_inv sends 0 to 0.
 *
 * point_add_proj forbids aliasing R with its third argument only; here R,
 * P and Q are all distinct locals.  All reads of the inputs happen before
 * any write to out, so out may alias p or q. */
CAMLprim value mc_secp256k1_point_add(value out, value p, value q)
{
	CAMLparam3(out, p, q);
	pt_prj_t P, Q, R;
	fe_t zero;
	limb_t nz;
	fiat_secp256k1_uint1 fin;

	fe_set_zero(zero);

	fiat_secp256k1_nonzero(&nz, PT(p)->Y);
	fin = (fiat_secp256k1_uint1)(!!nz);
	fiat_secp256k1_selectznz(P.X, fin, zero, PT(p)->X);
	fiat_secp256k1_selectznz(P.Y, fin, const_one, PT(p)->Y);
	fiat_secp256k1_selectznz(P.Z, fin, zero, const_one);

	fiat_secp256k1_nonzero(&nz, PT(q)->Y);
	fin = (fiat_secp256k1_uint1)(!!nz);
	fiat_secp256k1_selectznz(Q.X, fin, zero, PT(q)->X);
	fiat_secp256k1_selectznz(Q.Y, fin, const_one, PT(q)->Y);
	fiat_secp256k1_selectznz(Q.Z, fin, zero, const_one);

	point_add_proj(&R, &Q, &P);

	/* convert to affine -- same as the scalar multiplication tails above */
	fiat_secp256k1_inv(R.Z, R.Z);
	fiat_secp256k1_mul(PT_OUT(out)->X, R.X, R.Z);
	fiat_secp256k1_mul(PT_OUT(out)->Y, R.Y, R.Z);

	CAMLreturn(Val_unit);
}
