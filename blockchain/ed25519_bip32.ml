(* STUB -- NOT IMPLEMENTED.

   Hierarchical deterministic key derivation extending Ed25519, as
   specified in Cardano's "BIP32-Ed25519: Hierarchical Deterministic Keys
   over a Non-linear Keyspace" (Khovratovich & Law, 2017).

   Dependency gap: this repo's [mirage-crypto-ec] exposes
   [Ed25519.priv]/[Ed25519.pub] only as opaque, fully-encoded key types
   (see ec/mirage_crypto_ec.mli); there is no [Ed25519.Primitive]
   submodule analogous to the [Dsa.Primitive] exposed for
   P256/P384/P521 (generator, [add], [scalar_mult]). BIP32-Ed25519
   child-key derivation requires direct access to the 32-byte scalar and
   the curve point (for scalar tweaking: [k_child = k_parent + 8*Z_L mod
   L] and analogous point addition on the public side) that raw Ed25519
   signing does not need. A real implementation of this module therefore
   also requires extending [ec/mirage_crypto_ec.mli] with an
   [Ed25519.Primitive]-style submodule first; that is out of scope here.
   Every function below raises
   [Failure "not yet implemented: Ed25519_bip32.<fn>"]. *)

let unimplemented fn = failwith ("not yet implemented: Ed25519_bip32." ^ fn)

type error = [ `Invalid_format | `Invalid_length | `Invalid_derivation ]

let pp_error ppf = function
  | `Invalid_format -> Format.fprintf ppf "invalid format"
  | `Invalid_length -> Format.fprintf ppf "invalid length"
  | `Invalid_derivation -> Format.fprintf ppf "invalid derivation"

type extended_priv = string
(** Extended private key: 64-byte scalar-pair (left/right, per the
    "extended" Ed25519 secret key format) plus 32-byte chain code, per
    BIP32-Ed25519's master key generation. Opaque until implemented. *)

type extended_pub = string
(** Extended public key: 32-byte point plus 32-byte chain code. Opaque
    until implemented. *)

let master_key_of_seed (_ : string) : (extended_priv, error) result =
  unimplemented "master_key_of_seed"

let derive_priv_normal (_ : extended_priv) ~index:(_ : int32) : (extended_priv, error) result =
  unimplemented "derive_priv_normal"
(** "Normal" (non-hardened) child derivation; index [< 2^31]. *)

let derive_priv_hardened (_ : extended_priv) ~index:(_ : int32) : (extended_priv, error) result =
  unimplemented "derive_priv_hardened"
(** Hardened child derivation; index [>= 2^31]. *)

let derive_pub_normal (_ : extended_pub) ~index:(_ : int32) : (extended_pub, error) result =
  unimplemented "derive_pub_normal"
(** Public-only derivation; only valid for non-hardened indices. *)

let pub_of_priv (_ : extended_priv) : extended_pub = unimplemented "pub_of_priv"
let sign ~key:(_ : extended_priv) (_ : string) : string = unimplemented "sign"

let verify ~key:(_ : extended_pub) (_ : string) ~msg:(_ : string) : bool =
  unimplemented "verify"
