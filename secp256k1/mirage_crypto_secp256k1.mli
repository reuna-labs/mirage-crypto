(** Bignum-free libsecp256k1 signatures. Secret operations use upstream
    constant-time code with independently randomized contexts. An initialized
    Mirage RNG is required even for deterministic signing/public derivation.
    Verification and decoding operate on public data and may be variable-time.
    Secret OCaml strings are GC-managed; erasure of their copies is not promised. *)

type error = [ `Invalid_range | `Invalid_format | `Invalid_length | `Not_on_curve | `At_infinity ]
val pp_error : Format.formatter -> error -> unit
val p : string
val n : string
(** Field prime and group order, 32-byte big-endian. *)

type scalar
type priv = scalar
type pub
type signature
val scalar_of_octets : string -> (scalar, error) result
(** Exactly 32 big-endian bytes in [1,n). *)

val scalar_to_octets : scalar -> string
val priv_of_octets : string -> (priv, error) result
val priv_to_octets : priv -> string
val pub_of_octets : string -> (pub, error) result
val pub_to_octets : ?compress:bool -> pub -> string
(** SEC1, compressed by default. *)

val pub_of_priv : ?g:Mirage_crypto_rng.g -> priv -> pub
val generate : ?g:Mirage_crypto_rng.g -> unit -> priv * pub
val signature_of_octets : string -> (signature, error) result
(** 64-byte compact or strict DER; r and s must be in [1,n). *)

val signature_to_octets : ?compact:bool -> signature -> string
val sign : ?g:Mirage_crypto_rng.g -> key:priv -> string -> signature
val sign_recoverable : ?g:Mirage_crypto_rng.g -> key:priv -> string -> signature * int
(** RFC6979, low-S, 32-byte digest; recovery ID in [0,3]. *)

val verify : key:pub -> signature -> string -> bool
(** Accepts both high and low S. Protocols requiring low-S must enforce it. *)

val recover : msg:string -> signature -> recid:int -> (pub, error) result
module Bip340 : sig
  type nonrec priv = priv
  type xonly_pub
  type signature
  val xonly_pub_of_octets : string -> (xonly_pub, error) result
  val xonly_pub_to_octets : xonly_pub -> string
  val xonly_pub_of_priv : ?g:Mirage_crypto_rng.g -> priv -> xonly_pub
  val signature_of_octets : string -> (signature, error) result
  val signature_to_octets : signature -> string
  val sign : ?g:Mirage_crypto_rng.g -> ?aux_rand:string -> key:priv -> string -> signature
  (** Arbitrary-length message; auxiliary randomness defaults to fresh 32 bytes. *)

  val verify : key:xonly_pub -> signature -> string -> bool
end
