type error = [ `Invalid_format | `Invalid_length | `Invalid_derivation ]
(** BIP32-Ed25519 V2 using selected Cardano reference C, without RNG, Unix or
    arbitrary-precision arithmetic. Native arithmetic is reference code, not
    formally verified. Whole-protocol constant-time behavior and erasure of
    OCaml heap copies are not guaranteed. *)

val pp_error : Format.formatter -> error -> unit

type extended_priv
type extended_pub

val extended_priv_of_octets : string -> (extended_priv, error) result
(** Exactly 96 bytes: kL || kR || chain code. kL must have its lowest three bits
    clear, bit 255 clear and bit 254 set. Bit 253 is allowed in child keys.
    Imported keys are never reclamped. Malformed keys return [Invalid_format].
*)

val extended_priv_to_octets : extended_priv -> string

val extended_pub_of_octets : string -> (extended_pub, error) result
(** Exactly 64 bytes: public point || chain code. The point must be canonical,
    nonidentity and in the prime-order subgroup. *)

val extended_pub_to_octets : extended_pub -> string

val master_key_of_seed : string -> (extended_priv, error) result
(** Paper-style SHA512 master generation, preserving the existing API. This is
    distinct from Icarus; the forbidden third-highest bit yields
    [Invalid_derivation]. *)

val icarus_key_of_entropy :
  ?passphrase:string -> string -> (extended_priv, error) result
(** CIP-3: entropy length 16..32 bytes, passphrase as PBKDF2 password, entropy
    as salt, 4096 HMAC-SHA512 rounds, 96 output bytes and the Icarus clamp. *)

val derive_priv_normal :
  extended_priv -> index:int32 -> (extended_priv, error) result

val derive_priv_hardened :
  extended_priv -> index:int32 -> (extended_priv, error) result

val derive_pub_normal :
  extended_pub -> index:int32 -> (extended_pub, error) result
(** Unsigned index bit patterns, little-endian V2 serialization. Normal indices
    must have bit 31 clear, hardened indices set. No retry; an invalid derived
    scalar/point returns [Invalid_derivation]. *)

val pub_of_priv : extended_priv -> extended_pub
val sign : key:extended_priv -> string -> string
val verify : key:extended_pub -> string -> msg:string -> bool

val verify_raw : key:string -> string -> msg:string -> bool
(** Raw Ed25519 verification preserves the former Mirage verification policy,
    including S < L. It does not impose wallet-import subgroup restrictions on
    transaction verification. Wrong key/signature lengths return false. *)
