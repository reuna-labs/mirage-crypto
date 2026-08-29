(** The bignum-free core of {!Mirage_crypto_blockchain}.

    {!Blake2b} and {!Ed25519_bip32} depend only on [digestif] and
    [mirage-crypto-ec]. The rest of the blockchain library -- secp256k1,
    BLS12-381, the STARK curve, Poseidon, sr25519 -- needs arbitrary-precision
    arithmetic, and therefore zarith and GMP.

    Keeping these two here means a consumer that needs only Ed25519 can have
    them without that closure: no zarith, no GMP, and so no vendored GMP
    cross-compile in a MirageOS/Solo5 duniverse. Cardano is the motivating case,
    since its key derivation is BIP32-Ed25519 and it uses no other curve.

    {!Mirage_crypto_blockchain} re-exports both unchanged, so nothing that
    already depends on the full library has to move. *)

(** {b BLAKE2b}, RFC 7693. Thin wrapper over [Digestif.BLAKE2B]. *)
module Blake2b : sig
  val digest : ?digest_size:int -> string -> string
  (** [digest ?digest_size msg] is the BLAKE2b digest of [msg].
      [digest_size] defaults to 64 (bytes); RFC 7693 permits [1, 64].
      @raise Invalid_argument if [digest_size] is out of range. *)

  val hmac : ?digest_size:int -> key:string -> string -> string
  (** [hmac ?digest_size ~key msg] is HMAC-BLAKE2b(key, msg). *)
end


(** {b BIP32-Ed25519} hierarchical deterministic keys (Khovratovich & Law),
    child derivation per DerivationScheme V2 -- the scheme Cardano uses.

    {b Not constant time}: this inherits the variable-time point decoding of the
    ec Ed25519 primitives and does plain byte arithmetic on secret scalars. The
    derivation path of a live key is not a safe thing to expose to a co-resident
    attacker's timing measurements. *)
module Ed25519_bip32 : sig
  type error = [ `Invalid_format | `Invalid_length | `Invalid_derivation ]

  val pp_error : Format.formatter -> error -> unit

  type extended_priv
  (** 64-byte scalar-pair (the "extended" Ed25519 secret key format)
      plus 32-byte chain code, per BIP32-Ed25519's master key
      generation. *)

  type extended_pub
  (** 32-byte point plus 32-byte chain code. *)

  val extended_priv_of_octets : string -> (extended_priv, error) result
  (** Decodes a 96-byte [kL || kR || chain_code] extended private key. *)

  val extended_priv_to_octets : extended_priv -> string
  val extended_pub_of_octets : string -> (extended_pub, error) result
  (** Decodes a 64-byte [point || chain_code] extended public key;
      [Error `Invalid_format] if the point is not a valid encoding. *)

  val extended_pub_to_octets : extended_pub -> string

  val master_key_of_seed : string -> (extended_priv, error) result

  val derive_priv_normal : extended_priv -> index:int32 -> (extended_priv, error) result
  (** "Normal" (non-hardened) child derivation; [index < 2^31]. *)

  val derive_priv_hardened : extended_priv -> index:int32 -> (extended_priv, error) result
  (** Hardened child derivation; [index >= 2^31]. *)

  val derive_pub_normal : extended_pub -> index:int32 -> (extended_pub, error) result
  (** Public-only derivation; only valid for non-hardened indices. *)

  val pub_of_priv : extended_priv -> extended_pub
  val sign : key:extended_priv -> string -> string
  val verify : key:extended_pub -> string -> msg:string -> bool
end
