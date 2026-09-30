(** Bitcoin BIP32 over native libsecp256k1 and Digestif, without bignums.
    Secret arithmetic uses the native backend. Protocol/runtime integration
    has not independently been verified constant-time; OCaml secret copies
    cannot be guaranteed erased. Base58 and network/path policy belong to
    wallet libraries. This is distinct from Cardano's Ed25519-BIP32.

    Possession of a parent extended public key and a non-hardened child
    private key reveals the parent private key. Hardened derivation prevents
    this relationship. Fingerprints are short identifiers, not authentication. *)
type error = [ Mirage_crypto_secp256k1.error | `Hardened_from_public ]
val pp_error : Format.formatter -> error -> unit

type 'a extended = private {
  key : 'a;
  chain_code : string; (** Exactly 32 bytes. *)
  depth : int; (** 0..255. *)
  parent_fingerprint : string; (** Four bytes; zero for a master node. *)
  child_number : int32; (** Unsigned index bit pattern; zero for a master. *)
}

module Public : sig
  type t = Mirage_crypto_secp256k1.pub extended
  val fingerprint : t -> string
  val derive : t -> int32 -> (t, error) result
  (** Derive exactly the supplied unsigned index. Hardened indices fail with
      [Hardened_from_public]; invalid children or depth overflow fail with
      [Invalid_range]. No automatic index increment. Zero tweaks are valid. *)

  val derive_path : t -> int32 list -> (t, error) result
  val to_octets : version:int32 -> t -> string
  val of_octets : string -> (t * int32, error) result
  (** Exactly 78 bytes before Base58Check. The version is returned verbatim;
      callers enforce network/version policy. Only compressed keys are valid. *)
end
module Secret : sig
  type t = Mirage_crypto_secp256k1.priv extended
  val master : string -> (t, error) result
  (** Seed length 16..64 bytes. Invalid master scalars fail with [Invalid_range].
      This operation and parsing do not need an initialized RNG. *)

  val public : ?g:Mirage_crypto_rng.g -> t -> Public.t
  val fingerprint : ?g:Mirage_crypto_rng.g -> t -> string
  val derive : ?g:Mirage_crypto_rng.g -> t -> int32 -> (t, error) result
  val derive_path : ?g:Mirage_crypto_rng.g -> t -> int32 list -> (t, error) result
  (** Private derivation, neutering and fingerprints require an initialized
      Mirage RNG for native context blinding. Outputs remain deterministic.
      Children are derived at exactly the supplied indices, including hardened
      indices. Invalid children or depth overflow return [Invalid_range]. *)

  val to_octets : version:int32 -> t -> string
  val of_octets : string -> (t * int32, error) result
end
