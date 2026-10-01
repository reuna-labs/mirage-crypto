(** Bignum-free blockchain core. BLAKE2b uses Digestif; Ed25519-BIP32 uses the
    independent native package. Neither requires RNG initialization or Unix. *)

(** {b BLAKE2b}, RFC 7693. Thin wrapper over [Digestif.BLAKE2B]. *)
module Blake2b : sig
  val digest : ?digest_size:int -> string -> string
  (** [digest ?digest_size msg] is the BLAKE2b digest of [msg].
      [digest_size] defaults to 64 (bytes); RFC 7693 permits [1, 64].
      @raise Invalid_argument if [digest_size] is out of range. *)

  val hmac : ?digest_size:int -> key:string -> string -> string
  (** [hmac ?digest_size ~key msg] is HMAC-BLAKE2b(key, msg). *)
end


(** Native reference C, V2 derivation and Icarus. Strict wallet-key imports.
    Whole-protocol constant-time assurance and OCaml heap erasure remain qualified. *)
module Ed25519_bip32 = Mirage_crypto_ed25519_bip32
