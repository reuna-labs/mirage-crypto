(** BLST-backed BLS12-381. Basic scheme, G1 public keys and G2 signatures.
    Secret scalars use fixed-width encodings and upstream secret-key routines.
    Group encodings are ZCash compatible and subgroup checked. Verification
    rejects identity keys/signatures. The field prime p and order r below are
    big-endian byte strings (48 and 32 bytes). Upstream proofs cover selected
    functions/revisions, not this entire binding. OCaml secret copies are not
    guaranteed to be erased. *)

  type error = [ `Invalid_format | `Invalid_length | `Invalid_range | `Not_on_curve ]

  val pp_error : Format.formatter -> error -> unit

  val p : string
  (** The base field prime. *)

  val r : string
  (** The order of the G1/G2/GT subgroups. *)

  type scalar
  (** An integer mod {!r}. *)

  type g1
  (** A point on G1 (over [F_p]), including the point at infinity. *)

  type g2
  (** A point on G2 (over [F_p^2]), including the point at infinity. *)

  type gt
  (** An element of the target group ([F_p^12]), a pairing output. *)

  type priv = scalar
  type pub = g1
  type signature = g2

  val scalar_of_octets : string -> (scalar, error) result
  val scalar_to_octets : scalar -> string

  val g1_of_octets : string -> (g1, error) result
  (** Deserializes the ZCash/[draft-irtf-cfrg-pairing-friendly-curves]
      point format (48-byte compressed or 96-byte uncompressed),
      validating both the curve equation and G1-subgroup membership. *)

  val g2_of_octets : string -> (g2, error) result
  (** As {!g1_of_octets}, for the 96-byte compressed / 192-byte
      uncompressed G2 encoding. *)

  val g1_to_octets : ?compress:bool -> g1 -> string
  (** [compress] defaults to [true]. *)

  val g2_to_octets : ?compress:bool -> g2 -> string
  (** [compress] defaults to [true]. *)

  val g1_generator : g1
  val g2_generator : g2
  val g1_is_infinity : g1 -> bool
  val g2_is_infinity : g2 -> bool
  val g1_equal : g1 -> g1 -> bool
  val g2_equal : g2 -> g2 -> bool
  val g1_on_curve : g1 -> bool
  val g2_on_curve : g2 -> bool
  val g1_in_subgroup : g1 -> bool
  (** [true] iff the point lies in the prime-order G1 subgroup (as
      opposed to merely satisfying the curve equation). *)

  val g2_in_subgroup : g2 -> bool

  val g1_add : g1 -> g1 -> g1
  val g1_neg : g1 -> g1
  val g1_scalar_mult : scalar -> g1 -> g1
  val g2_add : g2 -> g2 -> g2
  val g2_neg : g2 -> g2
  val g2_scalar_mult : scalar -> g2 -> g2

  val generate : ?g:Mirage_crypto_rng.g -> unit -> priv
  val pub_of_priv : priv -> pub
  (** Rejects zero with [Invalid_argument]. Zero scalars remain valid for group operations. *)


  val pairing : g2 -> g1 -> gt
  (** [pairing q p] computes the optimal ate pairing [e(q, p)] for [q]
      in G2 and [p] in G1. *)

  val gt_equal : gt -> gt -> bool

  val hash_to_curve_g2 : ?dst:string -> string -> g2
  (** [hash_to_curve_g2 ?dst msg] hashes [msg] to a point in G2 per
      BLS12381G2_XMD:SHA-256_SSWU_RO_ (RFC 9380 Section 8.8.2). [dst]
      defaults to the "basic" BLS signature scheme's domain separation
      tag; {!sign} and {!verify} always use that default. *)

  val sign : key:priv -> string -> signature
  (** Rejects a zero private key with [Invalid_argument]. *)

  val verify : key:pub -> signature -> string -> bool

  val aggregate : signature list -> signature
  (** The identity (point at infinity) on the empty list. *)

  val aggregate_verify : (pub * string) list -> signature -> bool
  (** [false] if the list is empty, any public key is the point at
      infinity, or any two messages coincide (see the module-level
      rogue-key-defense note). *)
