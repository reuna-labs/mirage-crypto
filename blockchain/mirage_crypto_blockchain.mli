(** {1 Blockchain cryptography}

    Cryptographic primitives commonly used in blockchain protocols.

    All modules are implemented: {!Hashes}, {!Blake2b}, {!Ripemd160},
    {!Keccak256}, {!Blake3}, {!Secp256k1} (ECDSA, including public-key
    recovery), {!Bip340}, {!Bls12_381}, {!Sr25519} (Schnorrkel signatures
    and VRF pre-output), {!Stark_curve}, {!Poseidon}, and
    {!Ed25519_bip32}.

    {b Non-constant-time warning}: {!Secp256k1}, {!Bip340}, {!Bls12_381},
    {!Stark_curve}, {!Sr25519}, and {!Ed25519_bip32} use plain,
    non-constant-time scalar multiplication (and, for {!Sr25519},
    branch-on-value Ristretto255 field operations). See their module doc
    comments below before using them with secret key material. *)

(** {b SHA-256 helpers}. Thin wrappers over [Digestif.SHA256] shared by
    the blockchain codecs: raw SHA-256, Bitcoin's double-SHA256, and the
    BIP340 "tagged hash" (also used by BIP341 Taproot). *)
module Hashes : sig
  val sha256 : string -> string
  (** [sha256 msg] is the 32-byte SHA-256 digest of [msg]. *)

  val sha256d : string -> string
  (** [sha256d msg] is [sha256 (sha256 msg)], Bitcoin's "SHA256d" used
      for block and transaction identifiers. *)

  val tagged_hash : tag:string -> string -> string
  (** [tagged_hash ~tag msg] is
      [sha256 (sha256 tag || sha256 tag || msg)] per BIP340's "Design /
      Tagged Hashes". BIP341 Taproot reuses it with tags ["TapLeaf"],
      ["TapBranch"], ["TapTweak"], and ["TapSighash"]. *)
end

(** {b BLAKE2b}, RFC 7693. Re-exported from
    {!Mirage_crypto_blockchain_core}, which carries it without the bignum
    dependency the rest of this library has. *)
module Blake2b = Mirage_crypto_blockchain_core.Blake2b

(** {b RIPEMD-160}. Thin wrapper over [Digestif.RMD160]. *)
module Ripemd160 : sig
  val digest_size : int
  (** [20] bytes. *)

  val digest : string -> string
  (** [digest msg] is the 20-byte RIPEMD-160 digest of [msg]. *)

  val hash160 : string -> string
  (** [hash160 pubkey] is [digest (SHA256.digest pubkey)], the standard
      Bitcoin address-derivation composite ("Hash160"). *)
end

(** {b Keccak}, the pre-NIST-standardization Keccak padding used by
    Ethereum, Solidity's [keccak256], and most blockchain codebases.
    Thin wrappers over [Digestif.KECCAK_*]. This is {b not}
    interchangeable with SHA-3: the two use different padding
    domain-separator bytes ([0x01] vs NIST's [0x06]) and produce
    different digests for the same input.

    Keccak-256 is by far the common case here; the other three sizes are
    provided because a few protocols and the original Keccak submission
    use them. *)
module Keccak : sig
  module type S = sig
    val digest_size : int
    val digest : string -> string
    (** [digest msg] is the [digest_size]-byte Keccak digest of [msg]. *)
  end

  module K224 : S
  (** Keccak-224, 28-byte digest. *)

  module K256 : S
  (** Keccak-256, 32-byte digest. *)

  module K384 : S
  (** Keccak-384, 48-byte digest. *)

  module K512 : S
  (** Keccak-512, 64-byte digest. *)
end

(** {b Keccak-256}. Retained for compatibility; exactly [Keccak.K256]. *)
module Keccak256 : sig
  val digest_size : int
  (** [32] bytes. *)

  val digest : string -> string
  (** [digest msg] is the 32-byte Keccak-256 digest of [msg]. *)
end

(** {b BLAKE3}. From-scratch implementation ported from the official
    reference implementation
    (https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf),
    since no existing dependency of this repo provides it. *)
module Blake3 : sig
  val digest : ?digest_size:int -> string -> string
  (** [digest ?digest_size msg] is the BLAKE3 hash of [msg], extendable
      to arbitrary output length via the BLAKE3 XOF; [digest_size]
      defaults to 32 bytes. *)

  val keyed_digest : ?digest_size:int -> key:string -> string -> string
  (** [keyed_digest ~key msg] is BLAKE3 in keyed mode.
      @raise Invalid_argument if [key] is not exactly 32 bytes. *)

  val derive_key : ?digest_size:int -> context:string -> string -> string
  (** [derive_key ~context key_material] is BLAKE3 in key-derivation
      mode. [context] should be hardcoded, globally unique, and
      application-specific. *)
end

(** {b secp256k1}: the Weierstrass curve [y^2 = x^3 + 7] over
    [F_p], [p = 2^256 - 2^32 - 977], used by Bitcoin, Ethereum, and most
    other blockchains.

    {b NOT CONSTANT TIME.} Plain double-and-add scalar multiplication in
    Jacobian coordinates; timing leaks scalar bit patterns. Suitable for
    verification of public data or as a stepping stone toward a
    hardened implementation; not suitable for signing with secret keys
    in adversarial/timing-observable environments. This is a quick
    reference implementation pending a future constant-time revamp. *)
module Secp256k1 : sig
  type error =
    [ `Invalid_range | `Invalid_format | `Invalid_length | `Not_on_curve | `At_infinity ]

  val pp_error : Format.formatter -> error -> unit

  type point = private { x : Z.t; y : Z.t }
  (** An affine curve point (excludes the point at infinity; operations
      that would produce it return [Error `At_infinity] instead). *)

  type scalar = private Z.t
  (** A value in [[1, n)], [n] the curve order. *)

  type priv = scalar
  type pub = point

  val p : Z.t
  (** Field prime, [2^256 - 2^32 - 977]. *)

  val n : Z.t
  (** Curve order. *)

  val g : point
  (** Base point / generator. *)

  val scalar_of_octets : string -> (scalar, error) result
  val scalar_to_octets : scalar -> string
  (** 32-byte big-endian. *)

  val point_of_octets : string -> (point, error) result
  (** Accepts SEC1 compressed (33 bytes, [0x02]/[0x03] prefix) or
      uncompressed (65 bytes, [0x04] prefix) encodings. *)

  val point_to_octets : ?compress:bool -> point -> string
  (** [compress] defaults to [true]. *)

  val generate : ?g:Mirage_crypto_rng.g -> unit -> priv * pub
  val pub_of_priv : priv -> pub

  val add : point -> point -> (point, error) result
  val scalar_mult : scalar -> point -> (point, error) result

  type signature
  (** [(r, s)] pair, with [s] low-S normalized per Bitcoin's
      malleability convention (BIP62/BIP146): [s <= n/2]. *)

  val signature_of_octets : string -> (signature, error) result
  (** Accepts either 64-byte compact [r || s] or DER encoding. *)

  val signature_to_octets : ?compact:bool -> signature -> string
  (** [compact] (default [true]) is 64-byte [r || s]; [false] is DER. *)

  val sign : key:priv -> string -> signature
  (** [sign ~key digest] signs a 32-byte pre-hashed message digest
      (caller is responsible for hashing, e.g. with {!Keccak256.digest}
      or double-SHA256, per the target protocol's convention) using
      RFC 6979 deterministic nonce generation, and normalizes to low-S.
      @raise Invalid_argument if [digest] is not 32 bytes. *)

  val verify : key:pub -> signature -> string -> bool
  (** [verify ~key sig digest] verifies [sig] over the 32-byte [digest]. *)

  val sign_recoverable : key:priv -> string -> signature * int
  (** Like {!sign}, but additionally returns a recovery id in [[0, 3]]
      that, together with the signature and message digest, lets
      {!recover} reconstruct the public key. The id encodes the parity of
      the y-coordinate of the ephemeral point [R] (bit 0) and whether its
      x-coordinate exceeded the curve order [n] (bit 1). Ethereum's
      transaction [v] is [recid + 27] (legacy / [eth_sign]) or
      [recid + 35 + 2 * chain_id] (EIP-155); that mapping is left to the
      caller.
      @raise Invalid_argument if [digest] is not 32 bytes. *)

  val recover : msg:string -> signature -> recid:int -> (pub, error) result
  (** [recover ~msg sig ~recid] recovers the public key that produced
      [sig] over the 32-byte digest [msg], using the recovery id [recid]
      (in [[0, 3]], as returned by {!sign_recoverable}). Any valid [s] in
      [[1, n)] is accepted (low-S is not required for recovery). Returns
      [Error `Invalid_length] if [msg] is not 32 bytes,
      [Error `Invalid_format] if [recid] is out of range,
      [Error `Invalid_range] if the signature scalars or the
      reconstructed x-coordinate are out of range, [Error `Not_on_curve]
      if no curve point has that x-coordinate, and [Error `At_infinity]
      in the degenerate recovered-identity case. *)
end

(** {b BIP340} Schnorr signatures over secp256k1
    (https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).

    {b NOT CONSTANT TIME.} Built directly on {!Secp256k1}; inherits its
    timing-leak caveats -- see there for details. *)
module Bip340 : sig
  type error = Secp256k1.error

  val pp_error : Format.formatter -> error -> unit

  type priv = Secp256k1.scalar

  type xonly_pub
  (** The x-coordinate of a curve point, 32 bytes (BIP340's "x-only"
      public key encoding). *)

  val xonly_pub_of_octets : string -> (xonly_pub, error) result
  val xonly_pub_to_octets : xonly_pub -> string
  val xonly_pub_of_priv : priv -> xonly_pub

  type signature
  (** 64-byte [(r, s)] per BIP340 "Default Signing"; [r] is an x-only
      curve point x-coordinate, [s] a scalar. *)

  val signature_of_octets : string -> (signature, error) result
  val signature_to_octets : signature -> string
  (** Always 64 bytes. *)

  val tagged_hash : tag:string -> string -> string
  (** [tagged_hash ~tag msg] is
      [SHA256(SHA256(tag) || SHA256(tag) || msg)] per BIP340's "Design /
      Tagged Hashes". *)

  val sign : ?aux_rand:string -> key:priv -> string -> signature
  (** [sign ?aux_rand ~key msg] signs a message of any length per BIP340
      "Default Signing", with deterministic nonce derived via
      {!tagged_hash} tag ["BIP0340/nonce"]. [aux_rand], if provided,
      must be 32 bytes of auxiliary randomness (recommended by the spec
      though not required for validity); defaults to 32 zero bytes.
      @raise Invalid_argument if [aux_rand] is not 32 bytes. *)

  val verify : key:xonly_pub -> signature -> string -> bool
  (** [verify ~key sig msg] verifies per BIP340 "Verification". *)
end

(** {b BLS12-381} pairing-friendly curve: G1/G2 group arithmetic, the
    optimal ate pairing, RFC 9380 hash-to-curve for G2, and BLS
    signatures in the "minimal-pubkey-size" configuration (public keys
    in G1, signatures in G2), following the "basic" scheme of
    draft-irtf-cfrg-bls-signature ({!aggregate_verify} requires distinct
    messages as its rogue-key defense; this does not implement
    proof-of-possession or message augmentation).

    {b NOT CONSTANT TIME.} Scalar multiplication is plain
    double-and-add and the hash-to-curve mapping branches on the
    square-ness of field elements; both leak information about their
    inputs through timing. This is a quick reference implementation
    pending a future hardening pass -- do not use it to sign with
    secret keys in adversarial/timing-observable environments. See the
    top of [bls12_381.ml] for the primary sources (RFC 9380, the
    pairing-friendly-curves and bls-signature IETF drafts, and the
    py_ecc reference implementation) each constant and algorithm here
    was cross-checked against.

    {b Performance.} Final exponentiation is done as a single, literal
    exponentiation by [(p^12-1)/r] rather than the optimized
    easy/hard-part split most production implementations use; a single
    {!pairing} call, and hence {!verify}, may take a few seconds.

    {b Scope.} Hash-to-curve is implemented only for G2, which is all
    this signature scheme needs (messages hash into G2; public keys are
    plain scalar multiples of the G1 generator). G1 hash-to-curve is not
    implemented. *)
module Bls12_381 : sig
  type error = [ `Invalid_format | `Invalid_length | `Invalid_range | `Not_on_curve ]

  val pp_error : Format.formatter -> error -> unit

  val p : Z.t
  (** The base field prime. *)

  val r : Z.t
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
  val verify : key:pub -> signature -> string -> bool

  val aggregate : signature list -> signature
  (** The identity (point at infinity) on the empty list. *)

  val aggregate_verify : (pub * string) list -> signature -> bool
  (** [false] if the list is empty, any public key is the point at
      infinity, or any two messages coincide (see the module-level
      rogue-key-defense note). *)
end

(** {b sr25519}, as used by Substrate/Polkadot: Ristretto255 point
    encoding over Curve25519 (Edwards25519), the Schnorrkel Schnorr
    signature scheme, and a Merlin transcript (STROBE128 over
    Keccak-f[1600]) for Fiat-Shamir challenges and randomized,
    transcript-bound nonces.

    {b NOT CONSTANT TIME.} See {!Secp256k1}'s banner for the general
    caveat; here it also applies to the Ristretto255 field/point
    operations (branch-on-value square-root and sign selection), not
    just scalar multiplication.

    Parameters and algorithms were cross-checked against RFC 9496
    (ristretto255), the "keccak", "merlin", and "schnorrkel" Rust
    crates, and polkadot-sdk's own sr25519 wrapper (to confirm which
    [MiniSecretKey] expansion mode Substrate actually uses -- it is
    [ExpansionMode::Ed25519], not the library's own slightly-preferred
    [Uniform] mode), not reconstructed from memory; see the top of
    [sr25519.ml] for details and the specific fixed test vectors this
    package checks against.

    {b Randomized signing.} Unlike this package's other signature
    schemes, Schnorrkel deliberately folds fresh randomness into every
    signature's nonce (bound to the message transcript and the secret
    key's nonce seed), so {!sign} is not deterministic and has no fixed
    known-answer test vectors of its own -- this is also how
    schnorrkel's own upstream test suite tests it (sign, then verify).

    {b Scope.} {!vrf_output} provides the deterministic VRF pre-output;
    the randomized DLEQ proof is not implemented. *)
module Sr25519 : sig
  type error = [ `Invalid_format | `Invalid_length | `Invalid_range | `Not_on_curve ]

  val pp_error : Format.formatter -> error -> unit

  type priv
  (** A 32-byte [MiniSecretKey] seed. Any 32 bytes are valid. *)

  type pub
  (** A 32-byte compressed ristretto255 group element. *)

  type signature
  (** A 64-byte Schnorrkel signature (R || s, with s's top bit marking
      it as a Schnorrkel rather than an Ed25519 signature). *)

  val priv_of_octets : string -> (priv, error) result
  val priv_to_octets : priv -> string
  val pub_of_octets : string -> (pub, error) result
  val pub_to_octets : pub -> string
  val pub_of_priv : priv -> pub
  val signature_of_octets : string -> (signature, error) result
  val signature_to_octets : signature -> string

  val sign : ?g:Mirage_crypto_rng.g -> ?context:string -> key:priv -> string -> signature
  (** [context] is the Schnorrkel "signing context" label folded into
      the Merlin transcript; it defaults to ["substrate"], matching
      polkadot-sdk. *)

  val verify : ?context:string -> key:pub -> signature -> string -> bool

  val verify_deprecated : ?context:string -> key:pub -> signature -> string -> bool
  (** Verifies against schnorrkel's older, differently-labeled
      "preaudit_deprecated" transcript (predating [SigningContext] and
      the ["sign:*"] labels). Provided only for interop with signatures
      produced by that legacy path; ordinary sr25519 signatures should
      always be checked with {!verify}. *)

  val ristretto_from_uniform_bytes : string -> string
  (** [ristretto_from_uniform_bytes b] is the RFC 9496 Section 4.3.4
      one-way map (hash-to-group): 64 uniformly-distributed bytes [b] are
      mapped to a ristretto255 group element, returned as its 32-byte
      encoding. This is the primitive underlying {!vrf_output}'s input
      hashing, exposed for general hash-to-group use.
      @raise Invalid_argument if [b] is not 64 bytes. *)

  val vrf_output : key:priv -> string -> string
  (** [vrf_output ~key msg] is the Schnorrkel VRF pre-output
      (schnorrkel's [VRFInOut.output]) for message [msg] under the
      default ["substrate"] signing context: the VRF input is the
      malleable hash of the signing transcript
      ([challenge_bytes "VRFHash"] then {!ristretto_from_uniform_bytes}),
      and the result is [key_scalar * input], encoded as a 32-byte
      ristretto element. The (randomized) DLEQ proof and
      [VRFInOut::make_bytes] output-expansion step are out of scope. *)
end

(** {b Stark Curve}: the StarkNet/StarkEx short-Weierstrass curve
    [y^2 = x^3 + alpha*x + beta] over the STARK-friendly prime field
    [p = 2^251 + 17*2^192 + 1], and its ECDSA-variant signature scheme.

    {b NOT CONSTANT TIME.} See {!Secp256k1}'s banner — same caveat.

    Parameters and algorithm are ported directly from StarkWare's own
    reference implementation
    (https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/crypto/signature/signature.py),
    not derived from memory. This is {b not} textbook ECDSA: [r] is used
    directly rather than reduced mod the curve order, and signature
    verification uses StarkWare's own "AIR-mimicking" scalar
    multiplication, which is intentionally stricter than a generic
    implementation (it fails on certain point configurations a general
    curve library would happily add) — this module reproduces that
    exact behavior for interoperability with any spec-compliant
    StarkNet/StarkEx verifier. The nonce used by {!sign} is generated via
    this library's own deterministic HMAC-DRBG construction (as
    {!Secp256k1}'s does), not StarkWare's [generate_k_rfc6979]; this
    doesn't affect correctness or interoperability, since only the
    verification algorithm (which is faithfully ported) needs to match
    across implementations — nothing requires bit-for-bit identical
    nonces. *)
module Stark_curve : sig
  type error = [ `Invalid_range | `Invalid_format | `Not_on_curve | `At_infinity ]

  val pp_error : Format.formatter -> error -> unit

  type point = private { x : Z.t; y : Z.t }
  type scalar = private Z.t
  type priv = scalar
  type pub = point

  type field_element = Z.t
  (** A representative in [[0, p)]; the natural message type for this
      curve's signature scheme (typically a Pedersen-hash digest), not
      an arbitrary byte string. Interchangeable with
      {!Poseidon.field_element} once a shared field is decided (see
      {!Poseidon}'s doc comment). *)

  val p : Z.t
  (** Field prime, [2^251 + 17*2^192 + 1]. *)

  val alpha : Z.t
  val beta : Z.t

  val n : Z.t
  (** Curve order. *)

  val g : point
  (** Base point / generator. *)

  val scalar_of_octets : string -> (scalar, error) result
  val point_of_octets : string -> (point, error) result
  (** 64-byte [x || y] big-endian affine encoding. *)

  val point_to_octets : point -> string

  val field_element_of_octets : string -> (field_element, error) result
  val field_element_to_octets : field_element -> string

  val generate : ?g:Mirage_crypto_rng.g -> unit -> priv * pub
  val pub_of_priv : priv -> pub

  val add : point -> point -> (point, error) result
  val scalar_mult : scalar -> point -> (point, error) result

  type signature
  (** [(r, s)] pair per the StarkEx ECDSA variant. *)

  val signature_of_octets : string -> (signature, error) result
  val signature_to_octets : signature -> string
  (** 64-byte [r || s] big-endian. *)

  val sign : key:priv -> field_element -> signature
  (** [sign ~key msg_hash] signs a field element (typically a
      Pedersen-hash digest), per StarkWare's [sign].
      @raise Invalid_argument if [msg_hash] is not in [[0, 2^251)]. *)

  val verify : key:pub -> signature -> field_element -> bool
  (** [verify ~key sig msg_hash] verifies [sig] over [msg_hash], per
      StarkWare's [verify]. *)
end

(** {b Poseidon} (the Hades permutation), a ZK-SNARK-optimized sponge
    hash over {!Stark_curve}'s field, using StarkWare's own default
    parameters and construction, ported directly from their reference
    implementation
    (https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/cairo/common/poseidon_hash.py),
    not derived from memory. Round constants are not a hardcoded table;
    they are derived the same way the reference does, via a
    "nothing up my sleeve" construction ([SHA256("Hades" ^ idx) mod p]
    for each of the 273 constants needed) — simpler and safer than
    transcribing that many field elements by hand.

    {b Encoding & state gap.} Unlike {!Blake2b}/{!Keccak256}/{!Blake3}
    above, Poseidon's natural I/O is a sequence of field elements
    ({!field_element}, i.e. [Z.t] values reduced mod {!Stark_curve.p}),
    not an opaque byte string — it is used for Merkle state-commitment
    trees over field-element leaves (e.g. StarkNet contract storage
    tries). This module therefore intentionally has no byte-string
    convenience wrapper: StarkWare's own byte-oriented variant encodes
    each byte-string input as a single big-endian integer, which would
    be a surprising default to bake into a general "hash these bytes"
    function; build that explicitly from {!hash_pair} if you need it. *)
module Poseidon : sig
  type field_element = Z.t

  val hash_pair : field_element -> field_element -> field_element
  (** 2-ary hash (StarkWare's [poseidon_hash]): one Hades permutation
      with capacity/domain-separator element [2]. *)

  val hash_single : field_element -> field_element
  (** 1-ary hash (StarkWare's [poseidon_hash_single]): one Hades
      permutation with capacity/domain-separator element [1]. *)

  val hash : field_element list -> field_element
  (** Arbitrary-arity hash (StarkWare's [poseidon_hash_many]): a sponge
      over the Hades permutation, input padded with a single [1] then
      [0]s to a multiple of the rate (2 field elements). *)
end

(** {b Ed25519-BIP32} (a.k.a. ed25519e), hierarchical deterministic key
    derivation extending Ed25519, per Cardano's "BIP32-Ed25519:
    Hierarchical Deterministic Keys over a Non-linear Keyspace"
    (Khovratovich & Law, 2017); child derivation follows Cardano's
    DerivationScheme V2.

    {b NOT CONSTANT TIME.} Built on
    {!Mirage_crypto_ec.Ed25519.Primitive}; inherits its variable-time
    point decoding and does plain byte arithmetic over secret scalars.

    Master key generation uses the paper's SHA-512 scheme (k =
    SHA512(seed), clamp [kL], chain code = SHA256(0x01 || seed)); the
    3rd-highest bit of [kL]'s last byte must be clear, otherwise
    {!master_key_of_seed} returns [Error `Invalid_derivation]. *)
module Ed25519_bip32 = Mirage_crypto_blockchain_core.Ed25519_bip32
(** {b BIP32-Ed25519} hierarchical deterministic keys, DerivationScheme V2 --
    the scheme Cardano uses. Re-exported from {!Mirage_crypto_blockchain_core};
    see there for the constant-time caveat. *)
