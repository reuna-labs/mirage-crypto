(** Sr25519 using libsodium arithmetic and Digestif Keccak-f[1600].
    Secret scalar and Ristretto arithmetic is delegated to libsodium.
    The protocol and Merlin/STROBE integration have not independently
    been verified constant-time. Secret copies in the OCaml heap cannot
    be guaranteed erased. No full VRF proof or HDKD API is provided. *)

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
