(** Kerberos 5 / GSS-API cipher suites.

    Implements RFC 3961/3962, RFC 8009, and MS-KILE (Active Directory) cipher
    types as standalone encrypt/decrypt primitives.  No Kerberos protocol
    messages, ticket formats, or PAC handling are included. *)

(** Common interface for an RFC 3961 encryption type. *)
module type ENCRYPTION_TYPE = sig

  val etype : int
  (** IANA encryption type number. *)

  val block_size : int
  (** Cipher block size in bytes. *)

  val key_bytes : int
  (** Raw key length in bytes. *)

  val confounder_bytes : int
  (** Random confounder prepended to each message during encryption. *)

  val checksum_bytes : int
  (** MAC / integrity check value appended to each ciphertext. *)

  type key

  val of_secret : string -> key
  (** [of_secret raw] constructs a key from raw key bytes.

      @raise Invalid_argument if [String.length raw <> key_bytes]. *)

  val to_secret : key -> string
  (** [to_secret k] returns the raw key bytes. *)

  val generate : ?g:Mirage_crypto_rng.g -> unit -> key
  (** [generate ()] produces a fresh random key of the correct length for this
      encryption type (e.g. for subkey generation in AP-REQ/AP-REP).

      @raise Mirage_crypto_rng.Unseeded_generator if the RNG has not been
      seeded and no [g] is given. *)

  val string_to_key :
    password:string -> salt:string -> ?params:string -> unit -> key
  (** [string_to_key ~password ~salt ()] derives a key from a human-readable
      passphrase and salt per the specification for this encryption type.

      [params] is an optional encoding of iteration count or similar
      algorithm-specific parameters. If omitted, the default for the etype
      is used. *)

  val encrypt :
    ?g:Mirage_crypto_rng.g -> key:key -> key_usage:int -> string -> string
  (** [encrypt ~key ~key_usage msg] prepends a random confounder, encrypts the
      combined payload, and appends an integrity check value.

      [key_usage] is the RFC 3961 key usage number (e.g. 7 for AP-REQ
      authenticator encryption).

      @raise Mirage_crypto_rng.Unseeded_generator if the RNG has not been
      seeded and no [g] is given. *)

  val decrypt :
    key:key -> key_usage:int -> string -> string option
  (** [decrypt ~key ~key_usage ciphertext] verifies the integrity check value
      in constant time, decrypts the payload, and strips the confounder.
      Returns [None] if the ciphertext is malformed or the MAC does not verify. *)

  val checksum : key:key -> key_usage:int -> string -> string
  (** [checksum ~key ~key_usage msg] derives the integrity key Ki and returns
      HMAC(Ki, msg) truncated to [checksum_bytes].

      Use this for RFC 4121 GetMIC tokens and non-confidential Wrap tokens,
      where the caller constructs [msg] as the token header concatenated with
      the application message. *)

  val verify_checksum : key:key -> key_usage:int -> msg:string -> string -> bool
  (** [verify_checksum ~key ~key_usage ~msg mac] verifies that [mac] matches
      [checksum ~key ~key_usage msg] in constant time.  Returns [false] if
      [mac] has the wrong length or does not match. *)
end

(** {1 AES-CTS cipher suites} *)

(** etype 17: AES-128 / CTS / HMAC-SHA1-96 (RFC 3962). *)
module Aes128_cts_hmac_sha1_96 : ENCRYPTION_TYPE

(** etype 18: AES-256 / CTS / HMAC-SHA1-96 (RFC 3962). *)
module Aes256_cts_hmac_sha1_96 : ENCRYPTION_TYPE

(** etype 19: AES-128 / CTS / HMAC-SHA256-128 (RFC 8009). *)
module Aes128_cts_hmac_sha256_128 : ENCRYPTION_TYPE

(** etype 20: AES-256 / CTS / HMAC-SHA384-192 (RFC 8009). *)
module Aes256_cts_hmac_sha384_192 : ENCRYPTION_TYPE

(** {1 Dynamic dispatch} *)

val of_etype : int -> (module ENCRYPTION_TYPE) option
(** [of_etype n] returns the encryption-type module for wire etype number [n],
    or [None] if [n] is not supported.

    Supported etype numbers: 17, 18, 19, 20.
    For legacy etypes 16, 23, and 24 use [Mirage_crypto_kerberos_legacy.of_etype]. *)
