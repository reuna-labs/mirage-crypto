(** AES Key Wrap (RFC 3394) and AES Key Wrap with Padding (RFC 5649).

    A deterministic, nonce-free way to protect key material under another key,
    integrity included. Paired with RSA-OAEP this is PKCS#11's
    [CKM_RSA_AES_KEY_WRAP], which is how key material travels between an
    application and an HSM, a KMIP service or a cloud KMS.

    Not a general-purpose cipher: the value is held entirely in memory and
    processed in six passes over it, so this is for keys, not messages. *)

(** The key wrap interface, as a signature so it can be instantiated for any
    128-bit block cipher. RFC 3394 is defined for AES only, and {!AES} is the
    instantiation anyone should use. *)
module type S = sig

  type key

  val of_secret : string -> key
  (** [of_secret secret] is the key-encryption key.

      @raise Invalid_argument if the length of [secret] is not in
      {{!key_sizes}[key_sizes]}. *)

  val key_sizes : int array
  (** Key sizes allowed with this cipher. *)

  val wrap : key:key -> string -> string
  (** [wrap ~key data] is RFC 3394 key wrap. The result is 8 octets longer than
      [data].

      @raise Invalid_argument
        if [data] is not a multiple of 8 octets, or is shorter than 16. *)

  val unwrap : key:key -> string -> string option
  (** [unwrap ~key data] reverses {!wrap}, or is [None] if the integrity check
      fails. *)

  val wrap_padded : key:key -> string -> string
  (** [wrap_padded ~key data] is RFC 5649 key wrap with padding, which accepts
      any length from one octet upwards.

      @raise Invalid_argument if [data] is empty. *)

  val unwrap_padded : key:key -> string -> string option
  (** [unwrap_padded ~key data] reverses {!wrap_padded}, or is [None] if any
      check fails.

      A wrong initial value, an impossible length and non-zero padding are
      deliberately indistinguishable: reporting which one failed would make
      this an oracle against [key]. *)
end

(** AES key wrap, the only instantiation RFC 3394 defines. *)
module AES : S
