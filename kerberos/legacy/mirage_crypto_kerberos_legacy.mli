(** Kerberos 5 legacy cipher suites (etypes 16, 23, 24).

    Provides 3DES-CBC/SHA1 (RFC 3961) and RC4-HMAC-MD5 (MS-KILE / RFC 4757)
    alongside the AES suites from {!Mirage_crypto_kerberos}.

    Depend on this package only when you must interoperate with legacy Kerberos
    deployments.  These cipher suites have known weaknesses: 3DES has a 64-bit
    block size (Sweet32 attack) and RC4 is cryptographically broken. *)

module type ENCRYPTION_TYPE = Mirage_crypto_kerberos.ENCRYPTION_TYPE

(** {1 AES-CTS cipher suites (re-exported from {!Mirage_crypto_kerberos})} *)

module Aes128_cts_hmac_sha1_96    : ENCRYPTION_TYPE
module Aes256_cts_hmac_sha1_96    : ENCRYPTION_TYPE
module Aes128_cts_hmac_sha256_128 : ENCRYPTION_TYPE
module Aes256_cts_hmac_sha384_192 : ENCRYPTION_TYPE

(** {1 3DES cipher suite} *)

(** etype 16: 3DES-CBC / SHA-1-KD (RFC 3961).
    @deprecated Sweet32 (CVE-2016-2183); use an AES etype instead. *)
module Des3_cbc_sha1_kd : ENCRYPTION_TYPE

(** {1 RC4 cipher suites (MS-KILE / Active Directory)} *)

(** etype 23: RC4-HMAC-MD5 (MS-KILE).
    @deprecated RC4 is cryptographically broken; use an AES etype instead. *)
module Arcfour_hmac : ENCRYPTION_TYPE

(** etype 24: RC4-HMAC-MD5-EXP — 40-bit effective key (MS-KILE).
    @deprecated RC4 is cryptographically broken and this variant further
    weakens the key to 40 bits. *)
module Arcfour_hmac_exp : ENCRYPTION_TYPE

(** {1 Dynamic dispatch} *)

val of_etype : int -> (module ENCRYPTION_TYPE) option
(** [of_etype n] returns the encryption-type module for wire etype number [n],
    or [None] if [n] is not supported.

    Supported etype numbers: 16, 17, 18, 19, 20, 23, 24. *)
