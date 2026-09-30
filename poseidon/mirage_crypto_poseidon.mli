(** StarkWare Poseidon, width 3, rate 2, 8 full and 83 partial rounds.
    CryptoExperts ISO C backend. No claim of formal verification or independent
    audit. Input length is public. See BACKENDS.md for validation evidence and
    limitations. OCaml copies of secret field elements are not erased. *)

type error = [ `Invalid_length | `Invalid_range ]
type field_element
val field_element_of_octets : string -> (field_element, error) result
(** Canonical 32-byte big-endian integer in [0, 2^251 + 17*2^192 + 1). *)

val field_element_to_octets : field_element -> string
val hash_pair : field_element -> field_element -> field_element
val hash_single : field_element -> field_element
val hash : field_element list -> field_element
