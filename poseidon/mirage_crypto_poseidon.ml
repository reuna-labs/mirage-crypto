type error = [ `Invalid_length | `Invalid_range ]
type field_element = string
external valid : string -> bool = "mc_poseidon_valid"
external hash_raw : int -> string -> string = "mc_poseidon_hash"
let field_element_of_octets s =
 if String.length s <> 32 then Error `Invalid_length
 else if valid s then Ok s else Error `Invalid_range
let field_element_to_octets s = s
let hash_pair x y = hash_raw 2 (x ^ y)
let hash_single x = hash_raw 1 x
let hash xs = hash_raw 0 (String.concat "" xs)
