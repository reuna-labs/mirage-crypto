type error = [ `Invalid_format | `Invalid_length | `Invalid_derivation ]

let pp_error ppf = function
  | `Invalid_format -> Format.pp_print_string ppf "invalid format"
  | `Invalid_length -> Format.pp_print_string ppf "invalid length"
  | `Invalid_derivation -> Format.pp_print_string ppf "invalid derivation"

type extended_priv = string
type extended_pub = string

external private_valid : string -> bool = "mc_edb32_priv_valid_stub"
external public_valid : string -> bool = "mc_edb32_pub_valid_stub"
external root : string -> string -> string = "mc_edb32_root_stub"
external pub_of_priv : extended_priv -> extended_pub = "mc_edb32_public_stub"

external derive_private : extended_priv -> int32 -> string
  = "mc_edb32_derive_priv_stub"

external derive_public : extended_pub -> int32 -> string
  = "mc_edb32_derive_pub_stub"

external sign_raw : extended_priv -> string -> string = "mc_edb32_sign_stub"

external verify_native : string -> string -> string -> bool
  = "mc_edb32_verify_stub"

external icarus : string -> string -> string = "mc_edb32_icarus_stub"

let extended_priv_of_octets s =
  if String.length s <> 96 then Error `Invalid_length
  else if private_valid s then Ok s
  else Error `Invalid_format

let extended_priv_to_octets s = s

let extended_pub_of_octets s =
  if String.length s <> 64 then Error `Invalid_length
  else if public_valid (String.sub s 0 32) then Ok s
  else Error `Invalid_format

let extended_pub_to_octets s = s
let derivation s = if s = "" then Error `Invalid_derivation else Ok s

let master_key_of_seed seed =
  root
    Digestif.SHA512.(to_raw_string (digest_string seed))
    Digestif.SHA256.(to_raw_string (digest_string ("\001" ^ seed)))
  |> derivation

let is_hardened i = Int32.logand i Int32.min_int <> 0l

let derive_priv_normal key ~index =
  if is_hardened index then Error `Invalid_derivation
  else derivation (derive_private key index)

let derive_priv_hardened key ~index =
  if not (is_hardened index) then Error `Invalid_derivation
  else derivation (derive_private key index)

let derive_pub_normal key ~index =
  if is_hardened index then Error `Invalid_derivation
  else derivation (derive_public key index)

let sign ~key msg = sign_raw key msg

let verify_raw ~key signature ~msg =
  String.length key = 32
  && String.length signature = 64
  && verify_native key signature msg

let verify ~key signature ~msg =
  verify_raw ~key:(String.sub key 0 32) signature ~msg

let icarus_key_of_entropy ?(passphrase = "") entropy =
  let n = String.length entropy in
  if n < 16 || n > 32 then Error `Invalid_length
  else Ok (icarus entropy passphrase)
