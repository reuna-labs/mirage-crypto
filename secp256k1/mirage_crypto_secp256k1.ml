type error = [ `Invalid_range | `Invalid_format | `Invalid_length | `Not_on_curve | `At_infinity ]
let pp_error ppf = function
  | `Invalid_range -> Format.pp_print_string ppf "invalid range"
  | `Invalid_format -> Format.pp_print_string ppf "invalid format"
  | `Invalid_length -> Format.pp_print_string ppf "invalid length"
  | `Not_on_curve -> Format.pp_print_string ppf "point not on curve"
  | `At_infinity -> Format.pp_print_string ppf "point at infinity"

external valid : string -> bool = "mc_k1_valid"
external parse_pub : string -> string = "mc_k1_parse_pub"
external public_key : string -> string -> string = "mc_k1_pub"
external sign_raw : string -> string -> string -> string = "mc_k1_sign"
external parse_sig : string -> bool -> string = "mc_k1_parse_sig"
external der : string -> string = "mc_k1_der"
external verify_raw : string -> string -> string -> bool = "mc_k1_verify"
external recover_raw : string -> string -> int -> string = "mc_k1_recover"
external xvalid : string -> bool = "mc_k1_xvalid"
external schnorr_sign : string -> string -> string -> string -> string = "mc_k1_schnorr_sign"
external schnorr_verify : string -> string -> string -> bool = "mc_k1_schnorr_verify"

let p = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xff\xff\xfc\x2f"
let n = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xfe\xba\xae\xdc\xe6\xaf\x48\xa0\x3b\xbf\xd2\x5e\x8c\xd0\x36\x41\x41"
type scalar = string
type priv = scalar
type pub = string
type signature = string
let scalar_of_octets s =
  if String.length s <> 32 then Error `Invalid_length
  else if valid s then Ok s else Error `Invalid_range
let scalar_to_octets s = s
let priv_of_octets = scalar_of_octets
let priv_to_octets = scalar_to_octets
let pub_of_octets s =
  let len = String.length s in
  if len <> 33 && len <> 65 then Error `Invalid_length
  else if (len = 33 && s.[0] <> '\002' && s.[0] <> '\003') || (len = 65 && s.[0] <> '\004') then Error `Invalid_format
  else if String.sub s 1 32 >= p || (len = 65 && String.sub s 33 32 >= p) then Error `Invalid_range
  else let pk = parse_pub s in if pk = "" then Error `Not_on_curve else Ok pk
let pub_to_octets ?(compress=true) pk =
  if compress then String.make 1 (Char.chr (2 + (Char.code pk.[64] land 1))) ^ String.sub pk 1 32 else pk
let pub_of_priv ?g key = public_key key (Mirage_crypto_rng.generate ?g 32)
let generate ?g () =
  let rec sample () =
    let sk = Mirage_crypto_rng.generate ?g 32 in if valid sk then sk else sample ()
  in let sk = sample () in sk, pub_of_priv ?g sk
let signature_of_octets s =
  let compact = String.length s = 64 in
  let sg = parse_sig s compact in
  if sg = "" then Error (if compact then `Invalid_range else `Invalid_format)
  else if not (valid (String.sub sg 0 32) && valid (String.sub sg 32 32)) then Error `Invalid_range
  else Ok sg
let signature_to_octets ?(compact=true) s = if compact then s else der s
let sign_recoverable ?g ~key msg =
  if String.length msg <> 32 then invalid_arg "Secp256k1.sign: digest must be 32 bytes";
  let s = sign_raw key msg (Mirage_crypto_rng.generate ?g 32) in
  String.sub s 0 64, Char.code s.[64]
let sign ?g ~key msg = fst (sign_recoverable ?g ~key msg)
let verify ~key sig_ msg = String.length msg = 32 && verify_raw key sig_ msg
let recover ~msg sig_ ~recid =
  if String.length msg <> 32 then Error `Invalid_length
  else if recid < 0 || recid > 3 then Error `Invalid_format
  else let pk = recover_raw sig_ msg recid in
    if pk = "" then Error `Not_on_curve else Ok pk

module Bip340 = struct
  type nonrec priv = priv
  type xonly_pub = string
  type signature = string
  let xonly_pub_of_octets s =
    if String.length s <> 32 then Error `Invalid_length
    else if xvalid s then Ok s else Error `Not_on_curve
  let xonly_pub_to_octets s = s
  let xonly_pub_of_priv ?g key = String.sub (pub_of_priv ?g key) 1 32
  let signature_of_octets s =
    if String.length s <> 64 then Error `Invalid_length
    else if String.sub s 0 32 >= p || String.sub s 32 32 >= n then Error `Invalid_range
    else Ok s
  let signature_to_octets s = s
  let sign ?g ?aux_rand ~key msg =
    let aux = match aux_rand with Some s -> s | None -> Mirage_crypto_rng.generate ?g 32 in
    if String.length aux <> 32 then invalid_arg "Bip340.sign: aux_rand must be 32 bytes";
    schnorr_sign key msg aux (Mirage_crypto_rng.generate ?g 32)
  let verify ~key sig_ msg = schnorr_verify key sig_ msg
end
