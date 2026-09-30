type error = [ `Invalid_format | `Invalid_length | `Invalid_range | `Not_on_curve ]
let pp_error ppf e = Format.pp_print_string ppf (match e with
 | `Invalid_format -> "invalid format" | `Invalid_length -> "invalid length"
 | `Invalid_range -> "invalid range" | `Not_on_curve -> "not in curve subgroup")
type scalar = string
type g1 = string
type g2 = string
type gt = string
type priv = scalar
type pub = g1
type signature = g2
external scalar_valid : string -> bool = "mc_bls_scalar_valid"
external secret_valid : string -> bool = "mc_bls_secret_valid"
let scalar_of_octets s =
 if String.length s <> 32 then Error `Invalid_length
 else if scalar_valid s then Ok s else Error `Invalid_range
let scalar_to_octets s = s
let zero = String.make 32 '\000'
let generate ?g () =
 let rec sample () = let k = Mirage_crypto_rng.generate ?g 32 in
   if secret_valid k then k else sample () in sample ()
let p = "\x1a\x01\x11\xea\x39\x7f\xe6\x9a\x4b\x1b\xa7\xb6\x43\x4b\xac\xd7\x64\x77\x4b\x84\xf3\x85\x12\xbf\x67\x30\xd2\xa0\xf6\xb0\xf6\x24\x1e\xab\xff\xfe\xb1\x53\xff\xff\xb9\xfe\xff\xff\xff\xff\xaa\xab"
let r = "\x73\xed\xa7\x53\x29\x9d\x7d\x48\x33\x39\xd8\x08\x09\xa1\xd8\x05\x53\xbd\xa4\x02\xff\xfe\x5b\xfe\xff\xff\xff\xff\x00\x00\x00\x01"

external g1_parse : string -> g1 = "mc_bls_g1_parse"
external g1_serialize : g1 -> bool -> string = "mc_bls_g1_serialize"
external g1_gen : unit -> g1 = "mc_bls_g1_generator"
external g1_check : g1 -> int -> bool = "mc_bls_g1_check"
external g1_equal : g1 -> g1 -> bool = "mc_bls_g1_equal"
external g1_add : g1 -> g1 -> g1 = "mc_bls_g1_add"
external g1_neg : g1 -> g1 = "mc_bls_g1_neg"
external g1_mult : g1 -> scalar -> g1 = "mc_bls_g1_mult"
let g1_of_octets s =
 let len = String.length s in
 if len <> 48 && len <> 96 then Error `Invalid_length
 else if (Char.code s.[0] land 128 <> 0) <> (len = 48) then Error `Invalid_format
 else let p = g1_parse s in if p = "" then Error `Not_on_curve else Ok p
let g1_to_octets ?(compress=true) p = g1_serialize p compress
let g1_generator = g1_gen ()
let g1_is_infinity p = g1_check p 0
let g1_on_curve p = g1_check p 1
let g1_in_subgroup p = g1_check p 2
let g1_scalar_mult k p = g1_mult p k

external g2_parse : string -> g2 = "mc_bls_g2_parse"
external g2_serialize : g2 -> bool -> string = "mc_bls_g2_serialize"
external g2_gen : unit -> g2 = "mc_bls_g2_generator"
external g2_check : g2 -> int -> bool = "mc_bls_g2_check"
external g2_equal : g2 -> g2 -> bool = "mc_bls_g2_equal"
external g2_add : g2 -> g2 -> g2 = "mc_bls_g2_add"
external g2_neg : g2 -> g2 = "mc_bls_g2_neg"
external g2_mult : g2 -> scalar -> g2 = "mc_bls_g2_mult"
let g2_of_octets s =
 let len = String.length s in
 if len <> 96 && len <> 192 then Error `Invalid_length
 else if (Char.code s.[0] land 128 <> 0) <> (len = 96) then Error `Invalid_format
 else let p = g2_parse s in if p = "" then Error `Not_on_curve else Ok p
let g2_to_octets ?(compress=true) p = g2_serialize p compress
let g2_generator = g2_gen ()
let g2_is_infinity p = g2_check p 0
let g2_on_curve p = g2_check p 1
let g2_in_subgroup p = g2_check p 2
let g2_scalar_mult k p = g2_mult p k

external hash : string -> string -> g2 = "mc_bls_hash"
external pub_of_priv : priv -> pub = "mc_bls_pub"
external sign_hash : priv -> g2 -> signature = "mc_bls_sign"
external miller : g2 -> g1 -> gt = "mc_bls_miller"
external final_exp : gt -> gt = "mc_bls_final"
external gt_mul : gt -> gt -> gt = "mc_bls_gt_mul"
external gt_equal : gt -> gt -> bool = "mc_bls_gt_equal"
external final_verify : gt -> gt -> bool = "mc_bls_final_verify"
let dst_g2_sig = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"
let hash_to_curve_g2 ?(dst=dst_g2_sig) msg = hash dst msg
let pairing q p = final_exp (miller q p)
let sign ~key msg = sign_hash key (hash_to_curve_g2 msg)
let verify ~key sig_ msg =
 not (g1_is_infinity key || g2_is_infinity sig_) &&
 g1_in_subgroup key && g2_in_subgroup sig_ &&
 final_verify (miller sig_ g1_generator) (miller (hash_to_curve_g2 msg) key)
let g2_zero = g2_scalar_mult zero g2_generator
let aggregate signatures = List.fold_left g2_add g2_zero signatures
let aggregate_verify pairs agg =
 let msgs = List.map snd pairs in
 if pairs = [] || List.length (List.sort_uniq String.compare msgs) <> List.length msgs ||
   g2_is_infinity agg || not (g2_in_subgroup agg) ||
   List.exists (fun (pk,_) -> g1_is_infinity pk || not (g1_in_subgroup pk)) pairs then false
 else
   let rhs = List.fold_left (fun acc (pk,msg) -> gt_mul acc (miller (hash_to_curve_g2 msg) pk))
     (miller g2_zero g1_generator) pairs in
   final_verify (miller agg g1_generator) rhs
