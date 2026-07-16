(* NOT CONSTANT TIME: plain double-and-add scalar multiplication in
   Jacobian coordinates. Timing leaks scalar bit patterns. Suitable for
   verification of public data or as a stepping stone toward a hardened
   implementation; not suitable for signing with secret keys in
   adversarial/timing-observable environments. See
   mirage_crypto_blockchain.mli for the full caveat. *)

type error =
  [ `Invalid_range | `Invalid_format | `Invalid_length | `Not_on_curve | `At_infinity ]

let pp_error ppf = function
  | `Invalid_range -> Format.fprintf ppf "invalid range"
  | `Invalid_format -> Format.fprintf ppf "invalid format"
  | `Invalid_length -> Format.fprintf ppf "invalid length"
  | `Not_on_curve -> Format.fprintf ppf "point not on curve"
  | `At_infinity -> Format.fprintf ppf "result is the point at infinity"

(* SEC2 curve parameters for secp256k1: y^2 = x^3 + 7 over F_p. *)

let p =
  Z.of_string
    ("0x" ^ "FFFFFFFF" ^ "FFFFFFFF" ^ "FFFFFFFF" ^ "FFFFFFFF" ^ "FFFFFFFF"
   ^ "FFFFFFFF" ^ "FFFFFFFE" ^ "FFFFFC2F")

let n =
  Z.of_string
    ("0x" ^ "FFFFFFFF" ^ "FFFFFFFF" ^ "FFFFFFFF" ^ "FFFFFFFE" ^ "BAAEDCE6"
   ^ "AF48A03B" ^ "BFD25E8C" ^ "D0364141")

let gx =
  Z.of_string
    ("0x" ^ "79BE667E" ^ "F9DCBBAC" ^ "55A06295" ^ "CE870B07" ^ "029BFCDB"
   ^ "2DCE28D9" ^ "59F2815B" ^ "16F81798")

let gy =
  Z.of_string
    ("0x" ^ "483ADA77" ^ "26A3C465" ^ "5DA4FBFC" ^ "0E1108A8" ^ "FD17B448"
   ^ "A6855419" ^ "9C47D08F" ^ "FB10D4B8")

let curve_b = Z.of_int 7
let half_n = Z.(n asr 1)

(* Field arithmetic mod p. *)
let fadd a b = Z.(erem (a + b) p)
let fsub a b = Z.(erem (a - b) p)
let fmul a b = Z.(erem (a * b) p)
let fsquare a = fmul a a
let finv a = Z.invert a p

type point = { x : Z.t; y : Z.t }
type scalar = Z.t
type priv = scalar
type pub = point

let g = { x = gx; y = gy }

let on_curve { x; y } = Z.equal (fmul y y) (fadd (fmul x (fmul x x)) curve_b)

(* Internal Jacobian representation: affine (X/Z^2, Y/Z^3). Used so that
   point addition/doubling avoid a modular inverse per operation; only
   [of_jacobian] needs one, to convert back to affine. *)
type jacobian = Infinity | Jacobian of Z.t * Z.t * Z.t

let to_jacobian { x; y } = Jacobian (x, y, Z.one)

let of_jacobian = function
  | Infinity -> None
  | Jacobian (x, y, z) ->
    let zinv = finv z in
    let zinv2 = fsquare zinv in
    let zinv3 = fmul zinv2 zinv in
    Some { x = fmul x zinv2; y = fmul y zinv3 }

(* dbl-2009-l, specialized for a = 0. *)
let jdouble = function
  | Infinity -> Infinity
  | Jacobian (x1, y1, z1) ->
    if Z.equal y1 Z.zero then Infinity
    else
      let two = Z.of_int 2 and three = Z.of_int 3 and eight = Z.of_int 8 in
      let a = fsquare x1 in
      let b = fsquare y1 in
      let c = fsquare b in
      let d = fmul two (fsub (fsquare (fadd x1 b)) (fadd a c)) in
      let e = fmul three a in
      let f = fsquare e in
      let x3 = fsub f (fmul two d) in
      let y3 = fsub (fmul e (fsub d x3)) (fmul eight c) in
      let z3 = fmul (fmul two y1) z1 in
      Jacobian (x3, y3, z3)

(* add-2007-bl. *)
let jadd p1 p2 =
  match (p1, p2) with
  | Infinity, q -> q
  | q, Infinity -> q
  | Jacobian (x1, y1, z1), Jacobian (x2, y2, z2) ->
    let two = Z.of_int 2 in
    let z1z1 = fsquare z1 in
    let z2z2 = fsquare z2 in
    let u1 = fmul x1 z2z2 in
    let u2 = fmul x2 z1z1 in
    let s1 = fmul (fmul y1 z2) z2z2 in
    let s2 = fmul (fmul y2 z1) z1z1 in
    if Z.equal u1 u2 then
      if Z.equal s1 s2 then jdouble p1 else Infinity
    else
      let h = fsub u2 u1 in
      let i = fsquare (fmul two h) in
      let j = fmul h i in
      let r = fmul two (fsub s2 s1) in
      let v = fmul u1 i in
      let x3 = fsub (fsub (fsquare r) j) (fmul two v) in
      let y3 = fsub (fmul r (fsub v x3)) (fmul (fmul two s1) j) in
      let z3 = fmul (fsub (fsub (fsquare (fadd z1 z2)) z1z1) z2z2) h in
      Jacobian (x3, y3, z3)

(* Plain MSB-to-LSB double-and-add. NOT constant time: the sequence of
   doublings/additions depends directly on the bits of [k]. *)
let scalar_mult_jacobian k pt =
  let bits = Z.numbits k in
  let acc = ref Infinity in
  for i = bits - 1 downto 0 do
    acc := jdouble !acc;
    if Z.testbit k i then acc := jadd !acc pt
  done;
  !acc

let z_of_octets_be = Octets.of_be
let z_to_octets_be = Octets.to_be
let gen_in_range = Octets.gen_in_range
let gen_scalar ?g () = gen_in_range ?g n

let scalar_of_octets s =
  if String.length s <> 32 then Error `Invalid_length
  else
    let z = z_of_octets_be s in
    if Z.zero < z && z < n then Ok z else Error `Invalid_range

let scalar_to_octets s = z_to_octets_be ~size:32 s

let point_of_octets s =
  match String.length s with
  | 33 -> (
    let prefix = Char.code s.[0] in
    if prefix <> 0x02 && prefix <> 0x03 then Error `Invalid_format
    else
      let x = z_of_octets_be (String.sub s 1 32) in
      if Z.(x < zero || x >= p) then Error `Invalid_range
      else
        let rhs = fadd (fmul x (fmul x x)) curve_b in
        let y0 = Z.powm rhs Z.((p + one) / Z.of_int 4) p in
        if not (Z.equal (fmul y0 y0) rhs) then Error `Not_on_curve
        else
          let is_odd = Z.testbit y0 0 in
          let want_odd = prefix = 0x03 in
          let y = if is_odd = want_odd then y0 else Z.sub p y0 in
          Ok { x; y })
  | 65 ->
    if Char.code s.[0] <> 0x04 then Error `Invalid_format
    else
      let x = z_of_octets_be (String.sub s 1 32) in
      let y = z_of_octets_be (String.sub s 33 32) in
      if Z.(x < zero || x >= p) || Z.(y < zero || y >= p) then Error `Invalid_range
      else if not (on_curve { x; y }) then Error `Not_on_curve
      else Ok { x; y }
  | _ -> Error `Invalid_length

let point_to_octets ?(compress = true) { x; y } =
  if compress then
    let prefix = if Z.testbit y 0 then '\x03' else '\x02' in
    String.make 1 prefix ^ z_to_octets_be ~size:32 x
  else
    "\x04" ^ z_to_octets_be ~size:32 x ^ z_to_octets_be ~size:32 y

let pub_of_priv d =
  match of_jacobian (scalar_mult_jacobian d (to_jacobian g)) with
  | Some pt -> pt
  | None -> assert false (* d in [1, n), and g has order n, so d*g <> Infinity *)

let generate ?g () =
  let d = gen_scalar ?g () in
  (d, pub_of_priv d)

let add p1 p2 =
  match of_jacobian (jadd (to_jacobian p1) (to_jacobian p2)) with
  | Some pt -> Ok pt
  | None -> Error `At_infinity

let scalar_mult k pt =
  match of_jacobian (scalar_mult_jacobian k (to_jacobian pt)) with
  | Some pt -> Ok pt
  | None -> Error `At_infinity

(* ECDSA, RFC 6979 deterministic nonce generation (mirrors
   pk/dsa.ml's K_gen pattern, reusing Mirage_crypto_rng.Hmac_drbg). *)
module K_gen (H : Digestif.S) = struct
  let drbg : 'a Mirage_crypto_rng.generator =
    let module M = Mirage_crypto_rng.Hmac_drbg (H) in
    (module M)

  let gen_k ~priv:d z =
    let g = Mirage_crypto_rng.create ~strict:true drbg in
    Mirage_crypto_rng.reseed ~g
      (z_to_octets_be ~size:32 d ^ z_to_octets_be ~size:32 (Z.erem z n));
    gen_in_range ~g n
end

module K_gen_sha256 = K_gen (Digestif.SHA256)

let sign_z ~priv:d z =
  let rec loop () =
    let k = K_gen_sha256.gen_k ~priv:d z in
    match of_jacobian (scalar_mult_jacobian k (to_jacobian g)) with
    | None -> loop () (* astronomically unlikely; treat as bad k, retry *)
    | Some { x; _ } ->
      let r = Z.erem x n in
      if Z.equal r Z.zero then loop ()
      else
        let kinv = Z.invert k n in
        let s = Z.(erem (kinv * erem (z + (r * d)) n) n) in
        if Z.equal s Z.zero then loop ()
        else
          let s = if Z.gt s half_n then Z.sub n s else s in
          (r, s)
  in
  loop ()

let verify_z ~pub:q (r, s) z =
  if not (Z.zero < r && r < n && Z.zero < s && s < n) then false
  else
    let w = Z.invert s n in
    let u1 = Z.(erem (z * w) n) in
    let u2 = Z.(erem (r * w) n) in
    let pt1 = scalar_mult_jacobian u1 (to_jacobian g) in
    let pt2 = scalar_mult_jacobian u2 (to_jacobian q) in
    match of_jacobian (jadd pt1 pt2) with
    | None -> false
    | Some { x; _ } -> Z.equal (Z.erem x n) r

type signature = { r : Z.t; s : Z.t }

(* Minimal DER encoder/decoder for a SEQUENCE of two non-negative
   INTEGERs (r, s), sufficient for 32-byte secp256k1 scalars (short-form
   lengths only). *)

let der_encode_integer z =
  let raw =
    if Z.equal z Z.zero then "\000"
    else z_to_octets_be ~size:((Z.numbits z + 7) / 8) z
  in
  let raw = if Char.code raw.[0] >= 0x80 then "\000" ^ raw else raw in
  Printf.sprintf "\x02%c%s" (Char.chr (String.length raw)) raw

let der_encode_signature r s =
  let body = der_encode_integer r ^ der_encode_integer s in
  let len = String.length body in
  if len < 128 then Printf.sprintf "\x30%c%s" (Char.chr len) body
  else Printf.sprintf "\x30\x81%c%s" (Char.chr len) body

let der_decode_integer s pos =
  if pos + 1 >= String.length s || Char.code s.[pos] <> 0x02 then Error `Invalid_format
  else
    let len_byte = Char.code s.[pos + 1] in
    if len_byte land 0x80 <> 0 then Error `Invalid_format
    else
      let start = pos + 2 in
      if start + len_byte > String.length s then Error `Invalid_format
      else Ok (z_of_octets_be (String.sub s start len_byte), start + len_byte)

let der_decode_signature s =
  if String.length s < 8 || Char.code s.[0] <> 0x30 then Error `Invalid_format
  else
    let len_byte = Char.code s.[1] in
    let seq_start = if len_byte land 0x80 = 0 then 2 else 2 + (len_byte land 0x7f) in
    match der_decode_integer s seq_start with
    | Error e -> Error e
    | Ok (r, pos2) -> (
      match der_decode_integer s pos2 with
      | Error e -> Error e
      | Ok (sv, _) -> Ok (r, sv))

let signature_of_octets s =
  match String.length s with
  | 64 ->
    let r = z_of_octets_be (String.sub s 0 32) in
    let sv = z_of_octets_be (String.sub s 32 32) in
    if Z.zero < r && r < n && Z.zero < sv && sv < n then Ok { r; s = sv }
    else Error `Invalid_range
  | _ -> (
    match der_decode_signature s with
    | Error e -> Error e
    | Ok (r, sv) ->
      if Z.zero < r && r < n && Z.zero < sv && sv < n then Ok { r; s = sv }
      else Error `Invalid_range)

let signature_to_octets ?(compact = true) { r; s } =
  if compact then scalar_to_octets r ^ scalar_to_octets s else der_encode_signature r s

let sign ~key:d msg =
  if String.length msg <> 32 then
    invalid_arg "Secp256k1.sign: digest must be 32 bytes";
  let z = z_of_octets_be msg in
  let r, s = sign_z ~priv:d z in
  { r; s }

let verify ~key:q { r; s } msg =
  String.length msg = 32 && verify_z ~pub:q (r, s) (z_of_octets_be msg)
