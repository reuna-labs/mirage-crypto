(* NOT CONSTANT TIME: built directly on {!Secp256k1}; inherits its
   timing-leak caveats. See mirage_crypto_blockchain.mli for the full
   caveat. Spec: BIP340,
   https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki *)

type error = Secp256k1.error

let pp_error = Secp256k1.pp_error

type priv = Secp256k1.scalar
type xonly_pub = Z.t

let tagged_hash = Hashes.tagged_hash

(* BIP340 "lift_x": the unique point on the curve with the given
   x-coordinate and an even y, or [None] if [x] is not on the curve. *)
let lift_x x =
  if Z.(x < zero || x >= Secp256k1.p) then None
  else
    let rhs = Secp256k1.fadd (Secp256k1.fmul x (Secp256k1.fmul x x)) Secp256k1.curve_b in
    let y0 = Z.powm rhs Z.((Secp256k1.p + one) / Z.of_int 4) Secp256k1.p in
    if not (Z.equal (Secp256k1.fmul y0 y0) rhs) then None
    else
      let y = if Z.testbit y0 0 then Z.sub Secp256k1.p y0 else y0 in
      Some Secp256k1.{ x; y }

let xonly_pub_of_octets s =
  if String.length s <> 32 then Error `Invalid_length
  else
    let x = Secp256k1.z_of_octets_be s in
    match lift_x x with None -> Error `Not_on_curve | Some _ -> Ok x

let xonly_pub_to_octets x = Secp256k1.z_to_octets_be ~size:32 x

let xonly_pub_of_priv d = (Secp256k1.pub_of_priv d).Secp256k1.x

type signature = { rx : Z.t; s : Z.t }

let signature_of_octets s =
  if String.length s <> 64 then Error `Invalid_length
  else
    let rx = Secp256k1.z_of_octets_be (String.sub s 0 32) in
    let sv = Secp256k1.z_of_octets_be (String.sub s 32 32) in
    if Z.(rx < zero || rx >= Secp256k1.p) then Error `Invalid_range
    else if Z.(sv < zero || sv >= Secp256k1.n) then Error `Invalid_range
    else Ok { rx; s = sv }

let signature_to_octets { rx; s } =
  Secp256k1.z_to_octets_be ~size:32 rx ^ Secp256k1.z_to_octets_be ~size:32 s

let xor_bytes a b =
  String.init (String.length a) (fun i -> Char.chr (Char.code a.[i] lxor Char.code b.[i]))

let challenge ~rx ~px msg =
  let bytes =
    tagged_hash ~tag:"BIP0340/challenge"
      (Secp256k1.z_to_octets_be ~size:32 rx ^ Secp256k1.z_to_octets_be ~size:32 px ^ msg)
  in
  Z.erem (Secp256k1.z_of_octets_be bytes) Secp256k1.n

let sign ?aux_rand ~key:d' msg =
  let aux_rand =
    match aux_rand with
    | Some a ->
      if String.length a <> 32 then invalid_arg "Bip340.sign: aux_rand must be 32 bytes";
      a
    | None -> String.make 32 '\000'
  in
  let p = Secp256k1.pub_of_priv d' in
  let d = if Z.testbit p.Secp256k1.y 0 then Z.sub Secp256k1.n d' else d' in
  let px = Secp256k1.z_to_octets_be ~size:32 p.Secp256k1.x in
  let t =
    xor_bytes (Secp256k1.z_to_octets_be ~size:32 d) (tagged_hash ~tag:"BIP0340/aux" aux_rand)
  in
  let rand = tagged_hash ~tag:"BIP0340/nonce" (t ^ px ^ msg) in
  let k' = Z.erem (Secp256k1.z_of_octets_be rand) Secp256k1.n in
  if Z.equal k' Z.zero then
    failwith "Bip340.sign: derived nonce is zero (retry with different aux_rand)"
  else
    let r_pt = Secp256k1.pub_of_priv k' in
    let k = if Z.testbit r_pt.Secp256k1.y 0 then Z.sub Secp256k1.n k' else k' in
    let rx = r_pt.Secp256k1.x in
    let e = challenge ~rx ~px:p.Secp256k1.x msg in
    let s = Z.erem Z.(k + (e * d)) Secp256k1.n in
    { rx; s }

let verify ~key:px { rx; s } msg =
  Z.(zero <= rx && rx < Secp256k1.p)
  && Z.(zero <= s && s < Secp256k1.n)
  &&
  match lift_x px with
  | None -> false
  | Some p ->
    let e = challenge ~rx ~px msg in
    (* R' = s*G - e*P = s*G + (n - e)*P *)
    let sg = Secp256k1.scalar_mult_jacobian s (Secp256k1.to_jacobian Secp256k1.g) in
    let neg_e = Z.erem (Z.neg e) Secp256k1.n in
    let ep = Secp256k1.scalar_mult_jacobian neg_e (Secp256k1.to_jacobian p) in
    (match Secp256k1.of_jacobian (Secp256k1.jadd sg ep) with
    | None -> false
    | Some r' -> (not (Z.testbit r'.Secp256k1.y 0)) && Z.equal r'.Secp256k1.x rx)
