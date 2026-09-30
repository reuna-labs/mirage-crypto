(* Compatibility boundary: converting secret Z.t values is variable-time.
   Production callers should use Mirage_crypto_secp256k1 directly. *)
module Native = Mirage_crypto_secp256k1
module Group = Mirage_crypto_ec.P256k1.Primitive
type error = Native.error
let pp_error = Native.pp_error
let p = Octets.of_be Native.p
let n = Octets.of_be Native.n
type point = { x : Z.t; y : Z.t }
type scalar = Z.t
type priv = scalar
type pub = point
let unwrap = function Ok x -> x | Error _ -> invalid_arg "Secp256k1: invalid internal value"
let scalar_to_octets = Octets.to_be ~size:32
let native_scalar s = unwrap (Native.scalar_of_octets (scalar_to_octets s))
let scalar_of_octets s = Result.map (fun _ -> Octets.of_be s) (Native.scalar_of_octets s)
let of_native p =
  let s = Native.pub_to_octets ~compress:false p in
  { x = Octets.of_be (String.sub s 1 32); y = Octets.of_be (String.sub s 33 32) }
let point_to_octets ?(compress=true) {x;y} =
  if compress then String.make 1 (if Z.testbit y 0 then '\003' else '\002') ^ Octets.to_be ~size:32 x
  else "\004" ^ Octets.to_be ~size:32 x ^ Octets.to_be ~size:32 y
let to_native p = unwrap (Native.pub_of_octets (point_to_octets p))
let point_of_octets s = Result.map of_native (Native.pub_of_octets s)
let g = unwrap (point_of_octets ("\002" ^ Octets.to_be ~size:32 (Z.of_string "0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")))
let pub_of_priv d = of_native (Native.pub_of_priv (native_scalar d))
let generate ?g () =
  let d,p = Native.generate ?g () in Octets.of_be (Native.scalar_to_octets d), of_native p
let to_group p = match Group.point_of_octets (point_to_octets p) with
  | Ok x -> x | Error _ -> invalid_arg "Secp256k1: invalid point"
let from_group p = if Group.point_is_infinity p then Error `At_infinity else point_of_octets (Group.point_to_octets p)
let add a b = from_group (Group.point_add (to_group a) (to_group b))
let scalar_mult k p = from_group (Group.scalar_mult (scalar_to_octets k) (to_group p))
type signature = Native.signature
let signature_of_octets = Native.signature_of_octets
let signature_to_octets = Native.signature_to_octets
let sign ~key msg = Native.sign ~key:(native_scalar key) msg
let verify ~key sig_ msg = Native.verify ~key:(to_native key) sig_ msg
let sign_recoverable ~key msg = Native.sign_recoverable ~key:(native_scalar key) msg
let recover ~msg sig_ ~recid = Result.map of_native (Native.recover ~msg sig_ ~recid)
