(* NOT CONSTANT TIME: plain double-and-add scalar multiplication in
   Jacobian coordinates (for key generation), and a mix of Jacobian and
   affine arithmetic for the StarkEx signature-verification algorithm.
   See mirage_crypto_blockchain.mli for the full caveat.

   The StarkNet/StarkEx curve y^2 = x^3 + alpha*x + beta over the
   STARK-friendly prime field, and its ECDSA-variant signature scheme.
   Parameters and algorithm cross-checked directly against StarkWare's
   own reference implementation:
   https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/crypto/signature/signature.py
   https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/crypto/signature/pedersen_params.json
   https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/crypto/signature/math_utils.py

   This is a StarkEx-specific ECDSA variant, not textbook ECDSA: [r] is
   used directly (not reduced mod the curve order), [s] is the modular
   inverse of an intermediate value [w] rather than computed directly,
   and verification uses [mimic_ec_mult_air], which walks the scalar
   LSB-first and fails (mirroring an assertion in StarkWare's own code)
   whenever an intermediate sum would require adding two points that
   share an affine x-coordinate -- exactly the case their circuit's
   simplified addition formula cannot represent. See "Default Signing" /
   "Verification" analogues in signature.py's [sign]/[verify] for the
   full algorithm this ports. *)

type error = [ `Invalid_range | `Invalid_format | `Not_on_curve | `At_infinity ]

let pp_error ppf = function
  | `Invalid_range -> Format.fprintf ppf "invalid range"
  | `Invalid_format -> Format.fprintf ppf "invalid format"
  | `Not_on_curve -> Format.fprintf ppf "point not on curve"
  | `At_infinity -> Format.fprintf ppf "result is the point at infinity"

(* p = 2^251 + 17*2^192 + 1 *)
let p = Z.of_string "3618502788666131213697322783095070105623107215331596699973092056135872020481"
let alpha = Z.one
let beta = Z.of_string "3141592653589793238462643383279502884197169399375105820974944592307816406665"
let n = Z.of_string "3618502788666131213697322783095070105526743751716087489154079457884512865583"

let n_bits = 251
let n_bits_bound = Z.(one lsl n_bits)

let gx = Z.of_string "874739451078007766457464989774322083649278607533249481151382481072868806602"
let gy = Z.of_string "152666792071518830868575557812948353041420400780739481342941381225525861407"

let shift_x =
  Z.of_string "2089986280348253421170679821480865132823066470938446095505822317253594081284"
let shift_y =
  Z.of_string "1713931329540660377023406109199410414810705867260802078187082345529207694986"

let fadd a b = Z.(erem (a + b) p)
let fsub a b = Z.(erem (a - b) p)
let fmul a b = Z.(erem (a * b) p)
let fsquare a = fmul a a
let finv a = Z.invert a p

type point = { x : Z.t; y : Z.t }
type scalar = Z.t
type priv = scalar
type pub = point

type field_element = Z.t
(** A representative in [[0, p)]; the natural message type for this
    curve's signature scheme (typically a Pedersen-hash digest), not an
    arbitrary byte string. Interchangeable with {!Poseidon.field_element}
    once a shared field is decided (see {!Poseidon}'s doc comment). *)

let g = { x = gx; y = gy }
let shift_point = { x = shift_x; y = shift_y }
let minus_shift_point = { x = shift_x; y = Z.sub p shift_y }

let on_curve { x; y } =
  Z.equal (fmul y y) (fadd (fadd (fmul x (fmul x x)) (fmul alpha x)) beta)

(* Internal Jacobian representation, as in secp256k1.ml. *)
type jacobian = Infinity | Jacobian of Z.t * Z.t * Z.t

let to_jacobian { x; y } = Jacobian (x, y, Z.one)

let of_jacobian = function
  | Infinity -> None
  | Jacobian (x, y, z) ->
    let zinv = finv z in
    let zinv2 = fsquare zinv in
    let zinv3 = fmul zinv2 zinv in
    Some { x = fmul x zinv2; y = fmul y zinv3 }

(* dbl-2007-bl (general [a], unlike secp256k1's a=0-specialized formula). *)
let jdouble = function
  | Infinity -> Infinity
  | Jacobian (x1, y1, z1) ->
    if Z.equal y1 Z.zero then Infinity
    else
      let two = Z.of_int 2 and three = Z.of_int 3 and eight = Z.of_int 8 in
      let xx = fsquare x1 in
      let yy = fsquare y1 in
      let yyyy = fsquare yy in
      let zz = fsquare z1 in
      let s = fmul two (fsub (fsub (fsquare (fadd x1 yy)) xx) yyyy) in
      let m = fadd (fmul three xx) (fmul alpha (fsquare zz)) in
      let t = fsub (fsquare m) (fmul two s) in
      let x3 = t in
      let y3 = fsub (fmul m (fsub s t)) (fmul eight yyyy) in
      let z3 = fsub (fsub (fsquare (fadd y1 z1)) yy) zz in
      Jacobian (x3, y3, z3)

(* add-2007-bl, same as secp256k1.ml (the addition formula doesn't depend
   on [a]). *)
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

(* Plain MSB-to-LSB double-and-add, used for key generation
   (pub_of_priv). NOT constant time. *)
let scalar_mult_jacobian k pt =
  let bits = Z.numbits k in
  let acc = ref Infinity in
  for i = bits - 1 downto 0 do
    acc := jdouble !acc;
    if Z.testbit k i then acc := jadd !acc pt
  done;
  !acc

(* [same_x p1 p2] holds iff [p1] and [p2] share the same affine
   x-coordinate (i.e. are equal or negatives of each other) -- mirroring
   the [assert (point1[0] - point2[0]) % p != 0] in StarkWare's [ec_add],
   which their simplified addition formula cannot handle. Jacobian
   infinity is conservatively treated as always colliding, since the
   reference implementation has no representation for it at all (its
   [ECPoint] is a plain coordinate pair). *)
let same_x p1 p2 =
  match (p1, p2) with
  | Jacobian (x1, _, z1), Jacobian (x2, _, z2) ->
    Z.equal (fmul x1 (fsquare z2)) (fmul x2 (fsquare z1))
  | _ -> true

(* [jadd_checked p1 p2] is [None] iff [same_x p1 p2]. *)
let jadd_checked p1 p2 = if same_x p1 p2 then None else Some (jadd p1 p2)

(* Ports [mimic_ec_mult_air]: walks [m] LSB-first, doubling [point] each
   step and conditionally adding it into [partial_sum] (itself seeded
   with [shift_point], to keep the STARK-provable circuit's addition
   formula away from the doubling/infinity special cases along typical
   inputs). Fails (returns [None]) as soon as an addition would require
   summing two points with equal affine x-coordinates, exactly as the
   reference implementation's per-step assertion does. Operates
   throughout on the internal [jacobian] representation; callers convert
   to affine ([of_jacobian]) only where the algorithm actually needs it. *)
let mimic_ec_mult_air m (point : jacobian) (shift_point : jacobian) : jacobian option =
  if not Z.(zero < m && m < n_bits_bound) then None
  else
    let exception Fail in
    let partial_sum = ref shift_point in
    let pt = ref point in
    let mm = ref m in
    try
      for _ = 1 to n_bits do
        if same_x !partial_sum !pt then raise Fail;
        if Z.testbit !mm 0 then partial_sum := jadd !partial_sum !pt;
        pt := jdouble !pt;
        mm := Z.shift_right !mm 1
      done;
      Some !partial_sum
    with Fail -> None

let scalar_of_octets s =
  if String.length s <> 32 then Error `Invalid_range
  else
    let z = Octets.of_be s in
    if Z.zero <= z && z < n then Ok z else Error `Invalid_range

let point_of_octets s =
  if String.length s <> 64 then Error `Invalid_format
  else
    let x = Octets.of_be (String.sub s 0 32) in
    let y = Octets.of_be (String.sub s 32 32) in
    if Z.(x < zero || x >= p) || Z.(y < zero || y >= p) then Error `Invalid_range
    else
      let pt = { x; y } in
      if on_curve pt then Ok pt else Error `Not_on_curve

let point_to_octets { x; y } = Octets.to_be ~size:32 x ^ Octets.to_be ~size:32 y

let pub_of_priv d =
  match of_jacobian (scalar_mult_jacobian d (to_jacobian g)) with
  | Some pt -> pt
  | None -> assert false (* d in [1, n), and g has order n, so d*g <> Infinity *)

let field_element_of_octets s =
  if String.length s <> 32 then Error `Invalid_range
  else
    let z = Octets.of_be s in
    if Z.zero <= z && z < p then Ok z else Error `Invalid_range

let field_element_to_octets z = Octets.to_be ~size:32 z

let generate ?g () =
  let d = Octets.gen_in_range ?g n in
  (d, pub_of_priv d)

let add p1 p2 =
  match of_jacobian (jadd (to_jacobian p1) (to_jacobian p2)) with
  | Some pt -> Ok pt
  | None -> Error `At_infinity

let scalar_mult k pt =
  match of_jacobian (scalar_mult_jacobian k (to_jacobian pt)) with
  | Some pt -> Ok pt
  | None -> Error `At_infinity

type signature = { r : Z.t; s : Z.t }

(* Deterministic nonce generation via HMAC_DRBG (mirrors
   secp256k1.ml's K_gen). This is our own design choice for a
   collision-safe, deterministic [k] -- it is NOT bit-for-bit identical
   to StarkWare's own [generate_k_rfc6979] (which has its own padding
   and extra-entropy conventions on top of python-ecdsa's RFC 6979).
   That's fine: interoperability only requires that signatures we
   produce verify correctly (which they do, both against our own
   [verify] and, since [verify] itself is a faithful port, against any
   spec-compliant verifier); it does not require reproducing StarkWare's
   exact nonce byte-for-byte. *)
module K_gen (H : Digestif.S) = struct
  let drbg : 'a Mirage_crypto_rng.generator =
    let module M = Mirage_crypto_rng.Hmac_drbg (H) in
    (module M)

  let gen_k ~priv:d msg_hash =
    let g = Mirage_crypto_rng.create ~strict:true drbg in
    Mirage_crypto_rng.reseed ~g
      (Octets.to_be ~size:32 d ^ Octets.to_be ~size:32 (Z.erem msg_hash n));
    Octets.gen_in_range ~g n
end

module K_gen_sha256 = K_gen (Digestif.SHA256)

let sign ~key:d msg_hash =
  if not Z.(zero <= msg_hash && msg_hash < n_bits_bound) then
    invalid_arg "Stark_curve.sign: msg_hash must be in [0, 2^251)";
  let rec loop () =
    let k = K_gen_sha256.gen_k ~priv:d msg_hash in
    match of_jacobian (scalar_mult_jacobian k (to_jacobian g)) with
    | None -> loop ()
    | Some { x = r; _ } ->
      if not Z.(one <= r && r < n_bits_bound) then loop ()
      else
        let denom = Z.erem Z.(msg_hash + (r * d)) n in
        if Z.equal denom Z.zero then loop ()
        else
          let w = Z.(erem (k * invert denom n) n) in
          if not Z.(one <= w && w < n_bits_bound) then loop ()
          else { r; s = Z.invert w n }
  in
  loop ()

let verify ~key:pub { r; s } msg_hash =
  Z.(one <= s && s < n)
  && Z.(one <= r && r < n_bits_bound)
  && Z.(zero <= msg_hash && msg_hash < n_bits_bound)
  && on_curve pub
  &&
  let w = Z.invert s n in
  Z.(one <= w && w < n_bits_bound)
  &&
  let jg = to_jacobian g and j_shift = to_jacobian shift_point in
  let j_minus_shift = to_jacobian minus_shift_point in
  match mimic_ec_mult_air msg_hash jg j_minus_shift with
  | None -> false
  | Some zg -> (
    match mimic_ec_mult_air r (to_jacobian pub) j_shift with
    | None -> false
    | Some rq -> (
      match jadd_checked zg rq with
      | None -> false
      | Some sum -> (
        match mimic_ec_mult_air w sum j_shift with
        | None -> false
        | Some wb -> (
          match jadd_checked wb j_minus_shift with
          | None -> false
          | Some final -> (
            match of_jacobian final with
            | None -> false
            | Some { x; _ } -> Z.equal x r)))))

let signature_of_octets s =
  if String.length s <> 64 then Error `Invalid_range
  else
    let r = Octets.of_be (String.sub s 0 32) in
    let sv = Octets.of_be (String.sub s 32 32) in
    if Z.(one <= r && r < n_bits_bound) && Z.(one <= sv && sv < n) then Ok { r; s = sv }
    else Error `Invalid_range

let signature_to_octets { r; s } = Octets.to_be ~size:32 r ^ Octets.to_be ~size:32 s
