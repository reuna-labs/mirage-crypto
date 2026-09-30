(* BLS12-381 pairing-friendly curve: full stack -- generic extension-field
   arithmetic (used to build Fp2 and Fp12), G1/G2 affine group arithmetic,
   the optimal ate pairing (Miller loop followed by a literal, unoptimized
   final exponentiation by (p^12-1)/r), RFC 9380 hash-to-curve for G2, and
   BLS signatures in the "minimal-pubkey-size" configuration (public keys
   in G1, signatures in G2), following the "basic" scheme of
   draft-irtf-cfrg-bls-signature (distinct messages per aggregate_verify;
   no proof-of-possession / augmentation).

   NOT CONSTANT TIME: plain double-and-add scalar multiplication and
   branch-on-value (Simplified) SWU mapping, matching this package's
   Secp256k1 / Bip340 / Stark_curve stance. This is a quick reference
   implementation, not hardened against timing side channels.

   Every numeric constant below (the prime, curve/generator parameters,
   the RFC 9380 isogeny-map coefficients, the ate loop count, and the
   final-exponentiation exponent) was cross-checked against primary
   sources rather than reconstructed from memory:
   - RFC 9380 (hash-to-curve), sections 4, 5, 6.6, 8.8, and its official
     BLS12381G2_XMD:SHA-256_SSWU_RO_ test vectors (Appendix J.10.1), used
     verbatim in this package's test suite;
   - draft-irtf-cfrg-pairing-friendly-curves, section 4.2.1 (BLS12-381
     field/curve parameters and generators) and Appendix C (the "ZCash"
     point serialization format also used by draft-irtf-cfrg-bls-signature
     and the zkcrypto/blst implementations);
   - py_ecc (the Ethereum Foundation's reference BLS12-381 implementation),
     whose generic-extension-field, Miller-loop, and twist/cast strategy
     is ported here nearly line-for-line for the highest-risk arithmetic.

   Scope note: hash-to-curve is implemented only for G2, which is all the
   "minimal-pubkey-size" BLS signature scheme used here requires (messages
   hash into G2; public keys are plain scalar multiples of the G1
   generator). G1 hash-to-curve (an 11-isogeny map, per RFC 9380 Appendix
   E.2) is not implemented, to avoid transcribing that map's ~50 more huge
   constants for no use in this module's signature scheme. *)

type error =
  [ `Invalid_format | `Invalid_length | `Invalid_range | `Not_on_curve ]

let pp_error ppf = function
  | `Invalid_format -> Format.fprintf ppf "invalid format"
  | `Invalid_length -> Format.fprintf ppf "invalid length"
  | `Invalid_range -> Format.fprintf ppf "invalid range"
  | `Not_on_curve -> Format.fprintf ppf "point not on curve"

(* ---------------------------------------------------------------------- *)
(* Base field Fp. *)

let p =
  Z.of_string
    "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"

(* Subgroup order r, shared by G1 and G2. *)
let r =
  Z.of_string
    "0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"

let fmod z = Z.erem z p
let fadd a b = fmod (Z.add a b)
let fsub a b = fmod (Z.sub a b)
let fneg a = fmod (Z.neg a)
let fmul a b = fmod (Z.mul a b)
let fsquare a = fmul a a
let finv a = Z.invert a p
let fp_inv0 a = if Z.equal a Z.zero then Z.zero else finv a
let fp_pow a e = Z.powm a e p
let p_minus_1_div_2 = Z.div (Z.sub p Z.one) (Z.of_int 2)
let p_plus_1_div_4 = Z.div (Z.add p Z.one) (Z.of_int 4)
let inv2 = finv (Z.of_int 2)

(* p is 3 mod 4, so sqrt(a) = a^((p+1)/4) whenever a is a square. *)
let fp_sqrt a = fp_pow a p_plus_1_div_4

(* Euler's criterion: true for 0 and for nonzero quadratic residues. *)
let fp_is_square a = not (Z.equal (fp_pow a p_minus_1_div_2) (Z.sub p Z.one))
let fp_sign y = Z.gt y p_minus_1_div_2

(* ---------------------------------------------------------------------- *)
(* Generic polynomial-extension-field arithmetic, used below only to build
   Fp12 (as a degree-12 extension of Fp with modulus w^12 - 2*w^6 + 2, the
   flat, non-tower representation used by py_ecc). Elements are [Z.t array]
   of length [degree]; multiplication is schoolbook convolution followed
   by reduction using [modulus_coeffs] (x^degree = -sum modulus_coeffs.(i)
   * x^i); inversion is the extended-Euclidean algorithm on the
   coefficient (base-field) polynomials, which is what makes Fp12
   inversion cheap enough to call inside the Miller loop. *)

module type Fqp_params = sig
  val degree : int
  val modulus_coeffs : Z.t array
end

module MakeFqp (P : Fqp_params) = struct
  let degree = P.degree
  let zero () = Array.make degree Z.zero

  let one () =
    let a = zero () in
    a.(0) <- Z.one;
    a

  let equal a b =
    let ok = ref true in
    Array.iteri (fun i x -> if not (Z.equal x b.(i)) then ok := false) a;
    !ok

  let is_zero a = Array.for_all (fun x -> Z.equal x Z.zero) a
  let add a b = Array.init degree (fun i -> fadd a.(i) b.(i))
  let sub a b = Array.init degree (fun i -> fsub a.(i) b.(i))
  let neg a = Array.init degree (fun i -> fneg a.(i))
  let scale a c = Array.init degree (fun i -> fmul a.(i) c)

  let mul a b =
    let conv = Array.make ((2 * degree) - 1) Z.zero in
    for i = 0 to degree - 1 do
      for j = 0 to degree - 1 do
        conv.(i + j) <- fadd conv.(i + j) (fmul a.(i) b.(j))
      done
    done;
    let cur = ref conv in
    let len = ref (Array.length conv) in
    while !len > degree do
      let top = !cur.(!len - 1) in
      let exp = !len - degree - 1 in
      let nb = Array.sub !cur 0 (!len - 1) in
      for i = 0 to degree - 1 do
        nb.(exp + i) <- fsub nb.(exp + i) (fmul top P.modulus_coeffs.(i))
      done;
      cur := nb;
      decr len
    done;
    !cur

  let pow a n =
    let o = ref (one ()) in
    let t = ref a in
    let e = ref n in
    while Z.gt !e Z.zero do
      if Z.testbit !e 0 then o := mul !o !t;
      t := mul !t !t;
      e := Z.shift_right !e 1
    done;
    !o

  (* Base-field polynomial helpers for the extended-Euclidean inverse
     below; [pa]/[pb] here are plain length-(degree+1) Fp coefficient
     arrays, not field elements. *)
  let pdeg a =
    let d = ref (Array.length a - 1) in
    while !d > 0 && Z.equal a.(!d) Z.zero do
      decr d
    done;
    !d

  let poly_rounded_div a b =
    let dega = pdeg a and degb = pdeg b in
    let temp = Array.copy a in
    let o = Array.make (Array.length a) Z.zero in
    for i = dega - degb downto 0 do
      o.(i) <- fadd o.(i) (fmul temp.(degb + i) (finv b.(degb)));
      for c = 0 to degb do
        temp.(c + i) <- fsub temp.(c + i) (fmul o.(i) b.(c))
      done
    done;
    o

  let inv a =
    let d = degree in
    let lm0 = Array.make (d + 1) Z.zero in
    lm0.(0) <- Z.one;
    let hm0 = Array.make (d + 1) Z.zero in
    let low0 = Array.make (d + 1) Z.zero in
    Array.blit a 0 low0 0 d;
    let high0 = Array.make (d + 1) Z.zero in
    Array.blit P.modulus_coeffs 0 high0 0 d;
    high0.(d) <- Z.one;
    let lm = ref lm0 and hm = ref hm0 and low = ref low0 and high = ref high0 in
    while pdeg !low > 0 do
      let rq = poly_rounded_div !high !low in
      let nm = Array.copy !hm in
      let new_ = Array.copy !high in
      for i = 0 to d do
        for j = 0 to d - i do
          nm.(i + j) <- fsub nm.(i + j) (fmul !lm.(i) rq.(j));
          new_.(i + j) <- fsub new_.(i + j) (fmul !low.(i) rq.(j))
        done
      done;
      let old_lm = !lm and old_low = !low in
      lm := nm;
      low := new_;
      hm := old_lm;
      high := old_low
    done;
    scale (Array.sub !lm 0 d) (finv !low.(0))

  let div a b = mul a (inv b)
end

(* ---------------------------------------------------------------------- *)
(* Fp2 = Fp[i] / (i^2 + 1), hand-written (rather than via [MakeFqp]) so
   that the closed-form "complex method" sqrt below (valid because p = 3
   mod 4) can be used instead of a generic, bootstrap-needing algorithm.
   Elements are (real, imaginary) pairs. *)

type fq2 = Z.t * Z.t

let fq2_zero : fq2 = (Z.zero, Z.zero)
let fq2_one : fq2 = (Z.one, Z.zero)
let fq2_add ((a0, a1) : fq2) ((b0, b1) : fq2) : fq2 = (fadd a0 b0, fadd a1 b1)
let fq2_sub ((a0, a1) : fq2) ((b0, b1) : fq2) : fq2 = (fsub a0 b0, fsub a1 b1)
let fq2_neg ((a0, a1) : fq2) : fq2 = (fneg a0, fneg a1)

let fq2_mul ((a0, a1) : fq2) ((b0, b1) : fq2) : fq2 =
  (fsub (fmul a0 b0) (fmul a1 b1), fadd (fmul a0 b1) (fmul a1 b0))

let fq2_square a = fq2_mul a a
let fq2_scale ((a0, a1) : fq2) c : fq2 = (fmul a0 c, fmul a1 c)
let fq2_is_zero ((a0, a1) : fq2) = Z.equal a0 Z.zero && Z.equal a1 Z.zero
let fq2_equal ((a0, a1) : fq2) ((b0, b1) : fq2) = Z.equal a0 b0 && Z.equal a1 b1
let fq2_norm ((a0, a1) : fq2) = fadd (fmul a0 a0) (fmul a1 a1)

let fq2_inv ((a0, a1) : fq2) : fq2 =
  let ninv = finv (fq2_norm (a0, a1)) in
  (fmul a0 ninv, fneg (fmul a1 ninv))

let fq2_inv0 a = if fq2_is_zero a then fq2_zero else fq2_inv a
let fq2_div a b = fq2_mul a (fq2_inv b)

let fq2_pow a n =
  let o = ref fq2_one and t = ref a and e = ref n in
  while Z.gt !e Z.zero do
    if Z.testbit !e 0 then o := fq2_mul !o !t;
    t := fq2_square !t;
    e := Z.shift_right !e 1
  done;
  !o

let fq2_is_square a = fp_is_square (fq2_norm a)

(* "Complex method" square root for Fp2 = Fp[i], valid since p = 3 mod 4;
   assumes the caller already knows [a] is a square (RFC 9380's SSWU
   mapping guarantees this for the branch it is used in). *)
let fq2_sqrt ((a0, a1) : fq2) : fq2 =
  if Z.equal a1 Z.zero then
    if fp_is_square a0 then (fp_sqrt a0, Z.zero) else (Z.zero, fp_sqrt (fneg a0))
  else begin
    let alpha = fp_sqrt (fq2_norm (a0, a1)) in
    let delta1 = fmul (fadd a0 alpha) inv2 in
    let delta = if fp_is_square delta1 then delta1 else fmul (fsub a0 alpha) inv2 in
    let x0 = fp_sqrt delta in
    let x1 = fmul a1 (finv (fmul (Z.of_int 2) x0)) in
    (x0, x1)
  end

let fq2_sign ((a0, a1) : fq2) = if Z.equal a1 Z.zero then fp_sign a0 else fp_sign a1

(* RFC 9380 sgn0 for m = 2 (Section 4.1). *)
let fq2_sgn0 ((a0, a1) : fq2) =
  let sign0 = Z.testbit a0 0 and zero0 = Z.equal a0 Z.zero and sign1 = Z.testbit a1 0 in
  sign0 || (zero0 && sign1)

(* ---------------------------------------------------------------------- *)
(* Fp12, as the flat degree-12 extension Fp[w] / (w^12 - 2*w^6 + 2), via
   [MakeFqp]. This matches py_ecc's representation (rather than the
   tower Fp2 -> Fp6 -> Fp12 construction some other implementations use);
   the "twist" map below embeds G2 = E'(Fp2) into this field, following
   py_ecc exactly. *)

module Fq12_params = struct
  let degree = 12

  let modulus_coeffs =
    [| Z.of_int 2; Z.zero; Z.zero; Z.zero; Z.zero; Z.zero
     ; Z.of_int (-2); Z.zero; Z.zero; Z.zero; Z.zero; Z.zero
    |]
end

module Fq12 = MakeFqp (Fq12_params)

let fq12_of_fp x =
  let a = Fq12.zero () in
  a.(0) <- fmod x;
  a

let fq12_w =
  let a = Fq12.zero () in
  a.(1) <- Z.one;
  a

let fq12_w2 = Fq12.mul fq12_w fq12_w
let fq12_w3 = Fq12.mul fq12_w2 fq12_w
let fq12_two = fq12_of_fp (Z.of_int 2)
let fq12_three = fq12_of_fp (Z.of_int 3)

(* ---------------------------------------------------------------------- *)
(* Generic affine short-Weierstrass point arithmetic (a = 0, matching
   every curve used in this module: E, E', and their common embedding
   into Fp12) over any field satisfying [FIELD] below. Plain
   double-and-add: NOT constant time. [None] represents the point at
   infinity. *)

module type FIELD = sig
  type t

  val zero : t
  val one : t
  val add : t -> t -> t
  val sub : t -> t -> t
  val neg : t -> t
  val mul : t -> t -> t
  val div : t -> t -> t
  val equal : t -> t -> bool
end

module MakePoint (F : FIELD) = struct
  type point = (F.t * F.t) option

  let two = F.add F.one F.one
  let three = F.add two F.one

  let double : point -> point = function
    | None -> None
    | Some (x, y) ->
      let m = F.div (F.mul three (F.mul x x)) (F.mul two y) in
      let x3 = F.sub (F.mul m m) (F.mul two x) in
      let y3 = F.sub (F.mul m (F.sub x x3)) y in
      Some (x3, y3)

  let add_pt (p1 : point) (p2 : point) : point =
    match (p1, p2) with
    | None, _ -> p2
    | _, None -> p1
    | Some (x1, y1), Some (x2, y2) ->
      if F.equal x1 x2 then
        if F.equal y1 y2 then double p1 else None
      else
        let m = F.div (F.sub y2 y1) (F.sub x2 x1) in
        let x3 = F.sub (F.sub (F.mul m m) x1) x2 in
        let y3 = F.sub (F.mul m (F.sub x1 x3)) y1 in
        Some (x3, y3)

  let neg_pt : point -> point = function None -> None | Some (x, y) -> Some (x, F.neg y)

  (* Plain MSB-first double-and-add: NOT constant time. *)
  let scalar_mult (pt : point) (n : Z.t) : point =
    if Z.equal n Z.zero then None
    else
      let n, pt = if Z.lt n Z.zero then (Z.neg n, neg_pt pt) else (n, pt) in
      let bits = Z.numbits n in
      let acc = ref None in
      for i = bits - 1 downto 0 do
        acc := double !acc;
        if Z.testbit n i then acc := add_pt !acc pt
      done;
      !acc
end

module Field_fp = struct
  type t = Z.t

  let zero = Z.zero
  let one = Z.one
  let add = fadd
  let sub = fsub
  let neg = fneg
  let mul = fmul
  let div a b = fmul a (finv b)
  let equal = Z.equal
end

module Field_fq2 = struct
  type t = fq2

  let zero = fq2_zero
  let one = fq2_one
  let add = fq2_add
  let sub = fq2_sub
  let neg = fq2_neg
  let mul = fq2_mul
  let div = fq2_div
  let equal = fq2_equal
end

module Field_fq12 = struct
  type t = Z.t array

  let zero = Fq12.zero ()
  let one = Fq12.one ()
  let add = Fq12.add
  let sub = Fq12.sub
  let neg = Fq12.neg
  let mul = Fq12.mul
  let div = Fq12.div
  let equal = Fq12.equal
end

module Point_fp = MakePoint (Field_fp)
module Point_fq2 = MakePoint (Field_fq2)
module Point_fq12 = MakePoint (Field_fq12)

(* ---------------------------------------------------------------------- *)
(* Curve parameters and generators (draft-irtf-cfrg-pairing-friendly-
   curves, Section 4.2.1). E: y^2 = x^3 + 4 over Fp (G1's curve); E':
   y^2 = x^3 + 4*(1+i) over Fp2 (G2's curve). *)

let b1 = Z.of_int 4
let b2 : fq2 = (Z.of_int 4, Z.of_int 4)

let g1_generator : (Z.t * Z.t) option =
  Some
    ( Z.of_string
        "0x17f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
    , Z.of_string
        "0x08b3f481e3aaa0f1a09e30ed741d8ae4fcf5e095d5d00af600db18cb2c04b3edd03cc744a2888ae40caa232946c5e7e1"
    )

let g2_generator : (fq2 * fq2) option =
  let x0 =
    Z.of_string
      "0x024aa2b2f08f0a91260805272dc51051c6e47ad4fa403b02b4510b647ae3d1770bac0326a805bbefd48056c8c121bdb8"
  and x1 =
    Z.of_string
      "0x13e02b6052719f607dacd3a088274f65596bd0d09920b61ab5da61bbdc7f5049334cf11213945d57e5ac7d055d042b7e"
  and y0 =
    Z.of_string
      "0x0ce5d527727d6e118cc9cdc6da2e351aadfd9baa8cbdd3a76d429a695160d12c923ac9cc3baca289e193548608b82801"
  and y1 =
    Z.of_string
      "0x0606c4a02ea734cc32acd2b02bc28b99cb3e287e85a763af267492ab572e99ab3f370d275cec1da1aaa9075ff05f79be"
  in
  Some ((x0, x1), (y0, y1))

(* ---------------------------------------------------------------------- *)
(* Public G1/G2/scalar types and group operations. *)

type scalar = Z.t
type priv = scalar
type g1 = (Z.t * Z.t) option
type g2 = (fq2 * fq2) option
type pub = g1
type signature = g2
type gt = Z.t array

let scalar_of_octets s : (scalar, error) result =
  if String.length s <> 32 then Error `Invalid_length
  else
    let z = Octets.of_be s in
    if Z.geq z r then Error `Invalid_range else Ok z

let scalar_to_octets (z : scalar) = Octets.to_be ~size:32 z
let generate ?g () : priv = Octets.gen_in_range ?g r

let g1_is_infinity : g1 -> bool = function None -> true | Some _ -> false
let g2_is_infinity : g2 -> bool = function None -> true | Some _ -> false

let g1_equal (a : g1) (b : g1) =
  match (a, b) with
  | None, None -> true
  | Some (x1, y1), Some (x2, y2) -> Z.equal x1 x2 && Z.equal y1 y2
  | _ -> false

let g2_equal (a : g2) (b : g2) =
  match (a, b) with
  | None, None -> true
  | Some (x1, y1), Some (x2, y2) -> fq2_equal x1 x2 && fq2_equal y1 y2
  | _ -> false

let g1_on_curve : g1 -> bool = function
  | None -> true
  | Some (x, y) -> Z.equal (fsub (fmul y y) (fmul x (fmul x x))) b1

let g2_on_curve : g2 -> bool = function
  | None -> true
  | Some (x, y) -> fq2_equal (fq2_sub (fq2_mul y y) (fq2_mul x (fq2_mul x x))) b2

let g1_add (a : g1) (b : g1) : g1 = Point_fp.add_pt a b
let g1_neg (a : g1) : g1 = Point_fp.neg_pt a
let g1_scalar_mult (k : scalar) (a : g1) : g1 = Point_fp.scalar_mult a k
let g2_add (a : g2) (b : g2) : g2 = Point_fq2.add_pt a b
let g2_neg (a : g2) : g2 = Point_fq2.neg_pt a
let g2_scalar_mult (k : scalar) (a : g2) : g2 = Point_fq2.scalar_mult a k

(* Prime-order-subgroup membership check for deserialized points (both
   G1's and G2's cofactors are > 1, so an arbitrary curve point need not
   lie in the r-order subgroup). *)
let g1_in_subgroup (pt : g1) = g1_is_infinity (Point_fp.scalar_mult pt r)
let g2_in_subgroup (pt : g2) = g2_is_infinity (Point_fq2.scalar_mult pt r)

let pub_of_priv (k : priv) : pub = g1_scalar_mult k g1_generator

(* ---------------------------------------------------------------------- *)
(* ZCash point serialization (draft-irtf-cfrg-pairing-friendly-curves,
   Appendix C), also used by draft-irtf-cfrg-bls-signature and blst /
   zkcrypto. Top 3 bits of the first byte: compressed, infinity, sign. *)

let g1_to_octets ?(compress = true) (pt : g1) : string =
  match pt with
  | None ->
    let len = if compress then 48 else 96 in
    let b = Bytes.make len '\000' in
    Bytes.set b 0 (Char.chr (if compress then 0xC0 else 0x40));
    Bytes.unsafe_to_string b
  | Some (x, y) ->
    if compress then begin
      let xs = Bytes.of_string (Octets.to_be ~size:48 x) in
      let flags = 0x80 lor if fp_sign y then 0x20 else 0x00 in
      Bytes.set xs 0 (Char.chr (Char.code (Bytes.get xs 0) lor flags));
      Bytes.unsafe_to_string xs
    end
    else Octets.to_be ~size:48 x ^ Octets.to_be ~size:48 y

let g1_of_octets (s : string) : (g1, error) result =
  let len = String.length s in
  if len <> 48 && len <> 96 then Error `Invalid_length
  else
    let b0 = Char.code s.[0] in
    let m = b0 land 0xE0 in
    if m = 0x20 || m = 0x60 || m = 0xE0 then Error `Invalid_format
    else
      let c_bit = m land 0x80 <> 0 and i_bit = m land 0x40 <> 0 and s_bit = m land 0x20 <> 0 in
      if (c_bit && len <> 48) || ((not c_bit) && len <> 96) then Error `Invalid_length
      else
        let clean = Bytes.of_string s in
        Bytes.set clean 0 (Char.chr (b0 land 0x1F));
        let clean = Bytes.unsafe_to_string clean in
        if i_bit then
          if String.for_all (fun c -> c = '\000') clean then Ok None else Error `Invalid_format
        else if not c_bit then begin
          let x = Octets.of_be (String.sub clean 0 48) in
          let y = Octets.of_be (String.sub clean 48 48) in
          let pt = Some (x, y) in
          if g1_on_curve pt && g1_in_subgroup pt then Ok pt else Error `Not_on_curve
        end
        else begin
          let x = Octets.of_be clean in
          let y2 = fadd (fmul x (fmul x x)) b1 in
          if not (fp_is_square y2) then Error `Not_on_curve
          else
            let y0 = fp_sqrt y2 in
            let y = if Bool.equal (fp_sign y0) s_bit then y0 else fneg y0 in
            let pt = Some (x, y) in
            if g1_in_subgroup pt then Ok pt else Error `Not_on_curve
        end

let g2_to_octets ?(compress = true) (pt : g2) : string =
  match pt with
  | None ->
    let len = if compress then 96 else 192 in
    let b = Bytes.make len '\000' in
    Bytes.set b 0 (Char.chr (if compress then 0xC0 else 0x40));
    Bytes.unsafe_to_string b
  | Some ((x0, x1), (y0, y1)) ->
    if compress then begin
      let xs = Bytes.of_string (Octets.to_be ~size:48 x1 ^ Octets.to_be ~size:48 x0) in
      let flags = 0x80 lor if fq2_sign (y0, y1) then 0x20 else 0x00 in
      Bytes.set xs 0 (Char.chr (Char.code (Bytes.get xs 0) lor flags));
      Bytes.unsafe_to_string xs
    end
    else
      Octets.to_be ~size:48 x1 ^ Octets.to_be ~size:48 x0 ^ Octets.to_be ~size:48 y1
      ^ Octets.to_be ~size:48 y0

let g2_of_octets (s : string) : (g2, error) result =
  let len = String.length s in
  if len <> 96 && len <> 192 then Error `Invalid_length
  else
    let b0 = Char.code s.[0] in
    let m = b0 land 0xE0 in
    if m = 0x20 || m = 0x60 || m = 0xE0 then Error `Invalid_format
    else
      let c_bit = m land 0x80 <> 0 and i_bit = m land 0x40 <> 0 and s_bit = m land 0x20 <> 0 in
      if (c_bit && len <> 96) || ((not c_bit) && len <> 192) then Error `Invalid_length
      else
        let clean = Bytes.of_string s in
        Bytes.set clean 0 (Char.chr (b0 land 0x1F));
        let clean = Bytes.unsafe_to_string clean in
        if i_bit then
          if String.for_all (fun c -> c = '\000') clean then Ok None else Error `Invalid_format
        else if not c_bit then begin
          let x1 = Octets.of_be (String.sub clean 0 48) in
          let x0 = Octets.of_be (String.sub clean 48 48) in
          let y1 = Octets.of_be (String.sub clean 96 48) in
          let y0 = Octets.of_be (String.sub clean 144 48) in
          let pt = Some ((x0, x1), (y0, y1)) in
          if g2_on_curve pt && g2_in_subgroup pt then Ok pt else Error `Not_on_curve
        end
        else begin
          let x1 = Octets.of_be (String.sub clean 0 48) in
          let x0 = Octets.of_be (String.sub clean 48 48) in
          let x = (x0, x1) in
          let y2 = fq2_add (fq2_mul x (fq2_mul x x)) b2 in
          if not (fq2_is_square y2) then Error `Not_on_curve
          else
            let y0v = fq2_sqrt y2 in
            let y = if Bool.equal (fq2_sign y0v) s_bit then y0v else fq2_neg y0v in
            let pt = Some (x, y) in
            if g2_in_subgroup pt then Ok pt else Error `Not_on_curve
        end

(* ---------------------------------------------------------------------- *)
(* Optimal ate pairing: embed G1 and (twisted) G2 into Fp12, run the
   Miller loop, then finish with a literal final exponentiation by
   (p^12-1)/r. Ported from py_ecc's [bls12_381_pairing.py] /
   [bls12_381_curve.py] (the Ethereum Foundation's reference BLS12-381
   implementation), including its choice to skip the optional Frobenius
   "twist correction" lines, which py_ecc notes (and cross-checks via its
   own test suite) do nothing for this loop count. The direct final
   exponentiation (~4300-bit exponent, vs. an optimized ~1300-bit
   easy/hard-part split) trades some speed for a much smaller, easier to
   verify implementation -- consistent with this module's "quick, not
   constant time" stance. *)

let ate_loop_count = Z.of_string "0xd201000000010000"
let log_ate_loop_count = 62
let final_exp_exponent = Z.divexact (Z.sub (Z.pow p 12) Z.one) r

let cast_g1_to_fq12 : g1 -> Point_fq12.point = function
  | None -> None
  | Some (x, y) -> Some (fq12_of_fp x, fq12_of_fp y)

(* Field isomorphism embedding E'(Fp2) into the sextic-twist subfield of
   Fp12, following py_ecc's [twist]. *)
let twist_g2 : g2 -> Point_fq12.point = function
  | None -> None
  | Some ((x0, x1), (y0, y1)) ->
    let xc0 = fsub x0 x1 and xc1 = x1 in
    let yc0 = fsub y0 y1 and yc1 = y1 in
    let nx = Fq12.zero () in
    nx.(0) <- xc0;
    nx.(6) <- xc1;
    let ny = Fq12.zero () in
    ny.(0) <- yc0;
    ny.(6) <- yc1;
    Some (Fq12.div nx fq12_w2, Fq12.div ny fq12_w3)

let linefunc (p1 : Point_fq12.point) (p2 : Point_fq12.point) (t : Point_fq12.point) =
  match (p1, p2, t) with
  | Some (x1, y1), Some (x2, y2), Some (xt, yt) ->
    if not (Fq12.equal x1 x2) then
      let m = Fq12.div (Fq12.sub y2 y1) (Fq12.sub x2 x1) in
      Fq12.sub (Fq12.mul m (Fq12.sub xt x1)) (Fq12.sub yt y1)
    else if Fq12.equal y1 y2 then
      let m = Fq12.div (Fq12.mul fq12_three (Fq12.mul x1 x1)) (Fq12.mul fq12_two y1) in
      Fq12.sub (Fq12.mul m (Fq12.sub xt x1)) (Fq12.sub yt y1)
    else Fq12.sub xt x1
  | _ -> invalid_arg "linefunc: infinity not allowed"

let miller_loop (q : Point_fq12.point) (p : Point_fq12.point) : gt =
  match (q, p) with
  | None, _ | _, None -> Fq12.one ()
  | Some _, Some _ ->
    let r_pt = ref q in
    let f = ref (Fq12.one ()) in
    for i = log_ate_loop_count downto 0 do
      f := Fq12.mul (Fq12.mul !f !f) (linefunc !r_pt !r_pt p);
      r_pt := Point_fq12.double !r_pt;
      if Z.testbit ate_loop_count i then begin
        f := Fq12.mul !f (linefunc !r_pt q p);
        r_pt := Point_fq12.add_pt !r_pt q
      end
    done;
    !f

let final_exponentiate (f : gt) : gt = Fq12.pow f final_exp_exponent

(* [pairing q p] computes e(q, p) for [q : g2] and [p : g1]. *)
let pairing (q : g2) (p : g1) : gt = final_exponentiate (miller_loop (twist_g2 q) (cast_g1_to_fq12 p))

let gt_equal (a : gt) (b : gt) = Fq12.equal a b

(* ---------------------------------------------------------------------- *)
(* RFC 9380 hash-to-curve, instantiated only for
   BLS12381G2_XMD:SHA-256_SSWU_RO_ (Section 8.8.2), which is what the
   "minimal-pubkey-size" BLS signature scheme below needs to hash
   messages into G2. *)

let sha256 s = Digestif.SHA256.(to_raw_string (digest_string s))
let expand_b_in_bytes = 32
let expand_s_in_bytes = 64
let i2osp n len = Octets.to_be ~size:len (Z.of_int n)

(* RFC 9380 Section 5.3.1. *)
let expand_message_xmd msg dst len_in_bytes =
  let ell = (len_in_bytes + expand_b_in_bytes - 1) / expand_b_in_bytes in
  if ell > 255 || len_in_bytes > 65535 || String.length dst > 255 then
    invalid_arg "expand_message_xmd: parameters out of range";
  let dst_prime = dst ^ i2osp (String.length dst) 1 in
  let z_pad = String.make expand_s_in_bytes '\000' in
  let l_i_b_str = i2osp len_in_bytes 2 in
  let msg_prime = z_pad ^ msg ^ l_i_b_str ^ i2osp 0 1 ^ dst_prime in
  let b0 = sha256 msg_prime in
  let bs = Array.make (ell + 1) "" in
  bs.(1) <- sha256 (b0 ^ i2osp 1 1 ^ dst_prime);
  for i = 2 to ell do
    let xored =
      String.init expand_b_in_bytes (fun j -> Char.chr (Char.code b0.[j] lxor Char.code bs.(i - 1).[j]))
    in
    bs.(i) <- sha256 (xored ^ i2osp i 1 ^ dst_prime)
  done;
  let buf = Buffer.create len_in_bytes in
  for i = 1 to ell do
    Buffer.add_string buf bs.(i)
  done;
  String.sub (Buffer.contents buf) 0 len_in_bytes

(* RFC 9380 Section 5.2, specialized to F = Fp2 (m = 2), count = 2, L = 64
   (as specified for the BLS12381G2 suites in Section 8.8.2). *)
let hash_to_field_g2 msg dst : fq2 * fq2 =
  let l = 64 in
  let uniform = expand_message_xmd msg dst (2 * 2 * l) in
  let elm i j = fmod (Octets.of_be (String.sub uniform (l * (j + (i * 2))) l)) in
  ((elm 0 0, elm 0 1), (elm 1 0, elm 1 1))

(* Simplified SWU (RFC 9380 Section 6.6.2), for the isogenous curve
   E': y'^2 = x'^3 + A'*x' + B' over Fp2, with the suite's Z (Section
   8.8.2). *)
let sswu_a2 : fq2 = (Z.zero, Z.of_int 240)
let sswu_b2 : fq2 = (Z.of_int 1012, Z.of_int 1012)
let sswu_z2 : fq2 = (fneg (Z.of_int 2), fneg Z.one)

let map_to_curve_simple_swu_g2 (u : fq2) : fq2 * fq2 =
  let a = sswu_a2 and b = sswu_b2 and z = sswu_z2 in
  let gx x = fq2_add (fq2_add (fq2_mul x (fq2_mul x x)) (fq2_mul a x)) b in
  let u2 = fq2_mul u u in
  let u4 = fq2_mul u2 u2 in
  let zu2 = fq2_mul z u2 in
  (* tv1 = inv0(Z^2 * u^4 + Z * u^2) -- RFC 9380 Section 6.6.2, step 1. *)
  let z2u4 = fq2_mul (fq2_mul z z) u4 in
  let tv1 = fq2_inv0 (fq2_add z2u4 zu2) in
  let x1 =
    if fq2_is_zero tv1 then fq2_div b (fq2_mul z a)
    else fq2_mul (fq2_div (fq2_neg b) a) (fq2_add fq2_one tv1)
  in
  let gx1 = gx x1 in
  let x2 = fq2_mul zu2 x1 in
  let gx2 = gx x2 in
  let x, gxv = if fq2_is_square gx1 then (x1, gx1) else (x2, gx2) in
  let y0 = fq2_sqrt gxv in
  let y = if Bool.equal (fq2_sgn0 u) (fq2_sgn0 y0) then y0 else fq2_neg y0 in
  (x, y)

(* 3-isogeny map from E' to E for BLS12-381 G2 (RFC 9380 Appendix E.3). *)
let iso_g2_k1 : fq2 array =
  [| ( Z.of_string
         "0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6"
     , Z.of_string
         "0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97d6"
     )
   ; ( Z.zero
     , Z.of_string
         "0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71a"
     )
   ; ( Z.of_string
         "0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71e"
     , Z.of_string
         "0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38d"
     )
   ; ( Z.of_string
         "0x171d6541fa38ccfaed6dea691f5fb614cb14b4e7f4e810aa22d6108f142b85757098e38d0f671c7188e2aaaaaaaa5ed1"
     , Z.zero
     )
  |]

let iso_g2_k2 : fq2 array =
  [| ( Z.zero
     , Z.of_string
         "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa63"
     )
   ; ( Z.of_string "0xc"
     , Z.of_string
         "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa9f"
     )
   ; fq2_one
  |]

let iso_g2_k3 : fq2 array =
  [| ( Z.of_string
         "0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706"
     , Z.of_string
         "0x1530477c7ab4113b59a4c18b076d11930f7da5d4a07f649bf54439d87d27e500fc8c25ebf8c92f6812cfc71c71c6d706"
     )
   ; ( Z.zero
     , Z.of_string
         "0x5c759507e8e333ebb5b7a9a47d7ed8532c52d39fd3a042a88b58423c50ae15d5c2638e343d9c71c6238aaaaaaaa97be"
     )
   ; ( Z.of_string
         "0x11560bf17baa99bc32126fced787c88f984f87adf7ae0c7f9a208c6b4f20a4181472aaa9cb8d555526a9ffffffffc71c"
     , Z.of_string
         "0x8ab05f8bdd54cde190937e76bc3e447cc27c3d6fbd7063fcd104635a790520c0a395554e5c6aaaa9354ffffffffe38f"
     )
   ; ( Z.of_string
         "0x124c9ad43b6cf79bfbf7043de3811ad0761b0f37a1e26286b0e977c69aa274524e79097a56dc4bd9e1b371c71c718b10"
     , Z.zero
     )
  |]

let iso_g2_k4 : fq2 array =
  [| ( Z.of_string
         "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb"
     , Z.of_string
         "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa8fb"
     )
   ; ( Z.zero
     , Z.of_string
         "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffa9d3"
     )
   ; ( Z.of_string "0x12"
     , Z.of_string
         "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaa99"
     )
   ; fq2_one
  |]

let horner_fq2 (coeffs : fq2 array) (x : fq2) : fq2 =
  let n = Array.length coeffs in
  let acc = ref coeffs.(n - 1) in
  for i = n - 2 downto 0 do
    acc := fq2_add (fq2_mul !acc x) coeffs.(i)
  done;
  !acc

let iso_map_g2 ((xp, yp) : fq2 * fq2) : (fq2 * fq2) option =
  let x_num = horner_fq2 iso_g2_k1 xp in
  let x_den = horner_fq2 iso_g2_k2 xp in
  let y_num = horner_fq2 iso_g2_k3 xp in
  let y_den = horner_fq2 iso_g2_k4 xp in
  if fq2_is_zero x_den || fq2_is_zero y_den then None
  else Some (fq2_div x_num x_den, fq2_mul yp (fq2_div y_num y_den))

(* Fast cofactor clearing (RFC 9380 Section 8.8.2 / Wahby-Boneh, Section
   5): plain scalar multiplication of the mapped point by h_eff already
   lands in the r-order subgroup; no need for the optimized
   Budroni-Pintore psi-endomorphism method of Appendix G.3. *)
let h_eff_g2 =
  Z.of_string
    "0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551"

let dst_g2_sig = "BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_"

let hash_to_curve_g2 ?(dst = dst_g2_sig) (msg : string) : g2 =
  let u0, u1 = hash_to_field_g2 msg dst in
  let q0 = iso_map_g2 (map_to_curve_simple_swu_g2 u0) in
  let q1 = iso_map_g2 (map_to_curve_simple_swu_g2 u1) in
  Point_fq2.scalar_mult (Point_fq2.add_pt q0 q1) h_eff_g2

(* ---------------------------------------------------------------------- *)
(* BLS signatures, "minimal-pubkey-size" configuration, "basic" scheme
   (draft-irtf-cfrg-bls-signature): public keys in G1, signatures in G2.
   [aggregate_verify] enforces distinct messages, which is the basic
   scheme's rogue-key defense; it does not implement proof-of-possession
   or message augmentation. *)

let sign ~key:(k : priv) (msg : string) : signature = g2_scalar_mult k (hash_to_curve_g2 msg)

let verify ~key:(pk : pub) (s : signature) (msg : string) : bool =
  if g1_is_infinity pk then false
  else
    let h = hash_to_curve_g2 msg in
    gt_equal (pairing s g1_generator) (pairing h pk)

let aggregate (sigs : signature list) : signature = List.fold_left g2_add None sigs

let aggregate_verify (pairs : (pub * string) list) (agg : signature) : bool =
  let msgs = List.map snd pairs in
  let distinct = List.length (List.sort_uniq String.compare msgs) = List.length msgs in
  if (not distinct) || pairs = [] || List.exists (fun (pk, _) -> g1_is_infinity pk) pairs then false
  else
    let lhs = pairing agg g1_generator in
    let rhs =
      List.fold_left (fun acc (pk, msg) -> Fq12.mul acc (pairing (hash_to_curve_g2 msg) pk)) (Fq12.one ()) pairs
    in
    gt_equal lhs rhs
