type error = [
  | `Invalid_format
  | `Invalid_length
  | `Invalid_range
  | `Not_on_curve
  | `At_infinity
  | `Low_order
]

let error_to_string = function
  | `Invalid_format -> "invalid format"
  | `Not_on_curve -> "point is not on curve"
  | `At_infinity -> "point is at infinity"
  | `Invalid_length -> "invalid length"
  | `Invalid_range -> "invalid range"
  | `Low_order -> "low order"

let pp_error fmt e =
  Format.fprintf fmt "Cannot parse point: %s" (error_to_string e)

let rev_string buf =
  let len = String.length buf in
  let res = Bytes.create len in
  for i = 0 to len - 1 do
    Bytes.set res (len - 1 - i) (String.get buf i)
  done ;
  Bytes.unsafe_to_string res

exception Message_too_long

let bit_at buf i =
  let byte_num = i / 8 in
  let bit_num = i mod 8 in
  let byte = String.get_uint8 buf byte_num in
  byte land (1 lsl bit_num) <> 0

module type Dh = sig
  type secret
  val secret_of_octets : ?compress:bool -> string ->
    (secret * string, error) result
  val secret_to_octets : secret -> string
  val gen_key : ?compress:bool -> ?g:Mirage_crypto_rng.g -> unit ->
    secret * string
  val key_exchange : secret -> string -> (string, error) result
end

module type Dsa = sig
  type priv
  type pub
  val byte_length : int
  val bit_length : int
  val priv_of_octets : string -> (priv, error) result
  val priv_to_octets : priv -> string
  val pub_of_octets : string -> (pub, error) result
  val pub_to_octets : ?compress:bool -> pub -> string
  val pub_of_priv : priv -> pub
  val add_scalar : priv -> priv -> (priv, error) result
  val generate : ?g:Mirage_crypto_rng.g -> unit -> priv * pub
  val sign : key:priv -> ?k:string -> string -> string * string
  val verify : key:pub -> string * string -> string -> bool
  module K_gen (H : Digestif.S) : sig
    val generate : key:priv -> string -> string
  end
end

module type Dsa_bip340 = sig
  include Dsa
  val negate_scalar : priv -> priv
  val get_x : pub -> string
  val sign_bip340 : key:priv -> ?aux_rand:string -> string -> string * string
  val verify_bip340 : key:pub -> string * string -> string -> bool
end

module type Dh_dsa = sig
  module Dh : Dh
  module Dsa : Dsa
end

module type P256k1 = sig
  include Dh_dsa
  module Dsa_bip340 : Dsa_bip340 with type priv = Dsa.priv and type pub = Dsa.pub
end

type field_element = Fe of string [@@unboxed]
type out_field_element = Fe_out of bytes [@@unboxed]
type scalar_element = Se of string [@@unboxed]
type out_scalar_element = Se_out of bytes [@@unboxed]
type point = Point of string [@@unboxed]
type out_point = Point_out of bytes [@@unboxed]
type scalar = Scalar of string

module type Parameters = sig
  val a : string
  val b : string
  val g_x : string
  val g_y : string
  val p : string
  val n : string
  val pident: string
  val byte_length : int
  val bit_length : int
  val fe_length : int
  val first_byte_bits : int option
end

module type Parameters_twisted = sig
  include Parameters
  val z : string
end

module type Foreign_field = sig
  val mul : out_field_element -> field_element -> field_element -> unit
  val sub : out_field_element -> field_element -> field_element -> unit
  val add : out_field_element -> field_element -> field_element -> unit
  val from_octets : out_field_element -> string -> unit
  val set_one : out_field_element -> unit
  val nz : field_element -> bool
  val sqr : out_field_element -> field_element -> unit
  val to_octets : bytes -> field_element -> unit
  val inv : out_field_element -> field_element -> unit
  val select_c : out_field_element -> bool -> field_element -> field_element -> unit
end

module type Foreign_mont = sig
  include Foreign_field
  val to_montgomery : out_field_element -> field_element -> unit
  val from_montgomery : out_field_element -> field_element -> unit
end

module type Foreign_point = sig
  val scalar_mult_base_c : out_point -> string -> unit
  val scalar_mult_c : out_point -> string -> point -> unit
  val scalar_mult_add_c : out_point -> string -> string -> point -> unit
end

module type Field_element = sig
  val create : unit -> out_field_element
  val mul : field_element -> field_element -> field_element
  val sub : field_element -> field_element -> field_element
  val add : field_element -> field_element -> field_element
  val from_montgomery : field_element -> field_element
  val zero : field_element
  val one : field_element
  val nz : field_element -> bool
  val sqr : field_element -> field_element
  val inv : field_element -> field_element
  val select : bool -> then_:field_element -> else_:field_element -> field_element
  val mont_from_be_octets : string -> field_element
  val to_octets : field_element -> string
end

module Make_field_element_base (P : Parameters) (F : Foreign_field) = struct
  let of_fe_out (Fe_out b) = Fe (Bytes.unsafe_to_string b)

  let create () = Fe_out (Bytes.create P.fe_length)

  let mul a b =
    let tmp = create () in
    F.mul tmp a b;
    of_fe_out tmp

  let sub a b =
    let tmp = create () in
    F.sub tmp a b;
    of_fe_out tmp

  let add a b =
    let tmp = create () in
    F.add tmp a b;
    of_fe_out tmp

  let zero = Fe (String.make P.fe_length '\000')

  let one =
    let fe = create () in
    F.set_one fe;
    of_fe_out fe

  let nz a = F.nz a

  let sqr a =
    let tmp = create () in
    F.sqr tmp a;
    of_fe_out tmp

  let inv a =
    let tmp = create () in
    F.inv tmp a;
    of_fe_out tmp

  let select bit ~then_ ~else_ =
    let tmp = create () in
    F.select_c tmp bit then_ else_;
    of_fe_out tmp

  let create_octets () =
    Bytes.create P.byte_length

  let to_octets fe =
    let tmp = create_octets () in
    F.to_octets tmp fe;
    Bytes.unsafe_to_string tmp

  let from_be_octets ~to_montgomery buf =
    let buf_rev = rev_string buf in
    let tmp = create () in
    F.from_octets tmp buf_rev;
    let tmp = to_montgomery tmp in
    of_fe_out tmp

end

module Make_field_element (P : Parameters) (F : Foreign_mont) : Field_element = struct
  include Make_field_element_base(P)(F)

  let from_montgomery a =
    let tmp = create () in
    F.from_montgomery tmp a;
    of_fe_out tmp

  let to_montgomery x = F.to_montgomery x (of_fe_out x); x

  let mont_from_be_octets = from_be_octets ~to_montgomery
end

module Make_field_element_usol (P : Parameters) (F : Foreign_field) : Field_element = struct
  include Make_field_element_base(P)(F)

  let from_montgomery x = x

  let to_montgomery x = x
  let mont_from_be_octets = from_be_octets ~to_montgomery
end


module type Point = sig
  val is_infinity : point -> bool
  val of_octets : string -> (point, error) result
  val to_octets : compress:bool -> point -> string
  val to_affine : point -> (string * string) option
  val to_affine_raw : point -> (field_element * field_element) option
  val x_of_finite_point : point -> string
  val scalar_mult : scalar -> point -> point
  val scalar_mult_add : scalar -> scalar -> point -> point
  val scalar_mult_base : scalar -> point
end

module type Transform = sig
  val in_x : field_element -> field_element
  val in_y : field_element -> field_element
  val out_x : field_element -> field_element
  val out_y : field_element -> field_element
end

module Twist (P : Parameters_twisted) (Fe : Field_element) : Transform = struct
  let z = Fe.mont_from_be_octets P.z
  let z2 = Fe.sqr z
  let z3 = Fe.mul z2 z
  let z_inv = Fe.inv z
  let z_inv2 = Fe.sqr z_inv
  let z_inv3 = Fe.mul z_inv2 z_inv

  let in_x = Fe.mul z2
  let in_y = Fe.mul z3
  let out_x = Fe.mul z_inv2
  let out_y = Fe.mul z_inv3
end

module NoTransform : Transform = struct
  let noop x = x
  let in_x = noop
  let in_y = noop
  let out_x = noop
  let out_y = noop
end

module Make_point_base (P : Parameters) (F : Foreign_point) (Fe : Field_element)
    (T : Transform) : Point = struct

  let make (Fe x) (Fe y) = Point (String.cat x y)
  let p_x (Point p) = Fe (String.sub p 0 P.fe_length)
  let p_y (Point p) = Fe (String.sub p P.fe_length P.fe_length)
  let out_point () = Point_out (Bytes.create (P.fe_length * 2))
  let out_p_to_p (Point_out p) = Point (Bytes.unsafe_to_string p)

  let at_infinity () =
    let x = Fe.zero in
    let y = Fe.zero in
    make x y

  let is_infinity (p : point) = not (Fe.nz (p_y p))

  let add_ax =
    if String.length P.a = 0 then
      fun ~x:_ n -> n
    else
      let a = Fe.mont_from_be_octets P.a in
      fun ~x n ->
        let ax = Fe.mul a x in
        Fe.add n ax

  let is_solution_to_curve_equation =
    let b = Fe.mont_from_be_octets P.b in
    fun ~x ~y ->
      let x3 = Fe.mul x x in
      let x3 = Fe.mul x3 x in
      let y2 = Fe.mul y y in
      let sum = add_ax ~x x3 in
      let sum = Fe.add sum b in
      let sum = Fe.sub sum y2 in
      not (Fe.nz sum)

  let check_coordinate buf =
    (* ensure buf < p: *)
    match Eqaf.compare_be_with_len ~len:P.byte_length buf P.p >= 0 with
    | true -> None
    | exception Invalid_argument _ -> None
    | false -> Some (Fe.mont_from_be_octets buf)

  let validate_finite_point_fe x y =
    if is_solution_to_curve_equation ~x ~y then
      Ok (make x y)
    else Error `Not_on_curve

  (** Convert coordinates to a finite point ensuring:
      - x < p
      - y < p
      - y^2 = x^3 + ax + b
  *)
  let validate_finite_point ~x ~y =
    match (check_coordinate x, check_coordinate y) with
    | Some x, Some y ->
      let x, y = T.in_x x, T.in_y y in
      validate_finite_point_fe x y
    | _ -> Error `Invalid_range

  let to_affine_raw p =
    if is_infinity p then
      None
    else
      let x = Fe.from_montgomery (p_x p) in
      let y = Fe.from_montgomery (p_y p) in
      Some (T.out_x x, T.out_y y)

  let to_affine p =
    Option.map (fun (x, y) -> Fe.to_octets x, Fe.to_octets y)
      (to_affine_raw p)

  let to_octets ~compress p =
    match to_affine p with
    | None -> String.make 1 '\000'
    | Some (x, y) ->
      let len_x = String.length x and len_y = String.length y in
      let buf_len, ident = if compress then
        1 + len_x, 2 + String.(get_uint8 y 0) land 1
      else
        1 + len_x + len_y, 4
      in
      let buf = Bytes.create (buf_len) in
      Bytes.set_uint8 buf 0 ident;
      Bytes.unsafe_blit_string (rev_string x) 0 buf 1 len_x ;
      if not compress then
        Bytes.unsafe_blit_string (rev_string y) 0 buf (1 + len_x) len_y;
      Bytes.unsafe_to_string buf

  let x_of_finite_point p =
    match to_affine p with None -> assert false | Some (x, _) -> rev_string x

  let pow x exp =
    let r0 = ref Fe.one in
    let r1 =  ref x in
    for i = P.byte_length * 8 - 1 downto 0 do
      let bit = bit_at exp i in
      let multiplied = Fe.mul !r0 !r1 in
      let r0_sqr = Fe.sqr !r0 in
      let r1_sqr = Fe.sqr !r1 in
      r0 := Fe.select bit ~then_:multiplied ~else_:r0_sqr;
      r1 := Fe.select bit ~then_:r1_sqr ~else_:multiplied;
    done;
    !r0

  let decompress =
  (* When p = 4*k+3, as is the case of NIST-P256, there is an efficient square
     root algorithm to recover the y, as follows:

    Given the compact representation of Q as x,
     y2 = x^3 + a*x + b
     y' = y2^((p+1)/4)
     y = min(y',p-y')
     Q=(x,y) is the canonical representation of the point
  *)
    let pident = P.pident (* (Params.p + 1) / 4*) in
    let b = Fe.mont_from_be_octets P.b in
    let p = Fe.mont_from_be_octets P.p in
    fun pk ->
      match check_coordinate (String.sub pk 1 P.byte_length) with
      | None -> Error `Invalid_range
      | Some x ->
      let x = T.in_x x in
      let x3 = Fe.mul x x in
      let x3 = Fe.mul x3 x in (* x3 *)
      let sum = add_ax ~x x3 in
      let sum = Fe.add sum b in (* y^2 *)
      let y = pow sum pident in (* https://tools.ietf.org/id/draft-jivsov-ecc-compact-00.xml#sqrt point 4.3*)
      let y' = Fe.sub p y in
      let y_str = T.out_y y |> Fe.from_montgomery |> Fe.to_octets in (* number must not be in montgomery domain*)
      let ident = String.get_uint8 pk 0 in
      let signY =
        2 + (String.get_uint8 y_str 0) land 1
      in
      let y = if Int.equal signY ident then y else y' in
      validate_finite_point_fe x y

  let of_octets buf =
    let len = P.byte_length in
    if String.length buf = 0 then
      Error `Invalid_format
    else
      match String.get_uint8 buf 0 with
      | 0x00 when String.length buf = 1 ->
        Ok (at_infinity ())
      | 0x02 | 0x03 when String.length P.pident > 0 ->
        decompress buf
      | 0x04 when String.length buf = 1 + len + len ->
        let x = String.sub buf 1 len in
        let y = String.sub buf (1 + len) len in
        validate_finite_point ~x ~y
      | 0x00 | 0x04 -> Error `Invalid_length
      | _ -> Error `Invalid_format

  let scalar_mult_base (Scalar d) =
    assert (String.length d = P.byte_length);
    let tmp = out_point () in
    F.scalar_mult_base_c tmp (rev_string d);
    out_p_to_p tmp

  let scalar_mult (Scalar s) p =
    assert (String.length s = P.byte_length);
    let tmp = out_point () in
    F.scalar_mult_c tmp (rev_string s) p;
    out_p_to_p tmp

  let scalar_mult_add (Scalar a) (Scalar b) p =
    assert (String.length a = P.byte_length);
    assert (String.length b = P.byte_length);
    let tmp = out_point () in
    F.scalar_mult_add_c tmp (rev_string a) (rev_string b) p;
    out_p_to_p tmp
end

module Make_point
  (P : Parameters) (F : Foreign_point) (Fe : Field_element)
  : Point = Make_point_base(P)(F)(Fe)(NoTransform)

module Make_point_twisted
  (P : Parameters_twisted) (F : Foreign_point) (Fe : Field_element)
  : Point = Make_point_base(P)(F)(Fe)(Twist(P)(Fe))

module type Scalar = sig
  val not_zero : string -> bool
  val is_in_range : string -> bool
  val of_octets : string -> (scalar, error) result
  val to_octets : scalar -> string
end

module Make_scalar (P : Parameters) : Scalar = struct
  let not_zero =
    let zero = String.make P.byte_length '\000' in
    fun buf -> not (Eqaf.equal buf zero)

  let is_in_range buf =
    not_zero buf
    && Eqaf.compare_be_with_len ~len:P.byte_length P.n buf > 0

  let of_octets buf =
    match is_in_range buf with
    | exception Invalid_argument _ -> Error `Invalid_length
    | true -> Ok (Scalar buf)
    | false -> Error `Invalid_range

  let to_octets (Scalar buf) = buf
end

module Make_dh (P : Parameters) (Pt : Point) : Dh = struct
  module S = Make_scalar(P)

  let point_of_octets c =
    match Pt.of_octets c with
    | Ok p when not (Pt.is_infinity p) -> Ok p
    | Ok _ -> Error `At_infinity
    | Error _ as e -> e

  let point_to_octets = Pt.to_octets

  type secret = scalar

  let share ?(compress = false) private_key =
    let public_key = Pt.scalar_mult_base private_key in
    point_to_octets ~compress public_key

  let secret_of_octets ?compress s =
    match S.of_octets s with
    | Ok p -> Ok (p, share ?compress p)
    | Error _ as e -> e

  let secret_to_octets s =
    S.to_octets s

  let rec generate_private_key ?g () =
    let candidate = Mirage_crypto_rng.generate ?g P.byte_length in
    match S.of_octets candidate with
    | Ok secret -> secret
    | Error _ -> generate_private_key ?g ()

  let gen_key ?compress ?g () =
    let private_key = generate_private_key ?g () in
    private_key, share ?compress private_key

  let key_exchange secret received =
    match point_of_octets received with
    | Error _ as err -> err
    | Ok shared -> Ok Pt.(x_of_finite_point (scalar_mult secret shared))
end

module type Foreign_n = sig
  val mul : out_scalar_element -> scalar_element -> scalar_element -> unit
  val add : out_scalar_element -> scalar_element -> scalar_element -> unit
  val inv : out_scalar_element -> scalar_element -> unit
  val one : out_scalar_element -> unit
  val from_bytes : out_scalar_element -> string -> unit
  val to_bytes : bytes -> scalar_element -> unit
  val from_montgomery : out_scalar_element -> scalar_element -> unit
  val to_montgomery : out_scalar_element -> scalar_element -> unit
end

module type Scalar_element = sig
  val from_octets_raw : string -> scalar_element
  val mont_from_be_octets : string -> scalar_element
  val to_be_octets : scalar_element -> string
  val mul : scalar_element -> scalar_element -> scalar_element
  val add : scalar_element -> scalar_element -> scalar_element
  val inv : scalar_element -> scalar_element
  val one : scalar_element
  val from_montgomery : scalar_element -> scalar_element
  val to_montgomery : scalar_element -> scalar_element
end

module Make_scalar_element (P : Parameters) (F : Foreign_n) = struct
  let of_se_out (Se_out x) = Se (Bytes.unsafe_to_string x)

  let create () = Se_out (Bytes.create P.fe_length)

  let create_octets () = Bytes.create P.byte_length

  let from_octets_raw v =
    let v' = create () in
    F.from_bytes v' v;
    of_se_out v'

  let mont_from_be_octets v =
    let v' = create () in
    F.from_bytes v' (rev_string v);
    F.to_montgomery v' (of_se_out v');
    of_se_out v'

  let to_be_octets v =
    let buf = create_octets () in
    F.to_bytes buf v;
    rev_string (Bytes.unsafe_to_string buf)

  let mul a b =
    let tmp = create () in
    F.mul tmp a b;
    of_se_out tmp

  let add a b =
    let tmp = create () in
    F.add tmp a b;
    of_se_out tmp

  let inv a =
    let tmp = create () in
    F.inv tmp a;
    F.to_montgomery tmp (of_se_out tmp);
    of_se_out tmp

  let one =
    let tmp = create () in
    F.one tmp;
    of_se_out tmp

  let from_montgomery a =
    let tmp = create () in
    F.from_montgomery tmp a;
    of_se_out tmp

  let to_montgomery a =
    let tmp = create () in
    F.to_montgomery tmp a;
    of_se_out tmp
end

module Make_dsa (P : Parameters) (Se : Scalar_element) (Pt : Point) (H : Digestif.S) = struct
  module S = Make_scalar(P)

  type priv = scalar

  let byte_length = P.byte_length

  let bit_length = P.bit_length

  let priv_of_octets = S.of_octets

  let priv_to_octets = S.to_octets

  let padded msg =
    let l = String.length msg in
    let bl = P.byte_length in
    let first_byte_ok () =
      match P.first_byte_bits with
      | None -> true
      | Some m -> (String.get_uint8 msg 0) land (0xFF land (lnot m)) = 0
    in
    if l > bl || (l = bl && not (first_byte_ok ())) then
      raise Message_too_long
    else if l = bl then
      msg
    else
      ( let res = Bytes.make bl '\000' in
        Bytes.unsafe_blit_string msg 0 res (bl - l) l ;
        Bytes.unsafe_to_string res )

  (* RFC 6979: compute a deterministic k *)
  module K_gen (H : Digestif.S) = struct
    let drbg : 'a Mirage_crypto_rng.generator =
      let module M = Mirage_crypto_rng.Hmac_drbg (H) in (module M)
    let g ~key msg =
      let g = Mirage_crypto_rng.create ~strict:true drbg in
      Mirage_crypto_rng.reseed ~g (S.to_octets key ^ msg);
      g

    (* Defined in RFC 6979 sec 2.3.2 with
       - blen = 8 * P.byte_length
       - qlen = P.bit_length *)
    let bits2int r =
      (* keep qlen *leftmost* bits *)
      let shift = (8 * P.byte_length) - P.bit_length in
      if shift = 0 then
        Bytes.unsafe_to_string r
      else
        (* Assuming shift is < 8 *)
        let r' = Bytes.create P.byte_length in
        let p = ref 0x00 in
        for i = 0 to P.byte_length - 1 do
          let x = Bytes.get_uint8 r i in
          let v = (x lsr shift) lor (!p lsl (8 - shift)) in
          p := x;
          Bytes.set_uint8 r' i v
        done;
        Bytes.unsafe_to_string r'

    (* take qbit length, and ensure it is suitable for ECDSA (> 0 & < n) *)
    let gen g =
      let rec go () =
        let b = Bytes.create P.byte_length in
        Mirage_crypto_rng.generate_into ~g b P.byte_length;
        (* truncate to the desired number of bits *)
        let r = bits2int b in
        if S.is_in_range r then r else go ()
      in
      go ()

    let generate ~key buf = gen (g ~key (padded buf))
  end

  module K_gen_default = K_gen(H)

  type pub = point

  let pub_of_octets = Pt.of_octets

  let pub_to_octets ?(compress = false) pk = Pt.to_octets ~compress pk

  let generate ?g () =
    (* FIPS 186-4 B 4.2 *)
    let d =
      let rec one () =
        match S.of_octets (Mirage_crypto_rng.generate ?g P.byte_length) with
        | Ok x -> x
        | Error _ -> one ()
      in
      one ()
    in
    let q = Pt.scalar_mult_base d in
    (d, q)

  let x_of_finite_point_mod_n p =
    match Pt.to_affine p with
    | None -> None
    | Some (x, _) ->
      let x = Se.from_octets_raw x in
      let x = Se.mul x Se.one in
      Some (Se.to_be_octets x)

  let sign ~key ?k msg =
    let msg = padded msg in
    let e = Se.mont_from_be_octets msg in
    let g = K_gen_default.g ~key msg in
    let rec do_sign g =
      let again () =
        match k with
        | None -> do_sign g
        | Some _ -> invalid_arg "k not suitable"
      in
      let k' = match k with None -> K_gen_default.gen g | Some k -> k in
      let ksc = match S.of_octets k' with
        | Ok ksc -> ksc
        | Error _ -> invalid_arg "k not in range" (* if no k is provided, this cannot happen since K_gen_*.gen already preserves the Scalar invariants *)
      in
      let point = Pt.scalar_mult_base ksc in
      match x_of_finite_point_mod_n point with
      | None -> again ()
      | Some r ->
        let r_mon = Se.mont_from_be_octets r in
        let kmon = Se.mont_from_be_octets k' in
        let kinv = Se.inv kmon in
        let dmon = Se.mont_from_be_octets (S.to_octets key) in
        let rd = Se.mul r_mon dmon in
        let cmon = Se.add e rd in
        let smon = Se.mul kinv cmon in
        let s = Se.from_montgomery smon in
        let s = Se.to_be_octets s in
        if S.not_zero s && S.not_zero r then
          r, s
        else
          again ()
    in
    do_sign g

  let pub_of_priv priv = Pt.scalar_mult_base priv

  (* Montgomery representation is linear in addition, so
     mont(a) + mont(b) = mont(a + b) and no extra reduction is needed. The
     result goes back through S.of_octets, which rejects zero and anything
     at or above the group order in constant time. *)
  let add_scalar a b =
    let mont k = Se.mont_from_be_octets (S.to_octets k) in
    Se.add (mont a) (mont b) |> Se.from_montgomery |> Se.to_be_octets |> S.of_octets

  let verify ~key (r, s) msg =
    try
      let r = padded r and s = padded s in
      if not (S.is_in_range r && S.is_in_range s) then
        false
      else
        let msg = padded msg in
        let z = Se.mont_from_be_octets msg in
        let s_mon = Se.mont_from_be_octets s in
        let s_inv = Se.inv s_mon in
        let u1 = Se.mul z s_inv in
        let r_mon = Se.mont_from_be_octets r in
        let u2 = Se.mul r_mon s_inv in
        let u1 = Se.from_montgomery u1 in
        let u2 = Se.from_montgomery u2 in
        match
          S.of_octets (Se.to_be_octets u1),
          S.of_octets (Se.to_be_octets u2)
        with
        | Ok u1, Ok u2 ->
          let point = Pt.scalar_mult_add u1 u2 key
          in
          begin match x_of_finite_point_mod_n point with
            | None -> false (* point is infinity *)
            | Some r' -> String.equal r r'
          end
        | Error _, _ | _, Error _ -> false
    with
    | Message_too_long -> false

end

module type Scalar_element_bip340 = sig
  include Scalar_element
  val opp : scalar_element -> scalar_element
end

module type Foreign_n_bip340 = sig
  include Foreign_n
  val opp : out_scalar_element -> scalar_element -> unit
end

module Make_scalar_element_bip340 (P : Parameters)(F : Foreign_n_bip340) : Scalar_element_bip340 = struct
  include Make_scalar_element(P)(F)

  let opp a =
    let tmp = create () in
    F.opp tmp a;
    of_se_out tmp

end

module Make_dsa_bip340 (P : Parameters) (Se : Scalar_element_bip340) (Pt : Point) = struct
  module H = Digestif.SHA256
  include Make_dsa (P) (Se) (Pt) (H)

  (* Tagged hash function *)
  let tagged_hash tag =
    let tag_hash = H.digest_string tag |> H.to_raw_string in
    let ctx = H.feed_string H.empty (tag_hash ^ tag_hash) in
    fun msg ->
      H.feed_string ctx msg |> H.get |> H.to_raw_string

  let tagged_hash_aux = tagged_hash "BIP0340/aux"
  let tagged_hash_nonce = tagged_hash "BIP0340/nonce"
  let tagged_hash_challenge = tagged_hash "BIP0340/challenge"

  (* Check if a point has even Y coordinate *)
  let has_even_y point =
    match Pt.to_affine point with
    | None -> false (* Point at infinity *)
    | Some (_, y) ->
      (* Check if first byte is even in little-endian *)
      ((String.get_uint8 y 0) land 1) = 0

  (* Extract X coordinate from a point *)
  let get_x =
    let zero = String.make P.byte_length '\000' in
    fun point ->
      match Pt.to_affine point with
      | None -> zero (* Return zero bytes for infinity *)
      | Some (x, _) -> rev_string x (* Reverse to get big-endian format *)

  (* [n - d]. For d in [1, n) the result is also in [1, n), so of_octets
     cannot fail here. Constant time. *)
  let negate_scalar d =
    S.to_octets d |> Se.mont_from_be_octets |> Se.opp |> Se.from_montgomery
    |> Se.to_be_octets |> S.of_octets |> Result.get_ok

  (* Generate key pair with even public y *)
  let generate ?g () : priv * pub =
    let neg = negate_scalar in
    let key, pubkey = generate ?g () in
    let key, pubkey =
      if has_even_y pubkey then key, pubkey else
        let d = neg key in
        d, pub_of_priv d
    in
    (key, pubkey)

  (* Sign a message *)
  let sign_bip340 ~key ?aux_rand msg =
    (* Calculate P = key*G *)
    let p_point = Pt.scalar_mult_base key in
    (* Determine if d needs to be negated based on Y coordinate *)
    let d =
      let se = Se.mont_from_be_octets (S.to_octets key) in
      if has_even_y p_point then se else Se.opp se
    in
    (* Generate aux_rand if not provided *)
    let a = match aux_rand with
      | Some a -> a
      | None -> Mirage_crypto_rng.generate P.byte_length
    in
    (* Compute t = bytes(d) XOR hash_aux(a) *)
    let d_be = Se.from_montgomery d |> Se.to_be_octets in
    let t = Mirage_crypto.Uncommon.xor d_be (tagged_hash_aux a) in
    (* Compute rand *)
    let p_be = get_x p_point in
    let nonce_input = t ^ p_be ^ msg in
    let rand_be = tagged_hash_nonce nonce_input in
    (* Convert to field element, mont_from_be_octets implies (mod n) because of to_montgomery *)
    let k' = Se.mont_from_be_octets rand_be in
    (* Convert k' to scalar, fails if k' == 0 *)
    let k_sc' = Se.from_montgomery k' |> Se.to_be_octets |> S.of_octets |> Result.get_ok in
    (* Compute R = k'*G *)
    let r_point = Pt.scalar_mult_base k_sc' in
    (* Determine k based on Y coordinate of R *)
    let k = if has_even_y r_point
      then k'
      else Se.opp k'
    in
    (* Extract r from R *)
    let r_be = get_x r_point in
    (* Compute challenge e *)
    let challenge_input = r_be ^ p_be ^ msg in
    let e_be = tagged_hash_challenge challenge_input in
    (* Convert to field element, from_be_octets implies (mod n) because of to_montgomery *)
    let e = Se.mont_from_be_octets e_be in
    (* Compute e*d *)
    let ed = Se.mul e d in
    (* s = k + e*d *)
    let s = Se.add k ed in
    let s_be = Se.from_montgomery s |> Se.to_be_octets in
    (r_be, s_be)

  (* Verify a signature *)
  let verify_bip340 ~key:p_point (r, s) msg =
    let r = padded r and s = padded s in
    if not (S.is_in_range r && S.is_in_range s) then false else
    match S.of_octets s with Error _ -> false | Ok s_sc ->
    let x = get_x p_point in
    (* Compute challenge e *)
    let challenge_input = r ^ x ^ msg in
    let e_be = tagged_hash_challenge challenge_input in
    (* Convert to field element, from_be_octets implies (mod n) because of to_montgomery *)
    let e = Se.mont_from_be_octets e_be in
    (* negate e if y(P) is even *)
    let e = if has_even_y p_point
      then Se.opp e
      else e
    in
    match Se.from_montgomery e |> Se.to_be_octets |> S.of_octets with
    | Error _ -> false
    | Ok e_sc ->
    (* Compute R = s*G + e*P *)
    let r_point = Pt.scalar_mult_add s_sc e_sc p_point in
    let r' = get_x r_point in
    (* Check R is not infinity *)
    not (Pt.is_infinity r_point) &&
    (* Check appropriate Y coordinate parity *)
    has_even_y r_point &&
    (* Check x(R) = r *)
    r' = r
end

module P256 : Dh_dsa  = struct
  module Params = struct
    let a = "\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC"
    let b = "\x5A\xC6\x35\xD8\xAA\x3A\x93\xE7\xB3\xEB\xBD\x55\x76\x98\x86\xBC\x65\x1D\x06\xB0\xCC\x53\xB0\xF6\x3B\xCE\x3C\x3E\x27\xD2\x60\x4B"
    let g_x = "\x6B\x17\xD1\xF2\xE1\x2C\x42\x47\xF8\xBC\xE6\xE5\x63\xA4\x40\xF2\x77\x03\x7D\x81\x2D\xEB\x33\xA0\xF4\xA1\x39\x45\xD8\x98\xC2\x96"
    let g_y = "\x4F\xE3\x42\xE2\xFE\x1A\x7F\x9B\x8E\xE7\xEB\x4A\x7C\x0F\x9E\x16\x2B\xCE\x33\x57\x6B\x31\x5E\xCE\xCB\xB6\x40\x68\x37\xBF\x51\xF5"
    let p = "\xFF\xFF\xFF\xFF\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
    let n = "\xFF\xFF\xFF\xFF\x00\x00\x00\x00\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xBC\xE6\xFA\xAD\xA7\x17\x9E\x84\xF3\xB9\xCA\xC2\xFC\x63\x25\x51"
    let pident = "\x3F\xFF\xFF\xFF\xC0\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00" |> rev_string (* (Params.p + 1) / 4*)
    let byte_length = 32
    let bit_length = 256
    let fe_length = 32
    let first_byte_bits = None
  end

  module Foreign = struct
    external mul : out_field_element -> field_element -> field_element -> unit = "mc_p256_mul" [@@noalloc]
    external sub : out_field_element -> field_element -> field_element -> unit = "mc_p256_sub" [@@noalloc]
    external add : out_field_element -> field_element -> field_element -> unit = "mc_p256_add" [@@noalloc]
    external to_montgomery : out_field_element -> field_element -> unit = "mc_p256_to_montgomery" [@@noalloc]
    external from_octets : out_field_element -> string -> unit = "mc_p256_from_bytes" [@@noalloc]
    external set_one : out_field_element -> unit = "mc_p256_set_one" [@@noalloc]
    external nz : field_element -> bool = "mc_p256_nz" [@@noalloc]
    external sqr : out_field_element -> field_element -> unit = "mc_p256_sqr" [@@noalloc]
    external from_montgomery : out_field_element -> field_element -> unit = "mc_p256_from_montgomery" [@@noalloc]
    external to_octets : bytes -> field_element -> unit = "mc_p256_to_bytes" [@@noalloc]
    external inv : out_field_element -> field_element -> unit = "mc_p256_inv" [@@noalloc]
    external select_c : out_field_element -> bool -> field_element -> field_element -> unit = "mc_p256_select" [@@noalloc]
    external scalar_mult_c : out_point -> string -> point -> unit = "mc_p256_scalar_mult" [@@noalloc]
    external scalar_mult_add_c : out_point -> string -> string -> point -> unit = "mc_p256_scalar_mult_add" [@@noalloc]
    external scalar_mult_base_c : out_point -> string -> unit = "mc_p256_scalar_mult_base" [@@noalloc]
  end

  module Foreign_n = struct
    external mul : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_np256_mul" [@@noalloc]
    external add : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_np256_add" [@@noalloc]
    external inv : out_scalar_element -> scalar_element -> unit = "mc_np256_inv" [@@noalloc]
    external one : out_scalar_element -> unit = "mc_np256_one" [@@noalloc]
    external from_bytes : out_scalar_element -> string -> unit = "mc_np256_from_bytes" [@@noalloc]
    external to_bytes : bytes -> scalar_element -> unit = "mc_np256_to_bytes" [@@noalloc]
    external from_montgomery : out_scalar_element -> scalar_element -> unit = "mc_np256_from_montgomery" [@@noalloc]
    external to_montgomery : out_scalar_element -> scalar_element -> unit = "mc_np256_to_montgomery" [@@noalloc]
  end

  module Fe = Make_field_element(Params)(Foreign)
  module P = Make_point(Params)(Foreign)(Fe)
  module Dh = Make_dh(Params)(P)
  module Fn = Make_scalar_element(Params)(Foreign_n)
  module Dsa = Make_dsa(Params)(Fn)(P)(Digestif.SHA256)
end


module P256k1 : P256k1  = struct
  module Params = struct
    let a = ""
    let b = "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x07"
    let g_x = "\x79\xBE\x66\x7E\xF9\xDC\xBB\xAC\x55\xA0\x62\x95\xCE\x87\x0B\x07\x02\x9B\xFC\xDB\x2D\xCE\x28\xD9\x59\xF2\x81\x5B\x16\xF8\x17\x98"
    let g_y = "\x48\x3A\xDA\x77\x26\xA3\xC4\x65\x5D\xA4\xFB\xFC\x0E\x11\x08\xA8\xFD\x17\xB4\x48\xA6\x85\x54\x19\x9C\x47\xD0\x8F\xFB\x10\xD4\xB8"
    let p = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFC\x2F"
    let n = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xBA\xAE\xDC\xE6\xAF\x48\xA0\x3B\xBF\xD2\x5E\x8C\xD0\x36\x41\x41"
    let pident = "\x3F\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xBF\xFF\xFF\x0C" |> rev_string (* (Params.p + 1) / 4*)
    let byte_length = 32
    let bit_length = 256
    let fe_length = 32
    let first_byte_bits = None
  end

  module Foreign = struct
    external mul : out_field_element -> field_element -> field_element -> unit = "mc_secp256k1_mul" [@@noalloc]
    external sub : out_field_element -> field_element -> field_element -> unit = "mc_secp256k1_sub" [@@noalloc]
    external add : out_field_element -> field_element -> field_element -> unit = "mc_secp256k1_add" [@@noalloc]
    external to_montgomery : out_field_element -> field_element -> unit = "mc_secp256k1_to_montgomery" [@@noalloc]
    external from_octets : out_field_element -> string -> unit = "mc_secp256k1_from_bytes" [@@noalloc]
    external set_one : out_field_element -> unit = "mc_secp256k1_set_one" [@@noalloc]
    external nz : field_element -> bool = "mc_secp256k1_nz" [@@noalloc]
    external sqr : out_field_element -> field_element -> unit = "mc_secp256k1_sqr" [@@noalloc]
    external from_montgomery : out_field_element -> field_element -> unit = "mc_secp256k1_from_montgomery" [@@noalloc]
    external to_octets : bytes -> field_element -> unit = "mc_secp256k1_to_bytes" [@@noalloc]
    external inv : out_field_element -> field_element -> unit = "mc_secp256k1_inv" [@@noalloc]
    external select_c : out_field_element -> bool -> field_element -> field_element -> unit = "mc_secp256k1_select" [@@noalloc]
    external scalar_mult_c : out_point -> string -> point -> unit = "mc_secp256k1_scalar_mult" [@@noalloc]
    external scalar_mult_add_c : out_point -> string -> string -> point -> unit = "mc_secp256k1_scalar_mult_add" [@@noalloc]
    external scalar_mult_base_c : out_point -> string -> unit = "mc_secp256k1_scalar_mult_base" [@@noalloc]
  end

  module Foreign_n = struct
    external mul : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_nsecp256k1_mul" [@@noalloc]
    external add : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_nsecp256k1_add" [@@noalloc]
    external inv : out_scalar_element -> scalar_element -> unit = "mc_nsecp256k1_inv" [@@noalloc]
    external opp : out_scalar_element -> scalar_element -> unit = "mc_nsecp256k1_opp" [@@noalloc]
    external one : out_scalar_element -> unit = "mc_nsecp256k1_one" [@@noalloc]
    external from_bytes : out_scalar_element -> string -> unit = "mc_nsecp256k1_from_bytes" [@@noalloc]
    external to_bytes : bytes -> scalar_element -> unit = "mc_nsecp256k1_to_bytes" [@@noalloc]
    external from_montgomery : out_scalar_element -> scalar_element -> unit = "mc_nsecp256k1_from_montgomery" [@@noalloc]
    external to_montgomery : out_scalar_element -> scalar_element -> unit = "mc_nsecp256k1_to_montgomery" [@@noalloc]
  end

  module Fe = Make_field_element(Params)(Foreign)
  module P = Make_point(Params)(Foreign)(Fe)
  module Dh = Make_dh(Params)(P)
  module Fn = Make_scalar_element_bip340(Params)(Foreign_n)
  module Dsa = Make_dsa_bip340(Params)(Fn)(P)
  module Dsa_bip340 = Dsa
end

module P384 : Dh_dsa = struct
  module Params = struct
    let a = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFC"
    let b = "\xB3\x31\x2F\xA7\xE2\x3E\xE7\xE4\x98\x8E\x05\x6B\xE3\xF8\x2D\x19\x18\x1D\x9C\x6E\xFE\x81\x41\x12\x03\x14\x08\x8F\x50\x13\x87\x5A\xC6\x56\x39\x8D\x8A\x2E\xD1\x9D\x2A\x85\xC8\xED\xD3\xEC\x2A\xEF"
    let g_x = "\xAA\x87\xCA\x22\xBE\x8B\x05\x37\x8E\xB1\xC7\x1E\xF3\x20\xAD\x74\x6E\x1D\x3B\x62\x8B\xA7\x9B\x98\x59\xF7\x41\xE0\x82\x54\x2A\x38\x55\x02\xF2\x5D\xBF\x55\x29\x6C\x3A\x54\x5E\x38\x72\x76\x0A\xB7"
    let g_y = "\x36\x17\xde\x4a\x96\x26\x2c\x6f\x5d\x9e\x98\xbf\x92\x92\xdc\x29\xf8\xf4\x1d\xbd\x28\x9a\x14\x7c\xe9\xda\x31\x13\xb5\xf0\xb8\xc0\x0a\x60\xb1\xce\x1d\x7e\x81\x9d\x7a\x43\x1d\x7c\x90\xea\x0e\x5f"
    let p = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFE\xFF\xFF\xFF\xFF\x00\x00\x00\x00\x00\x00\x00\x00\xFF\xFF\xFF\xFF"
    let n = "\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xC7\x63\x4D\x81\xF4\x37\x2D\xDF\x58\x1A\x0D\xB2\x48\xB0\xA7\x7A\xEC\xEC\x19\x6A\xCC\xC5\x29\x73"
    let pident = "\x3F\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xBF\xFF\xFF\xFF\xC0\x00\x00\x00\x00\x00\x00\x00\x40\x00\x00\x00" |> rev_string (* (Params.p + 1) / 4*)
    let byte_length = 48
    let bit_length = 384
    let fe_length = 48
    let first_byte_bits = None
  end

  module Foreign = struct
    external mul : out_field_element -> field_element -> field_element -> unit = "mc_p384_mul" [@@noalloc]
    external sub : out_field_element -> field_element -> field_element -> unit = "mc_p384_sub" [@@noalloc]
    external add : out_field_element -> field_element -> field_element -> unit = "mc_p384_add" [@@noalloc]
    external to_montgomery : out_field_element -> field_element -> unit = "mc_p384_to_montgomery" [@@noalloc]
    external from_octets : out_field_element -> string -> unit = "mc_p384_from_bytes" [@@noalloc]
    external set_one : out_field_element -> unit = "mc_p384_set_one" [@@noalloc]
    external nz : field_element -> bool = "mc_p384_nz" [@@noalloc]
    external sqr : out_field_element -> field_element -> unit = "mc_p384_sqr" [@@noalloc]
    external from_montgomery : out_field_element -> field_element -> unit = "mc_p384_from_montgomery" [@@noalloc]
    external to_octets : bytes -> field_element -> unit = "mc_p384_to_bytes" [@@noalloc]
    external inv : out_field_element -> field_element -> unit = "mc_p384_inv" [@@noalloc]
    external select_c : out_field_element -> bool -> field_element -> field_element -> unit = "mc_p384_select" [@@noalloc]
    external scalar_mult_c : out_point -> string -> point -> unit = "mc_p384_scalar_mult" [@@noalloc]
    external scalar_mult_add_c : out_point -> string -> string -> point -> unit = "mc_p384_scalar_mult_add" [@@noalloc]
    external scalar_mult_base_c : out_point -> string -> unit = "mc_p384_scalar_mult_base" [@@noalloc]
  end

  module Foreign_n = struct
    external mul : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_np384_mul" [@@noalloc]
    external add : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_np384_add" [@@noalloc]
    external inv : out_scalar_element -> scalar_element -> unit = "mc_np384_inv" [@@noalloc]
    external one : out_scalar_element -> unit = "mc_np384_one" [@@noalloc]
    external from_bytes : out_scalar_element -> string -> unit = "mc_np384_from_bytes" [@@noalloc]
    external to_bytes : bytes -> scalar_element -> unit = "mc_np384_to_bytes" [@@noalloc]
    external from_montgomery : out_scalar_element -> scalar_element -> unit = "mc_np384_from_montgomery" [@@noalloc]
    external to_montgomery : out_scalar_element -> scalar_element -> unit = "mc_np384_to_montgomery" [@@noalloc]
  end

  module Fe = Make_field_element(Params)(Foreign)
  module P = Make_point(Params)(Foreign)(Fe)
  module Dh = Make_dh(Params)(P)
  module Fn = Make_scalar_element(Params)(Foreign_n)
  module Dsa = Make_dsa(Params)(Fn)(P)(Digestif.SHA384)
end

module P521 : Dh_dsa = struct
  module Params = struct
    let a = "\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFC"
    let b = "\x00\x51\x95\x3E\xB9\x61\x8E\x1C\x9A\x1F\x92\x9A\x21\xA0\xB6\x85\x40\xEE\xA2\xDA\x72\x5B\x99\xB3\x15\xF3\xB8\xB4\x89\x91\x8E\xF1\x09\xE1\x56\x19\x39\x51\xEC\x7E\x93\x7B\x16\x52\xC0\xBD\x3B\xB1\xBF\x07\x35\x73\xDF\x88\x3D\x2C\x34\xF1\xEF\x45\x1F\xD4\x6B\x50\x3F\x00"
    let g_x = "\x00\xC6\x85\x8E\x06\xB7\x04\x04\xE9\xCD\x9E\x3E\xCB\x66\x23\x95\xB4\x42\x9C\x64\x81\x39\x05\x3F\xB5\x21\xF8\x28\xAF\x60\x6B\x4D\x3D\xBA\xA1\x4B\x5E\x77\xEF\xE7\x59\x28\xFE\x1D\xC1\x27\xA2\xFF\xA8\xDE\x33\x48\xB3\xC1\x85\x6A\x42\x9B\xF9\x7E\x7E\x31\xC2\xE5\xBD\x66"
    let g_y = "\x01\x18\x39\x29\x6a\x78\x9a\x3b\xc0\x04\x5c\x8a\x5f\xb4\x2c\x7d\x1b\xd9\x98\xf5\x44\x49\x57\x9b\x44\x68\x17\xaf\xbd\x17\x27\x3e\x66\x2c\x97\xee\x72\x99\x5e\xf4\x26\x40\xc5\x50\xb9\x01\x3f\xad\x07\x61\x35\x3c\x70\x86\xa2\x72\xc2\x40\x88\xbe\x94\x76\x9f\xd1\x66\x50"
    let p = "\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF"
    let n = "\x01\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFF\xFA\x51\x86\x87\x83\xBF\x2F\x96\x6B\x7F\xCC\x01\x48\xF7\x09\xA5\xD0\x3B\xB5\xC9\xB8\x89\x9C\x47\xAE\xBB\x6F\xB7\x1E\x91\x38\x64\x09"
    let pident = "\x01\x7f\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff" |> rev_string
    let byte_length = 66
    let bit_length = 521
    let fe_length = if Sys.word_size == 64 then 72 else 68  (* TODO: is this congruent with C code? *)
    let first_byte_bits = Some 0x01
  end

  module Foreign = struct
    external mul : out_field_element -> field_element -> field_element -> unit = "mc_p521_mul" [@@noalloc]
    external sub : out_field_element -> field_element -> field_element -> unit = "mc_p521_sub" [@@noalloc]
    external add : out_field_element -> field_element -> field_element -> unit = "mc_p521_add" [@@noalloc]
    external from_octets : out_field_element -> string -> unit = "mc_p521_from_bytes" [@@noalloc]
    external set_one : out_field_element -> unit = "mc_p521_set_one" [@@noalloc]
    external sqr : out_field_element -> field_element -> unit = "mc_p521_sqr" [@@noalloc]
    external to_octets : bytes -> field_element -> unit = "mc_p521_to_bytes" [@@noalloc]
    external inv : out_field_element -> field_element -> unit = "mc_p521_inv" [@@noalloc]
    external select_c : out_field_element -> bool -> field_element -> field_element -> unit = "mc_p521_select" [@@noalloc]
    external scalar_mult_base_c : out_point -> string -> unit = "mc_p521_scalar_mult_base" [@@noalloc]
    external scalar_mult_c : out_point -> string -> point -> unit = "mc_p521_scalar_mult" [@@noalloc]
    external scalar_mult_add_c : out_point -> string -> string -> point -> unit = "mc_p521_scalar_mult_add" [@@noalloc]
    let nz =
      let zero = Bytes.make Params.byte_length '\000' in
      fun x ->
        let tmp = Bytes.create Params.byte_length in
        to_octets tmp x;
        not (Bytes.equal tmp zero)

  end

  module Foreign_n = struct
    external mul : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_np521_mul" [@@noalloc]
    external add : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_np521_add" [@@noalloc]
    external inv : out_scalar_element -> scalar_element -> unit = "mc_np521_inv" [@@noalloc]
    external one : out_scalar_element -> unit = "mc_np521_one" [@@noalloc]
    external from_bytes : out_scalar_element -> string -> unit = "mc_np521_from_bytes" [@@noalloc]
    external to_bytes : bytes -> scalar_element -> unit = "mc_np521_to_bytes" [@@noalloc]
    external from_montgomery : out_scalar_element -> scalar_element -> unit = "mc_np521_from_montgomery" [@@noalloc]
    external to_montgomery : out_scalar_element -> scalar_element -> unit = "mc_np521_to_montgomery" [@@noalloc]
  end

  module Fe = Make_field_element_usol(Params)(Foreign)
  module P = Make_point(Params)(Foreign)(Fe)
  module Dh = Make_dh(Params)(P)
  module Fn = Make_scalar_element(Params)(Foreign_n)
  module Dsa = Make_dsa(Params)(Fn)(P)(Digestif.SHA512)
end

module BrainpoolP256 : Dh_dsa  = struct
  (* These are the parameters of the twisted curve variant brainpoolP256t1,
  which allows use of optimized algorithms for a=-3. For the support of the
  regular curve brainpoolP256r1 the coordinates are mapped from regular to
  twisted representation and vice versa. *)
  module Params = struct
    let a = "\xA9\xFB\x57\xDB\xA1\xEE\xA9\xBC\x3E\x66\x0A\x90\x9D\x83\x8D\x72\x6E\x3B\xF6\x23\xD5\x26\x20\x28\x20\x13\x48\x1D\x1F\x6E\x53\x74"
    let b = "\x66\x2C\x61\xC4\x30\xD8\x4E\xA4\xFE\x66\xA7\x73\x3D\x0B\x76\xB7\xBF\x93\xEB\xC4\xAF\x2F\x49\x25\x6A\xE5\x81\x01\xFE\xE9\x2B\x04"
    let g_x = "\xA3\xE8\xEB\x3C\xC1\xCF\xE7\xB7\x73\x22\x13\xB2\x3A\x65\x61\x49\xAF\xA1\x42\xC4\x7A\xAF\xBC\x2B\x79\xA1\x91\x56\x2E\x13\x05\xF4"
    let g_y = "\x2D\x99\x6C\x82\x34\x39\xC5\x6D\x7F\x7B\x22\xE1\x46\x44\x41\x7E\x69\xBC\xB6\xDE\x39\xD0\x27\x00\x1D\xAB\xE8\xF3\x5B\x25\xC9\xBE"
    let p = "\xA9\xFB\x57\xDB\xA1\xEE\xA9\xBC\x3E\x66\x0A\x90\x9D\x83\x8D\x72\x6E\x3B\xF6\x23\xD5\x26\x20\x28\x20\x13\x48\x1D\x1F\x6E\x53\x77"
    let n = "\xA9\xFB\x57\xDB\xA1\xEE\xA9\xBC\x3E\x66\x0A\x90\x9D\x83\x8D\x71\x8C\x39\x7A\xA3\xB5\x61\xA6\xF7\x90\x1E\x0E\x82\x97\x48\x56\xA7"
    let pident = "\x2A\x7E\xD5\xF6\xE8\x7B\xAA\x6F\x0F\x99\x82\xA4\x27\x60\xE3\x5C\x9B\x8E\xFD\x88\xF5\x49\x88\x0A\x08\x04\xD2\x07\x47\xDB\x94\xDE" |> rev_string (* (Params.p + 1) / 4*)
    let byte_length = 32
    let bit_length = 256
    let fe_length = 32
    let first_byte_bits = None
    let z = "\x3E\x2D\x4B\xD9\x59\x7B\x58\x63\x9A\xE7\xAA\x66\x9C\xAB\x98\x37\xCF\x5C\xF2\x0A\x2C\x85\x2D\x10\xF6\x55\x66\x8D\xFC\x15\x0E\xF0"
  end

  module Foreign = struct
    external mul : out_field_element -> field_element -> field_element -> unit = "mc_brainpoolp256_mul" [@@noalloc]
    external sub : out_field_element -> field_element -> field_element -> unit = "mc_brainpoolp256_sub" [@@noalloc]
    external add : out_field_element -> field_element -> field_element -> unit = "mc_brainpoolp256_add" [@@noalloc]
    external to_montgomery : out_field_element -> field_element -> unit = "mc_brainpoolp256_to_montgomery" [@@noalloc]
    external from_octets : out_field_element -> string -> unit = "mc_brainpoolp256_from_bytes" [@@noalloc]
    external set_one : out_field_element -> unit = "mc_brainpoolp256_set_one" [@@noalloc]
    external nz : field_element -> bool = "mc_brainpoolp256_nz" [@@noalloc]
    external sqr : out_field_element -> field_element -> unit = "mc_brainpoolp256_sqr" [@@noalloc]
    external from_montgomery : out_field_element -> field_element -> unit = "mc_brainpoolp256_from_montgomery" [@@noalloc]
    external to_octets : bytes -> field_element -> unit = "mc_brainpoolp256_to_bytes" [@@noalloc]
    external inv : out_field_element -> field_element -> unit = "mc_brainpoolp256_inv" [@@noalloc]
    external select_c : out_field_element -> bool -> field_element -> field_element -> unit = "mc_brainpoolp256_select" [@@noalloc]
    external scalar_mult_base_c : out_point -> string -> unit = "mc_brainpoolp256t1_scalar_mult_base" [@@noalloc]
    external scalar_mult_c : out_point -> string -> point -> unit = "mc_brainpoolp256t1_scalar_mult" [@@noalloc]
    external scalar_mult_add_c : out_point -> string -> string -> point -> unit = "mc_brainpoolp256t1_scalar_mult_add" [@@noalloc]
  end

  module Foreign_n = struct
    external mul : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_nbrainpoolp256_mul" [@@noalloc]
    external add : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_nbrainpoolp256_add" [@@noalloc]
    external inv : out_scalar_element -> scalar_element -> unit = "mc_nbrainpoolp256_inv" [@@noalloc]
    external one : out_scalar_element -> unit = "mc_nbrainpoolp256_one" [@@noalloc]
    external from_bytes : out_scalar_element -> string -> unit = "mc_nbrainpoolp256_from_bytes" [@@noalloc]
    external to_bytes : bytes -> scalar_element -> unit = "mc_nbrainpoolp256_to_bytes" [@@noalloc]
    external from_montgomery : out_scalar_element -> scalar_element -> unit = "mc_nbrainpoolp256_from_montgomery" [@@noalloc]
    external to_montgomery : out_scalar_element -> scalar_element -> unit = "mc_nbrainpoolp256_to_montgomery" [@@noalloc]
  end

  module Fe = Make_field_element(Params)(Foreign)
  module P = Make_point_twisted(Params)(Foreign)(Fe)
  module Dh = Make_dh(Params)(P)
  module Fn = Make_scalar_element(Params)(Foreign_n)
  module Dsa = Make_dsa(Params)(Fn)(P)(Digestif.SHA256)
end

module BrainpoolP384 : Dh_dsa  = struct
  (* These are the parameters of the twisted curve variant *)
  module Params = struct
    let a = "\x8C\xB9\x1E\x82\xA3\x38\x6D\x28\x0F\x5D\x6F\x7E\x50\xE6\x41\xDF\x15\x2F\x71\x09\xED\x54\x56\xB4\x12\xB1\xDA\x19\x7F\xB7\x11\x23\xAC\xD3\xA7\x29\x90\x1D\x1A\x71\x87\x47\x00\x13\x31\x07\xEC\x50"
    let b = "\x7F\x51\x9E\xAD\xA7\xBD\xA8\x1B\xD8\x26\xDB\xA6\x47\x91\x0F\x8C\x4B\x93\x46\xED\x8C\xCD\xC6\x4E\x4B\x1A\xBD\x11\x75\x6D\xCE\x1D\x20\x74\xAA\x26\x3B\x88\x80\x5C\xED\x70\x35\x5A\x33\xB4\x71\xEE"
    let g_x = "\x18\xDE\x98\xB0\x2D\xB9\xA3\x06\xF2\xAF\xCD\x72\x35\xF7\x2A\x81\x9B\x80\xAB\x12\xEB\xD6\x53\x17\x24\x76\xFE\xCD\x46\x2A\xAB\xFF\xC4\xFF\x19\x1B\x94\x6A\x5F\x54\xD8\xD0\xAA\x2F\x41\x88\x08\xCC"
    let g_y = "\x25\xAB\x05\x69\x62\xD3\x06\x51\xA1\x14\xAF\xD2\x75\x5A\xD3\x36\x74\x7F\x93\x47\x5B\x7A\x1F\xCA\x3B\x88\xF2\xB6\xA2\x08\xCC\xFE\x46\x94\x08\x58\x4D\xC2\xB2\x91\x26\x75\xBF\x5B\x9E\x58\x29\x28"
    let p = "\x8C\xB9\x1E\x82\xA3\x38\x6D\x28\x0F\x5D\x6F\x7E\x50\xE6\x41\xDF\x15\x2F\x71\x09\xED\x54\x56\xB4\x12\xB1\xDA\x19\x7F\xB7\x11\x23\xAC\xD3\xA7\x29\x90\x1D\x1A\x71\x87\x47\x00\x13\x31\x07\xEC\x53"
    let n = "\x8C\xB9\x1E\x82\xA3\x38\x6D\x28\x0F\x5D\x6F\x7E\x50\xE6\x41\xDF\x15\x2F\x71\x09\xED\x54\x56\xB3\x1F\x16\x6E\x6C\xAC\x04\x25\xA7\xCF\x3A\xB6\xAF\x6B\x7F\xC3\x10\x3B\x88\x32\x02\xE9\x04\x65\x65"
    let pident = "\x23\x2E\x47\xA0\xA8\xCE\x1B\x4A\x03\xD7\x5B\xDF\x94\x39\x90\x77\xC5\x4B\xDC\x42\x7B\x55\x15\xAD\x04\xAC\x76\x86\x5F\xED\xC4\x48\xEB\x34\xE9\xCA\x64\x07\x46\x9C\x61\xD1\xC0\x04\xCC\x41\xFB\x15" |> rev_string (* (Params.p + 1) / 4*)
    let byte_length = 48
    let bit_length = 384
    let fe_length = 48
    let first_byte_bits = None
    let z = "\x41\xDF\xE8\xDD\x39\x93\x31\xF7\x16\x6A\x66\x07\x67\x34\xA8\x9C\xD0\xD2\xBC\xDB\x7D\x06\x8E\x44\xE1\xF3\x78\xF4\x1E\xCB\xAE\x97\xD2\xD6\x3D\xBC\x87\xBC\xCD\xDC\xCC\x5D\xA3\x9E\x85\x89\x29\x1C"
  end

  module Foreign = struct
    external mul : out_field_element -> field_element -> field_element -> unit = "mc_brainpoolp384_mul" [@@noalloc]
    external sub : out_field_element -> field_element -> field_element -> unit = "mc_brainpoolp384_sub" [@@noalloc]
    external add : out_field_element -> field_element -> field_element -> unit = "mc_brainpoolp384_add" [@@noalloc]
    external to_montgomery : out_field_element -> field_element -> unit = "mc_brainpoolp384_to_montgomery" [@@noalloc]
    external from_octets : out_field_element -> string -> unit = "mc_brainpoolp384_from_bytes" [@@noalloc]
    external set_one : out_field_element -> unit = "mc_brainpoolp384_set_one" [@@noalloc]
    external nz : field_element -> bool = "mc_brainpoolp384_nz" [@@noalloc]
    external sqr : out_field_element -> field_element -> unit = "mc_brainpoolp384_sqr" [@@noalloc]
    external from_montgomery : out_field_element -> field_element -> unit = "mc_brainpoolp384_from_montgomery" [@@noalloc]
    external to_octets : bytes -> field_element -> unit = "mc_brainpoolp384_to_bytes" [@@noalloc]
    external inv : out_field_element -> field_element -> unit = "mc_brainpoolp384_inv" [@@noalloc]
    external select_c : out_field_element -> bool -> field_element -> field_element -> unit = "mc_brainpoolp384_select" [@@noalloc]
    external scalar_mult_base_c : out_point -> string -> unit = "mc_brainpoolp384_scalar_mult_base" [@@noalloc]
    external scalar_mult_c : out_point -> string -> point -> unit = "mc_brainpoolp384_scalar_mult" [@@noalloc]
    external scalar_mult_add_c : out_point -> string -> string -> point -> unit = "mc_brainpoolp384_scalar_mult_add" [@@noalloc]
  end

  module Foreign_n = struct
    external mul : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_nbrainpoolp384_mul" [@@noalloc]
    external add : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_nbrainpoolp384_add" [@@noalloc]
    external inv : out_scalar_element -> scalar_element -> unit = "mc_nbrainpoolp384_inv" [@@noalloc]
    external one : out_scalar_element -> unit = "mc_nbrainpoolp384_one" [@@noalloc]
    external from_bytes : out_scalar_element -> string -> unit = "mc_nbrainpoolp384_from_bytes" [@@noalloc]
    external to_bytes : bytes -> scalar_element -> unit = "mc_nbrainpoolp384_to_bytes" [@@noalloc]
    external from_montgomery : out_scalar_element -> scalar_element -> unit = "mc_nbrainpoolp384_from_montgomery" [@@noalloc]
    external to_montgomery : out_scalar_element -> scalar_element -> unit = "mc_nbrainpoolp384_to_montgomery" [@@noalloc]
  end

  module Fe = Make_field_element(Params)(Foreign)
  module P = Make_point_twisted(Params)(Foreign)(Fe)
  module Dh = Make_dh(Params)(P)
  module Fn = Make_scalar_element(Params)(Foreign_n)
  module Dsa = Make_dsa(Params)(Fn)(P)(Digestif.SHA384)
end

module BrainpoolP512 : Dh_dsa  = struct
  (* These are the parameters of the twisted curve variant *)
  module Params = struct
    let a = "\xAA\xDD\x9D\xB8\xDB\xE9\xC4\x8B\x3F\xD4\xE6\xAE\x33\xC9\xFC\x07\xCB\x30\x8D\xB3\xB3\xC9\xD2\x0E\xD6\x63\x9C\xCA\x70\x33\x08\x71\x7D\x4D\x9B\x00\x9B\xC6\x68\x42\xAE\xCD\xA1\x2A\xE6\xA3\x80\xE6\x28\x81\xFF\x2F\x2D\x82\xC6\x85\x28\xAA\x60\x56\x58\x3A\x48\xF0"
    let b = "\x7C\xBB\xBC\xF9\x44\x1C\xFA\xB7\x6E\x18\x90\xE4\x68\x84\xEA\xE3\x21\xF7\x0C\x0B\xCB\x49\x81\x52\x78\x97\x50\x4B\xEC\x3E\x36\xA6\x2B\xCD\xFA\x23\x04\x97\x65\x40\xF6\x45\x00\x85\xF2\xDA\xE1\x45\xC2\x25\x53\xB4\x65\x76\x36\x89\x18\x0E\xA2\x57\x18\x67\x42\x3E"
    let g_x = "\x64\x0E\xCE\x5C\x12\x78\x87\x17\xB9\xC1\xBA\x06\xCB\xC2\xA6\xFE\xBA\x85\x84\x24\x58\xC5\x6D\xDE\x9D\xB1\x75\x8D\x39\xC0\x31\x3D\x82\xBA\x51\x73\x5C\xDB\x3E\xA4\x99\xAA\x77\xA7\xD6\x94\x3A\x64\xF7\xA3\xF2\x5F\xE2\x6F\x06\xB5\x1B\xAA\x26\x96\xFA\x90\x35\xDA"
    let g_y = "\x5B\x53\x4B\xD5\x95\xF5\xAF\x0F\xA2\xC8\x92\x37\x6C\x84\xAC\xE1\xBB\x4E\x30\x19\xB7\x16\x34\xC0\x11\x31\x15\x9C\xAE\x03\xCE\xE9\xD9\x93\x21\x84\xBE\xEF\x21\x6B\xD7\x1D\xF2\xDA\xDF\x86\xA6\x27\x30\x6E\xCF\xF9\x6D\xBB\x8B\xAC\xE1\x98\xB6\x1E\x00\xF8\xB3\x32"
    let p = "\xAA\xDD\x9D\xB8\xDB\xE9\xC4\x8B\x3F\xD4\xE6\xAE\x33\xC9\xFC\x07\xCB\x30\x8D\xB3\xB3\xC9\xD2\x0E\xD6\x63\x9C\xCA\x70\x33\x08\x71\x7D\x4D\x9B\x00\x9B\xC6\x68\x42\xAE\xCD\xA1\x2A\xE6\xA3\x80\xE6\x28\x81\xFF\x2F\x2D\x82\xC6\x85\x28\xAA\x60\x56\x58\x3A\x48\xF3"
    let n = "\xAA\xDD\x9D\xB8\xDB\xE9\xC4\x8B\x3F\xD4\xE6\xAE\x33\xC9\xFC\x07\xCB\x30\x8D\xB3\xB3\xC9\xD2\x0E\xD6\x63\x9C\xCA\x70\x33\x08\x70\x55\x3E\x5C\x41\x4C\xA9\x26\x19\x41\x86\x61\x19\x7F\xAC\x10\x47\x1D\xB1\xD3\x81\x08\x5D\xDA\xDD\xB5\x87\x96\x82\x9C\xA9\x00\x69"
    let pident = "\x2A\xB7\x67\x6E\x36\xFA\x71\x22\xCF\xF5\x39\xAB\x8C\xF2\x7F\x01\xF2\xCC\x23\x6C\xEC\xF2\x74\x83\xB5\x98\xE7\x32\x9C\x0C\xC2\x1C\x5F\x53\x66\xC0\x26\xF1\x9A\x10\xAB\xB3\x68\x4A\xB9\xA8\xE0\x39\x8A\x20\x7F\xCB\xCB\x60\xB1\xA1\x4A\x2A\x98\x15\x96\x0E\x92\x3D" |> rev_string (* (Params.p + 1) / 4*)
    let byte_length = 64
    let bit_length = 512
    let fe_length = 64
    let first_byte_bits = None
    let z = "\x12\xEE\x58\xE6\x76\x48\x38\xB6\x97\x82\x13\x6F\x0F\x2D\x3B\xA0\x6E\x27\x69\x57\x16\x05\x40\x92\xE6\x0A\x80\xBE\xDB\x21\x2B\x64\xE5\x85\xD9\x0B\xCE\x13\x76\x1F\x85\xC3\xF1\xD2\xA6\x4E\x3B\xE8\xFE\xA2\x22\x0F\x01\xEB\xA5\xEE\xB0\xF3\x5D\xBD\x29\xD9\x22\xAB"
  end

  module Foreign = struct
    external mul : out_field_element -> field_element -> field_element -> unit = "mc_brainpoolp512_mul" [@@noalloc]
    external sub : out_field_element -> field_element -> field_element -> unit = "mc_brainpoolp512_sub" [@@noalloc]
    external add : out_field_element -> field_element -> field_element -> unit = "mc_brainpoolp512_add" [@@noalloc]
    external to_montgomery : out_field_element -> field_element -> unit = "mc_brainpoolp512_to_montgomery" [@@noalloc]
    external from_octets : out_field_element -> string -> unit = "mc_brainpoolp512_from_bytes" [@@noalloc]
    external set_one : out_field_element -> unit = "mc_brainpoolp512_set_one" [@@noalloc]
    external nz : field_element -> bool = "mc_brainpoolp512_nz" [@@noalloc]
    external sqr : out_field_element -> field_element -> unit = "mc_brainpoolp512_sqr" [@@noalloc]
    external from_montgomery : out_field_element -> field_element -> unit = "mc_brainpoolp512_from_montgomery" [@@noalloc]
    external to_octets : bytes -> field_element -> unit = "mc_brainpoolp512_to_bytes" [@@noalloc]
    external inv : out_field_element -> field_element -> unit = "mc_brainpoolp512_inv" [@@noalloc]
    external select_c : out_field_element -> bool -> field_element -> field_element -> unit = "mc_brainpoolp512_select" [@@noalloc]
    external scalar_mult_base_c : out_point -> string -> unit = "mc_brainpoolp512_scalar_mult_base" [@@noalloc]
    external scalar_mult_c : out_point -> string -> point -> unit = "mc_brainpoolp512_scalar_mult" [@@noalloc]
    external scalar_mult_add_c : out_point -> string -> string -> point -> unit = "mc_brainpoolp512_scalar_mult_add" [@@noalloc]
  end

  module Foreign_n = struct
    external mul : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_nbrainpoolp512_mul" [@@noalloc]
    external add : out_scalar_element -> scalar_element -> scalar_element -> unit = "mc_nbrainpoolp512_add" [@@noalloc]
    external inv : out_scalar_element -> scalar_element -> unit = "mc_nbrainpoolp512_inv" [@@noalloc]
    external one : out_scalar_element -> unit = "mc_nbrainpoolp512_one" [@@noalloc]
    external from_bytes : out_scalar_element -> string -> unit = "mc_nbrainpoolp512_from_bytes" [@@noalloc]
    external to_bytes : bytes -> scalar_element -> unit = "mc_nbrainpoolp512_to_bytes" [@@noalloc]
    external from_montgomery : out_scalar_element -> scalar_element -> unit = "mc_nbrainpoolp512_from_montgomery" [@@noalloc]
    external to_montgomery : out_scalar_element -> scalar_element -> unit = "mc_nbrainpoolp512_to_montgomery" [@@noalloc]
  end

  module Fe = Make_field_element(Params)(Foreign)
  module P = Make_point_twisted(Params)(Foreign)(Fe)
  module Dh = Make_dh(Params)(P)
  module Fn = Make_scalar_element(Params)(Foreign_n)
  module Dsa = Make_dsa(Params)(Fn)(P)(Digestif.SHA512)
end

module X25519 = struct
  (* RFC 7748 *)
  external x25519_scalar_mult_generic : bytes -> string -> string -> unit = "mc_x25519_scalar_mult_generic" [@@noalloc]

  let key_len = 32

  let scalar_mult in_ base =
    let out = Bytes.create key_len in
    x25519_scalar_mult_generic out in_ base;
    Bytes.unsafe_to_string out

  type secret = string

  let basepoint = String.init key_len (function 0 -> '\009' | _ -> '\000')

  let public priv = scalar_mult priv basepoint

  let gen_key ?compress:_ ?g () =
    let secret = Mirage_crypto_rng.generate ?g key_len in
    secret, public secret

  let secret_of_octets ?compress:_ s =
    if String.length s = key_len then
      Ok (s, public s)
    else
      Error `Invalid_length

  let secret_to_octets s = s

  let is_zero =
    let zero = String.make key_len '\000' in
    fun buf -> String.equal zero buf

  let key_exchange secret public =
    if String.length public = key_len then
      let res = scalar_mult secret public in
      if is_zero res then Error `Low_order else Ok res
    else
      Error `Invalid_length
end

module Ed25519 = struct
  external scalar_mult_base_to_bytes : bytes -> string -> unit = "mc_25519_scalar_mult_base" [@@noalloc]
  external reduce_l : bytes -> unit = "mc_25519_reduce_l" [@@noalloc]
  external muladd : bytes -> string -> string -> string -> unit = "mc_25519_muladd" [@@noalloc]
  external double_scalar_mult : bytes -> string -> string -> string -> bool = "mc_25519_double_scalar_mult" [@@noalloc]
  external pub_ok : string -> bool = "mc_25519_pub_ok" [@@noalloc]
  external point_add : bytes -> string -> string -> bool = "mc_25519_point_add" [@@noalloc]
  external pub_to_x25519 : bytes -> string -> bool = "mc_25519_pub_to_x25519" [@@noalloc]

  let key_len = 32

  (* Keep handles on the raw externals before the allocating wrappers
     below shadow their names; [Primitive] needs them to write into
     caller-supplied buffers. *)
  let muladd_raw : bytes -> string -> string -> string -> unit = muladd
  let scalar_mult_base_raw : bytes -> string -> unit = scalar_mult_base_to_bytes

  let scalar_mult_base_to_bytes p =
    let tmp = Bytes.create key_len in
    scalar_mult_base_to_bytes tmp p;
    Bytes.unsafe_to_string tmp

  let muladd a b c =
    let tmp = Bytes.create key_len in
    muladd tmp a b c;
    Bytes.unsafe_to_string tmp

  let double_scalar_mult a b c =
    let tmp = Bytes.create key_len in
    let s = double_scalar_mult tmp a b c in
    s, Bytes.unsafe_to_string tmp

  type pub = string

  type priv = string

  let sha512 datas =
    let open Digestif.SHA512 in
    let buf = Bytes.create digest_size in
    let ctx = List.fold_left (feed_string ?off:None ?len:None) empty datas in
    get_into_bytes ctx buf;
    buf

  (* RFC 8032 *)
  let public secret =
    (* section 5.1.5 *)
    (* step 1 *)
    let h = sha512 [ secret ] in
    (* step 2 *)
    let s, rest =
      Bytes.sub h 0 key_len,
      Bytes.(sub h key_len (length h - key_len) |> unsafe_to_string)
    in
    Bytes.set_uint8 s 0 ((Bytes.get_uint8 s 0) land 248);
    Bytes.set_uint8 s 31 (((Bytes.get_uint8 s 31) land 127) lor 64);
    let s = Bytes.unsafe_to_string s in
    (* step 3 and 4 *)
    let public = scalar_mult_base_to_bytes s in
    public, (s, rest)

  let pub_of_priv secret = fst (public secret)

  let priv_of_octets buf =
    if String.length buf = key_len then Ok buf else Error `Invalid_length

  let priv_to_octets (priv : priv) = priv

  let pub_of_octets buf =
    if String.length buf = key_len then
      if pub_ok buf then
        Ok buf
      else
        Error `Not_on_curve
    else
      Error `Invalid_length

  let pub_to_octets pub = pub

  let generate ?g () =
    let secret = Mirage_crypto_rng.generate ?g key_len in
    secret, pub_of_priv secret

  let sign ~key msg =
    (* section 5.1.6 *)
    let pub, (s, prefix) = public key in
    let r = sha512 [ prefix; msg ] in
    reduce_l r;
    let r = Bytes.unsafe_to_string r in
    let r_big = scalar_mult_base_to_bytes r in
    let k = sha512 [ r_big; pub; msg] in
    reduce_l k;
    let k = Bytes.unsafe_to_string k in
    let s_out = muladd k s r in
    let res = Bytes.create (key_len + key_len) in
    Bytes.unsafe_blit_string r_big 0 res 0 key_len ;
    Bytes.unsafe_blit_string s_out 0 res key_len key_len ;
    Bytes.unsafe_to_string res

  let verify ~key signature ~msg =
    (* section 5.1.7 *)
    if String.length signature = 2 * key_len then
      let r, s =
        String.sub signature 0 key_len,
        String.sub signature key_len key_len
      in
      let s_smaller_l =
        (* check s within 0 <= s < L *)
        let s' = Bytes.make (key_len * 2) '\000' in
        Bytes.unsafe_blit_string s 0 s' 0 key_len;
        reduce_l s';
        let s' = Bytes.unsafe_to_string s' in
        let s'' = s ^ String.make key_len '\000' in
        String.equal s'' s'
      in
      if s_smaller_l then begin
        let k = sha512 [ r ; key ; msg ] in
        reduce_l k;
        let k = Bytes.unsafe_to_string k in
        let success, r' = double_scalar_mult k key s in
        success && String.equal r r'
      end else
        false
    else
      false

  (* Low-level scalar/point access for higher-level constructions (e.g.
     BIP32-Ed25519). Scalars are 32-byte little-endian values mod L;
     points are 32-byte RFC 8032 encodings. Point decoding is
     variable-time (NOT constant time). *)
  module Primitive = struct
    let check_dst name dst =
      if Bytes.length dst <> key_len then
        invalid_arg ("Ed25519.Primitive." ^ name ^
                     ": expected 32 byte destination")

    let to_x25519_pub_into dst pub =
      check_dst "to_x25519_pub_into" dst;
      if String.length pub <> key_len then
        invalid_arg "Ed25519.Primitive.to_x25519_pub: expected a 32 byte key";
      if pub_to_x25519 dst pub then Ok () else Error `Not_on_curve

    let to_x25519_pub pub =
      let dst = Bytes.create key_len in
      match to_x25519_pub_into dst pub with
      | Ok () -> Ok (Bytes.unsafe_to_string dst)
      | Error _ as e -> e

    let to_x25519_priv secret =
      if String.length secret <> key_len then
        invalid_arg "Ed25519.Primitive.to_x25519_priv: expected a 32 byte key";
      (* The X25519 scalar is exactly the clamped first half of SHA-512 of the
         seed, which is what RFC 8032 already derives for signing. *)
      let h = sha512 [ secret ] in
      let s = Bytes.sub h 0 key_len in
      Bytes.set_uint8 s 0 (Bytes.get_uint8 s 0 land 248);
      Bytes.set_uint8 s 31 (Bytes.get_uint8 s 31 land 127 lor 64);
      Bytes.fill h 0 (Bytes.length h) '\000';
      Bytes.unsafe_to_string s

    let scalar_reduce_into dst wide =
      check_dst "scalar_reduce_into" dst;
      if String.length wide <> 2 * key_len then
        invalid_arg "Ed25519.Primitive.scalar_reduce_into: expected 64 bytes";
      (* [reduce_l] works in place on a 64-byte buffer, so a temporary is
         unavoidable; wipe it once the result has been copied out. *)
      let tmp = Bytes.of_string wide in
      reduce_l tmp;
      Bytes.blit tmp 0 dst 0 key_len;
      Bytes.fill tmp 0 (2 * key_len) '\000'

    let scalar_reduce wide =
      if String.length wide <> 2 * key_len then
        invalid_arg "Ed25519.Primitive.scalar_reduce: expected 64 bytes";
      let dst = Bytes.create key_len in
      scalar_reduce_into dst wide;
      Bytes.unsafe_to_string dst

    let scalar_muladd_into dst a b c =
      check_dst "scalar_muladd_into" dst;
      if String.length a <> key_len || String.length b <> key_len ||
         String.length c <> key_len then
        invalid_arg
          "Ed25519.Primitive.scalar_muladd_into: expected 32 byte scalars";
      muladd_raw dst a b c

    let scalar_muladd a b c =
      let dst = Bytes.create key_len in
      scalar_muladd_into dst a b c;
      Bytes.unsafe_to_string dst

    let scalar_mult_base_into dst s =
      check_dst "scalar_mult_base_into" dst;
      if String.length s <> key_len then
        invalid_arg
          "Ed25519.Primitive.scalar_mult_base_into: expected 32 byte scalar";
      scalar_mult_base_raw dst s

    let scalar_mult_base s =
      let dst = Bytes.create key_len in
      scalar_mult_base_into dst s;
      Bytes.unsafe_to_string dst

    let point_add p q =
      let tmp = Bytes.create key_len in
      if point_add tmp p q then Ok (Bytes.unsafe_to_string tmp)
      else Error `Not_on_curve

    let point_valid p = String.length p = key_len && pub_ok p
    let verify_double_base ~k ~pub ~s = double_scalar_mult k pub s
  end
end
