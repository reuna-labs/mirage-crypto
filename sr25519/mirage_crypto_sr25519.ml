(* Schnorrkel sequencing in OCaml; scalar and Ristretto arithmetic in pinned
   libsodium; Keccak-f[1600] in Digestif C. The protocol and Merlin/STROBE
   integration have not independently been verified constant-time. *)

type error = [ `Invalid_format | `Invalid_length | `Invalid_range | `Not_on_curve ]

let pp_error ppf = function
  | `Invalid_format -> Format.fprintf ppf "invalid format"
  | `Invalid_length -> Format.fprintf ppf "invalid length"
  | `Invalid_range -> Format.fprintf ppf "invalid range"
  | `Not_on_curve -> Format.fprintf ppf "point not on curve"

let encode_u32_le n =
  if n < 0 || Int64.of_int n > 0xffff_ffffL then
    invalid_arg "Sr25519: transcript length exceeds uint32";
  let b = Bytes.create 4 in
  Bytes.set b 0 (Char.chr (n land 0xff));
  Bytes.set b 1 (Char.chr ((n lsr 8) land 0xff));
  Bytes.set b 2 (Char.chr ((n lsr 16) land 0xff));
  Bytes.set b 3 (Char.chr ((n lsr 24) land 0xff));
  Bytes.unsafe_to_string b

(* Only canonical byte encodings cross the C boundary. These bindings are
   private: scalars produced by reduction are always canonical. *)
external scalar_valid : string -> bool = "mc_sr_scalar_valid"
external scalar_reduce_wide : string -> string = "mc_sr_scalar_reduce"
external scalar_add : string -> string -> string = "mc_sr_scalar_add"
external scalar_mul : string -> string -> string = "mc_sr_scalar_mul"
external point_valid : string -> bool = "mc_sr_point_valid"
external ristretto_point_from_uniform_bytes : string -> string = "mc_sr_from_uniform"
external point_to_pub : string -> string = "mc_sr_point_base"
external scalar_mult : string -> string -> string = "mc_sr_point_mul"
external point_sub : string -> string -> string = "mc_sr_point_sub"

let scalar_of_bytes_canonical s =
  if String.length s <> 32 then Error `Invalid_length
  else if scalar_valid s then Ok s else Error `Invalid_range

(* Preserve the public parser's error categories; comparison is public-data
   only. Point decoding and validation itself belongs to libsodium. *)
let ristretto_decode s =
  if String.length s <> 32 then Error `Invalid_length
  else
    let prime = "\xed" ^ String.make 30 '\xff' ^ "\x7f" in
    let rec compare i =
      if i < 0 then 0 else
      let c = Char.compare s.[i] prime.[i] in
      if c = 0 then compare (i - 1) else c
    in
    if Char.code s.[0] land 1 <> 0 || compare 31 >= 0 then Error `Invalid_format
    else if point_valid s then Ok s else Error `Not_on_curve

(* STROBE128 (128-bit security level), supporting only the meta-AD, AD,
   KEY, and PRF operations Merlin uses. Ported from the "merlin" Rust
   crate's [strobe.rs]. *)

let strobe_r = 166
let strobe_flag_i = 1
let strobe_flag_a = 2
let strobe_flag_c = 4
let strobe_flag_t = 8
let strobe_flag_m = 16
let strobe_flag_k = 32

type strobe =
  { mutable state : bytes
  ; mutable pos : int
  ; mutable pos_begin : int
  ; mutable cur_flags : int
  }

let strobe_permute s =
  Digestif_keccak_f1600.permute s.state

let strobe_run_f s =
  Bytes.set s.state s.pos (Char.chr (Char.code (Bytes.get s.state s.pos) lxor s.pos_begin));
  Bytes.set s.state (s.pos + 1) (Char.chr (Char.code (Bytes.get s.state (s.pos + 1)) lxor 0x04));
  Bytes.set s.state (strobe_r + 1) (Char.chr (Char.code (Bytes.get s.state (strobe_r + 1)) lxor 0x80));
  strobe_permute s;
  s.pos <- 0;
  s.pos_begin <- 0

let strobe_absorb s data =
  String.iter
    (fun ch ->
      Bytes.set s.state s.pos (Char.chr (Char.code (Bytes.get s.state s.pos) lxor Char.code ch));
      s.pos <- s.pos + 1;
      if s.pos = strobe_r then strobe_run_f s)
    data

let strobe_overwrite s data =
  String.iter
    (fun ch ->
      Bytes.set s.state s.pos ch;
      s.pos <- s.pos + 1;
      if s.pos = strobe_r then strobe_run_f s)
    data

let strobe_squeeze s n =
  let out = Bytes.create n in
  for i = 0 to n - 1 do
    Bytes.set out i (Bytes.get s.state s.pos);
    Bytes.set s.state s.pos '\000';
    s.pos <- s.pos + 1;
    if s.pos = strobe_r then strobe_run_f s
  done;
  Bytes.unsafe_to_string out

let strobe_begin_op s flags more =
  if more then begin
    if s.cur_flags <> flags then invalid_arg "strobe: mismatched continued operation"
  end
  else begin
    if flags land strobe_flag_t <> 0 then invalid_arg "strobe: T flag not supported";
    let old_begin = s.pos_begin in
    s.pos_begin <- s.pos + 1;
    s.cur_flags <- flags;
    strobe_absorb s (String.init 2 (fun i -> Char.chr (if i = 0 then old_begin else flags)));
    let force_f = flags land (strobe_flag_c lor strobe_flag_k) <> 0 in
    if force_f && s.pos <> 0 then strobe_run_f s
  end

let strobe_meta_ad s data more =
  strobe_begin_op s (strobe_flag_m lor strobe_flag_a) more;
  strobe_absorb s data

let strobe_ad s data more =
  strobe_begin_op s strobe_flag_a more;
  strobe_absorb s data

let strobe_prf s n more =
  strobe_begin_op s (strobe_flag_i lor strobe_flag_a lor strobe_flag_c) more;
  strobe_squeeze s n

let strobe_key s data more =
  strobe_begin_op s (strobe_flag_a lor strobe_flag_c) more;
  strobe_overwrite s data

let strobe_new protocol_label =
  let state = Bytes.make 200 '\000' in
  Bytes.set state 0 (Char.chr 1);
  Bytes.set state 1 (Char.chr (strobe_r + 2));
  Bytes.set state 2 (Char.chr 1);
  Bytes.set state 3 (Char.chr 0);
  Bytes.set state 4 (Char.chr 1);
  Bytes.set state 5 (Char.chr 96);
  Bytes.blit_string "STROBEv1.0.2" 0 state 6 12;
  Digestif_keccak_f1600.permute state;
  let s = { state; pos = 0; pos_begin = 0; cur_flags = 0 } in
  strobe_meta_ad s protocol_label false;
  s

let strobe_copy s = { state = Bytes.copy s.state; pos = s.pos; pos_begin = s.pos_begin; cur_flags = s.cur_flags }

(* ---------------------------------------------------------------------- *)
(* Merlin transcripts, over STROBE128. Ported from the "merlin" Rust
   crate's [transcript.rs]: [append_message]/[challenge_bytes] use two
   meta-AD calls (label, then length-as-continuation); the witness/RNG
   path used for Schnorrkel's randomized nonce uses a differently
   shaped sequence of meta-AD/KEY/PRF calls -- both ported separately,
   matching their respective Rust functions rather than being merged. *)

let merlin_protocol_label = "Merlin v1.0"

let transcript_new label =
  let t = strobe_new merlin_protocol_label in
  strobe_meta_ad t "dom-sep" false;
  strobe_meta_ad t (encode_u32_le (String.length label)) true;
  strobe_ad t label false;
  t

let append_message t label data =
  strobe_meta_ad t label false;
  strobe_meta_ad t (encode_u32_le (String.length data)) true;
  strobe_ad t data false

let challenge_bytes t label n =
  strobe_meta_ad t label false;
  strobe_meta_ad t (encode_u32_le n) true;
  strobe_prf t n false

let challenge_scalar t label = scalar_reduce_wide (challenge_bytes t label 64)

let rekey_with_witness_bytes t label witness =
  strobe_meta_ad t label false;
  strobe_meta_ad t (encode_u32_le (String.length witness)) true;
  strobe_key t witness false

let finalize_rng t ?g () =
  let random_bytes = Mirage_crypto_rng.generate ?g 32 in
  strobe_meta_ad t "rng" false;
  strobe_key t random_bytes false

let transcript_rng_fill_bytes t n =
  strobe_meta_ad t (encode_u32_le n) false;
  strobe_prf t n false

let witness_bytes ?g t label nonce_seeds n =
  let br = strobe_copy t in
  Fun.protect ~finally:(fun () -> Bytes.fill br.state 0 200 '\000') (fun () ->
    List.iter (fun ns -> rekey_with_witness_bytes br label ns) nonce_seeds;
    finalize_rng br ?g ();
    transcript_rng_fill_bytes br n)

let witness_scalar ?g t label nonce_seeds = scalar_reduce_wide (witness_bytes ?g t label nonce_seeds 64)

(* SigningContext::new(ctx).bytes(msg), per schnorrkel's context.rs. *)
let signing_transcript ~context msg =
  let t = transcript_new "SigningContext" in
  append_message t "" context;
  let t = strobe_copy t in
  append_message t "sign-bytes" msg;
  t

(* ---------------------------------------------------------------------- *)
(* Schnorrkel: key expansion and Ristretto Schnorr sign/verify. Ported
   from the "schnorrkel" Rust crate's keys.rs/sign.rs. *)

let sha512 s = Digestif.SHA512.(to_raw_string (digest_string s))

(* schnorrkel's [divide_scalar_bytes_by_cofactor]/[multiply_...]: a
   32-byte little-endian integer divided (resp. multiplied) by 8,
   propagating carry bits between adjacent bytes by hand rather than
   using arbitrary-precision arithmetic, to match the Rust byte-level algorithm exactly. *)
let divide_scalar_bytes_by_cofactor bytes =
  let low = ref 0 in
  for i = 31 downto 0 do
    let b = Char.code (Bytes.get bytes i) in
    let r = b land 0b111 in
    Bytes.set bytes i (Char.chr ((b lsr 3) lor !low));
    low := (r lsl 5) land 0xff
  done

(* MiniSecretKey::expand(ExpansionMode::Ed25519) -- the mode
   polkadot-sdk's sp-core::sr25519 actually uses for [Pair::from_seed],
   confirmed by reading that crate's source, not assumed. *)
let expand_ed25519 (seed : string) : string * string =
  let h = sha512 seed in
  let key = Bytes.of_string (String.sub h 0 32) in
  Bytes.set key 0 (Char.chr (Char.code (Bytes.get key 0) land 0xf8));
  Bytes.set key 31 (Char.chr ((Char.code (Bytes.get key 31) land 0x3f) lor 0x40));
  divide_scalar_bytes_by_cofactor key;
  let key_scalar = scalar_reduce_wide (Bytes.to_string key ^ String.make 32 '\000') in
  let nonce = String.sub h 32 32 in
  (key_scalar, nonce)

(* Schnorrkel's Signature::to_bytes/from_bytes distinguish schnorrkel
   signatures from Ed25519 signatures via the top bit of the last byte
   (which is always unset on a canonical, reduced scalar, so it is safe
   to use as a marker). *)
let signature_marker_bit = 0x80

let encode_signature_parts ((r_bytes, s) : string * string) : string =
  let s_bytes = Bytes.of_string s in
  Bytes.set s_bytes 31 (Char.chr (Char.code (Bytes.get s_bytes 31) lor signature_marker_bit));
  r_bytes ^ Bytes.unsafe_to_string s_bytes

let decode_signature_parts (s : string) : (string * string, error) result =
  if String.length s <> 64 then Error `Invalid_length
  else
    let r_bytes = String.sub s 0 32 in
    let s_bytes = Bytes.of_string (String.sub s 32 32) in
    let top = Char.code (Bytes.get s_bytes 31) in
    if top land signature_marker_bit = 0 then Error `Invalid_format
    else begin
      Bytes.set s_bytes 31 (Char.chr (top land lnot signature_marker_bit));
      match scalar_of_bytes_canonical (Bytes.unsafe_to_string s_bytes) with
      | Error _ as e -> e
      | Ok sv -> Ok (r_bytes, sv)
    end

(* ---------------------------------------------------------------------- *)
(* Public API. [priv]/[pub]/[signature] are kept as opaque byte strings
   (32/32/64 bytes respectively) rather than richer abstract types,
   validated at each function boundary; a [MiniSecretKey] seed has no
   structural invariant beyond its length, so there is little to gain
   from a heavier wrapper type. *)

type priv = string
type pub = string
type signature = string

let default_context = "substrate"

let priv_of_octets (s : string) : (priv, error) result =
  if String.length s <> 32 then Error `Invalid_length else Ok s

let priv_to_octets (p : priv) : string = p

let pub_of_octets (s : string) : (pub, error) result =
  match ristretto_decode s with Ok _ -> Ok s | Error _ as e -> e

let pub_to_octets (p : pub) : string = p

let pub_of_priv (seed : priv) : pub =
  let key_scalar, _ = expand_ed25519 seed in
  point_to_pub key_scalar

let signature_of_octets (s : string) : (signature, error) result =
  match decode_signature_parts s with Ok _ -> Ok s | Error _ as e -> e

let signature_to_octets (s : signature) : string = s

(* Schnorr-sig transcript per schnorrkel::sign::{SecretKey::sign,
   PublicKey::verify}: proto-name, then commit the public key, then
   (only for signing) derive the witness nonce before committing R. *)
let sign ?g ?(context = default_context) ~key:(seed : priv) (msg : string) : signature =
  let key_scalar, nonce = expand_ed25519 seed in
  let pub_bytes = point_to_pub key_scalar in
  let t = signing_transcript ~context msg in
  append_message t "proto-name" "Schnorr-sig";
  append_message t "sign:pk" pub_bytes;
  let r = witness_scalar ?g t "signing" [ nonce ] in
  let big_r = point_to_pub r in
  append_message t "sign:R" big_r;
  let k = challenge_scalar t "sign:c" in
  let s = scalar_add (scalar_mul k key_scalar) r in
  encode_signature_parts (big_r, s)

let verify ?(context = default_context) ~key:(pk : pub) (signature : signature) (msg : string) : bool =
  match (ristretto_decode pk, decode_signature_parts signature) with
  | Error _, _ | _, Error _ -> false
  | Ok a, Ok (big_r, s) ->
    let t = signing_transcript ~context msg in
    append_message t "proto-name" "Schnorr-sig";
    append_message t "sign:pk" pk;
    append_message t "sign:R" big_r;
    let k = challenge_scalar t "sign:c" in
    let r' = point_sub (point_to_pub s) (scalar_mult k a) in
    Eqaf.equal r' big_r

(* schnorrkel::PublicKey::verify_simple_preaudit_deprecated: an older,
   differently-labeled transcript that predates [SigningContext] and
   the "sign:*" labels. Kept only to validate this module's STROBE128 /
   Merlin port against a real, fixed, externally-produced signature
   (schnorrkel-js) in this package's tests -- ordinary sr25519
   signatures should always be verified with {!verify}. *)
let verify_deprecated ?(context = default_context) ~key:(pk : pub) (signature : signature) (msg : string) : bool =
  match (ristretto_decode pk, decode_signature_parts signature) with
  | Error _, _ | _, Error _ -> false
  | Ok a, Ok (big_r, s) ->
    let t = transcript_new context in
    append_message t "sign-bytes" msg;
    append_message t "proto-name" "Schnorr-sig";
    append_message t "pk" pk;
    append_message t "no" big_r;
    let k = challenge_scalar t "" in
    let r' = point_sub (point_to_pub s) (scalar_mult k a) in
    Eqaf.equal r' big_r

let ristretto_from_uniform_bytes (b : string) : string =
  if String.length b <> 64 then
    invalid_arg "Sr25519.ristretto_from_uniform_bytes: input must be 64 bytes";
  ristretto_point_from_uniform_bytes b

(* Schnorrkel VRF pre-output (schnorrkel::vrf's VRFInOut.output). The VRF
   input is the malleable hash of the signing transcript
   (challenge_bytes "VRFHash" -> from_uniform_bytes, per schnorrkel's
   [vrf_malleable_hash]); the pre-output is [key_scalar * input], encoded
   as a 32-byte ristretto element. The randomized DLEQ proof, and
   [VRFInOut::make_bytes] (which folds the input/output points through a
   further "VRFResult" transcript to produce application randomness), are
   deliberately out of scope here. *)
let vrf_output ~key:(seed : priv) (msg : string) : string =
  let key_scalar, _ = expand_ed25519 seed in
  let t = signing_transcript ~context:default_context msg in
  let input = ristretto_point_from_uniform_bytes (challenge_bytes t "VRFHash" 64) in
  scalar_mult key_scalar input
