(* BIP32-Ed25519 hierarchical deterministic keys (Khovratovich & Law, as
   used by Cardano), child derivation per DerivationScheme V2. Built on
   the low-level Ed25519 scalar/point primitives exposed by
   mirage-crypto-ec ({!Mirage_crypto_ec.Ed25519.Primitive}).

   NOT CONSTANT TIME: inherits the variable-time point decoding of the ec
   Ed25519 primitives and does plain byte arithmetic on secret scalars.

   Master key generation follows the paper's SHA-512 scheme: k =
   SHA512(seed); the 3rd-highest bit of kL's last byte must be clear (so
   the 8*ZL additions never overflow across a derivation path); kL is
   then clamped; the chain code is SHA256(0x01 || seed). Child derivation
   and signing (V2) were cross-checked against Cardano's
   rust-ed25519-bip32 (add_28_mul8_v2 / add_256bits_v2, domain-separation
   tags 0x00/0x01 for hardened and 0x02/0x03 for soft), not reconstructed
   from memory. *)

module P = Mirage_crypto_ec.Ed25519.Primitive

type error = [ `Invalid_format | `Invalid_length | `Invalid_derivation ]

let pp_error ppf = function
  | `Invalid_format -> Format.fprintf ppf "invalid format"
  | `Invalid_length -> Format.fprintf ppf "invalid length"
  | `Invalid_derivation -> Format.fprintf ppf "invalid derivation"

(* kL(32) || kR(32) || chain code(32). *)
type extended_priv = string

(* A(32) || chain code(32). *)
type extended_pub = string

let sha512 s = Digestif.SHA512.(to_raw_string (digest_string s))
let sha256 s = Digestif.SHA256.(to_raw_string (digest_string s))
let hmac512 ~key data = Digestif.SHA512.(to_raw_string (hmac_string ~key data))

let zeros32 = String.make 32 '\000'

let le32 (i : int32) =
  let b = Bytes.create 4 in
  Bytes.set_int32_le b 0 i;
  Bytes.unsafe_to_string b

(* out = x + (8 * low-28-bytes-of y), 32-byte little-endian, final carry
   out of byte 31 dropped (mod 2^256). *)
let add_28_mul8 x y =
  let out = Bytes.create 32 in
  let carry = ref 0 in
  for i = 0 to 27 do
    let r = Char.code x.[i] + (Char.code y.[i] lsl 3) + !carry in
    Bytes.set out i (Char.chr (r land 0xff));
    carry := r lsr 8
  done;
  for i = 28 to 31 do
    let r = Char.code x.[i] + !carry in
    Bytes.set out i (Char.chr (r land 0xff));
    carry := r lsr 8
  done;
  Bytes.unsafe_to_string out

(* out = (x + y) mod 2^256, 32-byte little-endian. *)
let add_256bits x y =
  let out = Bytes.create 32 in
  let carry = ref 0 in
  for i = 0 to 31 do
    let r = Char.code x.[i] + Char.code y.[i] + !carry in
    Bytes.set out i (Char.chr (r land 0xff));
    carry := r lsr 8
  done;
  Bytes.unsafe_to_string out

(* 8 * int(low 28 bytes of zl), as a 32-byte little-endian scalar. *)
let trunc28_mul8 zl = add_28_mul8 zeros32 zl

(* Hardened iff the high bit of the index is set (index >= 2^31). *)
let is_hardened (i : int32) = Int32.compare i 0l < 0

let split_priv (xprv : extended_priv) =
  (String.sub xprv 0 32, String.sub xprv 32 32, String.sub xprv 64 32)

let split_pub (xpub : extended_pub) = (String.sub xpub 0 32, String.sub xpub 32 32)

let extended_priv_of_octets s =
  if String.length s = 96 then Ok s else Error `Invalid_length

let extended_priv_to_octets (xprv : extended_priv) = xprv

let extended_pub_of_octets s =
  if String.length s <> 64 then Error `Invalid_length
  else if not (P.point_valid (String.sub s 0 32)) then Error `Invalid_format
  else Ok s

let extended_pub_to_octets (xpub : extended_pub) = xpub

let master_key_of_seed (seed : string) : (extended_priv, error) result =
  let k = sha512 seed in
  let kl = Bytes.of_string (String.sub k 0 32) in
  if Char.code (Bytes.get kl 31) land 0x20 <> 0 then Error `Invalid_derivation
  else begin
    Bytes.set kl 0 (Char.chr (Char.code (Bytes.get kl 0) land 0xf8));
    Bytes.set kl 31 (Char.chr ((Char.code (Bytes.get kl 31) land 0x7f) lor 0x40));
    let kl = Bytes.unsafe_to_string kl in
    let kr = String.sub k 32 32 in
    let cc = sha256 ("\001" ^ seed) in
    Ok (kl ^ kr ^ cc)
  end

let pub_of_priv (xprv : extended_priv) : extended_pub =
  let kl, _kr, cc = split_priv xprv in
  P.scalar_mult_base kl ^ cc

let derive_priv (xprv : extended_priv) ~hardened ~index : (extended_priv, error) result =
  if String.length xprv <> 96 then Error `Invalid_length
  else
    let kl, kr, cc = split_priv xprv in
    let i = le32 index in
    let z_data, cc_data =
      if hardened then ("\000" ^ kl ^ kr ^ i, "\001" ^ kl ^ kr ^ i)
      else
        let a = P.scalar_mult_base kl in
        ("\002" ^ a ^ i, "\003" ^ a ^ i)
    in
    let z = hmac512 ~key:cc z_data in
    let child_kl = add_28_mul8 kl (String.sub z 0 32) in
    let child_kr = add_256bits kr (String.sub z 32 32) in
    let child_cc = String.sub (hmac512 ~key:cc cc_data) 32 32 in
    Ok (child_kl ^ child_kr ^ child_cc)

let derive_priv_normal xprv ~index =
  if is_hardened index then Error `Invalid_derivation
  else derive_priv xprv ~hardened:false ~index

let derive_priv_hardened xprv ~index =
  if is_hardened index then derive_priv xprv ~hardened:true ~index
  else Error `Invalid_derivation

let derive_pub_normal (xpub : extended_pub) ~index : (extended_pub, error) result =
  if is_hardened index then Error `Invalid_derivation
  else if String.length xpub <> 64 then Error `Invalid_length
  else
    let a, cc = split_pub xpub in
    let i = le32 index in
    let z = hmac512 ~key:cc ("\002" ^ a ^ i) in
    let child_cc = String.sub (hmac512 ~key:cc ("\003" ^ a ^ i)) 32 32 in
    let tweak = P.scalar_mult_base (trunc28_mul8 (String.sub z 0 32)) in
    match P.point_add a tweak with
    | Ok child_a -> Ok (child_a ^ child_cc)
    | Error _ -> Error `Invalid_derivation

(* Extended-key signing: kL is the scalar and kR the nonce prefix (as in
   the "extended" Ed25519 secret key), so no re-hashing/clamping of the
   key; otherwise identical to RFC 8032 Ed25519. *)
let sign ~key:(xprv : extended_priv) (msg : string) : string =
  let kl, kr, _cc = split_priv xprv in
  let a = P.scalar_mult_base kl in
  let r = P.scalar_reduce (sha512 (kr ^ msg)) in
  let big_r = P.scalar_mult_base r in
  let k = P.scalar_reduce (sha512 (big_r ^ a ^ msg)) in
  let s = P.scalar_muladd k kl r in
  big_r ^ s

let verify ~key:(xpub : extended_pub) (signature : string) ~msg : bool =
  if String.length signature <> 64 || String.length xpub <> 64 then false
  else
    let a, _cc = split_pub xpub in
    let big_r = String.sub signature 0 32 and s = String.sub signature 32 32 in
    (* reject non-canonical s (s >= L) *)
    if not (String.equal (P.scalar_reduce (s ^ zeros32)) s) then false
    else
      let k = P.scalar_reduce (sha512 (big_r ^ a ^ msg)) in
      let ok, r' = P.verify_double_base ~k ~pub:a ~s in
      ok && String.equal r' big_r
