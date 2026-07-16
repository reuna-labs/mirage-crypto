module type ENCRYPTION_TYPE = sig
  val etype           : int
  val block_size      : int
  val key_bytes       : int
  val confounder_bytes: int
  val checksum_bytes  : int
  type key
  val of_secret    : string -> key
  val to_secret    : key -> string
  val generate     : ?g:Mirage_crypto_rng.g -> unit -> key
  val string_to_key: password:string -> salt:string -> ?params:string -> unit -> key
  val encrypt : ?g:Mirage_crypto_rng.g -> key:key -> key_usage:int -> string -> string
  val decrypt : key:key -> key_usage:int -> string -> string option
  val checksum        : key:key -> key_usage:int -> string -> string
  val verify_checksum : key:key -> key_usage:int -> msg:string -> string -> bool
end

(* ===== n-fold (RFC 3961 §5.1) ===== *)

let n_fold s out_len =
  let k = String.length s in
  let n = out_len in
  let rec gcd a b = if b = 0 then a else gcd b (a mod b) in
  let lcm   = k * n / gcd k n in
  let nreps = lcm / k in
  let expanded = Bytes.make lcm '\x00' in
  for rep = 0 to nreps - 1 do
    let rot = (rep * 13) mod (k * 8) in
    for j = 0 to k - 1 do
      let src_bit = (j * 8 - rot + k * 8) mod (k * 8) in
      let r_bytes = src_bit / 8 in
      let r_bits  = src_bit mod 8 in
      let b0 = Char.code s.[r_bytes] in
      let b1 = Char.code s.[(r_bytes + 1) mod k] in
      let v  = ((b0 lsl r_bits) lor (b1 lsr (8 - r_bits))) land 0xFF in
      Bytes.set expanded (rep * k + j) (Char.chr v)
    done
  done;
  let result = Bytes.make n '\x00' in
  let carry  = ref 0 in
  for i = lcm - 1 downto 0 do
    let c = Char.code (Bytes.get expanded i)
          + Char.code (Bytes.get result (i mod n))
          + !carry in
    Bytes.set result (i mod n) (Char.chr (c land 0xFF));
    carry := c lsr 8
  done;
  let pos = ref (n - 1) in
  while !carry > 0 do
    let c = Char.code (Bytes.get result !pos) + !carry in
    Bytes.set result !pos (Char.chr (c land 0xFF));
    carry := c lsr 8;
    pos   := (!pos - 1 + n) mod n
  done;
  Bytes.unsafe_to_string result

(* ===== Miscellaneous helpers ===== *)

let xor_strings a b =
  let n = String.length a in
  assert (String.length b = n);
  let buf = Bytes.create n in
  for i = 0 to n - 1 do
    Bytes.set buf i (Char.chr (Char.code a.[i] lxor Char.code b.[i]))
  done;
  Bytes.unsafe_to_string buf

let usage_constant key_usage suffix =
  let b = Bytes.create 5 in
  Bytes.set_int32_be b 0 (Int32.of_int key_usage);
  Bytes.set b 4 (Char.chr suffix);
  Bytes.unsafe_to_string b

(* ===== PBKDF2 ===== *)

let pbkdf2 (module H : Digestif.S) ~password ~salt ~iterations ~key_len =
  let h_len    = H.digest_size in
  let n_blocks = (key_len + h_len - 1) / h_len in
  let dk = Buffer.create key_len in
  for i = 1 to n_blocks do
    let i_be = Bytes.create 4 in
    Bytes.set_int32_be i_be 0 (Int32.of_int i);
    let u1 = H.hmac_string ~key:password (salt ^ Bytes.unsafe_to_string i_be)
             |> H.to_raw_string in
    let u   = ref u1 in
    let acc = ref u1 in
    for _ = 2 to iterations do
      u := H.hmac_string ~key:password !u |> H.to_raw_string;
      acc := xor_strings !acc !u
    done;
    Buffer.add_string dk !acc
  done;
  String.sub (Buffer.contents dk) 0 key_len

(* ===== RFC 3962 key derivation (etypes 17/18): AES-CBC as PRF ===== *)

let dr_aes base_key key_bytes constant =
  (* RFC 3961 §5.1: n-fold to AES block size (16), then CBC-feedback until key_bytes *)
  let iv  = String.make 16 '\x00' in
  let k   = Mirage_crypto.AES.CBC.of_secret base_key in
  let t   = ref (n_fold constant 16) in
  let buf = Buffer.create key_bytes in
  while Buffer.length buf < key_bytes do
    t := Mirage_crypto.AES.CBC.encrypt ~key:k ~iv !t;
    Buffer.add_string buf !t
  done;
  String.sub (Buffer.contents buf) 0 key_bytes

let dk_aes base_key key_bytes key_usage suffix =
  dr_aes base_key key_bytes (usage_constant key_usage suffix)

(* ===== RFC 8009 key derivation (etypes 19/20): NIST SP 800-108 feedback mode ===== *)

(* KDF-HMAC-SHA2(key, constant, out_bytes):
   T(0) = ""
   T(i) = HMAC(key, T(i-1) || i_4BE || "kerberos\x00" || constant || out_bits_2BE) *)
let kdf_hmac_sha2 (module H : Digestif.S) key constant key_bytes =
  let k_bits_be = Bytes.create 2 in
  Bytes.set_uint16_be k_bits_be 0 (key_bytes * 8);
  let fixed    = "kerberos\x00" ^ constant ^ Bytes.unsafe_to_string k_bits_be in
  let n_blocks = (key_bytes + H.digest_size - 1) / H.digest_size in
  let buf = Buffer.create key_bytes in
  let t   = ref "" in
  for i = 1 to n_blocks do
    let i_be = Bytes.create 4 in
    Bytes.set_int32_be i_be 0 (Int32.of_int i);
    let input = !t ^ Bytes.unsafe_to_string i_be ^ fixed in
    t := H.hmac_string ~key input |> H.to_raw_string;
    Buffer.add_string buf !t
  done;
  String.sub (Buffer.contents buf) 0 key_bytes

(* ===== AES-CTS helpers ===== *)

let cts_encrypt ke iv msg =
  Mirage_crypto.AES.CTS.encrypt ~key:(Mirage_crypto.AES.CTS.of_secret ke) ~iv msg

let cts_decrypt ke iv msg =
  Mirage_crypto.AES.CTS.decrypt ~key:(Mirage_crypto.AES.CTS.of_secret ke) ~iv msg

(* ===== Generic AES-CTS + HMAC (etypes 17/18/19/20) ===== *)

let aes_cts_encrypt ~hmac ~derive_ke ~derive_ki ~confounder_len ~checksum_bytes
    ?g ~key ~key_usage msg =
  let ke  = derive_ke key key_usage in
  let ki  = derive_ki key key_usage in
  let cnf = Mirage_crypto_rng.generate ?g confounder_len in
  let plain = cnf ^ msg in
  let iv  = String.make 16 '\x00' in
  let enc = cts_encrypt ke iv plain in
  let mac = String.sub (hmac ki plain) 0 checksum_bytes in
  enc ^ mac

let aes_cts_decrypt ~hmac ~derive_ke ~derive_ki ~confounder_len ~checksum_bytes
    ~key ~key_usage ciphertext =
  let clen = String.length ciphertext in
  if clen < confounder_len + checksum_bytes then None
  else
    let enc_len = clen - checksum_bytes in
    let enc = String.sub ciphertext 0 enc_len in
    let mac = String.sub ciphertext enc_len checksum_bytes in
    let ke  = derive_ke key key_usage in
    let ki  = derive_ki key key_usage in
    let iv  = String.make 16 '\x00' in
    match (try Some (cts_decrypt ke iv enc) with Invalid_argument _ -> None) with
    | None -> None
    | Some plain ->
      let expected = String.sub (hmac ki plain) 0 checksum_bytes in
      if Eqaf.equal expected mac then
        Some (String.sub plain confounder_len (String.length plain - confounder_len))
      else None

(* ===== etype 17/18 (RFC 3962) ===== *)

module Make_aes_sha1 (P : sig
  val etype : int
  val key_bytes : int
  val string_to_key_iters : int
end) : ENCRYPTION_TYPE = struct
  let etype            = P.etype
  let block_size       = 16
  let key_bytes        = P.key_bytes
  let confounder_bytes = 16
  let checksum_bytes   = 12
  type key = string

  let of_secret s =
    if String.length s <> key_bytes then
      invalid_arg "Mirage_crypto_kerberos: wrong key length";
    s

  let to_secret k = k

  let string_to_key ~password ~salt ?(params = "") () =
    let iterations =
      if String.length params = 4
      then Int32.to_int (String.get_int32_be params 0) |> abs
      else P.string_to_key_iters
    in
    (* RFC 3962 §4: tkey = PBKDF2-SHA1, then base_key = DK(tkey, "kerberos") *)
    let tkey = pbkdf2 (module Digestif.SHA1) ~password ~salt ~iterations ~key_len:key_bytes in
    dr_aes tkey key_bytes "kerberos"

  let derive_ke key usage = dk_aes key key_bytes usage 0xAA
  let derive_ki key usage = dk_aes key key_bytes usage 0x55
  let hmac ki plain = Digestif.SHA1.hmac_string ~key:ki plain |> Digestif.SHA1.to_raw_string

  let generate ?g () = Mirage_crypto_rng.generate ?g key_bytes

  let encrypt ?g ~key ~key_usage msg =
    aes_cts_encrypt ~hmac ~derive_ke ~derive_ki
      ~confounder_len:confounder_bytes ~checksum_bytes ?g ~key ~key_usage msg

  let decrypt ~key ~key_usage ciphertext =
    aes_cts_decrypt ~hmac ~derive_ke ~derive_ki
      ~confounder_len:confounder_bytes ~checksum_bytes ~key ~key_usage ciphertext

  let checksum ~key ~key_usage msg =
    let ki = derive_ki key key_usage in
    String.sub (hmac ki msg) 0 checksum_bytes

  let verify_checksum ~key ~key_usage ~msg mac =
    String.length mac = checksum_bytes &&
    Eqaf.equal (checksum ~key ~key_usage msg) mac
end

module Aes128_cts_hmac_sha1_96 = Make_aes_sha1 (struct
  let etype = 17 let key_bytes = 16 let string_to_key_iters = 4096
end)

module Aes256_cts_hmac_sha1_96 = Make_aes_sha1 (struct
  let etype = 18 let key_bytes = 32 let string_to_key_iters = 4096
end)

(* ===== etype 19/20 (RFC 8009) ===== *)

module Make_aes_sha2 (P : sig
  val etype          : int
  val key_bytes      : int
  val checksum_bytes : int
  val string_to_key_iters : int
  module H : Digestif.S
end) : ENCRYPTION_TYPE = struct
  let etype            = P.etype
  let block_size       = 16
  let key_bytes        = P.key_bytes
  let confounder_bytes = 16
  let checksum_bytes   = P.checksum_bytes
  type key = string

  let of_secret s =
    if String.length s <> key_bytes then
      invalid_arg "Mirage_crypto_kerberos: wrong key length";
    s

  let to_secret k = k

  let string_to_key ~password ~salt ?(params = "") () =
    let iterations =
      if String.length params = 4
      then Int32.to_int (String.get_int32_be params 0) |> abs
      else P.string_to_key_iters
    in
    let tkey = pbkdf2 (module Digestif.SHA256) ~password ~salt ~iterations ~key_len:key_bytes in
    kdf_hmac_sha2 (module P.H) tkey "" key_bytes

  let derive_ke key usage = kdf_hmac_sha2 (module P.H) key (usage_constant usage 0xAA) key_bytes
  let derive_ki key usage = kdf_hmac_sha2 (module P.H) key (usage_constant usage 0x55) key_bytes
  let hmac ki plain = P.H.hmac_string ~key:ki plain |> P.H.to_raw_string

  let generate ?g () = Mirage_crypto_rng.generate ?g key_bytes

  let encrypt ?g ~key ~key_usage msg =
    aes_cts_encrypt ~hmac ~derive_ke ~derive_ki
      ~confounder_len:confounder_bytes ~checksum_bytes ?g ~key ~key_usage msg

  let decrypt ~key ~key_usage ciphertext =
    aes_cts_decrypt ~hmac ~derive_ke ~derive_ki
      ~confounder_len:confounder_bytes ~checksum_bytes ~key ~key_usage ciphertext

  let checksum ~key ~key_usage msg =
    let ki = derive_ki key key_usage in
    String.sub (hmac ki msg) 0 checksum_bytes

  let verify_checksum ~key ~key_usage ~msg mac =
    String.length mac = checksum_bytes &&
    Eqaf.equal (checksum ~key ~key_usage msg) mac
end

module Aes128_cts_hmac_sha256_128 = Make_aes_sha2 (struct
  let etype = 19 let key_bytes = 16 let checksum_bytes = 16 let string_to_key_iters = 32768
  module H = Digestif.SHA256
end)

module Aes256_cts_hmac_sha384_192 = Make_aes_sha2 (struct
  let etype = 20 let key_bytes = 32 let checksum_bytes = 24 let string_to_key_iters = 32768
  module H = Digestif.SHA384
end)

let of_etype = function
  | 17 -> Some (module Aes128_cts_hmac_sha1_96    : ENCRYPTION_TYPE)
  | 18 -> Some (module Aes256_cts_hmac_sha1_96    : ENCRYPTION_TYPE)
  | 19 -> Some (module Aes128_cts_hmac_sha256_128 : ENCRYPTION_TYPE)
  | 20 -> Some (module Aes256_cts_hmac_sha384_192 : ENCRYPTION_TYPE)
  | _  -> None
