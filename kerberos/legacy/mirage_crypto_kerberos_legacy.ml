module type ENCRYPTION_TYPE = Mirage_crypto_kerberos.ENCRYPTION_TYPE

module Aes128_cts_hmac_sha1_96    = Mirage_crypto_kerberos.Aes128_cts_hmac_sha1_96
module Aes256_cts_hmac_sha1_96    = Mirage_crypto_kerberos.Aes256_cts_hmac_sha1_96
module Aes128_cts_hmac_sha256_128 = Mirage_crypto_kerberos.Aes128_cts_hmac_sha256_128
module Aes256_cts_hmac_sha384_192 = Mirage_crypto_kerberos.Aes256_cts_hmac_sha384_192

(* ===== MD4 (RFC 1320) — needed for RC4-HMAC NT hash ===== *)

let md4 msg =
  let len = String.length msg in
  let bit_len = len * 8 in
  let r = (len + 1) mod 64 in
  let padding_len = if r <= 56 then 56 - r else 120 - r in
  let padded_len = len + 1 + padding_len + 8 in
  let buf = Bytes.make padded_len '\x00' in
  Bytes.blit_string msg 0 buf 0 len;
  Bytes.set buf len '\x80';
  for i = 0 to 7 do
    Bytes.set buf (padded_len - 8 + i)
      (Char.chr ((bit_len lsr (i * 8)) land 0xFF))
  done;
  let a0 = ref 0x67452301l in
  let b0 = ref 0xEFCDAB89l in
  let c0 = ref 0x98BADCFEl in
  let d0 = ref 0x10325476l in
  let get32le off =
    let b0 = Char.code (Bytes.get buf off) in
    let b1 = Char.code (Bytes.get buf (off+1)) in
    let b2 = Char.code (Bytes.get buf (off+2)) in
    let b3 = Char.code (Bytes.get buf (off+3)) in
    Int32.of_int (b0 lor (b1 lsl 8) lor (b2 lsl 16) lor (b3 lsl 24))
  in
  let ( +! ) = Int32.add in
  let ( &! ) = Int32.logand in
  let ( |! ) = Int32.logor in
  let ( ^! ) = Int32.logxor in
  let rotl32 x n = Int32.logor (Int32.shift_left x n) (Int32.shift_right_logical x (32-n)) in
  let ff a b c d x s =
    rotl32 (!a +! ((!b &! !c) |! (Int32.lognot !b &! !d)) +! x) s in
  let gg a b c d x s =
    rotl32 (!a +! ((!b &! !c) |! (!b &! !d) |! (!c &! !d)) +! x +! 0x5A827999l) s in
  let hh a b c d x s =
    rotl32 (!a +! (!b ^! !c ^! !d) +! x +! 0x6ED9EBA1l) s in
  let n_blocks = padded_len / 64 in
  for blk = 0 to n_blocks - 1 do
    let off = blk * 64 in
    let x = Array.init 16 (fun i -> get32le (off + i * 4)) in
    let a = ref !a0 and b = ref !b0 and c = ref !c0 and d = ref !d0 in
    a:=ff a b c d x.(0) 3; d:=ff d a b c x.(1) 7; c:=ff c d a b x.(2) 11; b:=ff b c d a x.(3) 19;
    a:=ff a b c d x.(4) 3; d:=ff d a b c x.(5) 7; c:=ff c d a b x.(6) 11; b:=ff b c d a x.(7) 19;
    a:=ff a b c d x.(8) 3; d:=ff d a b c x.(9) 7; c:=ff c d a b x.(10) 11; b:=ff b c d a x.(11) 19;
    a:=ff a b c d x.(12) 3; d:=ff d a b c x.(13) 7; c:=ff c d a b x.(14) 11; b:=ff b c d a x.(15) 19;
    a:=gg a b c d x.(0) 3; d:=gg d a b c x.(4) 5; c:=gg c d a b x.(8) 9; b:=gg b c d a x.(12) 13;
    a:=gg a b c d x.(1) 3; d:=gg d a b c x.(5) 5; c:=gg c d a b x.(9) 9; b:=gg b c d a x.(13) 13;
    a:=gg a b c d x.(2) 3; d:=gg d a b c x.(6) 5; c:=gg c d a b x.(10) 9; b:=gg b c d a x.(14) 13;
    a:=gg a b c d x.(3) 3; d:=gg d a b c x.(7) 5; c:=gg c d a b x.(11) 9; b:=gg b c d a x.(15) 13;
    a:=hh a b c d x.(0) 3; d:=hh d a b c x.(8) 9; c:=hh c d a b x.(4) 11; b:=hh b c d a x.(12) 15;
    a:=hh a b c d x.(2) 3; d:=hh d a b c x.(10) 9; c:=hh c d a b x.(6) 11; b:=hh b c d a x.(14) 15;
    a:=hh a b c d x.(1) 3; d:=hh d a b c x.(9) 9; c:=hh c d a b x.(5) 11; b:=hh b c d a x.(13) 15;
    a:=hh a b c d x.(3) 3; d:=hh d a b c x.(11) 9; c:=hh c d a b x.(7) 11; b:=hh b c d a x.(15) 15;
    a0 := !a0 +! !a; b0 := !b0 +! !b; c0 := !c0 +! !c; d0 := !d0 +! !d
  done;
  let result = Bytes.make 16 '\x00' in
  let put32le off v =
    for i = 0 to 3 do
      Bytes.set result (off + i)
        (Char.chr (Int32.to_int (Int32.logand (Int32.shift_right_logical v (i*8)) 0xFFl)))
    done
  in
  put32le 0 !a0; put32le 4 !b0; put32le 8 !c0; put32le 12 !d0;
  Bytes.unsafe_to_string result

(* ===== n-fold (RFC 3961 §5.1) — needed by 3DES key derivation ===== *)

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

(* ===== 3DES key handling (RFC 3961 §6.3.2) ===== *)

let usage_constant key_usage suffix =
  let b = Bytes.create 5 in
  Bytes.set_int32_be b 0 (Int32.of_int key_usage);
  Bytes.set b 4 (Char.chr suffix);
  Bytes.unsafe_to_string b

let des_fix_parity b =
  let count = ref 0 in
  for j = 1 to 7 do if b land (1 lsl j) <> 0 then incr count done;
  if !count mod 2 = 0 then b lor 1 else b land 0xFE

let des3_random_to_key raw =
  assert (String.length raw = 21);
  let result = Bytes.make 24 '\x00' in
  for s = 0 to 2 do
    let base_in  = s * 7 in
    let base_out = s * 8 in
    for i = 0 to 6 do
      let b = Char.code raw.[base_in + i] in
      Bytes.set result (base_out + i) (Char.chr (des_fix_parity (b land 0xFE)))
    done;
    let v = ref 0 in
    for i = 6 downto 0 do
      v := (!v lsl 1) lor (Char.code raw.[base_in + i] land 1)
    done;
    Bytes.set result (base_out + 7) (Char.chr (des_fix_parity (!v lsl 1)))
  done;
  Bytes.unsafe_to_string result

let dr_des3 base_key constant =
  let iv  = String.make 8 '\x00' in
  let k   = Mirage_crypto.DES.CBC.of_secret base_key in
  let t   = ref (n_fold constant 8) in
  let buf = Buffer.create 21 in
  while Buffer.length buf < 21 do
    t := Mirage_crypto.DES.CBC.encrypt ~key:k ~iv !t;
    Buffer.add_string buf !t
  done;
  des3_random_to_key (String.sub (Buffer.contents buf) 0 21)

let dk_des3 base_key key_usage suffix =
  dr_des3 base_key (usage_constant key_usage suffix)

(* ===== etype 16 (RFC 3961 §6.3.2): 3DES-CBC + HMAC-SHA1 ===== *)

module Des3_cbc_sha1_kd : ENCRYPTION_TYPE = struct
  let etype            = 16
  let block_size       = 8
  let key_bytes        = 24
  let confounder_bytes = 8
  let checksum_bytes   = 20
  type key = string

  let of_secret s =
    if String.length s <> 24 then
      invalid_arg "Mirage_crypto_kerberos: 3DES key must be 24 bytes";
    s

  let to_secret k = k

  let string_to_key ~password ~salt ?params:_ () =
    let tkey = des3_random_to_key (n_fold (password ^ salt) 21) in
    dr_des3 tkey "kerberos"

  let derive_ke key usage = dk_des3 key usage 0xAA
  let derive_ki key usage = dk_des3 key usage 0x55
  let hmac ki msg = Digestif.SHA1.hmac_string ~key:ki msg |> Digestif.SHA1.to_raw_string

  (* RFC 3961 §6.3.1: random-to-key requires exactly 21 raw bytes *)
  let generate ?g () = des3_random_to_key (Mirage_crypto_rng.generate ?g 21)

  let encrypt ?g ~key ~key_usage msg =
    let ke  = derive_ke key key_usage in
    let ki  = derive_ki key key_usage in
    let cnf = Mirage_crypto_rng.generate ?g confounder_bytes in
    let plain = cnf ^ msg in
    let len     = String.length plain in
    let pad_len = (8 - (len mod 8)) mod 8 in
    let padded  = plain ^ String.make pad_len '\x00' in
    let iv  = String.make 8 '\x00' in
    let k   = Mirage_crypto.DES.CBC.of_secret ke in
    let enc = Mirage_crypto.DES.CBC.encrypt ~key:k ~iv padded in
    let mac = hmac ki padded in
    enc ^ mac

  let decrypt ~key ~key_usage ciphertext =
    let clen = String.length ciphertext in
    if clen < confounder_bytes + checksum_bytes then None
    else
      let enc_len = clen - checksum_bytes in
      if enc_len mod 8 <> 0 then None
      else
        let enc  = String.sub ciphertext 0 enc_len in
        let mac  = String.sub ciphertext enc_len checksum_bytes in
        let ke   = derive_ke key key_usage in
        let ki   = derive_ki key key_usage in
        let iv   = String.make 8 '\x00' in
        let k    = Mirage_crypto.DES.CBC.of_secret ke in
        let plain = Mirage_crypto.DES.CBC.decrypt ~key:k ~iv enc in
        let expected = hmac ki plain in
        if Eqaf.equal expected mac then
          Some (String.sub plain confounder_bytes (enc_len - confounder_bytes))
        else None

  let checksum ~key ~key_usage msg =
    let ki = derive_ki key key_usage in
    String.sub (hmac ki msg) 0 checksum_bytes

  let verify_checksum ~key ~key_usage ~msg mac =
    String.length mac = checksum_bytes &&
    Eqaf.equal (checksum ~key ~key_usage msg) mac
end

(* ===== etypes 23/24 (MS-KILE, RFC 4757): RC4-HMAC-MD5 ===== *)

module Make_arcfour (P : sig
  val etype : int
  val exp   : bool
end) : ENCRYPTION_TYPE = struct
  let etype            = P.etype
  let block_size       = 1
  let key_bytes        = 16
  let confounder_bytes = 8
  let checksum_bytes   = 16
  type key = string

  let of_secret s =
    if String.length s <> key_bytes then
      invalid_arg "Mirage_crypto_kerberos: RC4-HMAC key must be 16 bytes";
    s

  let to_secret k = k

  (* NT hash = MD4(UTF-16LE(password)).  Only ASCII passwords are supported here;
     for non-ASCII passwords supply the NT hash directly via [of_secret]. *)
  let string_to_key ~password ~salt:_ ?params:_ () =
    let n     = String.length password in
    let utf16 = Bytes.make (n * 2) '\x00' in
    for i = 0 to n - 1 do Bytes.set utf16 (i * 2) password.[i] done;
    md4 (Bytes.unsafe_to_string utf16)

  let hmac_md5 key msg =
    Digestif.MD5.hmac_string ~key msg |> Digestif.MD5.to_raw_string

  let export_weaken key =
    if P.exp then begin
      let b = Bytes.of_string key in
      Bytes.fill b 9 7 '\x00';
      Bytes.unsafe_to_string b
    end else key

  (* RFC 4757 §4: K1 = HMAC-MD5(BaseKey, usage_LE32); K3 = HMAC-MD5(K1, checksum). *)
  let k1_of key key_usage =
    let usage_le = Bytes.create 4 in
    Bytes.set_int32_le usage_le 0 (Int32.of_int key_usage);
    export_weaken (hmac_md5 key (Bytes.unsafe_to_string usage_le))

  let generate ?g () = Mirage_crypto_rng.generate ?g key_bytes

  let encrypt ?g ~key ~key_usage msg =
    let cnf  = Mirage_crypto_rng.generate ?g confounder_bytes in
    let plain = cnf ^ msg in
    let k1   = k1_of key key_usage in
    let mac  = hmac_md5 k1 plain in
    let k3   = hmac_md5 k1 mac in
    let rc4  = Mirage_crypto.ARC4.of_secret k3 in
    let Mirage_crypto.ARC4.{ message = encrypted; _ } =
      Mirage_crypto.ARC4.encrypt ~key:rc4 plain in
    mac ^ encrypted

  let decrypt ~key ~key_usage ciphertext =
    let clen = String.length ciphertext in
    if clen < checksum_bytes + confounder_bytes then None
    else
      let mac       = String.sub ciphertext 0 checksum_bytes in
      let encrypted = String.sub ciphertext checksum_bytes (clen - checksum_bytes) in
      let k1 = k1_of key key_usage in
      let k3 = hmac_md5 k1 mac in
      let rc4 = Mirage_crypto.ARC4.of_secret k3 in
      let Mirage_crypto.ARC4.{ message = plain; _ } =
        Mirage_crypto.ARC4.decrypt ~key:rc4 encrypted in
      let expected = hmac_md5 k1 plain in
      if Eqaf.equal expected mac then
        Some (String.sub plain confounder_bytes (String.length plain - confounder_bytes))
      else None

  let checksum ~key ~key_usage msg =
    hmac_md5 (k1_of key key_usage) msg

  let verify_checksum ~key ~key_usage ~msg mac =
    String.length mac = checksum_bytes &&
    Eqaf.equal (checksum ~key ~key_usage msg) mac
end

module Arcfour_hmac     = Make_arcfour (struct let etype = 23 let exp = false end)
module Arcfour_hmac_exp = Make_arcfour (struct let etype = 24 let exp = true  end)

let of_etype = function
  | 16 -> Some (module Des3_cbc_sha1_kd  : ENCRYPTION_TYPE)
  | 23 -> Some (module Arcfour_hmac      : ENCRYPTION_TYPE)
  | 24 -> Some (module Arcfour_hmac_exp  : ENCRYPTION_TYPE)
  | n  -> Mirage_crypto_kerberos.of_etype n
