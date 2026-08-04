module type S = sig
  type key

  val of_secret : string -> key
  val key_sizes : int array
  val wrap : key:key -> string -> string
  val unwrap : key:key -> string -> string option
  val wrap_padded : key:key -> string -> string
  val unwrap_padded : key:key -> string -> string option
end

(* The block cipher this is built on. RFC 3394 is defined for AES, and the
   construction assumes a 128-bit block throughout — the wrapped value is a
   sequence of 64-bit half-blocks. *)
module type Block = sig
  type key

  val of_secret : string -> key
  val key_sizes : int array
  val block_size : int
  val encrypt : key:key -> string -> string
  val decrypt : key:key -> string -> string
end

module Make (C : Block) : S with type key = C.key = struct

  type key = C.key

  let key_sizes = C.key_sizes
  let block = C.block_size
  let half = block / 2
  let of_secret = C.of_secret

  (* RFC 3394 §2.2.3.1 *)
  let default_iv = "\xa6\xa6\xa6\xa6\xa6\xa6\xa6\xa6"

  (* RFC 5649 §3, the constant half of the alternative initial value. *)
  let aiv_prefix = "\xa6\x59\x59\xa6"

  let ct_equal a b =
    String.length a = String.length b &&
    (let acc = ref 0 in
     String.iteri (fun i c -> acc := !acc lor (Char.code c lxor Char.code b.[i])) a;
     !acc = 0)

  (* buf.[off..off+7] <- buf.[off..off+7] xor (t as 64-bit big endian) *)
  let xor_counter buf off t =
    for i = 0 to 7 do
      let shift = 8 * (7 - i) in
      let byte = Int64.to_int (Int64.logand (Int64.shift_right_logical t shift) 0xFFL) in
      Bytes.set_uint8 buf (off + i) (Bytes.get_uint8 buf (off + i) lxor byte)
    done

  (* RFC 3394 §2.2.1, mutating [a] (8 octets) and [r] (n * 8 octets). *)
  let core_wrap ~key a r n =
    let buf = Bytes.create block in
    for j = 0 to 5 do
      for i = 1 to n do
        Bytes.blit a 0 buf 0 half;
        Bytes.blit r ((i - 1) * half) buf half half;
        let b = C.encrypt ~key (Bytes.unsafe_to_string buf) in
        Bytes.blit_string b 0 a 0 half;
        Bytes.blit_string b half r ((i - 1) * half) half;
        xor_counter a 0 (Int64.of_int ((n * j) + i))
      done
    done

  (* RFC 3394 §2.2.2. Leaves the recovered integrity value in [a]; the check
     itself differs between KW and KWP, so it belongs to the caller. *)
  let core_unwrap ~key a r n =
    let buf = Bytes.create block in
    for j = 5 downto 0 do
      for i = n downto 1 do
        xor_counter a 0 (Int64.of_int ((n * j) + i));
        Bytes.blit a 0 buf 0 half;
        Bytes.blit r ((i - 1) * half) buf half half;
        let b = C.decrypt ~key (Bytes.unsafe_to_string buf) in
        Bytes.blit_string b 0 a 0 half;
        Bytes.blit_string b half r ((i - 1) * half) half
      done
    done

  let wrap ~key data =
    let len = String.length data in
    if len < block || len mod half <> 0 then
      invalid_arg
        (Printf.sprintf "AES-KW: data must be a multiple of %u octets, at least %u"
           half block);
    let n = len / half in
    let a = Bytes.of_string default_iv and r = Bytes.of_string data in
    core_wrap ~key a r n;
    Bytes.to_string a ^ Bytes.to_string r

  let unwrap ~key data =
    let len = String.length data in
    if len < block + half || len mod half <> 0 then None
    else
      let n = (len / half) - 1 in
      let a = Bytes.of_string (String.sub data 0 half) in
      let r = Bytes.of_string (String.sub data half (n * half)) in
      core_unwrap ~key a r n;
      if ct_equal (Bytes.to_string a) default_iv then Some (Bytes.to_string r) else None

  let wrap_padded ~key data =
    let mli = String.length data in
    if mli = 0 then invalid_arg "AES-KWP: data must be at least one octet";
    let padding = (half - (mli mod half)) mod half in
    let padded = Bytes.make (mli + padding) '\x00' in
    Bytes.blit_string data 0 padded 0 mli;
    let a = Bytes.create half in
    Bytes.blit_string aiv_prefix 0 a 0 4;
    Bytes.set_int32_be a 4 (Int32.of_int mli);
    let n = Bytes.length padded / half in
    if n = 1 then begin
      (* RFC 5649 §4.1 step 2: a single padded block is encrypted directly
         rather than run through the six rounds. *)
      let buf = Bytes.create block in
      Bytes.blit a 0 buf 0 half;
      Bytes.blit padded 0 buf half half;
      C.encrypt ~key (Bytes.unsafe_to_string buf)
    end else begin
      core_wrap ~key a padded n;
      Bytes.to_string a ^ Bytes.to_string padded
    end

  let unwrap_padded ~key data =
    let len = String.length data in
    if len < block || len mod half <> 0 then None
    else begin
      let a = Bytes.create half in
      let padded =
        if len = block then begin
          let b = C.decrypt ~key data in
          Bytes.blit_string b 0 a 0 half;
          Bytes.of_string (String.sub b half half)
        end else begin
          let n = (len / half) - 1 in
          Bytes.blit_string data 0 a 0 half;
          let r = Bytes.of_string (String.sub data half (n * half)) in
          core_unwrap ~key a r n;
          r
        end
      in
      let padded_len = Bytes.length padded in
      let ok_prefix = ct_equal (Bytes.sub_string a 0 4) aiv_prefix in
      let mli =
        Int64.to_int (Int64.logand (Int64.of_int32 (Bytes.get_int32_be a 4)) 0xFFFFFFFFL)
      in
      let ok_len = mli > padded_len - half && mli <= padded_len in
      (* Clamped so a bogus length cannot drive the scan out of bounds; the
         verdict still rests on [ok_len]. *)
      let scan_from = if ok_len then mli else padded_len in
      let pad_acc = ref 0 in
      for i = scan_from to padded_len - 1 do
        pad_acc := !pad_acc lor Bytes.get_uint8 padded i
      done;
      if ok_prefix && ok_len && !pad_acc = 0 then Some (Bytes.sub_string padded 0 mli)
      else None
    end
end

module AES = Make (struct
    include Mirage_crypto.AES.ECB

    let key_sizes = Mirage_crypto.AES.ECB.key_sizes
    let block_size = Mirage_crypto.AES.ECB.block_size
  end)
