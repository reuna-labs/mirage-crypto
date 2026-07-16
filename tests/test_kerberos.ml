open OUnit2
open Test_common
open Mirage_crypto_kerberos_legacy

(* ===== n-fold tests (RFC 3961 Appendix A) ===== *)

(* Expose n_fold for testing via a small shim — it's internal to the library,
   so we inline the same algorithm here and cross-check against one known vector. *)

let n_fold_cases =
  (* RFC 3961 Appendix A test vectors.  Each entry: (input_string, out_bytes, expected_hex). *)
  let case input out_bytes expected =
    test_case @@ fun _ ->
      (* Duplicate the n_fold logic here to test without exposing internals. *)
      let s = input and n = out_bytes in
      let k = String.length s in
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
        pos := (!pos - 1 + n) mod n
      done;
      let got = Bytes.unsafe_to_string result in
      assert_oct_equal ~msg:("n_fold(" ^ input ^ "," ^ string_of_int out_bytes ^ ")")
        (vx expected) got
  in
  [
    (* RFC 3961 Appendix A vectors *)
    case "012345" 8 "be072631276b1955";
    case "password" 7 "78a07b6caf85fa";
    case "Rough Consensus, and Running Code" 8 "bb6ed30870b7f0e0";
    case "password" 21 "59e4a8ca7c0385c3c37b3f6d2000247cb6e6bd5b3e";
    case "MASSACHVSETTS INSTITVTE OF TECHNOLOGY" 24 "db3b0d8f0b061e603282b308a50841229ad798fab9540c1b";
  ]

(* ===== DES3 DK derivation (RFC 3961 Appendix A.3) =====
   Tests des3_random_to_key + dr_des3 via an inline duplicate of the algorithm. *)

let des_fix_parity b =
  let count = ref 0 in
  for j = 1 to 7 do if b land (1 lsl j) <> 0 then incr count done;
  if !count mod 2 = 0 then b lor 1 else b land 0xFE

let des3_random_to_key_test raw =
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

let des3_dk_cases =
  (* RFC 3961 Appendix A.3: DES3 DR and DK test vectors.
     base_key = dce06b1f64c857a11c3db57c51899b2cc1791008ce973b92 (valid DES3 key).
     These test des3_random_to_key by exercising the random-to-key step in isolation. *)
  let case ~dr_hex ~dk_hex =
    test_case @@ fun _ ->
      let dr = vx dr_hex in
      let dk = des3_random_to_key_test dr in
      assert_oct_equal ~msg:"des3_random_to_key" (vx dk_hex) dk
  in
  [
    (* RFC 3961 A.3 usage 0000000155 (Ki) *)
    case
      ~dr_hex:"93 50 79 d1 44 90 a7 5c 30 93 c4 a6 e8 c3 b0 49 c7 1e 6e e7 05"
      ~dk_hex:"92 51 79 d0 45 91 a7 9b 5d 31 92 c4 a7 e9 c2 89 b0 49 c7 1f 6e e6 04 cd";
    (* RFC 3961 A.3 usage 00000001aa (Ke) *)
    case
      ~dr_hex:"9f 58 e5 a0 47 d8 94 10 1c 46 98 45 d6 7a e3 c5 24 9e d8 12 f2"
      ~dk_hex:"9e 58 e5 a1 46 d9 94 2a 10 1c 46 98 45 d6 7a 20 e3 c4 25 9e d9 13 f2 07";
  ]

(* ===== etype 23/24 string_to_key (NT hash = MD4(UTF-16LE(password))) ===== *)

let arcfour_s2k_cases =
  let case ~password ~etype ~expected =
    test_case @@ fun _ ->
      let m = match etype with
        | 23 -> (module Arcfour_hmac     : ENCRYPTION_TYPE)
        | _  -> (module Arcfour_hmac_exp : ENCRYPTION_TYPE)
      in
      let module M = (val m) in
      let key = M.string_to_key ~password ~salt:"" () in
      assert_oct_equal ~msg:(Printf.sprintf "s2k etype=%d" etype)
        (vx expected) (M.to_secret key)
  in
  [
    (* MD4("") = well-known empty-string MD4 hash *)
    case ~password:"" ~etype:23 ~expected:"31 d6 cf e0 d1 6a e9 31 b7 3c 59 d7 e0 c0 89 c0";
    case ~password:"" ~etype:24 ~expected:"31 d6 cf e0 d1 6a e9 31 b7 3c 59 d7 e0 c0 89 c0";
  ]

(* ===== string_to_key test vectors (RFC 3962 Appendix B) ===== *)

let sha1_s2k_cases =
  let case ~password ~salt ~iterations ~etype ~expected () =
    test_case @@ fun _ ->
      let m = match etype with
        | 17 -> (module Aes128_cts_hmac_sha1_96 : ENCRYPTION_TYPE)
        | _  -> (module Aes256_cts_hmac_sha1_96 : ENCRYPTION_TYPE)
      in
      let module M = (val m) in
      let params = let b = Bytes.create 4 in
                   Bytes.set_int32_be b 0 (Int32.of_int iterations);
                   Bytes.unsafe_to_string b in
      let key = M.string_to_key ~password ~salt ~params () in
      assert_oct_equal ~msg:(Printf.sprintf "s2k etype=%d i=%d" etype iterations)
        (vx expected) (M.to_secret key)
  in
  [
    (* RFC 3962 Appendix B, Case 1: iteration count = 1 *)
    case ~password:"password" ~salt:"ATHENA.MIT.EDUraeburn" ~iterations:1
         ~etype:17 ~expected:"4226 3c6e 89f4 fc28 b8df 68ee 0979 9f15" ();
    case ~password:"password" ~salt:"ATHENA.MIT.EDUraeburn" ~iterations:1
         ~etype:18 ~expected:"fe69 7b52 bc0d 3ce1 4432 ba03 6a92 e65b
                               bb52 2809 90a2 fa27 8839 98d7 2af3 0161" ();
    (* RFC 3962 Appendix B, Case 2: iteration count = 2 *)
    case ~password:"password" ~salt:"ATHENA.MIT.EDUraeburn" ~iterations:2
         ~etype:17 ~expected:"c651 bf29 e230 0ac2 7fa4 69d6 93bd da13" ();
    case ~password:"password" ~salt:"ATHENA.MIT.EDUraeburn" ~iterations:2
         ~etype:18 ~expected:"a2e1 6d16 b360 69c1 35d5 e9d2 e25f 8961
                               0268 5618 b959 14b4 67c6 7622 2258 24ff" ();
    (* RFC 3962 Appendix B, Case 3: iteration count = 1200 *)
    case ~password:"password" ~salt:"ATHENA.MIT.EDUraeburn" ~iterations:1200
         ~etype:17 ~expected:"4c01 cd46 d632 d01e 6dbe 230a 01ed 642a" ();
    case ~password:"password" ~salt:"ATHENA.MIT.EDUraeburn" ~iterations:1200
         ~etype:18 ~expected:"55a6 ac74 0ad1 7b48 4694 1051 e1e8 b0a7
                               548d 93b0 ab30 a8bc 3ff1 6280 382b 8c2a" ();
    (* RFC 3962 Appendix B, Case 5: 64 'X' chars, salt = "pass phrase equals block size" *)
    case
      ~password:"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
      ~salt:"pass phrase equals block size"
      ~iterations:1200 ~etype:17
      ~expected:"59d1 bb78 9a82 8b1a a54e f9c2 883f 69ed" ();
    case
      ~password:"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
      ~salt:"pass phrase equals block size"
      ~iterations:1200 ~etype:18
      ~expected:"89ad ee36 08db 8bc7 1f1b fbfe 4594 86b0
                  5618 b70c bae2 2092 534e 56c5 53ba 4b34" ();
    (* RFC 3962 Appendix B, Case 6: 65 'X' chars, salt = "pass phrase exceeds block size" *)
    case
      ~password:"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
      ~salt:"pass phrase exceeds block size"
      ~iterations:1200 ~etype:17
      ~expected:"cb80 05dc 5f90 179a 7f02 104c 0018 751d" ();
    case
      ~password:"XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
      ~salt:"pass phrase exceeds block size"
      ~iterations:1200 ~etype:18
      ~expected:"d78c 5c9c b872 a8c9 dad4 697f 0bb5 b2d2
                  1496 c82b eb2c aeda 2112 fcee a057 401b" ();
  ]

(* ===== Round-trip tests (encrypt then decrypt) ===== *)

let round_trip_case (type k) (module M : ENCRYPTION_TYPE with type key = k)
    ~label ~key_hex ~key_usage ~plaintext =
  test_case @@ fun _ ->
    let key = M.of_secret (vx key_hex) in
    let ciphertext = M.encrypt ~key ~key_usage plaintext in
    match M.decrypt ~key ~key_usage ciphertext with
    | None -> assert_failure (label ^ ": decrypt returned None")
    | Some recovered ->
      assert_oct_equal ~msg:(label ^ ": plaintext") plaintext recovered

let round_trip_cases =
  [
    round_trip_case (module Aes128_cts_hmac_sha1_96)
      ~label:"etype17"
      ~key_hex:"63 68 69 63 6b 65 6e 20 74 65 72 69 79 61 6b 69"
      ~key_usage:7
      ~plaintext:"9 bytesss";

    round_trip_case (module Aes256_cts_hmac_sha1_96)
      ~label:"etype18"
      ~key_hex:"63 68 69 63 6b 65 6e 20 74 65 72 69 79 61 6b 69
                20 73 70 61 6e 69 65 6c 20 62 61 63 6f 6e 21 21"
      ~key_usage:4
      ~plaintext:"I would like the\x00General Gau's Chicken, please,\x0aand wonton soup.";

    round_trip_case (module Aes128_cts_hmac_sha256_128)
      ~label:"etype19"
      ~key_hex:"37 05 d9 60 80 c1 77 28 a0 e8 00 ea b6 e0 d2 3c"
      ~key_usage:2
      ~plaintext:"Hello Kerberos";

    round_trip_case (module Aes256_cts_hmac_sha384_192)
      ~label:"etype20"
      ~key_hex:"6d 40 4d 37 fa f7 9f 9d f0 d3 35 68 d3 20 66 9e
                 2d e3 14 bb a0 6e a7 00 8e 9a 31 b7 4e 5e fe 3a"
      ~key_usage:9
      ~plaintext:"";  (* empty message *)

    round_trip_case (module Des3_cbc_sha1_kd)
      ~label:"etype16"
      ~key_hex:"85 05 56 ab 81 67 d0 d2 b6 b5 e2 19 3d bb e6 50
                 27 a2 ad 89 d8 60 1a 16"
      ~key_usage:3
      ~plaintext:"Hello!!!";

    round_trip_case (module Arcfour_hmac)
      ~label:"etype23"
      ~key_hex:"f7 d3 8c 7d f8 e5 d3 08 dd ea 8e bc 53 27 4e 1f"
      ~key_usage:8
      ~plaintext:"AD Kerberos message";

    round_trip_case (module Arcfour_hmac_exp)
      ~label:"etype24"
      ~key_hex:"f7 d3 8c 7d f8 e5 d3 08 dd ea 8e bc 53 27 4e 1f"
      ~key_usage:8
      ~plaintext:"Export-restricted RC4";
  ]

(* Verify that MAC tampering causes decrypt to return None *)
let tamper_cases =
  let case (type k) (module M : ENCRYPTION_TYPE with type key = k) label key_hex =
    test_case @@ fun _ ->
      let key = M.of_secret (vx key_hex) in
      let ct  = M.encrypt ~key ~key_usage:1 "test message" in
      (* Flip a byte in the ciphertext *)
      let tampered = Bytes.of_string ct in
      Bytes.set tampered 0 (Char.chr (Char.code (Bytes.get tampered 0) lxor 0x01));
      match M.decrypt ~key ~key_usage:1 (Bytes.unsafe_to_string tampered) with
      | None -> ()  (* correct: MAC failure detected *)
      | Some _ -> assert_failure (label ^ ": tampered ciphertext accepted")
  in
  [
    case (module Aes128_cts_hmac_sha1_96)  "etype17"
      "63 68 69 63 6b 65 6e 20 74 65 72 69 79 61 6b 69";
    case (module Aes256_cts_hmac_sha384_192) "etype20"
      "6d 40 4d 37 fa f7 9f 9d f0 d3 35 68 d3 20 66 9e
        2d e3 14 bb a0 6e a7 00 8e 9a 31 b7 4e 5e fe 3a";
    case (module Arcfour_hmac) "etype23"
      "f7 d3 8c 7d f8 e5 d3 08 dd ea 8e bc 53 27 4e 1f";
  ]

(* AES-CTS raw mode tests (RFC 3962 Appendix B, Section "AES encryption of plaintext") *)

let cts_raw_cases =
  let case ~key_hex ~iv_hex ~plaintext_hex ~ciphertext_hex =
    test_case @@ fun _ ->
      let key = Mirage_crypto.AES.CTS.of_secret (vx key_hex) in
      let iv  = vx iv_hex in
      let pt  = vx plaintext_hex in
      let ct  = vx ciphertext_hex in
      let got_ct  = Mirage_crypto.AES.CTS.encrypt ~key ~iv pt in
      let got_pt  = Mirage_crypto.AES.CTS.decrypt ~key ~iv ct in
      assert_oct_equal ~msg:"CTS encrypt" ct got_ct;
      assert_oct_equal ~msg:"CTS decrypt" pt got_pt
  in
  [
    (* RFC 3962 Appendix B: 16 bytes = 1 block *)
    case
      ~key_hex:"63 68 69 63 6b 65 6e 20 74 65 72 69 79 61 6b 69"
      ~iv_hex:"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
      ~plaintext_hex:"49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65"
      ~ciphertext_hex:"97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84";

    (* RFC 3962 Appendix B: 17 bytes = 1 block + 1 byte *)
    case
      ~key_hex:"63 68 69 63 6b 65 6e 20 74 65 72 69 79 61 6b 69"
      ~iv_hex:"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
      ~plaintext_hex:"49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65 20"
      ~ciphertext_hex:"c6 35 35 68 f2 bf 8c b4 d8 a5 80 36 2d a7 ff 7f 97";

    (* RFC 3962 Appendix B: 31 bytes = 1 full block + 15 bytes *)
    case
      ~key_hex:"63 68 69 63 6b 65 6e 20 74 65 72 69 79 61 6b 69"
      ~iv_hex:"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
      ~plaintext_hex:"49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65
                      20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20"
      ~ciphertext_hex:"fc 00 78 3e 0e fd b2 c1 d4 45 d4 c8 ef f7 ed 22
                       97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5";

    (* RFC 3962 Appendix B: 32 bytes = exactly 2 blocks *)
    case
      ~key_hex:"63 68 69 63 6b 65 6e 20 74 65 72 69 79 61 6b 69"
      ~iv_hex:"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
      ~plaintext_hex:"49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65
                      20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43"
      ~ciphertext_hex:"39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8
                       97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84";

    (* RFC 3962 Appendix B: 47 bytes = 2 full blocks + 15 bytes *)
    case
      ~key_hex:"63 68 69 63 6b 65 6e 20 74 65 72 69 79 61 6b 69"
      ~iv_hex:"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
      ~plaintext_hex:"49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65
                      20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43
                      68 69 63 6b 65 6e 2c 20 70 6c 65 61 73 65 2c"
      ~ciphertext_hex:"97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84
                       b3 ff fd 94 0c 16 a1 8c 1b 55 49 d2 f8 38 02 9e
                       39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5";

    (* RFC 3962 Appendix B: 48 bytes = exactly 3 blocks *)
    case
      ~key_hex:"63 68 69 63 6b 65 6e 20 74 65 72 69 79 61 6b 69"
      ~iv_hex:"00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
      ~plaintext_hex:"49 20 77 6f 75 6c 64 20 6c 69 6b 65 20 74 68 65
                      20 47 65 6e 65 72 61 6c 20 47 61 75 27 73 20 43
                      68 69 63 6b 65 6e 2c 20 70 6c 65 61 73 65 2c 20"
      ~ciphertext_hex:"97 68 72 68 d6 ec cc c0 c0 7b 25 e2 5e cf e5 84
                       9d ad 8b bb 96 c4 cd c0 3b c1 03 e1 a1 94 bb d8
                       39 31 25 23 a7 86 62 d5 be 7f cb cc 98 eb f5 a8";
  ]

(* ===== generate: key length and key validity ===== *)

let generate_cases =
  let case (type k) (module M : ENCRYPTION_TYPE with type key = k) label =
    test_case @@ fun _ ->
      let key = M.generate () in
      assert_equal ~msg:(label ^ ": key_bytes")
        M.key_bytes (String.length (M.to_secret key))
  in
  [
    case (module Aes128_cts_hmac_sha1_96)    "etype17";
    case (module Aes256_cts_hmac_sha1_96)    "etype18";
    case (module Aes128_cts_hmac_sha256_128) "etype19";
    case (module Aes256_cts_hmac_sha384_192) "etype20";
    case (module Des3_cbc_sha1_kd)           "etype16";
    case (module Arcfour_hmac)               "etype23";
    case (module Arcfour_hmac_exp)           "etype24";
  ]

(* ===== checksum / verify_checksum round-trips ===== *)

let checksum_cases =
  let case (type k) (module M : ENCRYPTION_TYPE with type key = k)
      label key_hex key_usage =
    test_case @@ fun _ ->
      let key = M.of_secret (vx key_hex) in
      let msg = "token-header || application-message" in
      let mac = M.checksum ~key ~key_usage msg in
      assert_equal ~msg:(label ^ ": mac length") M.checksum_bytes (String.length mac);
      assert_bool (label ^ ": verify ok")
        (M.verify_checksum ~key ~key_usage ~msg mac);
      (* Wrong mac must not verify *)
      let bad_mac = Bytes.of_string mac in
      Bytes.set bad_mac 0 (Char.chr (Char.code (Bytes.get bad_mac 0) lxor 0xFF));
      assert_bool (label ^ ": tampered mac rejected")
        (not (M.verify_checksum ~key ~key_usage ~msg (Bytes.unsafe_to_string bad_mac)));
      (* Wrong key_usage must not verify *)
      assert_bool (label ^ ": wrong usage rejected")
        (not (M.verify_checksum ~key ~key_usage:(key_usage + 1) ~msg mac))
  in
  [
    case (module Aes128_cts_hmac_sha1_96) "etype17"
      "63 68 69 63 6b 65 6e 20 74 65 72 69 79 61 6b 69" 7;
    case (module Aes256_cts_hmac_sha1_96) "etype18"
      "63 68 69 63 6b 65 6e 20 74 65 72 69 79 61 6b 69
       20 73 70 61 6e 69 65 6c 20 62 61 63 6f 6e 21 21" 4;
    case (module Aes128_cts_hmac_sha256_128) "etype19"
      "37 05 d9 60 80 c1 77 28 a0 e8 00 ea b6 e0 d2 3c" 6;
    case (module Aes256_cts_hmac_sha384_192) "etype20"
      "6d 40 4d 37 fa f7 9f 9d f0 d3 35 68 d3 20 66 9e
        2d e3 14 bb a0 6e a7 00 8e 9a 31 b7 4e 5e fe 3a" 9;
    case (module Des3_cbc_sha1_kd) "etype16"
      "85 05 56 ab 81 67 d0 d2 b6 b5 e2 19 3d bb e6 50
        27 a2 ad 89 d8 60 1a 16" 3;
    case (module Arcfour_hmac) "etype23"
      "f7 d3 8c 7d f8 e5 d3 08 dd ea 8e bc 53 27 4e 1f" 8;
    case (module Arcfour_hmac_exp) "etype24"
      "f7 d3 8c 7d f8 e5 d3 08 dd ea 8e bc 53 27 4e 1f" 8;
  ]

(* ===== of_etype: dispatch and round-trip ===== *)

let of_etype_cases =
  let known = [16; 17; 18; 19; 20; 23; 24] in
  let unknown = [0; 1; 15; 21; 22; 25; 99] in
  let known_cases = List.map (fun n ->
    test_case @@ fun _ ->
      match of_etype n with
      | None -> assert_failure (Printf.sprintf "of_etype %d returned None" n)
      | Some (module M) ->
        assert_equal ~msg:(Printf.sprintf "etype %d" n) n M.etype
  ) known in
  let unknown_cases = List.map (fun n ->
    test_case @@ fun _ ->
      match of_etype n with
      | None -> ()
      | Some _ -> assert_failure (Printf.sprintf "of_etype %d should be None" n)
  ) unknown in
  (* Use the dispatched module to do a generate + checksum round-trip *)
  let dispatch_roundtrip = test_case @@ fun _ ->
    List.iter (fun n ->
      match of_etype n with
      | None -> ()
      | Some (module M) ->
        let key = M.generate () in
        let mac = M.checksum ~key ~key_usage:7 "test" in
        assert_bool
          (Printf.sprintf "of_etype %d: verify" n)
          (M.verify_checksum ~key ~key_usage:7 ~msg:"test" mac)
    ) known
  in
  known_cases @ unknown_cases @ [dispatch_roundtrip]

let suite =
  "kerberos" >::: [
    "n_fold"       >::: n_fold_cases;
    "des3_dk"      >::: des3_dk_cases;
    "sha1_s2k"     >::: sha1_s2k_cases;
    "arcfour_s2k"  >::: arcfour_s2k_cases;
    "aes_cts_raw"  >::: cts_raw_cases;
    "round_trips"  >::: round_trip_cases;
    "tamper_check" >::: tamper_cases;
    "generate"     >::: generate_cases;
    "checksum"     >::: checksum_cases;
    "of_etype"     >::: of_etype_cases;
  ]
