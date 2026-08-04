open OUnit2
open Test_common

module KW = Mirage_crypto_kw.AES

(* RFC 3394 §4.1 - §4.6 *)
let kw_cases =
  let case ~key ~data ~out = KW.of_secret (vx key), vx data, vx out

  and check (key, data, out) _ =
    let wrapped = KW.wrap ~key data in
    assert_oct_equal ~msg:"wrapped" out wrapped ;
    match KW.unwrap ~key wrapped with
    | None -> assert_failure "unwrap rejected its own output"
    | Some plain -> assert_oct_equal ~msg:"plaintext" data plain in

  cases_of check [
    case
      ~key: "0001 0203 0405 0607  0809 0a0b 0c0d 0e0f"
      ~data:"0011 2233 4455 6677  8899 aabb ccdd eeff"
      ~out: "1fa6 8b0a 8112 b447  aef3 4bd8 fb5a 7b82 9d3e 8623 71d2 cfe5" ;
    case
      ~key: "0001 0203 0405 0607  0809 0a0b 0c0d 0e0f 1011 1213 1415 1617"
      ~data:"0011 2233 4455 6677  8899 aabb ccdd eeff"
      ~out: "9677 8b25 ae6c a435  f92b 5b97 c050 aed2 468a b8a1 7ad8 4e5d" ;
    case
      ~key: "0001 0203 0405 0607  0809 0a0b 0c0d 0e0f
             1011 1213 1415 1617  1819 1a1b 1c1d 1e1f"
      ~data:"0011 2233 4455 6677  8899 aabb ccdd eeff"
      ~out: "64e8 c3f9 ce0f 5ba2  63e9 7779 0581 8a2a 93c8 191e 7d6e 8ae7" ;
    case
      ~key: "0001 0203 0405 0607  0809 0a0b 0c0d 0e0f 1011 1213 1415 1617"
      ~data:"0011 2233 4455 6677  8899 aabb ccdd eeff 0001 0203 0405 0607"
      ~out: "031d 3326 4e15 d332  68f2 4ec2 6074 3edc
             e1c6 c7dd ee72 5a93  6ba8 1491 5c67 62d2" ;
    case
      ~key: "0001 0203 0405 0607  0809 0a0b 0c0d 0e0f
             1011 1213 1415 1617  1819 1a1b 1c1d 1e1f"
      ~data:"0011 2233 4455 6677  8899 aabb ccdd eeff 0001 0203 0405 0607"
      ~out: "a8f9 bc16 12c6 8b3f  f6e6 f4fb e30e 71e4
             769c 8b80 a32c b895  8cd5 d17d 6b25 4da1" ;
    case
      ~key: "0001 0203 0405 0607  0809 0a0b 0c0d 0e0f
             1011 1213 1415 1617  1819 1a1b 1c1d 1e1f"
      ~data:"0011 2233 4455 6677  8899 aabb ccdd eeff
             0001 0203 0405 0607  0809 0a0b 0c0d 0e0f"
      ~out: "28c9 f404 c4b8 10f4  cbcc b35c fb87 f826
             3f57 86e2 d80e d326  cbc7 f0e7 1a99 f43b fb98 8b9b 7a02 dd21"
  ]

(* RFC 5649 §6 *)
let kwp_cases =
  let case ~key ~data ~out = KW.of_secret (vx key), vx data, vx out

  and check (key, data, out) _ =
    let wrapped = KW.wrap_padded ~key data in
    assert_oct_equal ~msg:"wrapped" out wrapped ;
    match KW.unwrap_padded ~key wrapped with
    | None -> assert_failure "unwrap_padded rejected its own output"
    | Some plain -> assert_oct_equal ~msg:"plaintext" data plain in

  cases_of check [
    case
      ~key: "5840 df6e 29b0 2af1  ab49 3b70 5bf1 6ea1 ae83 38f4 dcc1 76a8"
      ~data:"c37b 7e64 9258 4340  bed1 2207 8089 4115 5068 f738"
      ~out: "138b deaa 9b8f a7fc  61f9 7742 e722 48ee
             5ae6 ae53 60d1 ae6a  5f54 f373 fa54 3b6a" ;
    (* Seven octets pad to a single block, which takes RFC 5649's direct ECB
       path rather than the six rounds. *)
    case
      ~key: "5840 df6e 29b0 2af1  ab49 3b70 5bf1 6ea1 ae83 38f4 dcc1 76a8"
      ~data:"466f 7250 6173 69"
      ~out: "afbe b0f0 7dfb f541  9200 f2cc b50b b24f"
  ]

let kwp_properties =
  let key = KW.of_secret (String.make 32 'K') in
  [
    "round-trips every length" >:: (fun _ ->
      for n = 1 to 64 do
        let data = String.init n (fun i -> Char.chr (i land 0xff)) in
        match KW.unwrap_padded ~key (KW.wrap_padded ~key data) with
        | Some plain -> assert_oct_equal ~msg:"plaintext" data plain
        | None -> assert_failure "unwrap_padded rejected its own output"
      done) ;
    "rejects a modified blob at every octet" >:: (fun _ ->
      let wrapped = KW.wrap_padded ~key "some key material" in
      String.iteri (fun i _ ->
        let b = Bytes.of_string wrapped in
        Bytes.set b i (Char.chr (Char.code (Bytes.get b i) lxor 1)) ;
        match KW.unwrap_padded ~key (Bytes.to_string b) with
        | None -> ()
        | Some _ -> assert_failure "accepted a modified blob") wrapped) ;
    "rejects the wrong key" >:: (fun _ ->
      let other = KW.of_secret (String.make 32 'X') in
      let wrapped = KW.wrap_padded ~key "some key material" in
      match KW.unwrap_padded ~key:other wrapped with
      | None -> ()
      | Some _ -> assert_failure "accepted the wrong key") ;
    "rejects malformed lengths" >:: (fun _ ->
      List.iter (fun n ->
        match KW.unwrap_padded ~key (String.make n 'z') with
        | None -> ()
        | Some _ -> assert_failure "accepted a malformed blob")
        [ 0; 1; 8; 15; 17; 23; 31 ]) ;
  ]

let suite =
  "KW" >::: [
    "AES-KW (RFC 3394)" >::: kw_cases ;
    "AES-KWP (RFC 5649)" >::: kwp_cases ;
    "AES-KWP properties" >::: kwp_properties ;
  ]
