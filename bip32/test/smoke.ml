module B = Mirage_crypto_bip32
let ok = function Ok x -> x | Error _ -> failwith "BIP32 smoke"
let () =
  (* Fixed entropy is for this test image only. *)
  let g = Mirage_crypto_rng.create ~seed:(String.make 48 '\042') (module Mirage_crypto_rng.Fortuna) in
  let master = ok (B.Secret.master (String.init 16 Char.chr)) in
  let child = ok (B.Secret.derive_path ~g master [Int32.min_int;1l]) in
  let pub = B.Secret.public ~g child in
  let a = ok (B.Public.derive pub 2l) in
  let b = B.Secret.public ~g (ok (B.Secret.derive ~g child 2l)) in
  assert (B.Public.to_octets ~version:0x0488b21el a = B.Public.to_octets ~version:0x0488b21el b);
  let expected = "3c6cb8d0f6a264c91ea8b5030fadaa8e538b020f0a387421a12de9319dc93368" in
  let actual = Mirage_crypto_secp256k1.priv_to_octets child.key in
  assert (String.concat "" (List.init 32 (fun i -> Printf.sprintf "%02x" (Char.code actual.[i]))) = expected);
  print_endline "BIP32 Solo5 smoke passed"
