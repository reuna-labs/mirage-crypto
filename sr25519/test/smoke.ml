module S = Mirage_crypto_sr25519
let ok = function Ok x -> x | Error _ -> failwith "sr25519 parse"
let () =
  let g = Mirage_crypto_rng.create ~seed:"sr25519 smoke only" (module Mirage_crypto_rng.Fortuna) in
  let key = ok (S.priv_of_octets (String.make 32 '\000')) in
  let pub = S.pub_of_priv key in
  let signature = S.sign ~g ~key "Solo5 sr25519" in
  assert (S.verify ~key:pub signature "Solo5 sr25519");
  assert (not (S.verify ~key:pub signature "tampered"));
  assert (String.length (S.vrf_output ~key "Solo5 sr25519") = 32);
  print_endline "sr25519 smoke passed"
