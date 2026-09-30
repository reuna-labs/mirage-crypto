let check label b = if not b then failwith label
let ok = function Ok x -> x | Error _ -> failwith "decode"
let hex s = String.init (String.length s / 2) (fun i -> Char.chr (int_of_string ("0x" ^ String.sub s (2*i) 2)))
let () = Mirage_crypto_rng.set_default_generator
 (Mirage_crypto_rng.create ~seed:(String.make 48 '\042') (module Mirage_crypto_rng.Fortuna))
module B = Mirage_crypto_bls12_381
let () =
 let sk = ok (B.scalar_of_octets (String.make 31 '\000' ^ "\001")) in
 let pub = B.pub_of_priv sk in
 check "generator" (B.g1_equal pub B.g1_generator);
 let sg = B.sign ~key:sk "message" in
 check "BLS" (B.verify ~key:pub sg "message");
 check "BLS wrong message" (not (B.verify ~key:pub sg "other"));
 check "BLS aggregate" (B.aggregate_verify [pub,"one";pub,"two"] (B.aggregate [B.sign ~key:sk "one";B.sign ~key:sk "two"]));
 print_endline "bls12-381 smoke passed"
