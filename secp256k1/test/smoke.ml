let check label b = if not b then failwith label
let ok = function Ok x -> x | Error _ -> failwith "decode"
let hex s = String.init (String.length s / 2) (fun i -> Char.chr (int_of_string ("0x" ^ String.sub s (2*i) 2)))
let () = Mirage_crypto_rng.set_default_generator
 (Mirage_crypto_rng.create ~seed:(String.make 48 '\042') (module Mirage_crypto_rng.Fortuna))
module K = Mirage_crypto_secp256k1
let () =
 let sk = ok (K.priv_of_octets (String.make 31 '\000' ^ "\001")) in
 let pub = K.pub_of_priv sk and msg = String.make 32 '\042' in
 let sig_,id = K.sign_recoverable ~key:sk msg in
 check "ECDSA" (K.verify ~key:pub sig_ msg);
 check "recovery" (K.pub_to_octets (ok (K.recover ~msg sig_ ~recid:id)) = K.pub_to_octets pub);
 let pk = K.Bip340.xonly_pub_of_priv sk in
 check "BIP340" (K.Bip340.verify ~key:pk (K.Bip340.sign ~key:sk "message") "message");
 check "G" (K.pub_to_octets pub = hex "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798");
 print_endline "secp256k1 smoke passed"
