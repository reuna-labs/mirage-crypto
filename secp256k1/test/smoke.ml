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
 (* d=1, k=1, z=0 gives r=s=x(G), with even R and no low-S flip. *)
 let nonce = String.make 31 '\000' ^ "\001" in
 let zero = String.make 32 '\000' in
 let fixed,fixed_id = K.sign_recoverable ~nonce ~key:sk zero in
 let x = hex "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798" in
 check "explicit nonce vector" (K.signature_to_octets fixed = x ^ x && fixed_id = 0);
 check "explicit nonce recovery" (K.pub_to_octets (ok (K.recover ~msg:zero fixed ~recid:fixed_id)) = K.pub_to_octets pub);
 List.iter (fun nonce ->
   check "invalid nonce" (try ignore (K.sign ~nonce ~key:sk zero); false
     with Invalid_argument _ -> true)) [""; zero; K.n; String.make 32 '\255'];
 (* z = n - x(G) produces s=0 with d=k=1. It must fail, not retry forever. *)
 let zero_s = hex "8641998106234453aa5f9d6a3178f4f7b812e00b817a776265dfdd31b93e29a9" in
 check "zero signature rejects fixed nonce" (try ignore (K.sign ~nonce ~key:sk zero_s); false
   with Invalid_argument _ -> true);
 (* Blinding is mandatory, including for deterministic or caller-nonce signing.
    Verification/recovery do not require secret-key context randomness. *)
 let signature = K.signature_to_octets sig_ in
 Mirage_crypto_rng.unset_default_generator ();
 let secret_ops = [
   (fun () -> ignore (K.pub_of_priv sk));
   (fun () -> ignore (K.generate ()));
   (fun () -> ignore (K.sign ~key:sk msg));
   (fun () -> ignore (K.sign ~nonce ~key:sk zero));
   (fun () -> ignore (K.Bip340.xonly_pub_of_priv sk));
   (fun () -> ignore (K.Bip340.sign ~key:sk "message"));
   (fun () -> ignore (K.Bip340.sign ~aux_rand:zero ~key:sk "message"))
 ] in
 List.iter (fun op -> check "missing RNG fails closed"
   (try op (); false with Mirage_crypto_rng.No_default_generator -> true)) secret_ops;
 check "verification needs no RNG" (K.verify ~key:pub sig_ msg);
 check "recovery needs no RNG"
   (K.pub_to_octets (ok (K.recover ~msg sig_ ~recid:id)) = K.pub_to_octets pub);
 Mirage_crypto_rng.set_default_generator
   (Mirage_crypto_rng.create (module Mirage_crypto_rng.Fortuna));
 List.iter (fun op -> check "unseeded RNG fails closed"
   (try op (); false with Mirage_crypto_rng.Unseeded_generator -> true)) secret_ops;
 Mirage_crypto_rng.set_default_generator
   (Mirage_crypto_rng.create ~seed:(String.make 48 '\043') (module Mirage_crypto_rng.Fortuna));
 check "blinding does not change RFC6979 bytes"
   (K.signature_to_octets (K.sign ~key:sk msg) = signature);
 check "blinding does not change explicit-nonce bytes"
   (K.signature_to_octets (K.sign ~nonce ~key:sk zero) = x ^ x);
 print_endline "secp256k1 smoke passed"
