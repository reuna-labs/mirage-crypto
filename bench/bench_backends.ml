let ok = function Ok x -> x | Error _ -> failwith "decode"
let measure name count fn =
  Gc.full_major ();
  let before = Gc.allocated_bytes () and start = Unix.gettimeofday () in
  for _ = 1 to count do ignore (Sys.opaque_identity (fn ())) done;
  let elapsed = Unix.gettimeofday () -. start in
  let allocated = Gc.allocated_bytes () -. before in
  Printf.printf "%s: %.2f us/op, %.0f OCaml bytes/op\n%!" name
    (elapsed *. 1e6 /. float count) (allocated /. float count)
let () =
  Mirage_crypto_rng.set_default_generator (Mirage_crypto_rng.create ~seed:(String.make 48 '\042') (module Mirage_crypto_rng.Fortuna));
  let module K = Mirage_crypto_secp256k1 in
  let module B = Mirage_crypto_bls12_381 in
  let module P = Mirage_crypto_poseidon in
  let msg = String.make 32 '\042' in
  let sk,pk = K.generate () in let sg = K.sign ~key:sk msg in
  measure "ECDSA sign (including context blinding)" 1000 (fun () -> K.sign ~key:sk msg);
  measure "ECDSA verify" 1000 (fun () -> K.verify ~key:pk sg msg);
  measure "BIP340 sign" 1000 (fun () -> K.Bip340.sign ~key:sk msg);
  let bk = B.generate () in let bp = B.pub_of_priv bk in let bs = B.sign ~key:bk msg in
  measure "BLS sign" 200 (fun () -> B.sign ~key:bk msg);
  measure "BLS verify" 200 (fun () -> B.verify ~key:bp bs msg);
  let input = String.make 1024 '\042' in
  measure "BLAKE3 1KiB" 10000 (fun () -> Mirage_crypto_blake3.digest input);
  let elt = ok (P.field_element_of_octets (String.make 31 '\000' ^ "\001")) in
  measure "Poseidon pair" 1000 (fun () -> P.hash_pair elt elt)
