(* OCaml 5: each worker owns its RNG; native signing contexts are per call. *)
let ok = function Ok x -> x | Error _ -> failwith "decode"
let check b = if not b then failwith "concurrent backend operation"
let worker i =
  let module K = Mirage_crypto_secp256k1 in
  let module B = Mirage_crypto_bls12_381 in
  let g = Mirage_crypto_rng.create ~seed:(String.make 48 (Char.chr (i+1))) (module Mirage_crypto_rng.Fortuna) in
  let sk = ok (K.priv_of_octets (String.make 31 '\000' ^ String.make 1 (Char.chr (i+1)))) in
  let pk = K.pub_of_priv ~g sk in
  let xpk = K.Bip340.xonly_pub_of_priv ~g sk in
  let module S = Mirage_crypto_sr25519 in
  let sr = ok (S.priv_of_octets (String.make 32 (Char.chr i))) in
  let sp = S.pub_of_priv sr in
  let bk = B.generate ~g () in
  let bp = B.pub_of_priv bk in
  for n=0 to 99 do
    let msg = String.make 32 (Char.chr n) in
    check (K.verify ~key:pk (K.sign ~g ~key:sk msg) msg);
    check (K.Bip340.verify ~key:xpk (K.Bip340.sign ~g ~key:sk msg) msg);
    check (S.verify ~key:sp (S.sign ~g ~key:sr msg) msg);
    check (B.verify ~key:bp (B.sign ~key:bk msg) msg);
    check (String.length (Mirage_crypto_blake3.digest msg) = 32)
  done
let () =
  List.init 4 (fun i -> Domain.spawn (fun () -> worker i)) |> List.iter Domain.join;
  print_endline "Four-domain backend checks passed."
