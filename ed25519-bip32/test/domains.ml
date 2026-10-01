module B = Mirage_crypto_ed25519_bip32

let ok = function Ok x -> x | Error _ -> failwith "domain operation"

let worker i =
  let root =
    ok
      (B.icarus_key_of_entropy ~passphrase:(string_of_int i)
         (String.make 16 (Char.chr i)))
  in
  for n = 0 to 99 do
    let child = ok (B.derive_priv_normal root ~index:(Int32.of_int n)) in
    let pub = B.pub_of_priv child in
    let message = String.make n (Char.chr i) in
    assert (B.verify ~key:pub (B.sign ~key:child message) ~msg:message)
  done

let () =
  List.init 4 (fun i -> Domain.spawn (fun () -> worker i))
  |> List.iter Domain.join;
  print_endline "Four-domain Ed25519-BIP32 stress passed"
