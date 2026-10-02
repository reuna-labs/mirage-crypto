let hex s = String.init (String.length s / 2) (fun i ->
    Char.chr (int_of_string ("0x" ^ String.sub s (2*i) 2)))
let () =
  let open Mirage_crypto_pbkdf2 in
  List.iter (fun (derive, length, expected) ->
      assert (derive ~password:"password" ~salt:"salt" ~iterations:1 ~length = hex expected);
      assert (derive ~password:"" ~salt:"" ~iterations:1 ~length:0 = "");
      List.iter (fun (iterations,length) ->
          assert (try ignore (derive ~password:"x" ~salt:"y" ~iterations ~length); false
                  with Invalid_argument _ -> true)) [0,1; -1,1; 1,-1])
    [sha1,20,"0c60c80f961f0e71f3a9b524af6012062fe037a6";
     sha256,32,"120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b";
     sha512,64,"867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"];
  if Sys.word_size = 64 then (
    let invalid ~iterations ~length =
      assert (try ignore (sha512 ~password:"" ~salt:"" ~iterations ~length); false
              with Invalid_argument _ -> true) in
    invalid ~iterations:(Int64.to_int 0x100000000L) ~length:1;
    invalid ~iterations:1 ~length:(Int64.to_int 0xffffffc1L));
  print_endline "PBKDF2 OCaml vectors and parameter checks passed"
