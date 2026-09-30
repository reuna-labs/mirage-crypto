let check label b = if not b then failwith label
let ok = function Ok x -> x | Error _ -> failwith "decode"
let hex s = String.init (String.length s / 2) (fun i -> Char.chr (int_of_string ("0x" ^ String.sub s (2*i) 2)))
let () =
 check "empty digest" (Mirage_crypto_blake3.digest "" = hex "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262");
 check "XOF" (String.length (Mirage_crypto_blake3.digest ~digest_size:131 "abc") = 131);
 print_endline "blake3 smoke passed"
