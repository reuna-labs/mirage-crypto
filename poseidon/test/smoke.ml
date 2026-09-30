let check label b = if not b then failwith label
let ok = function Ok x -> x | Error _ -> failwith "decode"
let hex s = String.init (String.length s / 2) (fun i -> Char.chr (int_of_string ("0x" ^ String.sub s (2*i) 2)))
let () =
 let elt n = ok (Mirage_crypto_poseidon.field_element_of_octets (String.make 31 '\000' ^ String.make 1 (Char.chr n))) in
 let result = Mirage_crypto_poseidon.hash_pair (elt 1) (elt 2) in
 check "Poseidon known answer" (Mirage_crypto_poseidon.field_element_to_octets result = hex "05d44a3decb2b2e0cc71071f7b802f45dd792d064f0fc7316c46514f70f9891a");
 print_endline "poseidon smoke passed"
