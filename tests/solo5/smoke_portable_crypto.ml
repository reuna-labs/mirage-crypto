let hex s =
  String.init (String.length s / 2) (fun i ->
      Char.chr (int_of_string ("0x" ^ String.sub s (2 * i) 2)))

let () =
  let plain = hex "00112233445566778899aabbccddeeff" in
  List.iter (fun (bytes, expected) ->
      let key = Mirage_crypto.AES.ECB.of_secret (String.init bytes Char.chr) in
      let cipher = Mirage_crypto.AES.ECB.encrypt ~key plain in
      assert (cipher = hex expected);
      assert (Mirage_crypto.AES.ECB.decrypt ~key cipher = plain))
    [16, "69c4e0d86a7b0430d8cdb78070b4c55a";
     24, "dda97ca4864cdfe06eaf70a0ec0d7191";
     32, "8ea2b7ca516745bfeafc49904b496089"];
  let key = Mirage_crypto.AES.GCM.of_secret (String.make 16 '\000') in
  let nonce = String.make 12 '\000' and plain = String.make 16 '\000' in
  let cipher = Mirage_crypto.AES.GCM.authenticate_encrypt ~key ~nonce plain in
  assert (cipher = hex "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf");
  assert (Mirage_crypto.AES.GCM.authenticate_decrypt ~key ~nonce cipher = Some plain);
  let bad = Bytes.of_string cipher in
  Bytes.set bad 31 (Char.chr (Char.code (Bytes.get bad 31) lxor 1));
  assert (Mirage_crypto.AES.GCM.authenticate_decrypt ~key ~nonce (Bytes.to_string bad) = None);
  print_endline "AES/GHASH Solo5 smoke passed"
