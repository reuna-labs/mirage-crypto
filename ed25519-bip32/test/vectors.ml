module B = Mirage_crypto_ed25519_bip32

let ok = function Ok x -> x | Error _ -> failwith "unexpected error"

let unhex s =
  String.init
    (String.length s / 2)
    (fun i -> Char.chr (int_of_string ("0x" ^ String.sub s (i * 2) 2)))

let eq name a b = if a <> b then failwith name

let lines file f =
  let ch = open_in file in
  Fun.protect
    ~finally:(fun () -> close_in ch)
    (fun () ->
      try
        while true do
          let s = input_line ch in
          if s <> "" && s.[0] <> '#' then f (String.split_on_char '\t' s)
        done
      with End_of_file -> ())

let child k i =
  ok
    ((if Int32.compare i 0l < 0 then B.derive_priv_hardened
      else B.derive_priv_normal)
       k ~index:i)

let () =
  lines "rust-vectors.tsv" (function
    | [ root; path; expected; pub; msg; sig_ ] ->
        let root = ok (B.extended_priv_of_octets (unhex root)) in
        let path =
          if path = "" then []
          else
            List.map
              (fun s -> Int64.to_int32 (Int64.of_string s))
              (String.split_on_char ',' path)
        in
        let key =
          List.fold_left
            (fun k i ->
              let c = child k i in
              if i >= 0l then
                eq "public derivation"
                  (B.extended_pub_to_octets (B.pub_of_priv c))
                  (B.extended_pub_to_octets
                     (ok (B.derive_pub_normal (B.pub_of_priv k) ~index:i)));
              c)
            root path
        in
        eq "Rust private" (unhex expected) (B.extended_priv_to_octets key);
        let pk = B.pub_of_priv key in
        eq "Rust public" (unhex pub) (B.extended_pub_to_octets pk);
        ignore (ok (B.extended_pub_of_octets (unhex pub)));
        let msg = unhex msg and signature = unhex sig_ in
        eq "Rust signature" signature (B.sign ~key msg);
        assert (B.verify ~key:pk signature ~msg);
        assert (not (B.verify ~key:pk signature ~msg:(msg ^ "!")))
    | _ -> failwith "Rust fixture format");
  lines "icarus-vectors.tsv" (function
    | [ entropy; pass; expected ] ->
        eq "Python PBKDF2" (unhex expected)
          (B.extended_priv_to_octets
             (ok
                (B.icarus_key_of_entropy ~passphrase:(unhex pass)
                   (unhex entropy))))
    | _ -> failwith "Icarus fixture format");
  lines "cardano-vectors.tsv" (function
    | [ entropy; path; expected; pub; msg; signature ] ->
        let key = ok (B.icarus_key_of_entropy (unhex entropy)) in
        let path =
          if path = "" then []
          else
            List.map
              (fun s -> Int64.to_int32 (Int64.of_string s))
              (String.split_on_char ',' path)
        in
        let key = List.fold_left child key path in
        eq "Cardano golden private" (unhex expected)
          (B.extended_priv_to_octets key);
        eq "Cardano golden public" (unhex pub)
          (B.extended_pub_to_octets (B.pub_of_priv key));
        eq "Cardano golden signature" (unhex signature)
          (B.sign ~key (unhex msg))
    | _ -> failwith "Cardano fixture format");
  lines "master-vectors.tsv" (function
    | [ seed; expected ] ->
        let actual =
          Result.map B.extended_priv_to_octets
            (B.master_key_of_seed (unhex seed))
        in
        eq "paper master"
          (if expected = "invalid" then Error `Invalid_derivation
           else Ok (unhex expected))
          actual
    | _ -> failwith "master fixture format");
  print_endline
    "128 Rust records, 85 independent PBKDF2 records, 5 Cardano goldens and \
     256 paper masters passed"
