module B = Mirage_crypto_ed25519_bip32
module Old = Blockchain_reference.Ed25519_bip32_legacy

let ok = function Ok x -> x | Error _ -> failwith "unexpected error"

let unhex s =
  String.init
    (String.length s / 2)
    (fun i -> Char.chr (int_of_string ("0x" ^ String.sub s (i * 2) 2)))

let change s i c =
  let b = Bytes.of_string s in
  Bytes.set b i (Char.chr c);
  Bytes.to_string b

let z = String.make 32 '\000'
let one = change z 0 1

let order =
  unhex "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010"

let base = unhex ("58" ^ String.make 62 '6')
let mixed = unhex ("95" ^ String.concat "" (List.init 30 (fun _ -> "99")) ^ "99")

let special =
  [
    z;
    one;
    change one 31 128;
    unhex ("ec" ^ String.make 60 'f' ^ "7f");
    unhex ("ed" ^ String.make 60 'f' ^ "7f");
    unhex ("ee" ^ String.make 60 'f' ^ "7f");
    mixed;
    String.make 32 '\255';
  ]

let () =
  (* Raw verification deliberately retains legacy torsion/noncanonical policy. *)
  let points = base :: special in
  List.iter
    (fun a ->
      List.iter
        (fun r ->
          List.iter
            (fun s ->
              List.iter
                (fun msg ->
                  let signature = r ^ s in
                  let expected = Old.verify ~key:(a ^ z) signature ~msg in
                  assert (B.verify_raw ~key:a signature ~msg = expected))
                [ ""; "raw compatibility" ])
            [ z; one; order ])
        points)
    points;
  print_endline "Legacy raw verifier edge matrix passed"
