module B = Mirage_crypto_ed25519_bip32

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
  let raw = change (String.make 96 '\000') 31 64 in
  let root = ok (B.extended_priv_of_octets raw) in
  List.iter
    (fun s -> assert (B.extended_priv_of_octets s = Error `Invalid_format))
    [ change raw 0 1; change raw 31 0; change raw 31 192 ];
  ignore (ok (B.extended_priv_of_octets (change raw 31 96)));
  assert (B.extended_priv_of_octets "" = Error `Invalid_length);
  List.iter
    (fun p -> assert (B.extended_pub_of_octets (p ^ z) = Error `Invalid_format))
    special;
  ignore (ok (B.extended_pub_of_octets (base ^ z)));
  assert (B.extended_pub_of_octets z = Error `Invalid_length);
  assert (
    B.derive_priv_normal root ~index:Int32.min_int = Error `Invalid_derivation);
  assert (
    B.derive_priv_hardened root ~index:Int32.max_int = Error `Invalid_derivation);
  assert (
    B.derive_pub_normal (B.pub_of_priv root) ~index:Int32.minus_one
    = Error `Invalid_derivation);
  let extreme =
    change (change (String.make 32 '\255' ^ String.make 64 '\000') 0 248) 31 127
  in
  assert (
    B.derive_priv_normal (ok (B.extended_priv_of_octets extreme)) ~index:0l
    = Error `Invalid_derivation);
  List.iter
    (fun n ->
      assert (
        B.icarus_key_of_entropy (String.make n 'x') = Error `Invalid_length))
    [ 0; 15; 33 ];
  let pk = B.pub_of_priv root in
  let sig_ = B.sign ~key:root "" in
  assert (not (B.verify ~key:pk (String.sub sig_ 0 32 ^ order) ~msg:""));
  let malleable = Bytes.of_string (String.sub sig_ 32 32) in
  let carry = ref 0 in
  for i = 0 to 31 do
    let n = Char.code (Bytes.get malleable i) + Char.code order.[i] + !carry in
    Bytes.set malleable i (Char.chr (n land 255));
    carry := n lsr 8
  done;
  assert (
    not
      (B.verify ~key:pk
         (String.sub sig_ 0 32 ^ Bytes.to_string malleable)
         ~msg:""));
  assert (not (B.verify_raw ~key:"" sig_ ~msg:""));
  assert (
    B.verify_raw ~key:one (one ^ z)
      ~msg:"raw identity remains legacy-compatible");
  for i = 0 to 500 do
    let key = ok (B.extended_priv_of_octets (change raw 32 (i land 255))) in
    Gc.minor ();
    let c = ok (B.derive_priv_normal key ~index:(Int32.of_int i)) in
    let s = B.sign ~key:c "gc" in
    if i mod 50 = 0 then Gc.compact ();
    assert (B.verify ~key:(B.pub_of_priv c) s ~msg:"gc")
  done;
  print_endline
    "strict imports, boundaries, raw verifier compatibility and GC stress \
     passed"
