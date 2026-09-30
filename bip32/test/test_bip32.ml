module B = Mirage_crypto_bip32
module K = Mirage_crypto_secp256k1
let ok = function Ok x -> x | Error _ -> failwith "unexpected error"
let check label b = if not b then failwith label
let fails label = function Error _ -> () | Ok _ -> failwith label
let unhex s = String.init (String.length s / 2) (fun i -> Char.chr (int_of_string ("0x" ^ String.sub s (i*2) 2)))
let path s = match String.split_on_char '/' s with
  | "m" :: parts -> List.map (fun s ->
      let n = String.length s in
      if s.[n-1] = '\'' then Int32.logor Int32.min_int (Int32.of_string (String.sub s 0 (n-1)))
      else Int32.of_string s) parts
  | _ -> failwith "path"
let g = Mirage_crypto_rng.create ~seed:(String.make 48 '\042') (module Mirage_crypto_rng.Fortuna)
let version = 0x0488ade4l and pub_version = 0x0488b21el
let secret t = B.Secret.to_octets ~version t
let public t = B.Public.to_octets ~version:pub_version t
let fixtures file =
  let ic = open_in file in
  Fun.protect ~finally:(fun () -> close_in ic) (fun () ->
    try while true do
      let line = input_line ic in
      if line <> "" && line.[0] <> '#' then match String.split_on_char '\t' line with
      | [seed; p; sk; pk] ->
        let node = ok (B.Secret.derive_path ~g (ok (B.Secret.master (unhex seed))) (path p)) in
        check ("secret " ^ p) (secret node = unhex sk);
        let pub = B.Secret.public ~g node in
        check ("public " ^ p) (public pub = unhex pk);
        let sk', v = ok (B.Secret.of_octets (unhex sk)) in
        check "private roundtrip" (v = version && secret sk' = unhex sk);
        let pk', v = ok (B.Public.of_octets (unhex pk)) in
        check "public roundtrip" (v = pub_version && public pk' = unhex pk);
        List.iter (fun i ->
          check "public/private child agreement"
            (public (ok (B.Public.derive pub i)) = public (B.Secret.public ~g (ok (B.Secret.derive ~g node i)))))
          [0l; 1l; Int32.max_int]
      | _ -> failwith "fixture format"
    done with End_of_file -> ())
let zero = String.make 32 '\000'
let one = String.make 31 '\000' ^ "\001"
let injected = ref (one ^ zero)
let calls = ref 0
module F = Bip32_core_test.Make(struct
  let hmac512 ~key:_ _ = incr calls; !injected
end)
let mutate s i c = let b = Bytes.of_string s in Bytes.set b i c; Bytes.to_string b
let () =
  for i=1 to Array.length Sys.argv - 1 do fixtures Sys.argv.(i) done;
  let parent = ok (F.Secret.master (String.make 16 '\000')) in
  let pub = F.Secret.public ~g parent in
  let chain = String.make 32 '\099' in
  injected := zero ^ chain;
  let child = ok (F.Secret.derive ~g parent Int32.minus_one) in
  check "zero tweak metadata" (K.priv_to_octets child.key = one && child.chain_code = chain && child.depth = 1 && child.child_number = Int32.minus_one);
  let cp = ok (F.Public.derive pub Int32.max_int) in
  check "zero public tweak" (K.pub_to_octets cp.key = K.pub_to_octets pub.key);
  fails "zero master" (F.Secret.master (String.make 16 '\000'));
  List.iter (fun tweak ->
    injected := tweak ^ chain;
    let count = !calls in
    check "invalid secret child" (F.Secret.derive ~g parent 7l = Error `Invalid_range);
    check "no retry" (!calls = count + 1);
    check "invalid public child" (F.Public.derive pub 7l = Error `Invalid_range))
    [K.n; K.priv_to_octets (K.priv_negate (ok (K.priv_of_octets one))); String.make 32 '\255'];
  injected := K.n ^ chain;
  fails "order master" (F.Secret.master (String.make 16 '\000'));
  let sk = ok (K.priv_of_octets one) in
  check "negate/add infinity" (K.pub_add (K.pub_of_priv ~g sk) (K.pub_negate (K.pub_of_priv ~g sk)) = Error `At_infinity);
  check "negate twice" (K.priv_to_octets (K.priv_negate (K.priv_negate sk)) = one);
  fails "short tweak" (K.priv_add_tweak sk "");
  let master = ok (B.Secret.master (String.make 16 '\001')) in
  let raw = secret master in
  let deep = fst (ok (B.Secret.of_octets (mutate raw 4 '\255'))) in
  check "depth overflow" (B.Secret.derive ~g deep 0l = Error `Invalid_range);
  check "public depth overflow" (B.Public.derive (B.Secret.public ~g deep) 0l = Error `Invalid_range);
  check "path overflow" (B.Secret.derive_path ~g master (List.init 256 (fun _ -> 0l)) = Error `Invalid_range);
  check "hardened public" (B.Public.derive (B.Secret.public ~g master) Int32.min_int = Error `Hardened_from_public);
  List.iter (fun n -> fails "seed length" (B.Secret.master (String.make n '\001'))) [0;15;65];
  ignore (ok (B.Secret.master (String.make 64 '\001')));
  List.iter (fun s -> fails "bad private encoding" (B.Secret.of_octets s))
    [""; raw ^ "x"; mutate raw 5 '\001'; mutate raw 12 '\001'; mutate raw 45 '\002'; String.sub raw 0 46 ^ zero; String.sub raw 0 46 ^ K.n];
  let rp = public (B.Secret.public ~g master) in
  List.iter (fun s -> fails "bad public encoding" (B.Public.of_octets s))
    [""; mutate rp 45 '\000'; mutate rp 45 '\004'; String.sub rp 0 46 ^ String.make 32 '\255'];
  let unknown = B.Secret.to_octets ~version:0xdeadbeefl master in
  let parsed, v = ok (B.Secret.of_octets unknown) in
  check "version preserved" (v = 0xdeadbeefl && B.Secret.to_octets ~version:v parsed = unknown);
  for _=1 to 100 do
    Gc.full_major ();
    let node = ok (B.Secret.derive_path ~g master [Int32.min_int;1l;Int32.minus_one]) in
    ignore (ok (B.Public.of_octets (public (B.Secret.public ~g node))))
  done;
  print_endline "BIP32 official/oracle vectors, invalid HMAC, boundaries and GC passed."
