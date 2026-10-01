module B = Mirage_crypto_ed25519_bip32

let ok = function
  | Ok x -> x
  | Error e -> failwith (Format.asprintf "%a" B.pp_error e)

let hex s =
  String.concat ""
    (List.init (String.length s) (fun i ->
         Printf.sprintf "%02x" (Char.code s.[i])))

let unhex s =
  String.init
    (String.length s / 2)
    (fun i -> Char.chr (int_of_string ("0x" ^ String.sub s (i * 2) 2)))

let () =
  let entropy = unhex "46e62370a138a182a498b8e2885bc032379ddf38" in
  let root = ok (B.icarus_key_of_entropy entropy) in
  assert (
    hex (B.extended_priv_to_octets root)
    = "c065afd2832cd8b087c4d9ab7011f481ee1e0721e78ea5dd609f3ab3f156d245d176bd8fd4ec60b4731c3918a2a72a0226c0cd119ec35b47e4d55884667f552a23f7fdcd4a10c6cd2c7393ac61d877873e248f417634aa3d812af327ffe9d620");
  let pub = B.pub_of_priv root in
  ignore (ok (B.extended_pub_of_octets (B.extended_pub_to_octets pub)));
  let child = ok (B.derive_priv_normal root ~index:0l) in
  let pubchild = ok (B.derive_pub_normal pub ~index:0l) in
  assert (
    B.extended_pub_to_octets pubchild
    = B.extended_pub_to_octets (B.pub_of_priv child));
  let sig_ = B.sign ~key:child "Cardano native smoke" in
  assert (B.verify ~key:pubchild sig_ ~msg:"Cardano native smoke");
  print_endline "Ed25519-BIP32/Icarus smoke passed (no RNG)"
