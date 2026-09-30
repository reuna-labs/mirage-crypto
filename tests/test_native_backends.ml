module K = Mirage_crypto_secp256k1
module S = K.Bip340
module B = Mirage_crypto_bls12_381
module H = Mirage_crypto_blake3
module P = Mirage_crypto_poseidon
module R = Blockchain_reference
let check label b = if not b then failwith label
let ok = function Ok x -> x | Error _ -> failwith "unexpected decoding failure"
let hex s = String.init (String.length s / 2) (fun i -> Char.chr (int_of_string ("0x" ^ String.sub s (2*i) 2)))
let be = R.Octets.to_be ~size:32
let bytes n = String.init n (fun _ -> Char.chr (Random.int 256))
let invalid f = try ignore (f ()); false with Invalid_argument _ -> true

let vectors () =
  List.iter (fun (len,h,k,d) ->
    let msg = String.init len (fun i -> Char.chr (i mod 251)) in
    let n = String.length h / 2 in
    check "BLAKE3 XOF vector" (H.digest ~digest_size:n msg = hex h);
    check "BLAKE3 vector prefix" (H.digest msg = String.sub (hex h) 0 32);
    check "BLAKE3 keyed vector" (H.keyed_digest ~digest_size:n ~key:Native_vectors.blake3_key msg = hex k);
    check "BLAKE3 derive vector" (H.derive_key ~digest_size:n ~context:Native_vectors.blake3_context msg = hex d)
  ) Native_vectors.blake3;
  List.iter (fun (id,sk,pk,aux,msg,sig_,expected) ->
    let verified = match S.xonly_pub_of_octets (hex pk), S.signature_of_octets (hex sig_) with
      | Ok key, Ok s -> S.verify ~key s (hex msg) | _ -> false in
    check (Printf.sprintf "BIP340 verify %d" id) (verified = expected);
    if sk <> "" then begin
      let key = ok (K.priv_of_octets (hex sk)) in
      check "BIP340 pub" (S.xonly_pub_to_octets (S.xonly_pub_of_priv key) = hex pk);
      check (Printf.sprintf "BIP340 sign %d" id)
        (S.signature_to_octets (S.sign ~aux_rand:(hex aux) ~key (hex msg)) = hex sig_)
    end
  ) Native_vectors.bip340;
  List.iter (fun (id,pk,msg,sig_,expected) ->
    let verified = match K.pub_of_octets (hex pk), K.signature_of_octets (hex sig_) with
      | Ok key, Ok s -> K.verify ~key s (hex msg) | _ -> false in
    check (Printf.sprintf "Wycheproof ECDSA %d" id) (verified = expected)
  ) Native_vectors.ecdsa;
  List.iter (fun (msg,dst,point) ->
    check "RFC9380 G2" (B.g2_to_octets ~compress:false (B.hash_to_curve_g2 ~dst msg) = hex point)
  ) Native_vectors.hash_to_g2

let secp () =
  List.iter (fun sk -> check "reject scalar" (Result.is_error (K.priv_of_octets sk)))
    [""; String.make 31 '\000'; String.make 32 '\000'; K.n; String.make 32 '\255'];
  for i = 1 to 48 do
    let key_bytes = be (Z.of_int i) in
    let key = ok (K.priv_of_octets key_bytes) and rk = ok (R.Secp256k1.scalar_of_octets key_bytes) in
    let msg = if i = 1 then String.make 32 '\000' else if i = 2 then String.make 32 '\255' else bytes 32 in
    let pub = K.pub_of_priv key in
    let sg,id = K.sign_recoverable ~key msg in
    check "reference ECDSA" (K.signature_to_octets sg = R.Secp256k1.signature_to_octets (R.Secp256k1.sign ~key:rk msg));
    check "ECDSA recovery" (K.pub_to_octets (ok (K.recover ~msg sg ~recid:id)) = K.pub_to_octets pub);
    check "DER roundtrip" (K.signature_to_octets (ok (K.signature_of_octets (K.signature_to_octets ~compact:false sg))) = K.signature_to_octets sg);
    let compact = K.signature_to_octets sg in
    let high = String.sub compact 0 32 ^ be Z.(R.Secp256k1.n - R.Octets.of_be (String.sub compact 32 32)) in
    check "high-S accepted" (K.verify ~key:pub (ok (K.signature_of_octets high)) msg);
    check "high-S recovery parity" (K.pub_to_octets (ok (K.recover ~msg (ok (K.signature_of_octets high)) ~recid:(id lxor 1))) = K.pub_to_octets pub);
    check "DER trailing bytes rejected" (Result.is_error (K.signature_of_octets (K.signature_to_octets ~compact:false sg ^ "\000")));
    check "invalid recovery id" (Result.is_error (K.recover ~msg sg ~recid:4));
    Gc.full_major ()
  done

let bls () =
  let zero = ok (B.scalar_of_octets (String.make 32 '\000')) in
  check "BLS zero private key rejected" (invalid (fun () -> B.pub_of_priv zero));
  check "BLS zero signing key rejected" (invalid (fun () -> B.sign ~key:zero "test"));
  let infinity = B.g1_scalar_mult zero B.g1_generator in
  check "BLS identity" (B.g1_is_infinity infinity);
  check "BLS subgroup identity" (B.g1_in_subgroup infinity);
  check "BLS empty aggregate" (B.g2_is_infinity (B.aggregate []));
  check "BLS empty verify" (not (B.aggregate_verify [] (B.aggregate [])));
  check "BLS order rejected" (Result.is_error (B.scalar_of_octets B.r));
  for i = 1 to 8 do
    let sk = be (Z.of_int i) in
    let key = ok (B.scalar_of_octets sk) and rk = ok (R.Bls12_381.scalar_of_octets sk) in
    let pub = B.pub_of_priv key in
    let msg = bytes (i*13) in
    let sg = B.sign ~key msg in
    check "BLS public reference" (B.g1_to_octets pub = R.Bls12_381.g1_to_octets (R.Bls12_381.pub_of_priv rk));
    check "BLS signature reference" (B.g2_to_octets sg = R.Bls12_381.g2_to_octets (R.Bls12_381.sign ~key:rk msg));
    check "BLS verify" (B.verify ~key:pub sg msg);
    check "BLS wrong message" (not (B.verify ~key:pub sg (msg ^ "x")));
    check "BLS identity pub rejected" (not (B.verify ~key:infinity sg msg));
    check "BLS identity sig rejected" (not (B.verify ~key:pub (B.aggregate []) msg));
    List.iter (fun compress ->
      check "BLS G1 roundtrip" (B.g1_equal pub (ok (B.g1_of_octets (B.g1_to_octets ~compress pub))));
      check "BLS G2 roundtrip" (B.g2_equal sg (ok (B.g2_of_octets (B.g2_to_octets ~compress sg))))) [false;true];
    let agg = B.aggregate [sg; B.sign ~key (msg ^ "x")] in
    check "BLS aggregate" (B.aggregate_verify [pub,msg; pub,msg ^ "x"] agg);
    check "BLS duplicate rejected" (not (B.aggregate_verify [pub,msg;pub,msg] agg));
    Gc.full_major ()
  done;
  (* (0,2) is on E1 but outside the prime-order subgroup. *)
  let outside = String.make 95 '\000' ^ "\002" in
  check "BLS non-subgroup rejected" (Result.is_error (B.g1_of_octets outside));
  check "BLS noncanonical infinity" (Result.is_error (B.g1_of_octets ("\192" ^ String.make 46 '\000' ^ "\001")))

let poseidon () =
  let prime = R.Poseidon.p in
  let elt x = ok (P.field_element_of_octets (be x)) in
  let value x = R.Octets.of_be (P.field_element_to_octets x) in
  check "Poseidon prime rejected" (Result.is_error (P.field_element_of_octets (be prime)));
  check "Poseidon max rejected" (Result.is_error (P.field_element_of_octets (String.make 32 '\255')));
  for len = 0 to 40 do
    let xs = List.init len (fun i -> if i=0 then Z.pred prime else Z.erem (R.Octets.of_be (bytes 32)) prime) in
    check "Poseidon sponge reference" (value (P.hash (List.map elt xs)) = R.Poseidon.hash xs)
  done;
  for i = 0 to 100 do
    let x = if i=0 then Z.zero else Z.erem (R.Octets.of_be (bytes 32)) prime in
    let y = Z.erem (R.Octets.of_be (bytes 32)) prime in
    check "Poseidon pair reference" (value (P.hash_pair (elt x) (elt y)) = R.Poseidon.hash_pair x y);
    check "Poseidon single reference" (value (P.hash_single (elt x)) = R.Poseidon.hash_single x)
  done

let fuzz_and_gc () =
  for i = 0 to 1000 do
    let s = bytes (i mod 200) in
    ignore (K.pub_of_octets s); ignore (K.signature_of_octets s);
    ignore (S.xonly_pub_of_octets s); ignore (S.signature_of_octets s);
    ignore (B.g1_of_octets s); ignore (B.g2_of_octets s);
    ignore (P.field_element_of_octets s);
    let ctx = "test\000context" ^ s in
    check "BLAKE3 binary context" (H.derive_key ~context:ctx s = R.Blake3.derive_key ~context:ctx s);
    if i mod 50 = 0 then Gc.compact ()
  done;
  check "BLAKE3 invalid output" (invalid (fun () -> H.digest ~digest_size:0 ""));
  check "BLAKE3 invalid key" (invalid (fun () -> H.keyed_digest ~key:"" ""))

let adapters () =
  let module C = Mirage_crypto_blockchain in
  let module G = Mirage_crypto_ec.P256k1.Primitive in
  for i = 1 to 16 do
    let k = be (Z.of_int i) in
    let sk = ok (C.Secp256k1.scalar_of_octets k) in
    let rk = ok (R.Secp256k1.scalar_of_octets k) in
    let expected = R.Secp256k1.pub_of_priv rk in
    let pk = ok (C.Secp256k1.scalar_mult sk C.Secp256k1.g) in
    check "legacy group multiply" (C.Secp256k1.point_to_octets pk = R.Secp256k1.point_to_octets expected);
    let sum = ok (C.Secp256k1.add pk C.Secp256k1.g) in
    check "legacy group add" (C.Secp256k1.point_to_octets sum =
      R.Secp256k1.point_to_octets (ok (R.Secp256k1.add expected R.Secp256k1.g)));
    check "EC primitive still independent" (G.point_to_octets (G.scalar_mult_base k) =
      R.Secp256k1.point_to_octets expected);
    let inv = G.scalar_inv k in
    check "EC scalar inversion" (G.scalar_mul k inv = G.scalar_one)
  done;
  let neg = ok (C.Secp256k1.scalar_of_octets (be Z.(R.Secp256k1.n - one))) in
  let minus_g = ok (C.Secp256k1.scalar_mult neg C.Secp256k1.g) in
  check "legacy group infinity" (C.Secp256k1.add C.Secp256k1.g minus_g = Error `At_infinity);
  List.iter (fun xs -> check "legacy Poseidon normalization"
    (C.Poseidon.hash xs = R.Poseidon.hash xs))
    [[]; [Z.minus_one]; [Z.succ R.Poseidon.p; Z.neg R.Poseidon.p]]

let () =
  Random.init 340;
  Mirage_crypto_rng.set_default_generator (Mirage_crypto_rng.create ~seed:(String.make 48 '\042') (module Mirage_crypto_rng.Fortuna));
  vectors (); secp (); bls (); poseidon (); fuzz_and_gc (); adapters ();
  Printf.printf "Native backends: %d ECDSA, %d BIP340, %d BLAKE3, %d hash-to-G2 vectors; differential and malformed-input/GC checks passed.\n%!"
    (List.length Native_vectors.ecdsa) (List.length Native_vectors.bip340)
    (List.length Native_vectors.blake3) (List.length Native_vectors.hash_to_g2)
