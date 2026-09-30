module S = Mirage_crypto_sr25519
module R = Blockchain_reference.Sr25519
external reduce : string -> string = "mc_sr_scalar_reduce"
external scalar_valid : string -> bool = "mc_sr_scalar_valid"
external add : string -> string -> string = "mc_sr_scalar_add"
external mul : string -> string -> string = "mc_sr_scalar_mul"
external base : string -> string = "mc_sr_point_base"
external point_mul : string -> string -> string = "mc_sr_point_mul"
external point_sub : string -> string -> string = "mc_sr_point_sub"
let ok = function Ok x -> x | Error _ -> failwith "unexpected parse failure"
let check name a b = if a <> b then failwith name
let unhex = Ohex.decode
let zero = String.make 32 '\000'
let one = "\001" ^ String.make 31 '\000'
module Fixed = struct
  type g = string ref
  let block = 1
  let create ?time:_ () = ref ""
  let reseed ~g seed = g := seed
  let generate_into ~g out ~off n =
    assert (n = 32 && String.length !g = 1);
    Bytes.fill out off n !g.[0]
  let accumulate ~g _ = `Acc (reseed ~g)
  let seeded ~g = String.length !g = 1
  let pools = 0
end
let rng i = Mirage_crypto_rng.create ~seed:(String.make 1 (Char.chr i)) (module Fixed)
let vector line = match String.split_on_char '\t' line with
  | ["S"; seed; ctx; msg; entropy; pk; sig_; vrf] ->
    let seed = unhex seed and context = unhex ctx and msg = unhex msg in
    let key = ok (S.priv_of_octets seed) and pk = unhex pk in
    let pub = S.pub_of_priv key in
    check "Rust public key" (S.pub_to_octets pub) pk;
    let sig_ = unhex sig_ in
    let actual = S.sign ~g:(rng (int_of_string entropy)) ~context ~key msg in
    check "Rust signature with identical entropy" (S.signature_to_octets actual) sig_;
    assert (S.verify ~context ~key:pub (ok (S.signature_of_octets sig_)) msg);
    assert (not (S.verify ~context ~key:pub actual (msg ^ "!")));
    assert (not (S.verify ~context:(context ^ "!") ~key:pub actual msg));
    check "Rust malleable VRF pre-output" (S.vrf_output ~key msg) (unhex vrf);
    (* Independent old OCaml protocol, including its own Keccak permutation. *)
    if int_of_string entropy < 3 then begin
      let rk = ok (R.priv_of_octets seed) in
      check "old protocol signature" (R.sign ~g:(rng (int_of_string entropy)) ~context ~key:rk msg) sig_;
      check "old VRF pre-output" (R.vrf_output ~key:rk msg) (unhex vrf)
    end
  | ["G"; wide; a; b; p; sum; product; ag; ap; hashed] ->
    let wide = unhex wide and a = unhex a and b = unhex b and p = unhex p in
    assert (scalar_valid a && scalar_valid b);
    if a <> zero then check "Rust wide reduction" (reduce wide) a;
    check "wide reduction" (reduce wide) (R.scalar_to_bytes (R.scalar_reduce_wide wide));
    check "Rust scalar addition" (add a b) (unhex sum);
    check "Rust scalar multiplication" (mul a b) (unhex product);
    check "Rust base multiplication" (base a) (unhex ag);
    check "Rust point multiplication" (point_mul a p) (unhex ap);
    check "Rust uniform map" (S.ristretto_from_uniform_bytes wide) (unhex hashed);
    check "point subtraction" (point_sub p p) zero;
    check "identity operand" (point_mul a zero) zero;
    check "zero operand" (point_mul zero p) zero
  | ["P"; p; valid] ->
    check "Rust point parsing" (Result.is_ok (S.pub_of_octets (unhex p))) (bool_of_string valid)
  | _ -> failwith "invalid Rust fixture"
let invalid f = try ignore (f ()); failwith "expected Invalid_argument" with Invalid_argument _ -> ()
let () =
  let input = open_in Sys.argv.(1) in
  let count = ref 0 in
  Fun.protect ~finally:(fun () -> close_in input) (fun () ->
    try while true do vector (input_line input); incr count done with End_of_file -> ());
  assert (!count = 194);
  let l = unhex "edd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010" in
  let lm1 = unhex "ecd3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010" in
  let lp1 = unhex "eed3f55c1a631258d69cf7a2def9de1400000000000000000000000000000010" in
  assert (scalar_valid zero && scalar_valid lm1 && not (scalar_valid l) && not (scalar_valid lp1));
  check "L reduction" (reduce (l ^ zero)) zero;
  check "L+1 reduction" (reduce (lp1 ^ zero)) one;
  check "scalar wrap" (add lm1 one) zero;
  check "zero base" (base zero) zero;
  check "identity decoding" (S.pub_to_octets (ok (S.pub_of_octets zero))) zero;
  List.iter (fun s -> check "parser errors preserved" (S.pub_of_octets s |> Result.map S.pub_to_octets)
    (R.pub_of_octets s))
    [""; String.make 31 '\000'; String.make 33 '\000'; one; String.make 32 '\xff';
     "\xed" ^ String.make 30 '\xff' ^ "\x7f"; "\xec" ^ String.make 30 '\xff' ^ "\x7f"];
  invalid (fun () -> point_mul zero (String.make 32 '\xff'));
  List.iter (fun n -> invalid (fun () -> reduce (String.make n '\000'))) [0;32;63;65];
  List.iter (fun n -> invalid (fun () -> base (String.make n '\000'))) [0;31;33];
  let marker s = let b = Bytes.of_string s in Bytes.set b 31 (Char.chr (Char.code s.[31] lor 128)); Bytes.to_string b in
  check "noncanonical signature scalar" (S.signature_of_octets (zero ^ marker l)) (Error `Invalid_range);
  check "missing signature marker" (S.signature_of_octets (zero ^ zero)) (Error `Invalid_format);
  (* Permutation differential checks cover the entire 200-byte state. *)
  for i = 0 to 127 do
    let state = Bytes.init 200 (fun j -> Char.chr ((i*71+j*13) land 255)) in
    let lanes = R.bytes_to_lanes state in
    R.keccak_f1600 lanes;
    Digestif_keccak_f1600.permute state;
    check "Keccak whole-state differential" state (R.lanes_to_bytes lanes)
  done;
  for i = 0 to 300 do
    let key = ok (S.priv_of_octets (String.make 32 (Char.chr (i land 255)))) in
    let sig_ = S.sign ~g:(rng 17) ~key "GC boundary" in
    if i mod 17 = 0 then Gc.compact ();
    assert (S.verify ~key:(S.pub_of_priv key) sig_ "GC boundary")
  done;
  print_endline "sr25519: Rust vectors, edge cases, GC and Keccak differential checks passed."
