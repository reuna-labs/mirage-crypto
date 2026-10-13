(* Exact shrunk operation sequence from the 2026-10-11 unit failure. *)
module D = Octez_riscv_nds_disk
module R = D.Normal.Registry
module B = D.Normal.Database
let ok = function Ok x -> x | Error _ -> failwith "operation rejected"
let () =
  let repo = D.Repo.create Sys.argv.(1) in
  let r = R.create repo in
  ok (R.resize r 1L); ok (R.resize r 2L);
  let key = Bytes.of_string "aaXa" in
  let set i s = ok (B.set r ~db_index:i ~key ~value:(Bytes.of_string s)) in
  let capture n =
    Printf.printf "capture %d\n%!" n;
    (R.to_imm r, R.hash r)
  in
  set 0L "aaaaaaaaaaaaaaaa";
  set 0L "";
  ok (B.write r ~db_index:0L ~key ~offset:0L ~value:Bytes.empty);
  set 0L "";
  let a = capture 1 in
  set 0L "";
  ok (R.copy_database r ~src:0L ~dst:1L);
  set 1L "a";
  ok (R.clear r 0L);
  let b = capture 2 in
  set 1L "";
  set 0L "";
  let c = capture 3 in
  List.iteri (fun i (imm,h) ->
    if not (Bytes.equal (R.hash (R.from_imm imm)) h) then
      failwith (Printf.sprintf "snapshot %d hash changed" (i+1))) [a;b;c];
  Gc.full_major ();
  print_endline "All three snapshots retained their captured hashes"
