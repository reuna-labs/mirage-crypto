(* Review reproducer, not a production implementation or deterministic test.
   Secret source: ocaml-mpc 7b78792ce64f9190b67491230931761af71cf737,
   lib/mpc/secret.ml. See PROTOCOL-REVIEW.md for scope and observed results. *)
module Secret = struct
type t = { buf : Bytes.t; mutable live : bool }

let of_bytes b = { buf = b; live = true }
let of_string s = of_bytes (Bytes.of_string s)
let length t = Bytes.length t.buf
let wiped t = not t.live
let get t = if t.live then Some (Bytes.to_string t.buf) else None
let with_bytes t f = if t.live then Some (f t.buf) else None

let wipe t =
  if t.live then begin
    Bytes.fill (Sys.opaque_identity t.buf) 0 (Bytes.length t.buf) '\000';
    t.live <- false
  end

let wipe_all = List.iter wipe

let equal a b =
  match (a.live, b.live) with
  | false, false -> true
  | false, true | true, false -> false
  | true, true ->
      Bytes.length a.buf = Bytes.length b.buf
      && Eqaf.equal
           (Bytes.unsafe_to_string a.buf)
           (Bytes.unsafe_to_string b.buf)

end
(* Exact get/wipe sequence from Sign.take_and_burn, before scalar parsing. *)
let take_and_burn cell = match Secret.get cell with
 | None -> None
 | Some s -> Secret.wipe cell; Some s
let () =
 let count = 100_000 in
 let value = String.make 64 '\042' in
 let cells = Array.init count (fun _ -> Secret.of_string value) in
 let ready = Array.init count (fun _ -> Atomic.make 0) in
 let results = Array.init count (fun _ -> Atomic.make 0) in
 let worker () = for i=0 to count-1 do
   ignore (Atomic.fetch_and_add ready.(i) 1);
   while Atomic.get ready.(i) <> 2 do Domain.cpu_relax () done;
   match take_and_burn cells.(i) with
   | Some s when s=value -> ignore (Atomic.fetch_and_add results.(i) 1)
   | _ -> ()
 done in
 let a=Domain.spawn worker and b=Domain.spawn worker in
 Domain.join a; Domain.join b;
 let reused=Array.fold_left (fun n x -> n + if Atomic.get x=2 then 1 else 0) 0 results in
 Printf.printf "Trials: %d; both domains received original nonce: %d\n%!" count reused
