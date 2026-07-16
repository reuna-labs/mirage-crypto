(* Z.t <-> big-endian-bytes helpers shared by the curve modules. *)

let of_be s =
  String.fold_left (fun acc c -> Z.logor (Z.shift_left acc 8) (Z.of_int (Char.code c))) Z.zero s

let to_be ~size z =
  let buf = Bytes.make size '\000' in
  let z = ref z in
  for i = size - 1 downto 0 do
    Bytes.set buf i (Char.chr (Z.to_int (Z.logand !z (Z.of_int 0xff))));
    z := Z.shift_right !z 8
  done;
  Bytes.unsafe_to_string buf

(* Uniform sample in [1, upper) via rejection sampling, pulling randomness
   from [g] (or the default generator if [g] is omitted). *)
let gen_in_range ?g upper =
  let byte_len = (Z.numbits upper + 7) / 8 in
  let rec loop () =
    let z = of_be (Mirage_crypto_rng.generate ?g byte_len) in
    if Z.zero < z && z < upper then z else loop ()
  in
  loop ()
