(* Poseidon (the Hades permutation) over the STARK-friendly prime field,
   using StarkWare's default parameters (state width m=3, rate r=2,
   capacity c=1, 8 full rounds, 83 partial rounds), ported directly from
   StarkWare's own reference implementation, not derived from memory:
   https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/cairo/common/poseidon_utils.py
   https://github.com/starkware-libs/cairo-lang/blob/master/src/starkware/cairo/common/poseidon_hash.py

   Round constants are NOT a hardcoded table (which would risk silent
   transcription errors across 273 large field elements); they are
   derived exactly as the reference does, from a "nothing up my sleeve"
   construction: [SHA256("Hades" ^ string_of_int idx) mod p]. This is
   both simpler and safer to get right than copying a giant constant
   table by hand.

   Encoding & state gap: Poseidon's natural I/O is field elements
   ({!field_element}, i.e. [Z.t] values reduced mod {!Stark_curve.p}),
   not byte strings -- it is used for Merkle state-commitment trees over
   field-element leaves (e.g. StarkNet contract storage tries). This
   module therefore exposes only the field-element-native API; it
   deliberately does not add a byte-string convenience wrapper, since
   StarkWare's own byte-oriented variant ([poseidon_hash_func] in the
   reference) is narrowly 2-ary and encodes bytes as a single big-endian
   integer, which would be a surprising, easy-to-misuse default for a
   general "hash these bytes" function; callers who need that exact
   convention can trivially build it from {!hash_pair} and their own
   byte<->field-element conversion. *)

type field_element = Z.t

let p = Stark_curve.p

let fadd a b = Z.(erem (a + b) p)
let fsub a b = Z.(erem (a - b) p)
let fmul a b = Z.(erem (a * b) p)
let fcube a = fmul a (fmul a a)

let state_width = 3 (* m = r + c *)
let rate = 2
let full_rounds = 8
let partial_rounds = 83
let n_rounds = full_rounds + partial_rounds

let round_constant idx =
  let msg = "Hades" ^ string_of_int idx in
  let digest = Digestif.SHA256.(to_raw_string (digest_string msg)) in
  Z.erem (Octets.of_be digest) p

(* ark.(round_idx).(j) = round_constant (state_width * round_idx + j) *)
let ark =
  Array.init n_rounds (fun i -> Array.init state_width (fun j -> round_constant ((state_width * i) + j)))

(* The "SmallMds" matrix StarkWare uses:
   [3  1  1]
   [1 -1  1]
   [1  1 -2] *)
let mds_dot v =
  let v0 = v.(0) and v1 = v.(1) and v2 = v.(2) in
  [|
    fadd (fadd (fmul (Z.of_int 3) v0) v1) v2;
    fadd (fsub v0 v1) v2;
    fsub (fadd v0 v1) (fmul (Z.of_int 2) v2);
  |]

let hades_round values ~full round_idx =
  let ark_row = ark.(round_idx) in
  let added = Array.mapi (fun i v -> fadd v ark_row.(i)) values in
  let subbed =
    if full then Array.map fcube added
    else begin
      let out = Array.copy added in
      out.(state_width - 1) <- fcube out.(state_width - 1);
      out
    end
  in
  mds_dot subbed

let hades_permutation values =
  let state = ref values in
  let round_idx = ref 0 in
  for _ = 1 to full_rounds / 2 do
    state := hades_round !state ~full:true !round_idx;
    incr round_idx
  done;
  for _ = 1 to partial_rounds do
    state := hades_round !state ~full:false !round_idx;
    incr round_idx
  done;
  for _ = 1 to full_rounds / 2 do
    state := hades_round !state ~full:true !round_idx;
    incr round_idx
  done;
  !state

(* poseidon_hash: 2-ary, capacity element (domain separator) = 2. *)
let hash_pair x y = (hades_permutation [| x; y; Z.of_int 2 |]).(0)

(* poseidon_hash_single: 1-ary, capacity element = 1. *)
let hash_single x = (hades_permutation [| x; Z.zero; Z.one |]).(0)

(* poseidon_hash_many: sponge construction over arbitrary-length input,
   padded with a single [1] followed by [0]s to a multiple of [rate]. *)
let hash values =
  let values = values @ [ Z.one ] in
  let pad_len = (rate - (List.length values mod rate)) mod rate in
  let values = values @ List.init pad_len (fun _ -> Z.zero) in
  let arr = Array.of_list values in
  let nblocks = Array.length arr / rate in
  let state = ref (Array.make state_width Z.zero) in
  for b = 0 to nblocks - 1 do
    let input =
      Array.init state_width (fun i ->
          if i < rate then fadd !state.(i) arr.((b * rate) + i) else !state.(i))
    in
    state := hades_permutation input
  done;
  !state.(0)
