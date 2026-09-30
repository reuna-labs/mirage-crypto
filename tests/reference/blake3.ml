(* Ported from the official BLAKE3 reference implementation
   (https://github.com/BLAKE3-team/BLAKE3/blob/master/reference_impl/reference_impl.rs),
   see also the spec at
   https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf *)

let out_len = 32
let key_len = 32
let block_len = 64
let chunk_len = 1024

let chunk_start = 1
let chunk_end = 2
let parent_flag = 4
let root_flag = 8
let keyed_hash_flag = 16
let derive_key_context_flag = 32
let derive_key_material_flag = 64

let mask32 = 0xFFFFFFFF

let iv =
  [| 0x6A09E667; 0xBB67AE85; 0x3C6EF372; 0xA54FF53A; 0x510E527F; 0x9B05688C;
     0x1F83D9AB; 0x5BE0CD19 |]

let msg_permutation = [| 2; 6; 3; 10; 7; 0; 4; 13; 1; 11; 12; 5; 9; 14; 15; 8 |]

let add a b = (a + b) land mask32
let xor a b = a lxor b
let rotr x n = ((x lsr n) lor (x lsl (32 - n))) land mask32

let g state a b c d mx my =
  state.(a) <- add state.(a) (add state.(b) mx);
  state.(d) <- rotr (xor state.(d) state.(a)) 16;
  state.(c) <- add state.(c) state.(d);
  state.(b) <- rotr (xor state.(b) state.(c)) 12;
  state.(a) <- add state.(a) (add state.(b) my);
  state.(d) <- rotr (xor state.(d) state.(a)) 8;
  state.(c) <- add state.(c) state.(d);
  state.(b) <- rotr (xor state.(b) state.(c)) 7

let round state m =
  g state 0 4 8 12 m.(0) m.(1);
  g state 1 5 9 13 m.(2) m.(3);
  g state 2 6 10 14 m.(4) m.(5);
  g state 3 7 11 15 m.(6) m.(7);
  g state 0 5 10 15 m.(8) m.(9);
  g state 1 6 11 12 m.(10) m.(11);
  g state 2 7 8 13 m.(12) m.(13);
  g state 3 4 9 14 m.(14) m.(15)

let permute m =
  let permuted = Array.make 16 0 in
  for i = 0 to 15 do
    permuted.(i) <- m.(msg_permutation.(i))
  done;
  Array.blit permuted 0 m 0 16

let compress chaining_value block_words counter block_len flags =
  let counter_low = counter land mask32 in
  let counter_high = (counter asr 32) land mask32 in
  let state = Array.make 16 0 in
  Array.blit chaining_value 0 state 0 8;
  state.(8) <- iv.(0);
  state.(9) <- iv.(1);
  state.(10) <- iv.(2);
  state.(11) <- iv.(3);
  state.(12) <- counter_low;
  state.(13) <- counter_high;
  state.(14) <- block_len;
  state.(15) <- flags;
  let block = Array.copy block_words in
  round state block;
  permute block;
  round state block;
  permute block;
  round state block;
  permute block;
  round state block;
  permute block;
  round state block;
  permute block;
  round state block;
  permute block;
  round state block;
  for i = 0 to 7 do
    state.(i) <- xor state.(i) state.(i + 8);
    state.(i + 8) <- xor state.(i + 8) chaining_value.(i)
  done;
  state

let word_of_le_bytes s off =
  Char.code s.[off]
  lor (Char.code s.[off + 1] lsl 8)
  lor (Char.code s.[off + 2] lsl 16)
  lor (Char.code s.[off + 3] lsl 24)

let words_of_le_bytes s n = Array.init n (fun i -> word_of_le_bytes s (i * 4))
let block_words_of_bytes s = words_of_le_bytes s 16

let word_to_le_bytes buf off w =
  Bytes.set buf off (Char.chr (w land 0xff));
  Bytes.set buf (off + 1) (Char.chr ((w lsr 8) land 0xff));
  Bytes.set buf (off + 2) (Char.chr ((w lsr 16) land 0xff));
  Bytes.set buf (off + 3) (Char.chr ((w lsr 24) land 0xff))

(* An "output" captures the state just prior to choosing between producing
   an 8-word chaining value or, with the ROOT flag, any number of output
   bytes. *)
type output = {
  input_chaining_value : int array;
  block_words : int array;
  counter : int;
  block_len : int;
  flags : int;
}

let output_chaining_value o =
  let full = compress o.input_chaining_value o.block_words o.counter o.block_len o.flags in
  Array.sub full 0 8

let output_root_bytes o digest_size =
  let out = Bytes.create digest_size in
  let block_counter = ref 0 in
  let pos = ref 0 in
  while !pos < digest_size do
    let words =
      compress o.input_chaining_value o.block_words !block_counter o.block_len
        (o.flags lor root_flag)
    in
    let tmp = Bytes.create 64 in
    for i = 0 to 15 do
      word_to_le_bytes tmp (i * 4) words.(i)
    done;
    let remaining = digest_size - !pos in
    let take = min remaining 64 in
    Bytes.blit tmp 0 out !pos take;
    pos := !pos + take;
    incr block_counter
  done;
  Bytes.unsafe_to_string out

(* Incremental state for the chunk currently being filled (up to 1024 bytes,
   compressed in 64-byte blocks). *)
type chunk_state = {
  mutable chaining_value : int array; (* 8 words *)
  chunk_counter : int;
  block : bytes; (* 64 bytes, zero-padded *)
  mutable filled_len : int;
  mutable blocks_compressed : int;
  cs_flags : int;
}

let new_chunk_state key_words chunk_counter flags =
  {
    chaining_value = Array.copy key_words;
    chunk_counter;
    block = Bytes.make block_len '\000';
    filled_len = 0;
    blocks_compressed = 0;
    cs_flags = flags;
  }

let chunk_state_len cs = (block_len * cs.blocks_compressed) + cs.filled_len

let chunk_state_start_flag cs =
  if cs.blocks_compressed = 0 then chunk_start else 0

let chunk_state_update cs input off len =
  let input_pos = ref off in
  let remaining = ref len in
  while !remaining > 0 do
    if cs.filled_len = block_len then begin
      let block_words = block_words_of_bytes (Bytes.unsafe_to_string cs.block) in
      let full =
        compress cs.chaining_value block_words cs.chunk_counter block_len
          (cs.cs_flags lor chunk_state_start_flag cs)
      in
      cs.chaining_value <- Array.sub full 0 8;
      cs.blocks_compressed <- cs.blocks_compressed + 1;
      Bytes.fill cs.block 0 block_len '\000';
      cs.filled_len <- 0
    end;
    let want = block_len - cs.filled_len in
    let take = min want !remaining in
    Bytes.blit_string input !input_pos cs.block cs.filled_len take;
    cs.filled_len <- cs.filled_len + take;
    input_pos := !input_pos + take;
    remaining := !remaining - take
  done

let chunk_state_output cs =
  let block_words = block_words_of_bytes (Bytes.unsafe_to_string cs.block) in
  {
    input_chaining_value = cs.chaining_value;
    block_words;
    counter = cs.chunk_counter;
    block_len = cs.filled_len;
    flags = cs.cs_flags lor chunk_state_start_flag cs lor chunk_end;
  }

let parent_output left_cv right_cv key_words flags =
  let block_words = Array.make 16 0 in
  Array.blit left_cv 0 block_words 0 8;
  Array.blit right_cv 0 block_words 8 8;
  {
    input_chaining_value = key_words;
    block_words;
    counter = 0;
    block_len;
    flags = parent_flag lor flags;
  }

let parent_cv left_cv right_cv key_words flags =
  output_chaining_value (parent_output left_cv right_cv key_words flags)

(* An incremental hasher, following the reference implementation's tree
   construction via a stack of subtree chaining values. 54 stack slots
   suffice for any input up to 2^54 chunks (2^64 bytes). *)
type hasher = {
  mutable chunk_state : chunk_state;
  key_words : int array;
  cv_stack : int array array;
  mutable cv_stack_len : int;
  h_flags : int;
}

let make_hasher key_words flags =
  {
    chunk_state = new_chunk_state key_words 0 flags;
    key_words;
    cv_stack = Array.init 54 (fun _ -> Array.make 8 0);
    cv_stack_len = 0;
    h_flags = flags;
  }

let push_stack h cv =
  h.cv_stack.(h.cv_stack_len) <- cv;
  h.cv_stack_len <- h.cv_stack_len + 1

let pop_stack h =
  h.cv_stack_len <- h.cv_stack_len - 1;
  h.cv_stack.(h.cv_stack_len)

let add_chunk_chaining_value h new_cv total_chunks =
  let cv = ref new_cv in
  let tc = ref total_chunks in
  while !tc land 1 = 0 do
    let left = pop_stack h in
    cv := parent_cv left !cv h.key_words h.h_flags;
    tc := !tc lsr 1
  done;
  push_stack h !cv

let hasher_update h input =
  let len = String.length input in
  let pos = ref 0 in
  while !pos < len do
    if chunk_state_len h.chunk_state = chunk_len then begin
      let chunk_cv = output_chaining_value (chunk_state_output h.chunk_state) in
      let total_chunks = h.chunk_state.chunk_counter + 1 in
      add_chunk_chaining_value h chunk_cv total_chunks;
      h.chunk_state <- new_chunk_state h.key_words total_chunks h.h_flags
    end;
    let want = chunk_len - chunk_state_len h.chunk_state in
    let take = min want (len - !pos) in
    chunk_state_update h.chunk_state input !pos take;
    pos := !pos + take
  done

let hasher_finalize h digest_size =
  let output = ref (chunk_state_output h.chunk_state) in
  let remaining = ref h.cv_stack_len in
  while !remaining > 0 do
    remaining := !remaining - 1;
    let right_cv = output_chaining_value !output in
    output := parent_output h.cv_stack.(!remaining) right_cv h.key_words h.h_flags
  done;
  output_root_bytes !output digest_size

let check_digest_size digest_size =
  if digest_size < 1 then invalid_arg "Blake3: digest_size must be >= 1"

let digest ?(digest_size = out_len) msg =
  check_digest_size digest_size;
  let h = make_hasher iv 0 in
  hasher_update h msg;
  hasher_finalize h digest_size

let keyed_digest ?(digest_size = out_len) ~key msg =
  check_digest_size digest_size;
  if String.length key <> key_len then
    invalid_arg "Blake3.keyed_digest: key must be 32 bytes";
  let key_words = words_of_le_bytes key 8 in
  let h = make_hasher key_words keyed_hash_flag in
  hasher_update h msg;
  hasher_finalize h digest_size

let derive_key ?(digest_size = out_len) ~context key_material =
  check_digest_size digest_size;
  let ctx_h = make_hasher iv derive_key_context_flag in
  hasher_update ctx_h context;
  let context_key = hasher_finalize ctx_h key_len in
  let context_key_words = words_of_le_bytes context_key 8 in
  let h = make_hasher context_key_words derive_key_material_flag in
  hasher_update h key_material;
  hasher_finalize h digest_size
