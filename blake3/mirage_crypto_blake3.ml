external hash : int -> string -> string -> int -> string = "mc_blake3"
let check n = if n < 1 then invalid_arg "Blake3: digest_size must be >= 1"
let digest ?(digest_size=32) msg = check digest_size; hash 0 "" msg digest_size
let keyed_digest ?(digest_size=32) ~key msg =
  check digest_size;
  if String.length key <> 32 then invalid_arg "Blake3.keyed_digest: key must be 32 bytes";
  hash 1 key msg digest_size
let derive_key ?(digest_size=32) ~context msg = check digest_size; hash 2 context msg digest_size
