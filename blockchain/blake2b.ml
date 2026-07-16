let max_digest_size = 64

let check_digest_size digest_size =
  if digest_size < 1 || digest_size > max_digest_size then
    invalid_arg "Blake2b: digest_size must be in [1, 64]"

let digest ?(digest_size = max_digest_size) msg =
  check_digest_size digest_size;
  if digest_size = max_digest_size then
    Digestif.BLAKE2B.(to_raw_string (digest_string msg))
  else
    let module H = Digestif.Make_BLAKE2B (struct
      let digest_size = digest_size
    end) in
    H.(to_raw_string (digest_string msg))

let hmac ?(digest_size = max_digest_size) ~key msg =
  check_digest_size digest_size;
  if digest_size = max_digest_size then
    Digestif.BLAKE2B.(to_raw_string (hmac_string ~key msg))
  else
    let module H = Digestif.Make_BLAKE2B (struct
      let digest_size = digest_size
    end) in
    H.(to_raw_string (hmac_string ~key msg))
