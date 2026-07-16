let digest_size = Digestif.RMD160.digest_size

let digest msg = Digestif.RMD160.(to_raw_string (digest_string msg))

let hash160 pubkey =
  let sha256 = Digestif.SHA256.(to_raw_string (digest_string pubkey)) in
  digest sha256
