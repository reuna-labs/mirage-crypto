(* Digestif.KECCAK_256 (available since digestif 1.1.0) is the legacy
   pre-NIST-standardization Keccak padding (delimiter byte 0x01), which is
   what Ethereum, Solidity's [keccak256], and most blockchain codebases mean
   by "Keccak-256". This is distinct from [Digestif.SHA3_256], which uses
   the NIST FIPS 202 domain-separator suffix (delimiter byte 0x06) and
   produces different digests for the same input. *)

let digest_size = Digestif.KECCAK_256.digest_size

let digest msg = Digestif.KECCAK_256.(to_raw_string (digest_string msg))
