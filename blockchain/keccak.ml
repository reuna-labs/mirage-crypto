(* Digestif's KECCAK_* modules are the legacy pre-NIST-standardization Keccak
   padding (delimiter byte 0x01), which is what Ethereum, Solidity's
   [keccak256], and most blockchain codebases mean by "Keccak". This is
   distinct from [Digestif.SHA3_*], which uses the NIST FIPS 202
   domain-separator suffix (delimiter byte 0x06) and produces different
   digests for the same input.

   Keccak-256 is by far the common case in this domain; the other three sizes
   are here because a few protocols and the original Keccak submission use
   them. *)

module type S = sig
  val digest_size : int
  val digest : string -> string
end

module Make (H : Digestif.S) : S = struct
  let digest_size = H.digest_size
  let digest msg = H.(to_raw_string (digest_string msg))
end

module K224 = Make (Digestif.KECCAK_224)
module K256 = Make (Digestif.KECCAK_256)
module K384 = Make (Digestif.KECCAK_384)
module K512 = Make (Digestif.KECCAK_512)
