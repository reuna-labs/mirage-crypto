(* Small SHA-256 helpers shared across blockchain codecs: raw SHA-256,
   Bitcoin's double-SHA256 ("SHA256d"), and the BIP340 tagged hash (also
   reused by BIP341 Taproot for TapLeaf/TapBranch/TapTweak/TapSighash).
   Thin wrappers over [Digestif.SHA256]. *)

let sha256 msg = Digestif.SHA256.(to_raw_string (digest_string msg))

let sha256d msg = sha256 (sha256 msg)

let tagged_hash ~tag msg =
  let h = sha256 tag in
  sha256 (h ^ h ^ msg)
