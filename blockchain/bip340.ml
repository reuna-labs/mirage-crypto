(* Secret Z.t conversion remains variable-time; use the native API directly. *)
module Native = Mirage_crypto_secp256k1.Bip340
type error = Secp256k1.error
let pp_error = Secp256k1.pp_error
type priv = Secp256k1.scalar
type xonly_pub = Native.xonly_pub
type signature = Native.signature
let tagged_hash = Hashes.tagged_hash
let xonly_pub_of_octets = Native.xonly_pub_of_octets
let xonly_pub_to_octets = Native.xonly_pub_to_octets
let xonly_pub_of_priv d = Native.xonly_pub_of_priv (Secp256k1.native_scalar d)
let signature_of_octets = Native.signature_of_octets
let signature_to_octets = Native.signature_to_octets
let sign ?(aux_rand=String.make 32 '\000') ~key msg =
  Native.sign ~aux_rand ~key:(Secp256k1.native_scalar key) msg
let verify = Native.verify
