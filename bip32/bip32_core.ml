(* BIP32 protocol only. Arithmetic belongs to libsecp256k1. The functor is
   private and permits deterministic invalid-HMAC tests without a public hook. *)
module K = Mirage_crypto_secp256k1

type error = [ K.error | `Hardened_from_public ]
let pp_error ppf = function
  | `Hardened_from_public -> Format.pp_print_string ppf "hardened derivation from public key"
  | #K.error as e -> K.pp_error ppf e

type 'a extended = {
  key : 'a;
  chain_code : string;
  depth : int;
  parent_fingerprint : string;
  child_number : int32;
}
let lift r = Result.map_error (fun (e : K.error) -> (e :> error)) r
let zero_fingerprint = String.make 4 '\000'
let hardened i = Int32.logand i 0x80000000l <> 0l
let hash160 s = Digestif.RMD160.(to_raw_string (digest_string
  Digestif.SHA256.(to_raw_string (digest_string s))))
let fingerprint_key key = String.sub (hash160 (K.pub_to_octets key)) 0 4
let u32 n = let b = Bytes.create 4 in Bytes.set_int32_be b 0 n; Bytes.to_string b
let map_key key t = { t with key }
let serialize ~version key t =
  u32 version ^ String.make 1 (Char.chr t.depth) ^ t.parent_fingerprint ^
  u32 t.child_number ^ t.chain_code ^ key
let parse s =
  if String.length s <> 78 then Error `Invalid_length else
  let depth = Char.code s.[4] in
  let parent_fingerprint = String.sub s 5 4 and child_number = String.get_int32_be s 9 in
  if depth = 0 && (parent_fingerprint <> zero_fingerprint || child_number <> 0l)
  then Error `Invalid_format
  else Ok ({ key = String.sub s 45 33; chain_code = String.sub s 13 32;
             depth; parent_fingerprint; child_number }, String.get_int32_be s 0)
let path derive t indices =
  if List.length indices > 255 - t.depth then Error `Invalid_range
  else List.fold_left (fun acc i -> Result.bind acc (fun t -> derive t i)) (Ok t) indices
let child t key chain_code parent_fingerprint child_number =
  { key; chain_code; parent_fingerprint; child_number; depth = t.depth + 1 }

module Make (H : sig val hmac512 : key:string -> string -> string end) = struct
  module Public = struct
    type t = K.pub extended
    let fingerprint t = fingerprint_key t.key
    let derive t i =
      if hardened i then Error `Hardened_from_public
      else if t.depth = 255 then Error `Invalid_range else
      let h = H.hmac512 ~key:t.chain_code (K.pub_to_octets t.key ^ u32 i) in
      match K.pub_add_tweak t.key (String.sub h 0 32) with
      | Error _ -> Error `Invalid_range
      | Ok key -> Ok (child t key (String.sub h 32 32) (fingerprint t) i)
    let derive_path t indices = path derive t indices
    let to_octets ~version t = serialize ~version (K.pub_to_octets t.key) t
    let of_octets s = match parse s with
      | Error _ as e -> e
      | Ok (raw, version) ->
        if raw.key.[0] <> '\002' && raw.key.[0] <> '\003' then Error `Invalid_format
        else Result.map (fun key -> map_key key raw, version) (lift (K.pub_of_octets raw.key))
  end
  module Secret = struct
    type t = K.priv extended
    let master seed =
      if String.length seed < 16 || String.length seed > 64 then Error `Invalid_length
      else
        let h = H.hmac512 ~key:"Bitcoin seed" seed in
        Result.map (fun key -> { key; chain_code = String.sub h 32 32;
          depth = 0; parent_fingerprint = zero_fingerprint; child_number = 0l })
          (lift (K.priv_of_octets (String.sub h 0 32)))
    let public ?g t = map_key (K.pub_of_priv ?g t.key) t
    let fingerprint ?g t = Public.fingerprint (public ?g t)
    let derive ?g t i =
      if t.depth = 255 then Error `Invalid_range else
      let pub = K.pub_of_priv ?g t.key in
      let data = (if hardened i then "\000" ^ K.priv_to_octets t.key
                  else K.pub_to_octets pub) ^ u32 i in
      let h = H.hmac512 ~key:t.chain_code data in
      match K.priv_add_tweak t.key (String.sub h 0 32) with
      | Error _ -> Error `Invalid_range
      | Ok key -> Ok (child t key (String.sub h 32 32) (fingerprint_key pub) i)
    let derive_path ?g t indices = path (derive ?g) t indices
    let to_octets ~version t = serialize ~version ("\000" ^ K.priv_to_octets t.key) t
    let of_octets s = match parse s with
      | Error _ as e -> e
      | Ok (raw, version) ->
        if raw.key.[0] <> '\000' then Error `Invalid_format
        else Result.map (fun key -> map_key key raw, version)
          (lift (K.priv_of_octets (String.sub raw.key 1 32)))
  end
end
