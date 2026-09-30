(* Z.t compatibility adapter; reductions/conversions are variable-time. *)
module Native = Mirage_crypto_poseidon
type field_element = Z.t
let p = Stark_curve.p
let to_native x =
  match Native.field_element_of_octets (Octets.to_be ~size:32 (Z.erem x p)) with
  | Ok x -> x | Error _ -> assert false
let of_native x = Octets.of_be (Native.field_element_to_octets x)
let hash_pair x y = of_native (Native.hash_pair (to_native x) (to_native y))
let hash_single x = of_native (Native.hash_single (to_native x))
let hash xs = of_native (Native.hash (List.map to_native xs))
