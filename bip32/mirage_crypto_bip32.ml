include Bip32_core
include Make (struct
  let hmac512 ~key data = Digestif.SHA512.(to_raw_string (hmac_string ~key data))
end)
