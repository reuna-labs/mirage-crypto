external derive : int -> string -> string -> int -> int -> string = "mc_pbkdf2_derive"
let sha1 ~password ~salt ~iterations ~length = derive 0 password salt iterations length
let sha256 ~password ~salt ~iterations ~length = derive 1 password salt iterations length
let sha512 ~password ~salt ~iterations ~length = derive 2 password salt iterations length
