(** Native PBKDF2-HMAC using the selected Crypton implementation and Digestif
    hash kernels. No RNG, Unix or arbitrary-precision arithmetic dependency.
    Password contents are processed by native constant-time hash operations;
    password/salt lengths, iterations and output length are public parameters.
    This is not a formal verification claim for the complete binding.

    [iterations] must be positive and at most 2^32-1 (also bounded by OCaml
    [max_int]). [length] is nonnegative and at most 2^32-64 and
    [Sys.max_string_length]. Invalid parameters raise [Invalid_argument].
    Zero length returns an empty string. Outputs are GC-managed; erasure of
    their copies is not guaranteed. Callers must bound attacker-chosen work. *)
val sha1 : password:string -> salt:string -> iterations:int -> length:int -> string
val sha256 : password:string -> salt:string -> iterations:int -> length:int -> string
val sha512 : password:string -> salt:string -> iterations:int -> length:int -> string
