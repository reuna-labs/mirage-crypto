(** Official BLAKE3 C implementation, portable and single-threaded. Lengths
    are public; keyed state is wiped before returning from the C binding. *)

val digest : ?digest_size:int -> string -> string
(** Default output length 32; any positive byte length is accepted. *)

val keyed_digest : ?digest_size:int -> key:string -> string -> string
(** Key must be exactly 32 bytes. *)

val derive_key : ?digest_size:int -> context:string -> string -> string
(** Context is an arbitrary byte string, including embedded NUL bytes. *)
