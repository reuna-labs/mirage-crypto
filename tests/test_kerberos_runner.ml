open OUnit2

let () = Mirage_crypto_rng_unix.use_default ()

let suite =
  "Kerberos" >::: [ Test_kerberos.suite ]

let () = run_test_tt_main suite
