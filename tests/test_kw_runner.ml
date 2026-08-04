open OUnit2

let suite =
  "Key wrap" >::: [ Test_kw.suite ]

let () = run_test_tt_main suite
