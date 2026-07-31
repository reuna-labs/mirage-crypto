open OUnit2
open Test_common
open Mirage_crypto_blockchain

(* ===== Blake2b (RFC 7693 / official BLAKE2 test vectors, BLAKE2b-512) ===== *)

let blake2b_cases =
  [
    ( "",
      "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce"
    );
    ( "abc",
      "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923"
    );
  ]
  |> List.map (fun (msg, expected) ->
         test_case (fun _ -> assert_oct_equal (vx expected) (Blake2b.digest msg)))

(* ===== RIPEMD-160 (canonical test vectors) ===== *)

let ripemd160_cases =
  [
    ("", "9c1185a5c5e9fc54612808977ee8f548b2258d31");
    ("abc", "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc");
    ("message digest", "5d0689ef49d2fae572b881b123a85ffa21595f36");
  ]
  |> List.map (fun (msg, expected) ->
         test_case (fun _ -> assert_oct_equal (vx expected) (Ripemd160.digest msg)))

(* ===== Keccak-256 (official Ethereum-style Keccak256 vectors) ===== *)

let keccak256_cases =
  [
    ("", "c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470");
    ("abc", "4e03657aea45a94fc7d47ba826c8d667c0d1e6e33a64a036ec44f58fa12d6c45");
  ]
  |> List.map (fun (msg, expected) ->
         test_case (fun _ -> assert_oct_equal (vx expected) (Keccak256.digest msg)))

let keccak256_multiblock_case =
  (* 200-byte input (> 136-byte sponge rate), exercises the multi-block
     absorb path. *)
  test_case (fun _ ->
      let msg = String.init 200 (fun i -> Char.chr i) in
      assert_oct_equal
        (vx "bfb0aa97863e797943cf7c33bb7e880bb4543f3d2703c0923c6901c2af57b890")
        (Keccak256.digest msg))

(* ===== BLAKE3 (subset of the official test_vectors.json) =====

   Input for length [n] is the repeating byte pattern [0, 1, .., 250, 0, 1,
   ..], per the official test vector generator. Each expected value is the
   first 32 bytes of the (longer) extended output. *)

let blake3_input n = String.init n (fun i -> Char.chr (i mod 251))

let blake3_key = "whats the Elvish word for friend"
let blake3_context = "BLAKE3 2019-12-27 16:29:52 test vectors context"

let blake3_vectors =
  [
    (0, "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262", "92b2b75604ed3c761f9d6f62392c8a9227ad0ea3f09573e783f1498a4ed60d26", "2cc39783c223154fea8dfb7c1b1660f2ac2dcbd1c1de8277b0b0dd39b7e50d7d");
    (1, "2d3adedff11b61f14c886e35afa036736dcd87a74d27b5c1510225d0f592e213", "6d7878dfff2f485635d39013278ae14f1454b8c0a3a2d34bc1ab38228a80c95b", "b3e2e340a117a499c6cf2398a19ee0d29cca2bb7404c73063382693bf66cb06c");
    (63, "e9bc37a594daad83be9470df7f7b3798297c3d834ce80ba85d6e207627b7db7b", "bb1eb5d4afa793c1ebdd9fb08def6c36d10096986ae0cfe148cd101170ce37ae", "b6451e30b953c206e34644c6803724e9d2725e0893039cfc49584f991f451af3");
    (64, "4eed7141ea4a5cd4b788606bd23f46e212af9cacebacdc7d1f4c6dc7f2511b98", "ba8ced36f327700d213f120b1a207a3b8c04330528586f414d09f2f7d9ccb7e6", "a5c4a7053fa86b64746d4bb688d06ad1f02a18fce9afd3e818fefaa7126bf73e");
    (65, "de1e5fa0be70df6d2be8fffd0e99ceaa8eb6e8c93a63f2d8d1c30ecb6b263dee", "c0a4edefa2d2accb9277c371ac12fcdbb52988a86edc54f0716e1591b4326e72", "51fd05c3c1cfbc8ed67d139ad76f5cf8236cd2acd26627a30c104dfd9d3ff8a8");
    (1023, "10108970eeda3eb932baac1428c7a2163b0e924c9a9e25b35bba72b28f70bd11", "c951ecdf03288d0fcc96ee3413563d8a6d3589547f2c2fb36d9786470f1b9d6e", "74a16c1c3d44368a86e1ca6df64be6a2f64cce8f09220787450722d85725dea5");
    (1024, "42214739f095a406f3fc83deb889744ac00df831c10daa55189b5d121c855af7", "75c46f6f3d9eb4f55ecaaee480db732e6c2105546f1e675003687c31719c7ba4", "7356cd7720d5b66b6d0697eb3177d9f8d73a4a5c5e968896eb6a689684302706");
    (1025, "d00278ae47eb27b34faecf67b4fe263f82d5412916c1ffd97c8cb7fb814b8444", "357dc55de0c7e382c900fd6e320acc04146be01db6a8ce7210b7189bd664ea69", "effaa245f065fbf82ac186839a249707c3bddf6d3fdda22d1b95a3c970379bcb");
    (2048, "e776b6028c7cd22a4d0ba182a8bf62205d2ef576467e838ed6f2529b85fba24a", "879cf1fa2ea0e79126cb1063617a05b6ad9d0b696d0d757cf053439f60a99dd1", "7b2945cb4fef70885cc5d78a87bf6f6207dd901ff239201351ffac04e1088a23");
  ]

let blake3_hash_cases =
  blake3_vectors
  |> List.map (fun (len, hash, _, _) ->
         test_case (fun _ -> assert_oct_equal (vx hash) (Blake3.digest (blake3_input len))))

let blake3_keyed_cases =
  blake3_vectors
  |> List.map (fun (len, _, keyed, _) ->
         test_case (fun _ ->
             assert_oct_equal (vx keyed)
               (Blake3.keyed_digest ~key:blake3_key (blake3_input len))))

let blake3_derive_key_cases =
  blake3_vectors
  |> List.map (fun (len, _, _, derived) ->
         test_case (fun _ ->
             assert_oct_equal (vx derived)
               (Blake3.derive_key ~context:blake3_context (blake3_input len))))

(* ===== SHA-256 helpers (Hashes) ===== *)
let hashes_cases =
  [
    test_case (fun _ ->
        (* FIPS 180-4 SHA-256("abc"). *)
        assert_oct_equal ~msg:"sha256(abc)"
          (vx "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
          (Hashes.sha256 "abc");
        (* sha256d("abc") = sha256(sha256("abc")). *)
        assert_oct_equal ~msg:"sha256d(abc)"
          (vx "4f8b42c22dd3729b519ba6f68d2da7cc5b2d606d05daed5ad5128cc03e6c6358")
          (Hashes.sha256d "abc");
        assert_oct_equal ~msg:"sha256d = sha256 . sha256"
          (Hashes.sha256 (Hashes.sha256 "abc"))
          (Hashes.sha256d "abc"));
    test_case (fun _ ->
        (* The hoisted tagged_hash must agree with Bip340's (delegated). *)
        assert_oct_equal ~msg:"tagged_hash agrees with Bip340"
          (Bip340.tagged_hash ~tag:"BIP0340/challenge" "hello")
          (Hashes.tagged_hash ~tag:"BIP0340/challenge" "hello"));
  ]

(* ===== secp256k1 =====

   The ECDSA vector below was generated independently via Python's
   `cryptography` library (deterministic_signing=True, i.e. RFC 6979) for
   private key 0x3d and digest SHA256("test message"), then cross-checked
   for the low-S normalization our implementation applies. *)

let secp256k1_generator_on_curve_case =
  test_case (fun _ ->
      assert_bool "generator round-trips through octet encoding"
        (match Secp256k1.point_of_octets (Secp256k1.point_to_octets Secp256k1.g) with
        | Ok p ->
          Z.equal p.Secp256k1.x Secp256k1.g.Secp256k1.x
          && Z.equal p.Secp256k1.y Secp256k1.g.Secp256k1.y
        | Error _ -> false))

let secp256k1_ecdsa_case =
  test_case (fun _ ->
      let priv_hex = "000000000000000000000000000000000000000000000000000000000000003d" in
      let pub_x = "754e3239f325570cdbbf4a87deee8a66b7f2b33479d468fbc1a50743bf56cc18" in
      let pub_y = "0673fb86e5bda30fb3cd0ed304ea49a023ee33d0197a695d0c5d98093c536683" in
      let digest = "3f0a377ba0a4a460ecb616f6507ce0d8cfa3e704025d4fda3ed0c5ca05468728" in
      let expected_r = "6a28203a57228a722098002e1a985a0ce14bca5c3fc6927498ce8c21295fa793" in
      let expected_low_s = "48183aa25f71af4262c5d151095bc032a25e7842f76852c18247841e7e05c6be" in
      let key =
        match Secp256k1.scalar_of_octets (vx priv_hex) with
        | Ok k -> k
        | Error _ -> assert_failure "bad private key"
      in
      let pub =
        match Secp256k1.point_of_octets (vx ("04" ^ pub_x ^ pub_y)) with
        | Ok p -> p
        | Error _ -> assert_failure "bad public key"
      in
      let derived_pub = Secp256k1.pub_of_priv key in
      assert_bool "pub_of_priv matches"
        (Z.equal derived_pub.Secp256k1.x pub.Secp256k1.x
        && Z.equal derived_pub.Secp256k1.y pub.Secp256k1.y);
      let signature = Secp256k1.sign ~key (vx digest) in
      assert_oct_equal ~msg:"compact signature (r || low-s)"
        (vx (expected_r ^ expected_low_s))
        (Secp256k1.signature_to_octets signature);
      assert_bool "verify accepts own signature" (Secp256k1.verify ~key:pub signature (vx digest));
      assert_bool "verify rejects tampered digest"
        (not (Secp256k1.verify ~key:pub signature (vx ("00" ^ String.sub digest 2 62)))))

(* Public-key recovery: the fixed vector is go-ethereum's canonical
   ecrecover test (crypto/signature_test.go: testmsg/testsig/testpubkey),
   with the trailing recovery byte 0x01 as [recid]. *)
let secp256k1_recover_case =
  test_case (fun _ ->
      let msg = "ce0677bb30baa8cf067c88db9811f4333d131bf8bcf12fe7065d211dce971008" in
      let r = "90f27b8b488db00b00606796d2987f6a5f59ae62ea05effe84fef5b8b0e54998" in
      let s = "4a691139ad57a3f0b906637673aa2f63d1f55cb1a69199d4009eea23ceaddc93" in
      let expected_pub =
        "04e32df42865e97135acfb65f3bae71bdc86f4d49150ad6a440b6f158781098"
        ^ "80a0a2b2667f7e725ceea70c673093bf67663e0312623c8e091b13cf2c0f11ef652"
      in
      let sg =
        match Secp256k1.signature_of_octets (vx (r ^ s)) with
        | Ok x -> x
        | Error _ -> assert_failure "bad signature"
      in
      (match Secp256k1.recover ~msg:(vx msg) sg ~recid:1 with
      | Ok pub ->
        assert_oct_equal ~msg:"recovered pubkey (go-ethereum vector)"
          (vx expected_pub)
          (Secp256k1.point_to_octets ~compress:false pub)
      | Error _ -> assert_failure "recover failed on known vector");
      assert_bool "wrong recid does not recover the same key"
        (match Secp256k1.recover ~msg:(vx msg) sg ~recid:0 with
        | Ok pub ->
          not (String.equal (vx expected_pub)
                 (Secp256k1.point_to_octets ~compress:false pub))
        | Error _ -> true);
      (* sign_recoverable -> recover round-trip, key 0x3d. *)
      let key =
        match Secp256k1.scalar_of_octets
                (vx "000000000000000000000000000000000000000000000000000000000000003d")
        with
        | Ok k -> k
        | Error _ -> assert_failure "bad private key"
      in
      let digest = vx "3f0a377ba0a4a460ecb616f6507ce0d8cfa3e704025d4fda3ed0c5ca05468728" in
      let sg2, recid = Secp256k1.sign_recoverable ~key digest in
      let pub = Secp256k1.pub_of_priv key in
      (match Secp256k1.recover ~msg:digest sg2 ~recid with
      | Ok rpub ->
        assert_bool "round-trip recovers the signer"
          (Z.equal rpub.Secp256k1.x pub.Secp256k1.x
          && Z.equal rpub.Secp256k1.y pub.Secp256k1.y)
      | Error _ -> assert_failure "round-trip recover failed");
      assert_oct_equal ~msg:"recoverable signature matches deterministic sign"
        (Secp256k1.signature_to_octets (Secp256k1.sign ~key digest))
        (Secp256k1.signature_to_octets sg2);
      assert_bool "recid out of range rejected"
        (match Secp256k1.recover ~msg:digest sg2 ~recid:4 with
        | Error `Invalid_format -> true
        | _ -> false))

(* ===== BIP340 (official test vectors from
   https://github.com/bitcoin/bips/blob/master/bip-0340/test-vectors.csv) ===== *)

let bip340_full_cases =
  let row ~sk ~pk ~aux ~msg ~sig_ ~comment:_ =
    test_case (fun _ ->
        let key =
          match Secp256k1.scalar_of_octets (vx sk) with
          | Ok k -> k
          | Error _ -> assert_failure "bad secret key"
        in
        let signature = Bip340.sign ~aux_rand:(vx aux) ~key (vx msg) in
        assert_oct_equal ~msg:"signature bytes" (vx sig_) (Bip340.signature_to_octets signature);
        match Bip340.xonly_pub_of_octets (vx pk) with
        | Error _ -> assert_failure "bad public key"
        | Ok pubkey -> assert_bool "verify" (Bip340.verify ~key:pubkey signature (vx msg)))
  in
  [
    row ~sk:"0000000000000000000000000000000000000000000000000000000000000003" ~pk:"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" ~aux:"0000000000000000000000000000000000000000000000000000000000000000" ~msg:"0000000000000000000000000000000000000000000000000000000000000000" ~sig_:"e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0" ~comment:"";
    row ~sk:"b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef" ~pk:"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659" ~aux:"0000000000000000000000000000000000000000000000000000000000000001" ~msg:"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89" ~sig_:"6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a" ~comment:"";
    row ~sk:"c90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b14e5c9" ~pk:"dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8" ~aux:"c87aa53824b4d7ae2eb035a2b5bbbccc080e76cdc6d1692c4b0b62d798e6d906" ~msg:"7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c" ~sig_:"5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7" ~comment:"";
    row ~sk:"0b432b2677937381aef05bb02a66ecd012773062cf3fa2549e44f58ed2401710" ~pk:"25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517" ~aux:"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" ~msg:"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" ~sig_:"7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3" ~comment:"test fails if msg is reduced modulo p or n";
    row ~sk:"0340034003400340034003400340034003400340034003400340034003400340" ~pk:"778caa53b4393ac467774d09497a87224bf9fab6f6e68b23086497324d6fd117" ~aux:"0000000000000000000000000000000000000000000000000000000000000000" ~msg:"" ~sig_:"71535db165ecd9fbbc046e5ffaea61186bb6ad436732fccc25291a55895464cf6069ce26bf03466228f19a3a62db8a649f2d560fac652827d1af0574e427ab63" ~comment:"message of size 0 (added 2022-12)";
    row ~sk:"0340034003400340034003400340034003400340034003400340034003400340" ~pk:"778caa53b4393ac467774d09497a87224bf9fab6f6e68b23086497324d6fd117" ~aux:"0000000000000000000000000000000000000000000000000000000000000000" ~msg:"11" ~sig_:"08a20a0afef64124649232e0693c583ab1b9934ae63b4c3511f3ae1134c6a303ea3173bfea6683bd101fa5aa5dbc1996fe7cacfc5a577d33ec14564cec2bacbf" ~comment:"message of size 1 (added 2022-12)";
    row ~sk:"0340034003400340034003400340034003400340034003400340034003400340" ~pk:"778caa53b4393ac467774d09497a87224bf9fab6f6e68b23086497324d6fd117" ~aux:"0000000000000000000000000000000000000000000000000000000000000000" ~msg:"0102030405060708090a0b0c0d0e0f1011" ~sig_:"5130f39a4059b43bc7cac09a19ece52b5d8699d1a71e3c52da9afdb6b50ac370c4a482b77bf960f8681540e25b6771ece1e5a37fd80e5a51897c5566a97ea5a5" ~comment:"message of size 17 (added 2022-12)";
    row ~sk:"0340034003400340034003400340034003400340034003400340034003400340" ~pk:"778caa53b4393ac467774d09497a87224bf9fab6f6e68b23086497324d6fd117" ~aux:"0000000000000000000000000000000000000000000000000000000000000000" ~msg:"99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999" ~sig_:"403b12b0d8555a344175ea7ec746566303321e5dbfa8be6f091635163eca79a8585ed3e3170807e7c03b720fc54c7b23897fcba0e9d0b4a06894cfd249f22367" ~comment:"message of size 100 (added 2022-12)";
  ]

let bip340_verify_cases =
  let vrow ~pk ~msg ~sig_ ~expected ~comment:_ =
    test_case (fun _ ->
        let result =
          match Bip340.xonly_pub_of_octets (vx pk) with
          | Error _ -> false
          | Ok pubkey -> (
            match Bip340.signature_of_octets (vx sig_) with
            | Error _ -> false
            | Ok signature -> Bip340.verify ~key:pubkey signature (vx msg))
        in
        assert_equal ~printer:string_of_bool expected result)
  in
  [
    vrow ~pk:"f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9" ~msg:"0000000000000000000000000000000000000000000000000000000000000000" ~sig_:"e907831f80848d1069a5371b402410364bdf1c5f8307b0084c55f1ce2dca821525f66a4a85ea8b71e482a74f382d2ce5ebeee8fdb2172f477df4900d310536c0" ~expected:true ~comment:"";
    vrow ~pk:"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659" ~msg:"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89" ~sig_:"6896bd60eeae296db48a229ff71dfe071bde413e6d43f917dc8dcf8c78de33418906d11ac976abccb20b091292bff4ea897efcb639ea871cfa95f6de339e4b0a" ~expected:true ~comment:"";
    vrow ~pk:"dd308afec5777e13121fa72b9cc1b7cc0139715309b086c960e18fd969774eb8" ~msg:"7e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c" ~sig_:"5831aaeed7b44bb74e5eab94ba9d4294c49bcf2a60728d8b4c200f50dd313c1bab745879a5ad954a72c45a91c3a51d3c7adea98d82f8481e0e1e03674a6f3fb7" ~expected:true ~comment:"";
    vrow ~pk:"25d1dff95105f5253c4022f628a996ad3a0d95fbf21d468a1b33f8c160d8f517" ~msg:"ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" ~sig_:"7eb0509757e246f19449885651611cb965ecc1a187dd51b64fda1edc9637d5ec97582b9cb13db3933705b32ba982af5af25fd78881ebb32771fc5922efc66ea3" ~expected:true ~comment:"test fails if msg is reduced modulo p or n";
    vrow ~pk:"d69c3509bb99e412e68b0fe8544e72837dfa30746d8be2aa65975f29d22dc7b9" ~msg:"4df3c3f68fcc83b27e9d42c90431a72499f17875c81a599b566c9889b9696703" ~sig_:"00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c6376afb1548af603b3eb45c9f8207dee1060cb71c04e80f593060b07d28308d7f4" ~expected:true ~comment:"";
    vrow ~pk:"eefdea4cdb677750a420fee807eacf21eb9898ae79b9768766e4faa04a2d4a34" ~msg:"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89" ~sig_:"6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b" ~expected:false ~comment:"public key not on the curve";
    vrow ~pk:"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659" ~msg:"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89" ~sig_:"fff97bd5755eeea420453a14355235d382f6472f8568a18b2f057a14602975563cc27944640ac607cd107ae10923d9ef7a73c643e166be5ebeafa34b1ac553e2" ~expected:false ~comment:"has_even_y(R) is false";
    vrow ~pk:"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659" ~msg:"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89" ~sig_:"1fa62e331edbc21c394792d2ab1100a7b432b013df3f6ff4f99fcb33e0e1515f28890b3edb6e7189b630448b515ce4f8622a954cfe545735aaea5134fccdb2bd" ~expected:false ~comment:"negated message";
    vrow ~pk:"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659" ~msg:"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89" ~sig_:"6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769961764b3aa9b2ffcb6ef947b6887a226e8d7c93e00c5ed0c1834ff0d0c2e6da6" ~expected:false ~comment:"negated s value";
    vrow ~pk:"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659" ~msg:"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89" ~sig_:"0000000000000000000000000000000000000000000000000000000000000000123dda8328af9c23a94c1feecfd123ba4fb73476f0d594dcb65c6425bd186051" ~expected:false ~comment:"sG - eP is infinite";
    vrow ~pk:"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659" ~msg:"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89" ~sig_:"00000000000000000000000000000000000000000000000000000000000000017615fbaf5ae28864013c099742deadb4dba87f11ac6754f93780d5a1837cf197" ~expected:false ~comment:"sG - eP is infinite (x = 1)";
    vrow ~pk:"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659" ~msg:"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89" ~sig_:"4a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b" ~expected:false ~comment:"sig[0:32] is not an X coordinate on the curve";
    vrow ~pk:"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659" ~msg:"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89" ~sig_:"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f69e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b" ~expected:false ~comment:"sig[0:32] is equal to field size";
    vrow ~pk:"dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659" ~msg:"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89" ~sig_:"6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e177769fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141" ~expected:false ~comment:"sig[32:64] is equal to curve order";
    vrow ~pk:"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc30" ~msg:"243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89" ~sig_:"6cff5c3ba86c69ea4b7376f31a9bcb4f74c1976089b2d9963da2e5543e17776969e89b4c5564d00349106b8497785dd7d1d713a8ae82b32fa79d5f7fc407d39b" ~expected:false ~comment:"public key exceeds the field size";
    vrow ~pk:"778caa53b4393ac467774d09497a87224bf9fab6f6e68b23086497324d6fd117" ~msg:"" ~sig_:"71535db165ecd9fbbc046e5ffaea61186bb6ad436732fccc25291a55895464cf6069ce26bf03466228f19a3a62db8a649f2d560fac652827d1af0574e427ab63" ~expected:true ~comment:"message of size 0";
    vrow ~pk:"778caa53b4393ac467774d09497a87224bf9fab6f6e68b23086497324d6fd117" ~msg:"11" ~sig_:"08a20a0afef64124649232e0693c583ab1b9934ae63b4c3511f3ae1134c6a303ea3173bfea6683bd101fa5aa5dbc1996fe7cacfc5a577d33ec14564cec2bacbf" ~expected:true ~comment:"message of size 1";
    vrow ~pk:"778caa53b4393ac467774d09497a87224bf9fab6f6e68b23086497324d6fd117" ~msg:"0102030405060708090a0b0c0d0e0f1011" ~sig_:"5130f39a4059b43bc7cac09a19ece52b5d8699d1a71e3c52da9afdb6b50ac370c4a482b77bf960f8681540e25b6771ece1e5a37fd80e5a51897c5566a97ea5a5" ~expected:true ~comment:"message of size 17";
    vrow ~pk:"778caa53b4393ac467774d09497a87224bf9fab6f6e68b23086497324d6fd117" ~msg:"99999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999999" ~sig_:"403b12b0d8555a344175ea7ec746566303321e5dbfa8be6f091635163eca79a8585ed3e3170807e7c03b720fc54c7b23897fcba0e9d0b4a06894cfd249f22367" ~expected:true ~comment:"message of size 100";
  ]

(* ===== Stark Curve =====

   Parameters and the vector below come from running StarkWare's own
   reference implementation locally (signature.py from
   https://github.com/starkware-libs/cairo-lang), not from memory:
     priv_key = 12345678, msg_hash = 1234567891011121314151617, seed = 1
   gives pub_key_x, r, s below, with verify() = True. *)

let stark_be32 z =
  let buf = Bytes.make 32 '\000' in
  let z = ref z in
  for i = 31 downto 0 do
    Bytes.set buf i (Char.chr (Z.to_int (Z.logand !z (Z.of_int 0xff))));
    z := Z.shift_right !z 8
  done;
  Bytes.unsafe_to_string buf

let stark_priv_of_int n =
  match Stark_curve.scalar_of_octets (stark_be32 (Z.of_int n)) with
  | Ok s -> s
  | Error _ -> assert_failure "bad test private key"

let stark_curve_pub_of_priv_case =
  test_case (fun _ ->
      let priv = stark_priv_of_int 12345678 in
      let pub = Stark_curve.pub_of_priv priv in
      let expected_x =
        Z.of_string
          "700486945785093896215451679915330918764422796552594089817843617223540797798"
      in
      assert_bool "pub_of_priv.x matches StarkWare reference"
        (Z.equal pub.Stark_curve.x expected_x))

let stark_curve_verify_reference_case =
  test_case (fun _ ->
      let priv = stark_priv_of_int 12345678 in
      let pub = Stark_curve.pub_of_priv priv in
      let msg_hash = Z.of_string "1234567891011121314151617" in
      let r =
        Z.of_string
          "2218720482695932882837546683089453741197218609621547502105997284477070725371"
      in
      let s =
        Z.of_string
          "886701380936891062501223511822044863540924656280432297169757336672715510517"
      in
      match Stark_curve.signature_of_octets (stark_be32 r ^ stark_be32 s) with
      | Error _ -> assert_failure "failed to parse reference signature"
      | Ok signature ->
        assert_bool "verify accepts StarkWare-reference signature"
          (Stark_curve.verify ~key:pub signature msg_hash))

let stark_curve_sign_verify_roundtrip_case =
  test_case (fun _ ->
      let priv = stark_priv_of_int 12345678 in
      let pub = Stark_curve.pub_of_priv priv in
      let msg_hash = Z.of_string "1234567891011121314151617" in
      let signature = Stark_curve.sign ~key:priv msg_hash in
      assert_bool "self-signed signature verifies"
        (Stark_curve.verify ~key:pub signature msg_hash))

let stark_curve_tamper_case =
  test_case (fun _ ->
      let priv = stark_priv_of_int 12345678 in
      let pub = Stark_curve.pub_of_priv priv in
      let msg_hash = Z.of_string "1234567891011121314151617" in
      let signature = Stark_curve.sign ~key:priv msg_hash in
      let other_msg_hash = Z.of_string "1234567891011121314151618" in
      assert_bool "verify rejects a different message"
        (not (Stark_curve.verify ~key:pub signature other_msg_hash)))

(* ===== Poseidon =====

   Vectors below come from running StarkWare's own reference
   implementation locally (poseidon_hash.py from
   https://github.com/starkware-libs/cairo-lang), not from memory. *)

let poseidon_cases =
  [
    test_case (fun _ ->
        assert_equal ~cmp:Z.equal ~printer:Z.to_string
          (Z.of_string
             "2636648219362971850283425434366427370362725365790740855428580782178634926362")
          (Poseidon.hash_pair Z.one (Z.of_int 2)));
    test_case (fun _ ->
        assert_equal ~cmp:Z.equal ~printer:Z.to_string
          (Z.of_string
             "1165814756574493433332935684348403390128033890862827107228326727661107483845")
          (Poseidon.hash_pair Z.zero Z.zero));
    test_case (fun _ ->
        assert_equal ~cmp:Z.equal ~printer:Z.to_string
          (Z.of_string
             "3085182978037364507644541379307921604860861694664657935759708330416374536741")
          (Poseidon.hash_single Z.one));
    test_case (fun _ ->
        assert_equal ~cmp:Z.equal ~printer:Z.to_string
          (Z.of_string
             "1330163329880897963929329415144033128916878238201091319571200413658610585730")
          (Poseidon.hash [ Z.one; Z.of_int 2; Z.of_int 3 ]));
    test_case (fun _ ->
        assert_equal ~cmp:Z.equal ~printer:Z.to_string
          (Z.of_string
             "973835572668429495915136902981656666590582180872133591629269551720657739196")
          (Poseidon.hash []));
    test_case (fun _ ->
        assert_equal ~cmp:Z.equal ~printer:Z.to_string
          (Z.of_string
             "1557996165160500454210437319447297236715335099509187222888255133199463084263")
          (Poseidon.hash [ Z.one; Z.of_int 2 ]));
  ]

(* ===== BLS12-381 =====

   Curve/generator parameters cross-checked against
   draft-irtf-cfrg-pairing-friendly-curves Section 4.2.1. The
   hash-to-curve vectors below are RFC 9380's own official
   BLS12381G2_XMD:SHA-256_SSWU_RO_ test vectors (Appendix J.10.1),
   extracted programmatically from the RFC text rather than
   hand-transcribed. *)

let bls_be48 hex =
  let z = Z.of_string ("0x" ^ hex) in
  let buf = Bytes.make 48 '\000' in
  let z = ref z in
  for i = 47 downto 0 do
    Bytes.set buf i (Char.chr (Z.to_int (Z.logand !z (Z.of_int 0xff))));
    z := Z.shift_right !z 8
  done;
  Bytes.unsafe_to_string buf

let bls_g1_generator_on_curve_case =
  test_case (fun _ ->
      assert_bool "g1_generator is on curve" (Bls12_381.g1_on_curve Bls12_381.g1_generator);
      assert_bool "g1_generator is in subgroup" (Bls12_381.g1_in_subgroup Bls12_381.g1_generator))

let bls_g2_generator_on_curve_case =
  test_case (fun _ ->
      assert_bool "g2_generator is on curve" (Bls12_381.g2_on_curve Bls12_381.g2_generator);
      assert_bool "g2_generator is in subgroup" (Bls12_381.g2_in_subgroup Bls12_381.g2_generator))

let bls_be32 z =
  let buf = Bytes.make 32 '\000' in
  let z = ref z in
  for i = 31 downto 0 do
    Bytes.set buf i (Char.chr (Z.to_int (Z.logand !z (Z.of_int 0xff))));
    z := Z.shift_right !z 8
  done;
  Bytes.unsafe_to_string buf

let bls_scalar_of_int n =
  match Bls12_381.scalar_of_octets (bls_be32 (Z.of_int n)) with
  | Ok s -> s
  | Error _ -> assert_failure "bad test scalar"

(* r is out of scalar's valid range [0, r) by definition, so the order
   is instead checked as (r - 1) * G1 + G1 = infinity. *)
let bls_g1_order_case =
  test_case (fun _ ->
      let r_minus_1 =
        match Bls12_381.scalar_of_octets (bls_be32 (Z.sub Bls12_381.r Z.one)) with
        | Ok s -> s
        | Error _ -> assert_failure "bad test scalar"
      in
      let pt = Bls12_381.g1_add (Bls12_381.g1_scalar_mult r_minus_1 Bls12_381.g1_generator) Bls12_381.g1_generator in
      assert_bool "(r-1) * g1_generator + g1_generator = infinity" (Bls12_381.g1_is_infinity pt))

let bls_g1_octets_roundtrip_case =
  test_case (fun _ ->
      let pt = Bls12_381.g1_scalar_mult (bls_scalar_of_int 12345) Bls12_381.g1_generator in
      List.iter
        (fun compress ->
          match Bls12_381.g1_of_octets (Bls12_381.g1_to_octets ~compress pt) with
          | Error _ -> assert_failure "g1 octets roundtrip failed to parse"
          | Ok pt' -> assert_bool "g1 octets roundtrip" (Bls12_381.g1_equal pt pt'))
        [ true; false ])

let bls_g2_octets_roundtrip_case =
  test_case (fun _ ->
      let pt = Bls12_381.g2_scalar_mult (bls_scalar_of_int 12345) Bls12_381.g2_generator in
      List.iter
        (fun compress ->
          match Bls12_381.g2_of_octets (Bls12_381.g2_to_octets ~compress pt) with
          | Error _ -> assert_failure "g2 octets roundtrip failed to parse"
          | Ok pt' -> assert_bool "g2 octets roundtrip" (Bls12_381.g2_equal pt pt'))
        [ true; false ])

(* e(a*G1, b*G2) = e(G1, G2)^(a*b): checked via e(2G1,3G2) = e(3G1,2G2). *)
let bls_pairing_bilinearity_case =
  test_case (fun _ ->
      let g1_2 = Bls12_381.g1_scalar_mult (bls_scalar_of_int 2) Bls12_381.g1_generator in
      let g1_3 = Bls12_381.g1_scalar_mult (bls_scalar_of_int 3) Bls12_381.g1_generator in
      let g2_2 = Bls12_381.g2_scalar_mult (bls_scalar_of_int 2) Bls12_381.g2_generator in
      let g2_3 = Bls12_381.g2_scalar_mult (bls_scalar_of_int 3) Bls12_381.g2_generator in
      let lhs = Bls12_381.pairing g2_3 g1_2 in
      let rhs = Bls12_381.pairing g2_2 g1_3 in
      assert_bool "e(2G1,3G2) = e(3G1,2G2)" (Bls12_381.gt_equal lhs rhs))

let bls_hash_to_curve_g2_case ~msg ~x0 ~x1 ~y0 ~y1 =
  test_case (fun _ ->
      let expected_octets = bls_be48 x1 ^ bls_be48 x0 ^ bls_be48 y1 ^ bls_be48 y0 in
      match Bls12_381.g2_of_octets expected_octets with
      | Error _ -> assert_failure "failed to parse expected G2 point"
      | Ok expected ->
        let got =
          Bls12_381.hash_to_curve_g2
            ~dst:"QUUX-V01-CS02-with-BLS12381G2_XMD:SHA-256_SSWU_RO_" msg
        in
        assert_bool "hash_to_curve_g2 matches RFC 9380 test vector"
          (Bls12_381.g2_equal expected got))

let bls_hash_to_curve_g2_cases =
  [
    bls_hash_to_curve_g2_case ~msg:""
      ~x0:"0141ebfbdca40eb85b87142e130ab689c673cf60f1a3e98d69335266f30d9b8d4ac44c1038e9dcdd5393faf5c41fb78a"
      ~x1:"05cb8437535e20ecffaef7752baddf98034139c38452458baeefab379ba13dff5bf5dd71b72418717047f5b0f37da03d"
      ~y0:"0503921d7f6a12805e72940b963c0cf3471c7b2a524950ca195d11062ee75ec076daf2d4bc358c4b190c0c98064fdd92"
      ~y1:"12424ac32561493f3fe3c260708a12b7c620e7be00099a974e259ddc7d1f6395c3c811cdd19f1e8dbf3e9ecfdcbab8d6";
    bls_hash_to_curve_g2_case ~msg:"abc"
      ~x0:"02c2d18e033b960562aae3cab37a27ce00d80ccd5ba4b7fe0e7a210245129dbec7780ccc7954725f4168aff2787776e6"
      ~x1:"139cddbccdc5e91b9623efd38c49f81a6f83f175e80b06fc374de9eb4b41dfe4ca3a230ed250fbe3a2acf73a41177fd8"
      ~y0:"1787327b68159716a37440985269cf584bcb1e621d3a7202be6ea05c4cfe244aeb197642555a0645fb87bf7466b2ba48"
      ~y1:"00aa65dae3c8d732d10ecd2c50f8a1baf3001578f71c694e03866e9f3d49ac1e1ce70dd94a733534f106d4cec0eddd16";
  ]

let bls_sign_verify_roundtrip_case =
  test_case (fun _ ->
      let priv = Bls12_381.generate () in
      let pub = Bls12_381.pub_of_priv priv in
      let msg = "mirage-crypto-blockchain BLS12-381 test" in
      let signature = Bls12_381.sign ~key:priv msg in
      assert_bool "self-signed signature verifies" (Bls12_381.verify ~key:pub signature msg))

let bls_tamper_case =
  test_case (fun _ ->
      let priv = Bls12_381.generate () in
      let pub = Bls12_381.pub_of_priv priv in
      let signature = Bls12_381.sign ~key:priv "message one" in
      assert_bool "verify rejects a different message"
        (not (Bls12_381.verify ~key:pub signature "message two")))

let bls_aggregate_verify_case =
  test_case (fun _ ->
      let priv1 = Bls12_381.generate () and priv2 = Bls12_381.generate () in
      let pub1 = Bls12_381.pub_of_priv priv1 and pub2 = Bls12_381.pub_of_priv priv2 in
      let sig1 = Bls12_381.sign ~key:priv1 "message one" in
      let sig2 = Bls12_381.sign ~key:priv2 "message two" in
      let agg = Bls12_381.aggregate [ sig1; sig2 ] in
      assert_bool "aggregate_verify accepts a valid aggregate"
        (Bls12_381.aggregate_verify [ (pub1, "message one"); (pub2, "message two") ] agg);
      assert_bool "aggregate_verify rejects duplicate messages (rogue-key defense)"
        (not (Bls12_381.aggregate_verify [ (pub1, "message one"); (pub2, "message one") ] agg)))

let bls12_381_cases =
  [
    bls_g1_generator_on_curve_case;
    bls_g2_generator_on_curve_case;
    bls_g1_order_case;
    bls_g1_octets_roundtrip_case;
    bls_g2_octets_roundtrip_case;
    bls_pairing_bilinearity_case;
  ]
  @ bls_hash_to_curve_g2_cases
  @ [ bls_sign_verify_roundtrip_case; bls_tamper_case; bls_aggregate_verify_case ]

(* ===== sr25519 =====

   The ristretto255 vectors below are RFC 9496's own official test
   vectors (Appendix A.1/A.2), extracted programmatically from the RFC
   text. The seed -> public-key vectors and the legacy-signature vector
   are taken verbatim from polkadot-sdk's own sr25519 test suite
   (substrate/primitives/core/src/sr25519.rs: sr_test_vector_should_work,
   seeded_pair_should_work, verify_from_old_wasm_works). Ordinary
   sign/verify is exercised only via roundtrip and tamper checks,
   because Schnorrkel signing is intentionally randomized -- see
   sr25519.ml's module-level comment. *)

let ristretto_valid_encodings =
  [| "0000000000000000000000000000000000000000000000000000000000000000"
   ; "e2f2ae0a6abc4e71a884a961c500515f58e30b6aa582dd8db6a65945e08d2d76"
   ; "6a493210f7499cd17fecb510ae0cea23a110e8d5b901f8acadd3095c73a3b919"
   ; "94741f5d5d52755ece4f23f044ee27d5d1ea1e2bd196b462166b16152a9d0259"
   ; "da80862773358b466ffadfe0b3293ab3d9fd53c5ea6c955358f568322daf6a57"
   ; "e882b131016b52c1d3337080187cf768423efccbb517bb495ab812c4160ff44e"
   ; "f64746d3c92b13050ed8d80236a7f0007c3b3f962f5ba793d19a601ebb1df403"
   ; "44f53520926ec81fbd5a387845beb7df85a96a24ece18738bdcfa6a7822a176d"
   ; "903293d8f2287ebe10e2374dc1a53e0bc887e592699f02d077d5263cdd55601c"
   ; "02622ace8f7303a31cafc63f8fc48fdc16e1c8c8d234b2f0d6685282a9076031"
   ; "20706fd788b2720a1ed2a5dad4952b01f413bcf0e7564de8cdc816689e2db95f"
   ; "bce83f8ba5dd2fa572864c24ba1810f9522bc6004afe95877ac73241cafdab42"
   ; "e4549ee16b9aa03099ca208c67adafcafa4c3f3e4e5303de6026e3ca8ff84460"
   ; "aa52e000df2e16f55fb1032fc33bc42742dad6bd5a8fc0be0167436c5948501f"
   ; "46376b80f409b29dc2b5f6f0c52591990896e5716f41477cd30085ab7f10301e"
   ; "e0c418f7c8d9c4cdd7395b93ea124f3ad99021bb681dfc3302a9d99a2e53e64e"
  |]

let ristretto_valid_cases =
  ristretto_valid_encodings
  |> Array.to_list
  |> List.map (fun h ->
         test_case (fun _ ->
             match Sr25519.pub_of_octets (vx h) with
             | Ok _ -> ()
             | Error _ -> assert_failure ("rejected valid ristretto255 encoding " ^ h)))

let ristretto_invalid_encodings =
  [ "00ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
  ; "0100000000000000000000000000000000000000000000000000000000000000"
  ; "26948d35ca62e643e26a83177332e6b6afeb9d08e4268b650f1f5bbd8d81d371"
  ; "3eb858e78f5a7254d8c9731174a94f76755fd3941c0ac93735c07ba14579630e"
  ; "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f"
  ]

let ristretto_invalid_cases =
  ristretto_invalid_encodings
  |> List.map (fun h ->
         test_case (fun _ ->
             match Sr25519.pub_of_octets (vx h) with
             | Error _ -> ()
             | Ok _ -> assert_failure ("accepted invalid ristretto255 encoding " ^ h)))

let sr25519_seed_to_pubkey_cases =
  [
    ( vx "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60"
    , "44a996beb1eef7bdcab976ab6d2ca26104834164ecf28fb375600576fcc6eb0f" );
    ("12345678901234567890123456789012", "741c08a06f41c596608f6774259bd9043304adfa5d3eea62760bd9be97634d63");
  ]
  |> List.map (fun (seed, expected_pub) ->
         test_case (fun _ ->
             match Sr25519.priv_of_octets seed with
             | Error _ -> assert_failure "bad test seed"
             | Ok priv ->
               assert_oct_equal ~msg:"seed -> public key" (vx expected_pub)
                 (Sr25519.pub_to_octets (Sr25519.pub_of_priv priv))))

let sr25519_legacy_signature_case =
  test_case (fun _ ->
      let seed = String.make 32 '\000' in
      match Sr25519.priv_of_octets seed with
      | Error _ -> assert_failure "bad test seed"
      | Ok priv ->
        let pub = Sr25519.pub_of_priv priv in
        let sig_hex =
          "28a854d54903e056f89581c691c1f7d2ff39f8f896c9e9c22475e60902cc2b3547199e0e91fa32902028f2ca2355e8cdd16cfe19ba5e8b658c94aa80f3b81a00"
        in
        (* This legacy signature predates the marker bit that
           distinguishes Schnorrkel signatures from Ed25519 ones (see
           schnorrkel's [from_bytes_not_distinguished_from_ed25519]);
           force it before parsing. *)
        let sig_bytes = Bytes.of_string (vx sig_hex) in
        Bytes.set sig_bytes 63 (Char.chr (Char.code (Bytes.get sig_bytes 63) lor 0x80));
        match Sr25519.signature_of_octets (Bytes.unsafe_to_string sig_bytes) with
        | Error _ -> assert_failure "failed to parse legacy signature"
        | Ok signature ->
          assert_bool "verify_deprecated accepts the legacy schnorrkel-js signature"
            (Sr25519.verify_deprecated ~key:pub signature "SUBSTRATE"))

let sr25519_sign_verify_roundtrip_case =
  test_case (fun _ ->
      match Sr25519.priv_of_octets (Mirage_crypto_rng.generate 32) with
      | Error _ -> assert_failure "bad generated seed"
      | Ok priv ->
        let pub = Sr25519.pub_of_priv priv in
        let msg = "mirage-crypto-blockchain sr25519 test" in
        let signature = Sr25519.sign ~key:priv msg in
        assert_bool "self-signed signature verifies" (Sr25519.verify ~key:pub signature msg))

let sr25519_tamper_case =
  test_case (fun _ ->
      match Sr25519.priv_of_octets (Mirage_crypto_rng.generate 32) with
      | Error _ -> assert_failure "bad generated seed"
      | Ok priv ->
        let pub = Sr25519.pub_of_priv priv in
        let signature = Sr25519.sign ~key:priv "message one" in
        assert_bool "verify rejects a different message"
          (not (Sr25519.verify ~key:pub signature "message two")))

(* RFC 9496 Appendix A.4 one-way-map (hash-to-group) test vectors:
   64-byte uniform input -> 32-byte ristretto255 encoding. *)
let ristretto_one_way_map_case =
  test_case (fun _ ->
      let vectors =
        [
          ( "5d1be09e3d0c82fc538112490e35701979d99e06ca3e2b5b54bffe8b4dc772c1"
            ^ "4d98b696a1bbfb5ca32c436cc61c16563790306c79eaca7705668b47dffe5bb6",
            "3066f82a1a747d45120d1740f14358531a8f04bbffe6a819f86dfe50f44a0a46" );
          ( "f116b34b8f17ceb56e8732a60d913dd10cce47a6d53bee9204be8b44f6678b27"
            ^ "0102a56902e2488c46120e9276cfe54638286b9e4b3cdb470b542d46c2068d38",
            "f26e5b6f7d362d2d2a94c5d0e7602cb4773c95a2e5c31a64f133189fa76ed61b" );
          ( "8422e1bbdaab52938b81fd602effb6f89110e1e57208ad12d9ad767e2e25510c"
            ^ "27140775f9337088b982d83d7fcf0b2fa1edffe51952cbe7365e95c86eaf325c",
            "006ccd2a9e6867e6a2c5cea83d3302cc9de128dd2a9a57dd8ee7b9d7ffe02826" );
          ( "165d697a1ef3d5cf3c38565beefcf88c0f282b8e7dbd28544c483432f1cec767"
            ^ "5debea8ebb4e5fe7d6f6e5db15f15587ac4d4d4a1de7191e0c1ca6664abcc413",
            "ae81e7dedf20a497e10c304a765c1767a42d6e06029758d2d7e8ef7cc4c41179" );
          ( "a836e6c9a9ca9f1e8d486273ad56a78c70cf18f0ce10abb1c7172ddd605d7fd2"
            ^ "979854f47ae1ccf204a33102095b4200e5befc0465accc263175485f0e17ea5c",
            "e2705652ff9f5e44d3e841bf1c251cf7dddb77d140870d1ab2ed64f1a9ce8628" );
        ]
      in
      List.iter
        (fun (input, expected) ->
          assert_oct_equal ~msg:"RFC 9496 one-way map"
            (vx expected)
            (Sr25519.ristretto_from_uniform_bytes (vx input)))
        vectors)

(* vrf_output is deterministic; its result must be a valid ristretto
   point, stable across calls, and message-dependent. *)
let sr25519_vrf_output_case =
  test_case (fun _ ->
      match Sr25519.priv_of_octets (String.make 32 '\042') with
      | Error _ -> assert_failure "bad test seed"
      | Ok priv ->
        let out1 = Sr25519.vrf_output ~key:priv "vrf message" in
        let out2 = Sr25519.vrf_output ~key:priv "vrf message" in
        assert_oct_equal ~msg:"vrf_output is deterministic" out1 out2;
        assert_bool "vrf_output is a valid ristretto point (32 bytes)"
          (String.length out1 = 32);
        (match Sr25519.pub_of_octets out1 with
        | Ok _ -> ()
        | Error _ -> assert_failure "vrf_output is not a decodable ristretto point");
        assert_bool "vrf_output depends on the message"
          (not (String.equal out1 (Sr25519.vrf_output ~key:priv "other message"))))

let sr25519_cases =
  ristretto_valid_cases @ ristretto_invalid_cases @ sr25519_seed_to_pubkey_cases
  @ [ sr25519_legacy_signature_case; sr25519_sign_verify_roundtrip_case;
      sr25519_tamper_case; ristretto_one_way_map_case; sr25519_vrf_output_case ]

(* ===== Ed25519-BIP32 (V2). Fixed derivation vectors are from
   BitBoxSwiss/rust-bip32-ed25519's tests/testdata/table.json, which
   cross-checks against an independent ed25519-bip32 implementation. ===== *)
let ed25519_bip32_cases =
  let module B = Ed25519_bip32 in
  let root_kl = "c8e9654cee5526f2a0ea31c7b05f57f5295135e46ded2c747191f34ab98f3d50" in
  let root_kr = "8757f37b66d61b1f102b00ffd4007c7660d4948c9ec809c847a84b15e60d89b7" in
  let root_cc = "59b469554385d460a79105f422421e2de565afa315a8defd37dbc3ab2b63546d" in
  let root =
    match B.extended_priv_of_octets (vx (root_kl ^ root_kr ^ root_cc)) with
    | Ok r -> r
    | Error _ -> assert_failure "bad root xprv"
  in
  [
    (* soft derivation, index 0 *)
    test_case (fun _ ->
        let child_kl = "a0b23454924c145df960caba91f3a1ec65bc097b3e7f47849d614e19c08f3d50" in
        let child_kr = "1bac817a12e10402e991257cef4df7f8553bb33684315f70177be041f2c79b63" in
        let child_cc = "5bcc2e27c743f9d3302e8850ef27214d2b9fb000a901034008c323e6ccfd2f63" in
        let child_pub = "9dce4c2940f0ad02461c96dbce2be07cc05bfd7f6110192f4c3f59db334f3f75" in
        let child =
          match B.derive_priv_normal root ~index:0l with
          | Ok c -> c
          | Error _ -> assert_failure "soft derivation failed"
        in
        assert_oct_equal ~msg:"soft child xprv"
          (vx (child_kl ^ child_kr ^ child_cc))
          (B.extended_priv_to_octets child);
        assert_oct_equal ~msg:"soft child extended pub"
          (vx (child_pub ^ child_cc))
          (B.extended_pub_to_octets (B.pub_of_priv child));
        match B.derive_pub_normal (B.pub_of_priv root) ~index:0l with
        | Ok pchild ->
          assert_oct_equal ~msg:"public-only derivation agrees with private"
            (vx (child_pub ^ child_cc))
            (B.extended_pub_to_octets pchild)
        | Error _ -> assert_failure "public derivation failed");
    (* hardened derivation, index 2^31 *)
    test_case (fun _ ->
        let child_kl = "800cdbee97b1151e0c241bacc25e88debb501e2c08356201c0871249bc8f3d50" in
        let child_kr = "ac0fb5dbfb854692498b502444e936d35642fde5ae4244905d0aef2743152e13" in
        let child_cc = "11b22d1d5a245253e0905fd7cbb9e131ebc60609774e5ca2712afb7f35427de5" in
        let child =
          match B.derive_priv_hardened root ~index:Int32.min_int with
          | Ok c -> c
          | Error _ -> assert_failure "hardened derivation failed"
        in
        assert_oct_equal ~msg:"hardened child xprv"
          (vx (child_kl ^ child_kr ^ child_cc))
          (B.extended_priv_to_octets child));
    (* index-range guards *)
    test_case (fun _ ->
        assert_bool "normal rejects a hardened index"
          (match B.derive_priv_normal root ~index:Int32.min_int with
          | Error `Invalid_derivation -> true
          | _ -> false);
        assert_bool "hardened rejects a soft index"
          (match B.derive_priv_hardened root ~index:0l with
          | Error `Invalid_derivation -> true
          | _ -> false);
        assert_bool "public derivation rejects a hardened index"
          (match B.derive_pub_normal (B.pub_of_priv root) ~index:Int32.min_int with
          | Error `Invalid_derivation -> true
          | _ -> false));
    (* sign / verify round-trip and tamper *)
    test_case (fun _ ->
        let child =
          match B.derive_priv_normal root ~index:0l with
          | Ok c -> c
          | Error _ -> assert_failure "derivation failed"
        in
        let pub = B.pub_of_priv child in
        let msg = "bip32-ed25519 signing test" in
        let signature = B.sign ~key:child msg in
        assert_bool "signature verifies" (B.verify ~key:pub signature ~msg);
        assert_bool "verify rejects a different message"
          (not (B.verify ~key:pub signature ~msg:"other message")));
    (* master_key_of_seed: clamping and usability *)
    test_case (fun _ ->
        let rec find n =
          if n > 100 then assert_failure "no valid seed found"
          else
            match B.master_key_of_seed (Printf.sprintf "reuna-bip32-seed-%d" n) with
            | Ok m -> m
            | Error _ -> find (n + 1)
        in
        let bytes = B.extended_priv_to_octets (find 0) in
        assert_bool "xprv is 96 bytes" (String.length bytes = 96);
        let kl0 = Char.code bytes.[0] and kl31 = Char.code bytes.[31] in
        assert_bool "kL low 3 bits cleared" (kl0 land 0x07 = 0);
        assert_bool "kL top bit cleared" (kl31 land 0x80 = 0);
        assert_bool "kL bit 254 set" (kl31 land 0x40 <> 0));
  ]

let suite =
  "blockchain" >::: [
    "hashes" >::: hashes_cases;
    "blake2b" >::: blake2b_cases;
    "ripemd160" >::: ripemd160_cases;
    "keccak256" >::: keccak256_cases @ [ keccak256_multiblock_case ];
    "blake3_hash" >::: blake3_hash_cases;
    "blake3_keyed" >::: blake3_keyed_cases;
    "blake3_derive_key" >::: blake3_derive_key_cases;
    "secp256k1" >::: [ secp256k1_generator_on_curve_case; secp256k1_ecdsa_case;
                       secp256k1_recover_case ];
    "bip340_sign_verify" >::: bip340_full_cases;
    "bip340_verify_only" >::: bip340_verify_cases;
    "stark_curve" >::: [
      stark_curve_pub_of_priv_case;
      stark_curve_verify_reference_case;
      stark_curve_sign_verify_roundtrip_case;
      stark_curve_tamper_case;
    ];
    "poseidon" >::: poseidon_cases;
    "bls12_381" >::: bls12_381_cases;
    "sr25519" >::: sr25519_cases;
    "ed25519_bip32" >::: ed25519_bip32_cases;
  ]
