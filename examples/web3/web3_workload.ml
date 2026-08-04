(* A small multi-chain "wallet / verifier" that drives the
   mirage-crypto-blockchain primitives through realistic end-to-end flows
   and cross-checks the results against published protocol test vectors
   (EIP-155, BIP341, Cardano ed25519-bip32, and an sr25519 round-trip).

   It also carries minimal inline RLP and bech32m codecs -- the kind of
   thing the eventual web3 codec library will provide -- so the crypto
   primitives are exercised the way a real client uses them, not in
   isolation. Exits non-zero if any check fails. *)

open Mirage_crypto_blockchain

(* ------------------------------------------------------------------ *)
(* tiny helpers                                                        *)

let hexdec s =
  let s = String.concat "" (String.split_on_char ' ' s) in
  String.init
    (String.length s / 2)
    (fun i -> Char.chr (int_of_string ("0x" ^ String.sub s (2 * i) 2)))

let hexenc s =
  String.concat ""
    (List.init (String.length s) (fun i -> Printf.sprintf "%02x" (Char.code s.[i])))

let get_ok = function Ok x -> x | Error _ -> failwith "unexpected Error result"
let rev s = String.init (String.length s) (fun i -> s.[String.length s - 1 - i])
let lpad n s = if String.length s >= n then s else String.make (n - String.length s) '\000' ^ s

let strip s =
  let n = String.length s in
  let i = ref 0 in
  while !i < n && s.[!i] = '\000' do incr i done;
  String.sub s !i (n - !i)

let failures = ref 0

let check name ok =
  Printf.printf "  [%s] %s\n" (if ok then "OK" else "FAIL") name;
  if not ok then incr failures

let check_eq name ~expected ~got =
  let ok = String.equal expected got in
  Printf.printf "  [%s] %s\n" (if ok then "OK" else "FAIL") name;
  if not ok then begin
    incr failures;
    Printf.printf "        expected %s\n        got      %s\n" expected got
  end

(* ------------------------------------------------------------------ *)
(* minimal RLP (Ethereum)                                             *)

type rlp = Str of string | Lst of rlp list

let be_of_int n =
  if n = 0 then ""
  else
    let rec go n acc =
      if n = 0 then acc
      else go (n lsr 8) (String.make 1 (Char.chr (n land 0xff)) ^ acc)
    in
    go n ""

let be_int s = String.fold_left (fun acc c -> (acc lsl 8) lor Char.code c) 0 s

let rlp_bytes s =
  let n = String.length s in
  if n = 1 && Char.code s.[0] < 0x80 then s
  else if n <= 55 then String.make 1 (Char.chr (0x80 + n)) ^ s
  else
    let lb = be_of_int n in
    String.make 1 (Char.chr (0xb7 + String.length lb)) ^ lb ^ s

let rlp_list items =
  let payload = String.concat "" items in
  let n = String.length payload in
  if n <= 55 then String.make 1 (Char.chr (0xc0 + n)) ^ payload
  else
    let lb = be_of_int n in
    String.make 1 (Char.chr (0xf7 + String.length lb)) ^ lb ^ payload

let rec rlp_decode_at s pos =
  let b = Char.code s.[pos] in
  if b < 0x80 then (Str (String.sub s pos 1), pos + 1)
  else if b < 0xb8 then
    let len = b - 0x80 in
    (Str (String.sub s (pos + 1) len), pos + 1 + len)
  else if b < 0xc0 then
    let nl = b - 0xb7 in
    let len = be_int (String.sub s (pos + 1) nl) in
    (Str (String.sub s (pos + 1 + nl) len), pos + 1 + nl + len)
  else if b < 0xf8 then
    let len = b - 0xc0 in
    (Lst (decode_list s (pos + 1) (pos + 1 + len)), pos + 1 + len)
  else
    let nl = b - 0xf7 in
    let len = be_int (String.sub s (pos + 1) nl) in
    (Lst (decode_list s (pos + 1 + nl) (pos + 1 + nl + len)), pos + 1 + nl + len)

and decode_list s pos stop =
  if pos >= stop then []
  else
    let it, p = rlp_decode_at s pos in
    it :: decode_list s p stop

let rlp_decode s = fst (rlp_decode_at s 0)

(* ------------------------------------------------------------------ *)
(* minimal bech32m (Bitcoin segwit v1 / Taproot)                      *)

let charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"

let bech32_polymod values =
  let gen = [| 0x3b6a57b2; 0x26508e6d; 0x1ea119fa; 0x3d4233dd; 0x2a1462b3 |] in
  let chk = ref 1 in
  List.iter
    (fun v ->
      let top = !chk lsr 25 in
      chk := ((!chk land 0x1ffffff) lsl 5) lxor v;
      for i = 0 to 4 do
        if (top lsr i) land 1 <> 0 then chk := !chk lxor gen.(i)
      done)
    values;
  !chk

let hrp_expand hrp =
  let n = String.length hrp in
  List.init n (fun i -> Char.code hrp.[i] lsr 5)
  @ [ 0 ]
  @ List.init n (fun i -> Char.code hrp.[i] land 31)

let bech32m_const = 0x2bc830a3

let create_checksum hrp data =
  let values = hrp_expand hrp @ data @ [ 0; 0; 0; 0; 0; 0 ] in
  let polymod = bech32_polymod values lxor bech32m_const in
  List.init 6 (fun i -> (polymod lsr (5 * (5 - i))) land 31)

let convertbits data frombits tobits pad =
  let acc = ref 0 and bits = ref 0 and out = ref [] in
  let maxv = (1 lsl tobits) - 1 in
  List.iter
    (fun value ->
      acc := (!acc lsl frombits) lor value;
      bits := !bits + frombits;
      while !bits >= tobits do
        bits := !bits - tobits;
        out := ((!acc lsr !bits) land maxv) :: !out
      done)
    data;
  if pad && !bits > 0 then out := ((!acc lsl (tobits - !bits)) land maxv) :: !out;
  List.rev !out

(* segwit v1+ address (bech32m). *)
let segwit_encode hrp witver program =
  let prog_5bit =
    convertbits (List.init (String.length program) (fun i -> Char.code program.[i])) 8 5 true
  in
  let data = witver :: prog_5bit in
  let combined = data @ create_checksum hrp data in
  hrp ^ "1" ^ String.concat "" (List.map (fun d -> String.make 1 charset.[d]) combined)

(* ------------------------------------------------------------------ *)
(* Ethereum: EIP-155 tx signing + sender recovery                     *)

let eth_address_of_pub pub =
  let uncompressed = Secp256k1.point_to_octets ~compress:false pub in
  String.sub (Keccak256.digest (String.sub uncompressed 1 64)) 12 20

let section_ethereum () =
  Printf.printf "\n== Ethereum: EIP-155 transaction signing + sender recovery ==\n";
  let key = get_ok (Secp256k1.scalar_of_octets (hexdec (String.concat "" (List.init 32 (fun _ -> "46"))))) in
  let my_addr = eth_address_of_pub (Secp256k1.pub_of_priv key) in
  Printf.printf "  sender address : 0x%s\n" (hexenc my_addr);
  check_eq "address derives to the known EIP-155 account"
    ~expected:"9d8a62f656a8d1615c1294fd71e9cfb3e4855a4f" ~got:(hexenc my_addr);

  let to_addr = hexdec (String.concat "" (List.init 20 (fun _ -> "35"))) in
  let chain_id = 1 in
  let fields_for_signing =
    [ rlp_bytes "\x09"; rlp_bytes (hexdec "04a817c800"); rlp_bytes "\x52\x08";
      rlp_bytes to_addr; rlp_bytes (hexdec "0de0b6b3a7640000"); rlp_bytes "";
      rlp_bytes (String.make 1 (Char.chr chain_id)); rlp_bytes ""; rlp_bytes "" ]
  in
  let signing_rlp = rlp_list fields_for_signing in
  check_eq "signing RLP matches EIP-155"
    ~expected:"ec098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a764000080018080"
    ~got:(hexenc signing_rlp);
  let sighash = Keccak256.digest signing_rlp in
  check_eq "signing hash (keccak256) matches EIP-155"
    ~expected:"daf5a779ae972f972197303d7b574746c7ef83eadac0f2791ad23db92e4c8e53"
    ~got:(hexenc sighash);

  let sg, recid = Secp256k1.sign_recoverable ~key sighash in
  let rs = Secp256k1.signature_to_octets sg in
  let r = String.sub rs 0 32 and s = String.sub rs 32 32 in
  check_eq "r matches EIP-155"
    ~expected:"28ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276" ~got:(hexenc r);
  check_eq "s matches EIP-155"
    ~expected:"67cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83" ~got:(hexenc s);
  let v = recid + 35 + (2 * chain_id) in
  check "recovery id yields v = 37" (v = 37);

  let signed =
    rlp_list
      [ rlp_bytes "\x09"; rlp_bytes (hexdec "04a817c800"); rlp_bytes "\x52\x08";
        rlp_bytes to_addr; rlp_bytes (hexdec "0de0b6b3a7640000"); rlp_bytes "";
        rlp_bytes (String.make 1 (Char.chr v)); rlp_bytes (strip r); rlp_bytes (strip s) ]
  in
  check_eq "signed transaction RLP matches EIP-155"
    ~expected:"f86c098504a817c800825208943535353535353535353535353535353535353535880de0b6b3a76400008025a028ef61340bd939bc2195fe537567866003e1a15d3c71ff63e1590620aa636276a067cbe9d8997f761aecb703304b3800ccf555c9f3dc64214b297fb1966a3b6d83"
    ~got:(hexenc signed);

  (* Now act as a node: decode the signed tx and recover the sender. *)
  (match rlp_decode signed with
  | Lst [ Str nonce; Str gp; Str gas; Str to_; Str value; Str data; Str vb; Str rb; Str sb ] ->
    let v = be_int vb in
    let cid = (v - 35) / 2 in
    let recid = v - 35 - (2 * cid) in
    let recompute_hash =
      Keccak256.digest
        (rlp_list
           [ rlp_bytes nonce; rlp_bytes gp; rlp_bytes gas; rlp_bytes to_;
             rlp_bytes value; rlp_bytes data;
             rlp_bytes (String.make 1 (Char.chr cid)); rlp_bytes ""; rlp_bytes "" ])
    in
    let sg' = get_ok (Secp256k1.signature_of_octets (lpad 32 rb ^ lpad 32 sb)) in
    let recovered = get_ok (Secp256k1.recover ~msg:recompute_hash sg' ~recid) in
    let recovered_addr = eth_address_of_pub recovered in
    Printf.printf "  recovered from signed tx : 0x%s\n" (hexenc recovered_addr);
    check_eq "recovered sender equals signer" ~expected:(hexenc my_addr) ~got:(hexenc recovered_addr)
  | _ -> check "signed tx decodes to 9 fields" false)

(* ------------------------------------------------------------------ *)
(* Bitcoin: genesis txid (SHA256d) + Taproot address (BIP341)         *)

let section_bitcoin () =
  Printf.printf "\n== Bitcoin: genesis txid (SHA256d) + Taproot address (BIP341) ==\n";
  let genesis_raw =
    hexdec
      ("01000000010000000000000000000000000000000000000000000000000000000000000000"
     ^ "ffffffff4d04ffff001d0104455468652054696d65732030332f4a616e2f323030392043"
     ^ "68616e63656c6c6f72206f6e206272696e6b206f66207365636f6e64206261696c6f7574"
     ^ "20666f722062616e6b73ffffffff0100f2052a0100000043410467"
     ^ "8afdb0fe5548271967f1a67130b7105cd6a828e03909a67962e0ea1f61deb649f6bc3f4c"
     ^ "ef38c4f35504e51ec112de5c384df7ba0b8d578a4c702b6bf11d5fac00000000")
  in
  let txid = rev (Hashes.sha256d genesis_raw) in
  Printf.printf "  genesis txid : %s\n" (hexenc txid);
  check_eq "genesis coinbase txid (SHA256d, display order)"
    ~expected:"4a5e1e4baab89f3a32518a88c31bc87f618f76673e2cc77ab2127b7afdeda33b"
    ~got:(hexenc txid);

  (* BIP341 key-path Taproot: Q = lift_x(P) + H_TapTweak(P)*G. *)
  let p = hexdec "d6889cb081036e0faefa3a35157ad71086b123b2b144b649798b494c300a961d" in
  let tweak = Hashes.tagged_hash ~tag:"TapTweak" p in
  check_eq "TapTweak tagged hash matches BIP341"
    ~expected:"b86e7be8f39bab32a6f2c0443abbc210f0edac0e2c53d501b36b64437d9c6c70"
    ~got:(hexenc tweak);
  let p_point = get_ok (Secp256k1.point_of_octets ("\x02" ^ p)) in
  let t_scalar = get_ok (Secp256k1.scalar_of_octets tweak) in
  let tweak_point = get_ok (Secp256k1.scalar_mult t_scalar Secp256k1.g) in
  let q = get_ok (Secp256k1.add p_point tweak_point) in
  let q_x = String.sub (Secp256k1.point_to_octets ~compress:true q) 1 32 in
  check_eq "tweaked output key matches BIP341"
    ~expected:"53a1f6e454df1aa2776a2814a721372d6258050de330b3c6d10ee8f4e0dda343"
    ~got:(hexenc q_x);
  let addr = segwit_encode "bc" 1 q_x in
  Printf.printf "  taproot addr : %s\n" addr;
  check_eq "Taproot bech32m address matches BIP350"
    ~expected:"bc1p2wsldez5mud2yam29q22wgfh9439spgduvct83k3pm50fcxa5dps59h4z5" ~got:addr

(* ------------------------------------------------------------------ *)
(* Cardano: BIP32-Ed25519 HD wallet                                   *)

let section_cardano () =
  Printf.printf "\n== Cardano: BIP32-Ed25519 HD wallet ==\n";
  let root =
    get_ok
      (Ed25519_bip32.extended_priv_of_octets
         (hexdec
            ("c8e9654cee5526f2a0ea31c7b05f57f5295135e46ded2c747191f34ab98f3d50"
           ^ "8757f37b66d61b1f102b00ffd4007c7660d4948c9ec809c847a84b15e60d89b7"
           ^ "59b469554385d460a79105f422421e2de565afa315a8defd37dbc3ab2b63546d")))
  in
  (* soft m/0: cross-check the child public key against the vector. *)
  let child0 = get_ok (Ed25519_bip32.derive_priv_normal root ~index:0l) in
  let child0_point =
    String.sub (Ed25519_bip32.extended_pub_to_octets (Ed25519_bip32.pub_of_priv child0)) 0 32
  in
  check_eq "m/0 child public key (KAT)"
    ~expected:"9dce4c2940f0ad02461c96dbce2be07cc05bfd7f6110192f4c3f59db334f3f75"
    ~got:(hexenc child0_point);

  (* A realistic Cardano-style path m/1852'/1815'/0'/0/0, then sign. *)
  let harden i = Int32.logor Int32.min_int (Int32.of_int i) in
  let dh k i = get_ok (Ed25519_bip32.derive_priv_hardened k ~index:(harden i)) in
  let dn k i = get_ok (Ed25519_bip32.derive_priv_normal k ~index:(Int32.of_int i)) in
  let acct = dh (dh (dh root 1852) 1815) 0 in
  let leaf = dn (dn acct 0) 0 in
  let leaf_pub = Ed25519_bip32.pub_of_priv leaf in
  Printf.printf "  m/1852'/1815'/0'/0/0 pubkey : %s\n"
    (hexenc (String.sub (Ed25519_bip32.extended_pub_to_octets leaf_pub) 0 32));
  let msg = "reuna cardano payment auth" in
  let sg = Ed25519_bip32.sign ~key:leaf msg in
  check "leaf key signs and verifies" (Ed25519_bip32.verify ~key:leaf_pub sg ~msg);
  check "verify rejects a tampered message" (not (Ed25519_bip32.verify ~key:leaf_pub sg ~msg:"tampered"));

  (* watch-only wallet: public-only soft derivation must match the private path. *)
  let via_pub = get_ok (Ed25519_bip32.derive_pub_normal (Ed25519_bip32.pub_of_priv acct) ~index:0l) in
  let via_priv = Ed25519_bip32.pub_of_priv (dn acct 0) in
  check_eq "public-only derivation matches private derivation"
    ~expected:(hexenc (Ed25519_bip32.extended_pub_to_octets via_priv))
    ~got:(hexenc (Ed25519_bip32.extended_pub_to_octets via_pub))

(* ------------------------------------------------------------------ *)
(* Polkadot: sr25519 signing + VRF                                    *)

let section_polkadot () =
  Printf.printf "\n== Polkadot: sr25519 signing + VRF pre-output ==\n";
  let seed = hexdec "fac7959dbfe72f052e5a0c3c8d6530f202b02fd8f9f5ca3580ec8deb7797479e" in
  let priv = get_ok (Sr25519.priv_of_octets seed) in
  let pub = Sr25519.pub_of_priv priv in
  Printf.printf "  account pubkey : %s\n" (hexenc (Sr25519.pub_to_octets pub));
  let msg = "reuna substrate extrinsic" in
  let sg = Sr25519.sign ~key:priv msg in
  check "sr25519 signs and verifies" (Sr25519.verify ~key:pub sg msg);
  check "verify rejects a different message" (not (Sr25519.verify ~key:pub sg "other"));

  let vrf1 = Sr25519.vrf_output ~key:priv msg in
  let vrf2 = Sr25519.vrf_output ~key:priv msg in
  Printf.printf "  vrf pre-output : %s\n" (hexenc vrf1);
  check "vrf_output is deterministic" (String.equal vrf1 vrf2);
  check "vrf output is a valid ristretto point"
    (match Sr25519.pub_of_octets vrf1 with Ok _ -> true | Error _ -> false);
  check "vrf output is message-dependent"
    (not (String.equal vrf1 (Sr25519.vrf_output ~key:priv "different input")))

(* ------------------------------------------------------------------ *)

let () =
  Mirage_crypto_rng_unix.use_default ();
  Printf.printf "reuna web3 crypto workload -- driving mirage-crypto-blockchain end-to-end\n";
  section_ethereum ();
  section_bitcoin ();
  section_cardano ();
  section_polkadot ();
  Printf.printf "\n%s\n" (if !failures = 0 then "All checks passed." else Printf.sprintf "%d check(s) FAILED." !failures);
  exit (if !failures = 0 then 0 else 1)
