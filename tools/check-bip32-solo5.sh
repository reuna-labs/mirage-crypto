#!/bin/sh
# Optional downstream Bitcoin smoke in the backend Solo5 workspace.
# Run check-backend-solo5.sh first, retaining its STAGE directory.
set -eu
: "${STAGE:?set STAGE to a completed backend Solo5 workspace}"
: "${BITCOIN_SOURCE:?set BITCOIN_SOURCE to the migrated ocaml-bitcoin checkout}"
SOLO5_TOOLCHAIN=${SOLO5_TOOLCHAIN:-solo5}
MODE=${MODE:-spt}
RUN=${RUN:-1}
export STAGE BITCOIN_SOURCE
export BASE64_LIB="$(opam var base64:lib)"
python3 - <<'PY'
import os, shutil
from pathlib import Path
stage=Path(os.environ['STAGE']); bitcoin=stage/'duniverse/bitcoin'
def ignore(directory,names):
    return [n for n in names if n in ('.git','_opam','duniverse') or n.startswith(('_build','._'))]
shutil.copytree(os.environ['BITCOIN_SOURCE'],bitcoin,ignore=ignore)
base=stage/'duniverse/base64';base.mkdir()
for f in ('base64.ml','base64.mli'):shutil.copyfile(Path(os.environ['BASE64_LIB'])/f,base/f)
(base/'dune-project').write_text('(lang dune 2.7)\n(name base64)\n')
(base/'base64.opam').write_text('opam-version: "2.0"\n')
(base/'dune').write_text('(library (name base64) (public_name base64))\n')
src=stage/'tests/solo5'
(src/'smoke_bitcoin.ml').write_text('''
let ok = function Ok x -> x | Error _ -> failwith "Bitcoin smoke"
let () =
  (* This standalone test has fixed entropy; real Mirage apps use default_random. *)
  Mirage_crypto_rng.set_default_generator
    (Mirage_crypto_rng.create ~seed:(String.make 48 '\\042') (module Mirage_crypto_rng.Fortuna));
  let open Bitcoin in
  let master = ok (Bip32.Secret.master (String.init 16 Char.chr)) in
  let path = ok (Derivation_path.of_string "m/0'/1/2'") in
  let child = ok (Bip32.Secret.derive_path master path) in
  let encoded = Bip32.Secret.to_base58 ~network:Network.Mainnet child in
  assert (encoded = "xprv9z4pot5VBttmtdRTWfWQmoH1taj2axGVzFqSb8C9xaxKymcFzXBDptWmT7FwuEzG3ryjH4ktypQSAewRiNMjANTtpgP4mLTj34bhnZX7UiM");
  let imported, _ = ok (Bip32.Secret.of_base58 encoded) in
  assert (Key.Secret.to_octets imported.key = Key.Secret.to_octets child.key);
  let public = Key.Secret.public child.key in
  let digest = Hash.sha256 "BIP32 Bitcoin Solo5" in
  let sig_ = Key.Ecdsa.sign ~key:child.key ~digest in
  assert (Key.Ecdsa.verify ~key:public sig_ ~digest);
  let sig_ = Key.Schnorr.sign ~key:child.key ~msg:digest () in
  assert (Key.Schnorr.verify ~x_only:(Key.Public.x_only public) sig_ ~msg:digest);
  ignore (ok (Taproot.spend_info ~internal_key:public ()));
  print_endline "Bitcoin BIP32/ECDSA/BIP340/Taproot Solo5 smoke passed"
''')
with (src/'dune').open('a') as f:f.write('''
(executable (name smoke_bitcoin) (modules smoke_bitcoin) (modes native)
 (enabled_if (= %{context_name} solo5))
 (libraries backend_startup bitcoin mirage-crypto-rng)
 (link_flags :standard -cclib "-z solo5-abi=%{env:MODE=spt}"
  -cclib "-u __solo5_mft1_note"))
''')
PY
cd "$STAGE"
export MODE
dune build --profile release --workspace tests/solo5/workspace _build/solo5/tests/solo5/smoke_bitcoin.exe
image=_build/solo5/tests/solo5/smoke_bitcoin.exe
if nm "$image" | grep -E '(camlZ__|__gmp|ctypes|camlUnix__)'; then
  echo "Unexpected dependency in $image" >&2; exit 1
fi
size "$image"
if [ "$RUN" = 1 ]; then "solo5-$MODE" "$image"; fi
