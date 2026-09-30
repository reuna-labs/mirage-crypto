#!/bin/sh
# Run in a Linux switch containing ocaml-solo5, Solo5, eqaf and logs.
# Dependencies are rebuilt from source in an isolated workspace.
set -eu
ROOT=$(CDPATH= cd -- "$(dirname "$0")/.." && pwd)
DIGESTIF_SOURCE=${DIGESTIF_SOURCE:-"$ROOT/../digestif"}
MODE=${MODE:-spt}
RUN=${RUN:-1}
SOLO5_TOOLCHAIN=${SOLO5_TOOLCHAIN:-solo5}
STAGE=${STAGE:-$(mktemp -d "${TMPDIR:-/tmp}/mc-solo5.XXXXXX")}
export ROOT DIGESTIF_SOURCE STAGE SOLO5_TOOLCHAIN
export EQAF_LIB="$(opam var eqaf:lib)"
export LOGS_LIB="$(opam var logs:lib)"
python3 - <<'PY'
import os, shutil
from pathlib import Path
root, stage = Path(os.environ['ROOT']), Path(os.environ['STAGE'])
def ignore(directory, names):
    return [n for n in names if n in ('.git', '_opam', 'duniverse') or n.startswith(('_build', '._'))]
shutil.copytree(root, stage, dirs_exist_ok=True, ignore=ignore)
(stage / 'tests/solo5/dune').write_text((stage / 'tests/solo5/dune.in').read_text())
workspace = stage / 'tests/solo5/workspace'
workspace.write_text(workspace.read_text().replace('(toolchain solo5)',
    '(toolchain ' + os.environ['SOLO5_TOOLCHAIN'] + ')'))
project = stage / 'dune-project'
project.write_text(project.read_text().replace('(lang dune 2.7)', '(lang dune 2.8)'))
deps = stage / 'duniverse'
shutil.copytree(os.environ['DIGESTIF_SOURCE'], deps / 'digestif', ignore=ignore)
for name, files in [('eqaf', ['eqaf.ml', 'eqaf.mli', 'unsafe.ml']), ('logs', ['logs.ml', 'logs.mli'])]:
    dest = deps / name
    dest.mkdir(parents=True)
    src = Path(os.environ[name.upper() + '_LIB'])
    for f in files:
        shutil.copyfile(src / f, dest / f)
    (dest / 'dune-project').write_text(f'(lang dune 2.7)\n(name {name})\n')
    (dest / (name + '.opam')).write_text('opam-version: "2.0"\n')
    options = '(private_modules unsafe)' if name == 'eqaf' else '(wrapped false)'
    (dest / 'dune').write_text(f'(library (name {name}) (public_name {name}) {options})\n')
PY
cd "$STAGE"
export MODE
dune build --profile release --workspace tests/solo5/workspace \
  _build/solo5/tests/solo5/smoke_secp256k1.exe \
  _build/solo5/tests/solo5/smoke_bls12_381.exe \
  _build/solo5/tests/solo5/smoke_blake3.exe \
  _build/solo5/tests/solo5/smoke_poseidon.exe \
  _build/solo5/tests/solo5/smoke_sr25519.exe
for backend in secp256k1 bls12_381 blake3 poseidon sr25519; do
  image="_build/solo5/tests/solo5/smoke_$backend.exe"
  if nm "$image" | grep -E '(camlZ__|__gmp|ctypes|camlUnix__)'; then
    echo "Unexpected dependency in $image" >&2; exit 1
  fi
  size "$image"
  if [ "$RUN" = 1 ]; then "solo5-$MODE" "$image"; fi
done
echo "Solo5 artifacts: $STAGE/_build/solo5/tests/solo5"
