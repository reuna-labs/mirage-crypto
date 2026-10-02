#!/usr/bin/env python3
"""Verify the Crypton import and reproduce the shared PBKDF2 selection."""
import argparse
import hashlib
import json
from pathlib import Path

root = Path(__file__).resolve().parent.parent / 'pbkdf2'
parser = argparse.ArgumentParser()
parser.add_argument('--check', action='store_true')
args = parser.parse_args()
base = root / 'vendor'
manifest = json.loads((base / 'manifest.json').read_text())
for name, digest in manifest['sha256'].items():
    if hashlib.sha256((base / name).read_bytes()).hexdigest() != digest:
        raise SystemExit(f'Crypton source mismatch: {name}')
actual = {str(p.relative_to(base)) for p in base.rglob('*') if p.is_file()}
assert actual == set(manifest['sha256']) | {'manifest.json', 'dune'}
source = (base / 'cbits/crypton_pbkdf2.c').read_text()

def replace(old, new):
    global source
    assert source.count(old) == 1, old
    source = source.replace(old, new)

# Upstream algorithm and optimized iteration loop are unchanged. Wipe local
# HMAC keys, contexts and intermediate blocks after their final use.
replace('    _xtract(&result, out);',
        '    _xtract(&result, out); \\\n    mc_pbkdf2_wipe(&ctx,sizeof ctx); mc_pbkdf2_wipe(&result,sizeof result); \\\n    mc_pbkdf2_wipe(Ublock,sizeof Ublock);')
replace('      memcpy(out + offset, block, taken);',
        '      memcpy(out + offset, block, taken); mc_pbkdf2_wipe(block,sizeof block);')
marker = '    _update(&ctx->outer, blk_outer, sizeof blk_outer);'
replace(marker, marker + ' mc_pbkdf2_wipe(k,sizeof k); \\\n    mc_pbkdf2_wipe(blk_inner,sizeof blk_inner); mc_pbkdf2_wipe(blk_outer,sizeof blk_outer);')
marker = '    }                                                                         \\\n  }\n\nstatic inline void sha1_extract'
replace(marker, '    }                                                                         \\\n    mc_pbkdf2_wipe(&ctx,sizeof ctx); \\\n  }\n\nstatic inline void sha1_extract')
target = root / 'pbkdf2.inc'
if args.check:
    if not target.exists() or target.read_text() != source:
        raise SystemExit('stale pbkdf2/pbkdf2.inc')
else:
    target.write_text(source)
print(f"PBKDF2: {manifest['commit']}; import and selection verified")
