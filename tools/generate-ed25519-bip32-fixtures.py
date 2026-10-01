#!/usr/bin/env python3
"""Regenerate independent Python and Cardano fixtures; Rust has its own oracle."""
import argparse
import hashlib
import re
import subprocess
from pathlib import Path

PIN = 'ac2e12a471b735ad80949bcbf0f6f634e5dbef77'
p = argparse.ArgumentParser()
p.add_argument('--cardano-source', type=Path, required=True)
a = p.parse_args()
assert subprocess.check_output(['git', '-C', str(a.cardano_source), 'rev-parse', 'HEAD'], text=True).strip() == PIN
out = Path(__file__).resolve().parent.parent / 'ed25519-bip32/test'
with (out / 'icarus-vectors.tsv').open('w') as f:
    for n in range(16, 33):
        for plen in [0, 3, 128, 129, 257]:
            entropy = bytes(range(n))
            password = bytes(i % 256 for i in range(plen))
            key = bytearray(hashlib.pbkdf2_hmac('sha512', password, entropy, 4096, 96))
            key[0] &= 248
            key[31] = (key[31] & 31) | 64
            f.write(f'{entropy.hex()}\t{password.hex()}\t{key.hex()}\n')
with (out / 'master-vectors.tsv').open('w') as f:
    for n in range(256):
        seed = bytes((i+n) % 256 for i in range(n))
        key = bytearray(hashlib.sha512(seed).digest())
        expected = 'invalid'
        if not key[31] & 32:
            key[0] &= 248
            key[31] = (key[31] & 127) | 64
            expected = (key + hashlib.sha256(b'\x01' + seed).digest()).hex()
        f.write(f'{seed.hex()}\t{expected}\n')
records = []
for file in sorted((a.cardano_source / 'tests/goldens/cardano/crypto/wallet').glob('BIP39-*')):
    for rec in file.read_text().split('TestVector\n')[1:]:
        d = dict(re.findall(r'^(\w+) = "([^"]*)"', rec, re.M))
        if (d.get('derivation_scheme'), d.get('master_key_generation'), d.get('passphrase')) != ('derivation-scheme2', 'pbkdf', ''):
            continue
        path = ','.join(re.findall(r'\d+', re.search(r'path = \[(.*?)\]', rec, re.S)[1]))
        private = d['xPriv']
        records.append('\t'.join([d['seed'], path, private[:128] + private[192:],
                                   d['xPub'], d['data_to_sign'].encode().hex(), d['signature']]))
assert len(records) == 5
(out / 'cardano-vectors.tsv').write_text(f'# Cardano {PIN} wallet goldens, V2/pbkdf/unprotected\n' + '\n'.join(records) + '\n')
