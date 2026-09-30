// Development oracle only; no JavaScript participates in the OCaml runtime.
import { HDKey } from '@scure/bip32';
import { base58check } from '@scure/base';
import { sha256 } from '@noble/hashes/sha2.js';
const hex = b => Buffer.from(b).toString('hex');
const decode = base58check(sha256).decode;
console.log('# @scure/bip32 2.4.0; regenerate: npm ci && npm run --silent vectors');
for (let i = 0; i < 32; i++) {
  const seed = Uint8Array.from({length:16+(i%4)*16}, (_, j) => (i*37+j*11)&255);
  const paths = ['m', `m/${i}'/0/2147483647/2147483647'/${i*100003}`];
  for (const path of paths) {
    const key = HDKey.fromMasterSeed(seed).derive(path);
    console.log([hex(seed), path, hex(decode(key.privateExtendedKey)), hex(decode(key.publicExtendedKey))].join('\t'));
  }
}
