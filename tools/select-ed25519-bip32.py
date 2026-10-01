#!/usr/bin/env python3
"""Reproduce selected Cardano/Crypton sources; --check never writes files."""
from pathlib import Path
import argparse, hashlib, json, re
root=Path(__file__).resolve().parent.parent/'ed25519-bip32'
def read(name,path):return (root/'vendor'/name/path).read_text()
def function(source,name):
    # Include preceding static/return-type lines, then balance the function body.
    match=re.search(r'(?m)^(?:static[^\n]*\n)?(?:void|int|static void|static int)\s*\n?'+re.escape(name)+r'\s*\(',source)
    if not match:raise ValueError(name)
    start=match.start();b=source.index('{',match.end());depth=1;i=b+1
    while depth:
        depth+=(source[i]=='{')-(source[i]=='}');i+=1
    return source[start:i]+'\n'
def generate():
    curve=read('cardano','cbits/ed25519/ed25519.c')
    curve=curve.replace('#include "ed25519-randombytes.h"','/* No randomness or batch verification in this selection. */')
    curve=curve.replace('#include "ed25519-donna.h"','#include "cardano_donna.inc"')
    # Wipe native secret temporaries. The upstream curve formulas are unchanged.
    curve=curve.replace('ge25519_pack(pk, &A);','ge25519_pack(pk, &A);\n mc_edb32_wipe(a,sizeof a); mc_edb32_wipe(extsk,sizeof extsk); mc_edb32_wipe(&A,sizeof A);')
    curve=curve.replace('contract256_modm(RS + 32, S);','contract256_modm(RS + 32, S);\n mc_edb32_wipe(&ctx,sizeof ctx); mc_edb32_wipe(r,sizeof r); mc_edb32_wipe(S,sizeof S); mc_edb32_wipe(a,sizeof a);\n mc_edb32_wipe(extsk,sizeof extsk); mc_edb32_wipe(hashr,sizeof hashr); mc_edb32_wipe(hram,sizeof hram); mc_edb32_wipe(&R,sizeof R);')
    curve=curve.replace('ed25519_hash_final(&ctx, hram);','ed25519_hash_final(&ctx, hram);\n mc_edb32_wipe(&ctx,sizeof ctx);')
    deriv=read('cardano','cbits/encrypted_sign.c')
    arithmetic=''.join(function(deriv,n) for n in ['multiply8_v2','add_256bits_v2','scalar_add_no_overflow'])
    # The legacy ternary is mathematically equivalent to an unsigned carry shift.
    arithmetic=arithmetic.replace('(r >= 0x100) ? 1 : 0','r >> 8')
    arithmetic=arithmetic.replace('void scalar_add_no_overflow','static void scalar_add_no_overflow')
    hmac=read('cardano','cbits/hmac.h').replace('#include "crypton_sha512.h"','#include "crypton_sha512.h"\n#include <assert.h>')
    # Macro-local secret copies and states must survive no return path unwiped.
    hmac=hmac.replace('  }                                                                           \\\n                                                                              \\\n  static inline void HMAC_UPDATE', '    mc_edb32_wipe(k, sizeof k); mc_edb32_wipe(blk_inner, sizeof blk_inner); \\\n    mc_edb32_wipe(blk_outer, sizeof blk_outer); \\\n  }                                                                           \\\n                                                                              \\\n  static inline void HMAC_UPDATE')
    pb=read('crypton','cbits/crypton_pbkdf2.c')
    pb=pb[:pb.index('static inline void sha1_extract')]+pb[pb.index('static inline void sha512_extract'):pb.index('void crypton_fastpbkdf2_hmac_sha1')]+pb[pb.index('void crypton_fastpbkdf2_hmac_sha512'):]
    pb=pb.replace('#include "crypton_sha1.h"','').replace('#include "crypton_sha256.h"','')
    pb=pb.replace('    _xtract(&result, out);', '    _xtract(&result, out); \\\n    mc_edb32_wipe(&ctx,sizeof ctx); mc_edb32_wipe(&result,sizeof result); \\\n    mc_edb32_wipe(Ublock,sizeof Ublock);')
    pb=pb.replace('      memcpy(out + offset, block, taken);', '      memcpy(out + offset, block, taken); mc_edb32_wipe(block,sizeof block);')
    # Wipe HMAC local padded key after both contexts have consumed it.
    marker='    _update(&ctx->outer, blk_outer, sizeof blk_outer);'
    assert marker in pb
    pb=pb.replace(marker,marker+' mc_edb32_wipe(k,sizeof k); \\\n    mc_edb32_wipe(blk_inner,sizeof blk_inner); mc_edb32_wipe(blk_outer,sizeof blk_outer);')
    pb=pb.replace('    }                                                                         \\\n  }\n\nstatic inline void sha512_extract', '    }                                                                         \\\n    mc_edb32_wipe(&ctx,sizeof ctx); \\\n  }\n\nstatic inline void sha512_extract')
    donna=read('cardano','cbits/ed25519/ed25519-donna.h')
    selected={}
    for bits in [32,64]:
        name=f'curve25519-donna-{bits}bit.h'
        data=read('cardano','cbits/ed25519/'+name)
        for i in range(256//bits):
            old=f'x{i} = *(uint{bits}_t *)(in + {i*(bits//8)});'
            assert old in data
            data=data.replace(old,f'memcpy(&x{i}, in + {i*(bits//8)}, sizeof x{i});')
        target=f'cardano_curve{bits}.inc'
        selected[target]=data
        donna=donna.replace(f'#include "{name}"',f'#include "{target}"')
    selected.update({'cardano_donna.inc':donna,'cardano_curve.inc':curve,
        'cardano_arithmetic.inc':arithmetic,'cardano_hmac.inc':hmac,'pbkdf2_sha512.inc':pb})
    return selected

p=argparse.ArgumentParser();p.add_argument('--check',action='store_true');args=p.parse_args()
for name in ['cardano','crypton']:
    base=root/'vendor'/name;m=json.loads((base/'manifest.json').read_text())
    expected=set(m['sha256'])|{'manifest.json'}
    assert {str(p.relative_to(base)) for p in base.rglob('*') if p.is_file()}==expected
    for path,digest in m['sha256'].items():assert hashlib.sha256((base/path).read_bytes()).hexdigest()==digest,path
for name,content in generate().items():
    content='/* Generated by tools/select-ed25519-bip32.py; see vendor manifests. */\n'+content
    if args.check:assert (root/name).read_text()==content,name
    else:(root/name).write_text(content)
print('Cardano/Crypton selection verified' if args.check else 'Cardano/Crypton selection generated')
