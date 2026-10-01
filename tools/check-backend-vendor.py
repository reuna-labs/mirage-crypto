#!/usr/bin/env python3
"""Check every vendored source against its pinned import manifest."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

root = Path(__file__).resolve().parent.parent
for name in ("secp256k1", "bls12-381", "blake3", "poseidon", "sr25519"):
    base = root / name / "vendor"
    manifest = json.loads((base / "manifest.json").read_text())
    actual_files = {str(p.relative_to(base)) for p in base.rglob("*") if p.is_file()}
    expected_files = set(manifest["sha256"]) | {"dune", "manifest.json"}
    if actual_files != expected_files:
        raise SystemExit(f"vendor inventory mismatch: {name}: {actual_files ^ expected_files}")
    for filename, expected in manifest["sha256"].items():
        actual = hashlib.sha256((base / filename).read_bytes()).hexdigest()
        if actual != expected:
            raise SystemExit(f"vendor mismatch: {name}/{filename}")
    print(f"{name}: {manifest['commit']} ({len(manifest['sha256'])} files)")

subprocess.run([sys.executable, str(root / "tools/select-ed25519-bip32.py"), "--check"], check=True)
