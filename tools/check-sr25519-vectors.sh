#!/bin/sh
# Rust is only a development oracle; ordinary tests use checked-in fixtures.
set -eu
cd "$(dirname "$0")/.."
vector_tmp=$(mktemp)
trap 'rm -f "$vector_tmp"' EXIT HUP INT TERM
cargo run --locked --release --manifest-path tests/rust-sr25519/Cargo.toml > "$vector_tmp"
cmp tests/sr25519_vectors.tsv "$vector_tmp"
echo 'Rust Schnorrkel/Dalek fixtures reproduced exactly.'
