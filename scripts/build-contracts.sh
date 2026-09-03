#!/usr/bin/env bash
#
# Deterministic rebuild of the two contract WASM artifacts, and the BLAKE3
# hashes of the result.
#
# WHY THIS EXISTS
#
# A Freenet contract's on-network address is
# `BLAKE3(BLAKE3(wasm) || serialize(params))`, so the compiled bytes ARE the
# address. `crates/freenet-git/contracts/*.wasm` are checked-in artifacts and
# the shipped binary embeds them verbatim (`src/lib.rs`, `include_bytes!`), so
# nothing about a normal `cargo build` reveals that a change to the workspace
# — a dependency bump in `Cargo.lock` most of all — has moved what those
# sources now compile to. The drift accumulates silently until someone
# rebuilds, and then a single commit ships an intended change plus however
# many months of unnoticed dependency drift, re-keying every repo and pack on
# the network at once.
#
# `scripts/check-contract-wasm.sh` runs this and compares the result against
# the recorded hashes in `crates/freenet-git/contracts/wasm-hashes.txt`, so
# that drift becomes a red CI job on the PR that introduces it.
#
# DETERMINISM
#
# Two things have to hold for the comparison to mean anything.
#
#   1. Same inputs, same bytes. `rust-toolchain.toml` pins the compiler and
#      `--locked` pins every dependency version, which is what makes a moved
#      hash attributable to a real input change rather than to noise.
#
#   2. Same bytes on any machine. `panic = "abort"` still records panic
#      locations, so source paths are embedded in the output: an unremapped
#      build on a contributor's machine and one on a CI runner differ purely
#      because `$HOME` differs. Both prefixes are remapped below to fixed
#      strings so that a contributor and CI compute the same hash.
#
# RUSTFLAGS is set rather than appended to. CI exports `-D warnings`
# workspace-wide; lint level does not affect codegen today, but this script's
# entire job is byte identity and the next flag added to that env block might.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

cargo_home="${CARGO_HOME:-$HOME/.cargo}"

# Deleted first, so a build that fails to write an artifact surfaces as a
# missing file rather than as a stale one from a previous run silently
# passing the comparison.
out_dir="target/wasm32-unknown-unknown/release"
rm -f "$out_dir/freenet_git_repo_contract.wasm" "$out_dir/freenet_git_pack_contract.wasm"

RUSTFLAGS="--remap-path-prefix=$root=/freenet-git --remap-path-prefix=$cargo_home=/cargo" \
  cargo build --locked --release --target wasm32-unknown-unknown \
    -p freenet-git-repo-contract \
    -p freenet-git-pack-contract

for f in freenet_git_repo_contract.wasm freenet_git_pack_contract.wasm; do
  test -s "$out_dir/$f" || { echo "build produced no $out_dir/$f" >&2; exit 1; }
done
