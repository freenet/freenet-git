#!/usr/bin/env bash
#
# The contract-address gate: rebuild the contract WASM from source and verify
# that neither the checked-in artifacts nor the compiled-from-source bytes have
# moved without being recorded.
#
# See `crates/freenet-git/contracts/wasm-hashes.txt` for what each recorded
# hash means and why the two sets are distinct.
set -euo pipefail

root="$(git rev-parse --show-toplevel)"
cd "$root"

hashes="crates/freenet-git/contracts/wasm-hashes.txt"

# The artifact lines and the rebuild lines guard different things, so a
# deletion must not read as a pass. Pinning the count means dropping a line to
# get green fails instead, and the count is stated here rather than derived
# from the file, which would make the assertion vacuous.
expected_entries=4

command -v b3sum >/dev/null || {
  echo "b3sum not found; install with: cargo install b3sum --locked" >&2
  exit 1
}

"$root/scripts/build-contracts.sh"

entries="$(grep -vE '^[[:space:]]*(#|$)' "$hashes")"
count="$(printf '%s\n' "$entries" | wc -l)"
if [ "$count" -ne "$expected_entries" ]; then
  echo "$hashes lists $count hashes, expected $expected_entries." >&2
  echo "Every line guards a distinct artifact; removing one removes a check." >&2
  exit 1
fi

artifact_drift=0
rebuild_drift=0

while read -r want path; do
  if [ ! -f "$path" ]; then
    echo "MISSING  $path (recorded in $hashes but not present)" >&2
    exit 1
  fi
  got="$(b3sum --no-names "$path")"
  if [ "$got" = "$want" ]; then
    printf 'ok       %s\n' "$path"
    continue
  fi
  printf 'CHANGED  %s\n         recorded %s\n         actual   %s\n' "$path" "$want" "$got" >&2
  case "$path" in
    crates/freenet-git/contracts/*) artifact_drift=1 ;;
    *) rebuild_drift=1 ;;
  esac
done <<< "$entries"

if [ "$artifact_drift" = 1 ]; then
  cat >&2 <<'MSG'

::error::A checked-in contract artifact changed. This RE-KEYS live data.

The shipped binary embeds crates/freenet-git/contracts/*.wasm verbatim, and a
contract's address is BLAKE3(BLAKE3(wasm) || serialize(params)). Changing these
bytes gives every existing repo (repo-contract) or every existing pack
(pack-contract) a new address, and anything published under the old one is
unreachable except through a migration path.

If the change is deliberate, follow the procedure in
crates/freenet-git/legacy_contracts.toml: register the OUTGOING hash as a
[[contract]] predecessor, update PINNED_CURRENT_WASM_HASH_B58 in
crates/freenet-git/tests/migration_guard.rs, and update the corresponding line
in crates/freenet-git/contracts/wasm-hashes.txt. Note that pack-contract has no
legacy-migration path at all (issue #64), so re-keying it orphans history with
no fallback.
MSG
fi

if [ "$rebuild_drift" = 1 ]; then
  cat >&2 <<'MSG'

::error::The contract sources no longer compile to the recorded bytes.

Some build input moved: a dependency version in Cargo.lock (the usual cause, and
what a Dependabot PR does), the pinned compiler in rust-toolchain.toml, or the
contract crates or their workspace-internal dependencies.

Nothing has re-keyed yet — the checked-in artifacts are unchanged, so the
deployed addresses are unchanged. What changed is what the NEXT rebuild will
ship. Left unrecorded, that difference rides along silently inside whatever
future commit rebuilds the artifacts.

If the input change is wanted, run scripts/check-contract-wasm.sh locally and
copy the actual hashes into crates/freenet-git/contracts/wasm-hashes.txt in the
same PR, so the enlarged re-key is visible in review. If it is not wanted,
revert the input change instead.
MSG
fi

if [ "$artifact_drift" = 1 ] || [ "$rebuild_drift" = 1 ]; then
  exit 1
fi

# Reconciliation, reported rather than enforced: while issue #63 is open these
# deliberately differ, so this cannot be an assertion. It is printed because a
# gate that only ever says "ok" hides the one number a reader wants.
repo_artifact="$(b3sum --no-names crates/freenet-git/contracts/repo-contract.wasm)"
repo_rebuilt="$(b3sum --no-names target/wasm32-unknown-unknown/release/freenet_git_repo_contract.wasm)"
pack_artifact="$(b3sum --no-names crates/freenet-git/contracts/pack-contract.wasm)"
pack_rebuilt="$(b3sum --no-names target/wasm32-unknown-unknown/release/freenet_git_pack_contract.wasm)"

echo
for c in "repo:$repo_artifact:$repo_rebuilt" "pack:$pack_artifact:$pack_rebuilt"; do
  name="${c%%:*}"; rest="${c#*:}"; a="${rest%%:*}"; b="${rest#*:}"
  if [ "$a" = "$b" ]; then
    echo "$name-contract: deployed artifact matches source"
  else
    echo "$name-contract: deployed artifact is STALE vs source (tracked by issue #63)"
  fi
done
