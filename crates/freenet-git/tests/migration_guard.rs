//! The re-key guard: "if the committed repo-contract WASM changed, its
//! previous hash must be registered in `legacy_contracts.toml`".
//!
//! `contracts/repo-contract.wasm` is a checked-in artifact, and CI
//! neither rebuilds nor verifies it (freenet-git#63) — so before this
//! guard, nothing stopped a PR from swapping the WASM (a re-key of
//! EVERY repo on the network) without registering the outgoing hash,
//! which would strand all existing repos with no migration path. That
//! is the exact failure `freenet-migrate-build`'s `check_migration_guard`
//! exists for; this wires it to the committed artifact.
//!
//! The pinned hash below is the "base" side of the guard (what River's
//! CI derives from the git merge-base). Pinning it as a literal keeps
//! the check hermetic: a test run needs no git history, only the
//! working tree.

use freenet_migrate_build::{check_migration_guard, code_hash_b58, Component, Registry};

/// BLAKE3 of the committed `contracts/repo-contract.wasm`, base58
/// (stdlib's string form). Update this ONLY as step 3 of the re-key
/// procedure documented in `legacy_contracts.toml` — after registering
/// the outgoing hash as a `[[contract]]` predecessor.
const PINNED_CURRENT_WASM_HASH_B58: &str = "C1bhzU2LbdyNt8jBAZNpcqqPeQvpcWU3hkYUQ1ZfZnNW";

const COMMITTED_WASM: &[u8] = include_bytes!("../contracts/repo-contract.wasm");

/// A changed WASM artifact without a registry entry for the outgoing
/// hash must fail. An unchanged artifact passes; a changed artifact
/// passes only once the pinned (now previous) hash is registered.
#[test]
fn a_wasm_change_requires_registering_the_outgoing_hash() {
    let head = code_hash_b58(COMMITTED_WASM);
    let registry = Registry::from_toml_str(include_str!("../legacy_contracts.toml"))
        .expect("the shipped registry must parse");

    let outcome = check_migration_guard(
        Component::Contract,
        PINNED_CURRENT_WASM_HASH_B58,
        &head,
        &registry,
    )
    .expect("both hashes decode");

    assert!(
        outcome.passes(),
        "contracts/repo-contract.wasm changed (its BLAKE3 is now {head}), but the \
         outgoing hash {PINNED_CURRENT_WASM_HASH_B58} is not registered in \
         legacy_contracts.toml. Shipping this re-keys EVERY repo on the network \
         and strands their state with no migration path. Follow the procedure in \
         legacy_contracts.toml: (1) add a [[contract]] entry for \
         {PINNED_CURRENT_WASM_HASH_B58}, (2) update PINNED_CURRENT_WASM_HASH_B58 \
         in this test to {head}. Guard advice: {:?}",
        outcome.advice(Component::Contract),
    );
}

/// The pin itself must track the committed artifact, or the guard
/// above rots: with a stale pin, a SECOND re-key would compare against
/// a hash two generations back and miss the unregistered intermediate
/// one. Together the two tests form the ratchet: a WASM change first
/// fails here; registering the outgoing hash (test above) and then
/// updating the pin is the only path back to green.
///
/// Honest limit: updating the pin and the WASM in one commit WITHOUT
/// registering would slip past both tests (the guard then reads
/// "unchanged"). The failure messages make the right order explicit;
/// a git-history-based base (what River's CI derives) would close
/// that hole at the cost of tests depending on git state.
#[test]
fn the_pinned_hash_tracks_the_committed_wasm() {
    let head = code_hash_b58(COMMITTED_WASM);
    assert_eq!(
        head, PINNED_CURRENT_WASM_HASH_B58,
        "contracts/repo-contract.wasm changed. FIRST register the outgoing hash \
         {PINNED_CURRENT_WASM_HASH_B58} as a [[contract]] entry in \
         legacy_contracts.toml (a_wasm_change_requires_registering_the_outgoing_hash \
         checks that), THEN update PINNED_CURRENT_WASM_HASH_B58 to {head}"
    );
}

/// The CURRENT WASM's hash must never itself be registered as a
/// predecessor: a registered current hash means either the registry got
/// a stale/wrong entry, or a "re-key" shipped the same bytes — both are
/// registry mistakes, and the probe would GET the current key twice.
#[test]
fn the_current_wasm_hash_is_not_a_registered_predecessor() {
    let head = code_hash_b58(COMMITTED_WASM);
    let registry = Registry::from_toml_str(include_str!("../legacy_contracts.toml"))
        .expect("the shipped registry must parse");
    assert!(
        registry.find_contract_code_hash(&head).is_none(),
        "the committed WASM's own hash {head} is registered as a predecessor \
         generation — remove the stale entry (predecessors are RETIRED hashes only)"
    );
}
