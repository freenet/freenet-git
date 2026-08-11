//! Library half of `freenet-git`. Holds the bits that are easier to test
//! when not wrapped in `clap`.

#![deny(unsafe_code)]
#![warn(missing_docs)]

pub mod chunked;
pub mod ids;
pub mod local_pack;
pub mod pack_cache;
pub mod state_init;
pub mod url;
pub mod wsclient;

/// The compiled `repo-contract` WASM bytes, embedded at build time.
///
/// Bundling the WASM means a `cargo install freenet-git` user does not
/// have to download or compile contracts separately. The bytes are pinned
/// against the `freenet-git` package version: every release carries the
/// exact contract WASM it was tested against.
pub const REPO_CONTRACT_WASM: &[u8] = include_bytes!("../contracts/repo-contract.wasm");

/// The compiled `pack-contract` WASM bytes, embedded at build time.
pub const PACK_CONTRACT_WASM: &[u8] = include_bytes!("../contracts/pack-contract.wasm");

/// Prior repo-contract generations for permissionless migration.
///
/// When a new freenet-git release ships a different repo-contract
/// WASM, the contract key for any given prefix changes. The on-host
/// helper falls back through `CONTRACT_LINEAGE` (newest generation
/// first) when a fetch hits the current key and finds nothing — a
/// prior version's contract may still hold the user's data, in which
/// case we GET it from the legacy key and PUT it to the current key.
///
/// Generated at build time by `freenet-migrate-build` from
/// `legacy_contracts.toml`; see that file and `build.rs`. The codegen
/// also emits an (empty) `DELEGATE_LINEAGE`; freenet-git has no
/// delegates, so it is unused by design.
// The generated file carries no per-const rustdoc (it is machine-written
// by freenet-migrate-build), so exempt it from this crate's missing_docs
// lint; the module doc above documents both consts.
#[allow(missing_docs)]
pub mod legacy {
    include!(concat!(env!("OUT_DIR"), "/legacy_contracts.rs"));
}
