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

/// Prior repo-contract WASM hashes for permissionless migration.
///
/// When a new freenet-git release ships a different repo-contract
/// WASM, the contract key for any given prefix changes. The on-host
/// helper falls back through these hashes when a fetch hits the
/// current key and finds nothing — the prior version's contract may
/// still hold the user's data, in which case we GET it from the
/// legacy key and PUT it to the current key.
///
/// See `legacy_contracts.toml` and `build.rs` for how this is
/// populated.
pub mod legacy {
    include!(concat!(env!("OUT_DIR"), "/legacy_contracts.rs"));
}
