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
///
/// The entry types are defined here rather than imported from the
/// `freenet-migrate` runtime crate (whose codegen emits the same field
/// layout): that crate is built against freenet-stdlib 0.8.x, and
/// stdlib's `__frnt_set_id` is an unconditional `#[no_mangle]` export,
/// so it cannot link alongside this workspace's 0.6.0 (see the
/// workspace Cargo.toml). `build.rs` points the codegen's `crate_path`
/// at this module instead.
// The generated file carries no per-const rustdoc (it is machine-written
// by freenet-migrate-build), so exempt it from this crate's missing_docs
// lint; the module doc above documents both consts.
#[allow(missing_docs)]
pub mod legacy {
    /// One predecessor generation of the repo contract. Field-compatible
    /// with `freenet_migrate::ContractLineageEntry` (the shared registry
    /// shape), so a future move to the runtime crate is a type swap.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct ContractLineageEntry {
        /// Monotonic generation number (older = smaller). The fallback
        /// probes highest generation first.
        pub generation: u32,
        /// The 32-byte code hash `blake3(wasm)`, decoded and validated
        /// at build time.
        pub code_hash: [u8; 32],
        /// Human note (which release, why retired) — printed in the
        /// migration log line.
        pub note: &'static str,
    }

    /// One predecessor generation of a delegate. freenet-git has no
    /// delegates; this exists only because the codegen emits an (empty)
    /// `DELEGATE_LINEAGE` const alongside the contract one.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct DelegateLineageEntry {
        /// Monotonic generation number.
        pub generation: u32,
        /// The 32-byte code hash `blake3(wasm)`.
        pub code_hash: [u8; 32],
        /// The delegate's historical on-network key.
        pub delegate_key: [u8; 32],
        /// Whether `delegate_key` predates the standard derivation.
        pub irregular_key: bool,
        /// Human note.
        pub note: &'static str,
    }

    include!(concat!(env!("OUT_DIR"), "/legacy_contracts.rs"));
}
