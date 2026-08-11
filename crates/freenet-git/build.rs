//! Build script: turns `legacy_contracts.toml` into the `CONTRACT_LINEAGE`
//! const the binary walks for permissionless migration on `git fetch`.
//!
//! The parsing, hash validation, and codegen are `freenet-migrate-build`'s
//! (the shared Freenet upgrade-migration machinery): a malformed or duplicate
//! hash is a build failure, never a silently-skipped entry. The codegen
//! declares `cargo:rerun-if-changed` for the registry file itself, so a
//! registry edit always regenerates the const.
//!
//! See `legacy_contracts.toml` for the registry format and rationale.

fn main() {
    freenet_migrate_build::codegen()
        .registry("legacy_contracts.toml")
        // The emitted consts name their entry types through this path:
        // `crate::legacy::{Contract,Delegate}LineageEntry`, defined in
        // src/lib.rs. The freenet-migrate RUNTIME crate (whose types the
        // codegen references by default) cannot be linked here — see the
        // workspace Cargo.toml on the stdlib 0.6/0.8 `__frnt_set_id`
        // duplicate-symbol conflict.
        .crate_path("crate::legacy")
        .out_file("legacy_contracts.rs")
        .emit()
        .expect("parse legacy_contracts.toml and generate lineage consts");
}
