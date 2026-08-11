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

/// Reject any top-level table the registry schema does not define.
///
/// `freenet-migrate-build` 0.2.0 derives `Registry` with `#[serde(default)]` on
/// both fields and no `deny_unknown_fields` (freenet/freenet-migrate#20), so a
/// row written under the wrong table name deserializes to an EMPTY registry and
/// the build succeeds. The likeliest wrong name is `[[entry]]` — the format this
/// very file used before adopting the crate, and the one older procedure text
/// still describes.
///
/// That is the failure this whole mechanism exists to prevent, arriving through
/// the parser: an empty lineage means the probe walk asks nobody, so a user's
/// repo is intact on the network and permanently unreachable, with no error.
///
/// This repo is unusually exposed. Its registry is legitimately EMPTY during the
/// pre-1.0 phase, so an "is the lineage empty?" canary cannot tell a correct
/// empty file from one full of unparsed rows. Checking the table names is the
/// only local signal that distinguishes them.
///
/// Red input: add an `[[entry]]` block to the registry and build.
fn reject_unknown_tables(toml_src: &str, path: &str) {
    const KNOWN: [&str; 2] = ["contract", "delegate"];
    for (lineno, raw) in toml_src.lines().enumerate() {
        let line = raw.trim();
        let Some(name) = line
            .strip_prefix("[[")
            .and_then(|r| r.strip_suffix("]]"))
            .map(str::trim)
        else {
            continue;
        };
        assert!(
            KNOWN.contains(&name),
            "{path}:{}: unknown table `[[{name}]]`.\n\n\
             The registry schema defines only [[contract]] and [[delegate]]. \
             Rows under any other name are SILENTLY IGNORED by the parser \
             (freenet/freenet-migrate#20), which would compile an EMPTY \
             migration lineage into the binary: the fallback would then probe \
             no predecessor at all and every repo published under an older \
             contract WASM would be unreachable, with no error at any layer.\n\n\
             If this was an `[[entry]]` block, it is the pre-adoption format — \
             rewrite it as [[contract]] with an explicit `generation`.",
            lineno + 1,
        );
    }
}

fn main() {
    let registry = "legacy_contracts.toml";
    // Guard BEFORE codegen: the parser cannot report what it silently drops.
    let src = std::fs::read_to_string(registry).unwrap_or_else(|e| panic!("read {registry}: {e}"));
    reject_unknown_tables(&src, registry);

    freenet_migrate_build::codegen()
        .registry(registry)
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
