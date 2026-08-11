//! Exercise the *other* half of the legacy-contract machinery: the
//! build-time registry reader that turns `legacy_contracts.toml` into
//! the `CONTRACT_LINEAGE` const the client walks.
//!
//! `tests/legacy_fallback.rs` covers what happens once a generation is
//! in that const. This file covers how a generation gets there. Since
//! the freenet-migrate adoption, the parsing/validation/codegen is
//! `freenet-migrate-build`'s (a dev-dependency here, the same crate
//! `build.rs` runs) — these tests drive it through the same
//! `codegen().registry(..)` entry point `build.rs` uses, with this
//! repo's own registry schema and consumers, so an upstream behaviour
//! change that would break freenet-git's registry fails a test run
//! here rather than surfacing at the first real re-key.
//!
//! The registry is parsed at compile time, so a mistake here is a
//! mistake baked into every published binary — and it would surface
//! only on the first real re-key, which is exactly when users' repos
//! depend on it.

use freenet_git_cli::legacy::ContractLineageEntry;
use freenet_migrate_build::{codegen, BuildError, Registry};
use freenet_stdlib::prelude::{ContractCode, ContractInstanceId, Parameters};
use std::io::Write as _;

/// Synthetic stand-in for a previously-shipped repo-contract WASM.
fn synthetic_wasm(tag: u8) -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0synthetic-repo-contract-".to_vec();
    bytes.extend(std::iter::repeat_n(tag, 512));
    bytes
}

fn hex_of(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

/// Run the registry text through the same `codegen().registry(path)`
/// pipeline `build.rs` runs (including the file read), returning the
/// generated Rust source.
fn generate(toml: &str) -> Result<String, BuildError> {
    let mut file = tempfile::NamedTempFile::new().expect("tempfile");
    file.write_all(toml.as_bytes()).expect("write registry");
    codegen()
        .registry(file.path())
        // Match build.rs: consts name their entry types through the
        // crate-local `legacy` module, not the (unlinkable) runtime crate.
        .crate_path("crate::legacy")
        .generate_string()
}

/// Pull each emitted entry's `(generation, code_hash)` back out of the
/// generated Rust source.
///
/// Reading the emitted text rather than trusting the parsed `Registry`
/// is the point: the parser could be perfect while the generator
/// emitted the bytes reversed, truncated, or in the wrong entry, and
/// nothing downstream would notice until a migration probed a key that
/// has never existed.
fn extract_generated_entries(generated: &str) -> Vec<(u32, [u8; 32])> {
    let mut out = Vec::new();
    for line in generated.lines() {
        // Entry lines look like
        // `    crate::legacy::ContractLineageEntry { generation: 1u32,
        //  code_hash: [12, 34, …], note: "…" },`.
        let Some(rest) = line
            .trim_start()
            .strip_prefix("crate::legacy::ContractLineageEntry { generation: ")
        else {
            continue;
        };
        let generation: u32 = rest
            .split("u32")
            .next()
            .expect("generation literal")
            .parse()
            .expect("generation must be a u32 literal");
        let bytes_start = rest.find('[').expect("code_hash array literal") + 1;
        let bytes_end = rest.find(']').expect("code_hash array literal end");
        let bytes: Vec<u8> = rest[bytes_start..bytes_end]
            .split(',')
            .map(|token| token.trim().parse().expect("byte literal is decimal"))
            .collect();
        let arr: [u8; 32] = bytes
            .try_into()
            .expect("generated array literal must be exactly 32 bytes");
        out.push((generation, arr));
    }
    out
}

/// The whole chain, end to end: a hash written into
/// `legacy_contracts.toml` must come out of the generated code as the
/// same 32 bytes, and those bytes must derive the same contract key
/// that the predecessor WASM itself would have produced.
///
/// The final assertion is the one that matters. It compares against
/// `ContractInstanceId::from_params_and_code` over the original WASM —
/// the stdlib's own derivation — so a byte-order or truncation bug
/// anywhere in TOML → parse → codegen → `wsclient::legacy_instance_id`
/// shows up as a key mismatch rather than as a self-consistent pass.
#[test]
fn a_registry_entry_survives_the_trip_to_a_probeable_contract_key() {
    let legacy_wasm = synthetic_wasm(0x1E);
    let legacy_hash = *blake3::hash(&legacy_wasm).as_bytes();

    let toml = format!(
        "# a comment that must be ignored\n\
         [[contract]]\n\
         generation = 1\n\
         code_hash  = \"{}\"\n\
         note       = \"0.1.3 repo-contract\"\n",
        hex_of(&legacy_hash)
    );

    let generated = generate(&toml).expect("a well-formed registry must generate");
    let emitted = extract_generated_entries(&generated);
    assert_eq!(
        emitted,
        vec![(1, legacy_hash)],
        "codegen must emit the generation and the exact hash bytes"
    );
    assert!(
        generated.contains("\"0.1.3 repo-contract\""),
        "the note is what a migration log line prints; generated:\n{generated}"
    );

    // The payoff: the emitted bytes must address the same contract the
    // predecessor WASM did.
    let params = freenet_git_types::RepoParams {
        prefix: "abc1234567".to_string(),
    }
    .to_bytes();
    let entry = ContractLineageEntry {
        generation: emitted[0].0,
        code_hash: emitted[0].1,
        note: "0.1.3 repo-contract",
    };
    let from_registry = freenet_git_cli::wsclient::legacy_instance_id(&entry, &params);
    let from_wasm = ContractInstanceId::from_params_and_code(
        Parameters::from(params.clone()),
        ContractCode::from(legacy_wasm),
    );
    assert_eq!(
        from_registry, from_wasm,
        "a registry entry must probe the contract key the predecessor WASM actually had"
    );
}

/// Multiple entries keep their registry (file) order in the emitted
/// slice and stay distinct. `GetSource::Legacy { index }` indexes back
/// into this slice to name the generation in a log line — probe order
/// is generation-descending, but the INDEX contract is slice order, so
/// a reordering here would mislabel (or panic) a real migration's log
/// line.
#[test]
fn multiple_entries_keep_registry_order() {
    let hashes: Vec<[u8; 32]> = (0..3)
        .map(|i| *blake3::hash(&synthetic_wasm(0xA0 + i)).as_bytes())
        .collect();
    let mut toml = String::from("# registry\n");
    for (i, h) in hashes.iter().enumerate() {
        toml.push_str(&format!(
            "\n[[contract]]\ngeneration = {}\ncode_hash = \"{}\"\nnote = \"0.1.{i} repo-contract\"\n",
            i + 1,
            hex_of(h)
        ));
    }

    let emitted = extract_generated_entries(&generate(&toml).expect("well-formed registry"));
    let expected: Vec<(u32, [u8; 32])> = hashes
        .iter()
        .enumerate()
        .map(|(i, h)| (i as u32 + 1, *h))
        .collect();
    assert_eq!(
        emitted, expected,
        "generated slice must preserve the order entries appear in the registry"
    );
}

/// The shipped registry is empty and must generate an empty slice
/// rather than, say, a syntax error or a phantom entry. This asserts on
/// the *actually compiled* const, so it is also the canary that fires
/// the day the first real entry is added: when it does, update the
/// expectation (and re-check the migration path before releasing) —
/// do not delete the test.
#[test]
fn a_comments_only_registry_generates_an_empty_array() {
    let shipped = include_str!("../legacy_contracts.toml");
    let registry = Registry::from_toml_str(shipped).expect("the shipped registry must parse");
    assert!(
        registry.contract.is_empty(),
        "the shipped registry has no [[contract]] rows; if this fires, an entry \
         was added and the fallback is now live — good, but re-check the \
         migration path (and tests/migration_guard.rs) before releasing"
    );
    assert!(
        freenet_git_cli::legacy::CONTRACT_LINEAGE.is_empty(),
        "the compiled CONTRACT_LINEAGE must match the (empty) shipped registry; \
         a non-empty const from an empty registry means the build is reading a \
         different file than ships"
    );
    assert!(
        freenet_git_cli::legacy::DELEGATE_LINEAGE.is_empty(),
        "freenet-git has no delegates; a delegate row in legacy_contracts.toml \
         is a mistake"
    );
}

/// A malformed entry must fail the build loudly. The dangerous
/// alternative is silently dropping it: the registry would look
/// populated, the binary would carry no such hash, and the migration
/// would quietly not happen.
#[test]
fn an_entry_without_a_hash_fails_the_build() {
    let err = generate("[[contract]]\ngeneration = 1\nnote = \"0.1.3 repo-contract\"\n")
        .expect_err("a [[contract]] row without code_hash must fail");
    let msg = err.to_string();
    assert!(
        msg.contains("code_hash"),
        "the error must name the missing field: {msg}"
    );
}

/// Likewise for a hash that is neither 64 hex chars nor 32 bytes of
/// base58 — a truncated paste is the realistic version of this mistake.
#[test]
fn a_truncated_hash_fails_the_build() {
    let err = generate("[[contract]]\ngeneration = 1\ncode_hash = \"deadbeef\"\nnote = \"oops\"\n")
        .expect_err("a truncated hash must fail");
    assert!(
        matches!(err, BuildError::InvalidCodeHash { .. }),
        "expected InvalidCodeHash, got: {err}"
    );
}

/// Two rows with the same generation number must fail the build: the
/// probe order is generation-descending, so a duplicate makes the
/// anti-rollback ordering ambiguous. (The hand-rolled parser this
/// replaced would have accepted it silently.)
#[test]
fn a_duplicate_generation_fails_the_build() {
    let h1 = hex_of(blake3::hash(&synthetic_wasm(0xB1)).as_bytes());
    let h2 = hex_of(blake3::hash(&synthetic_wasm(0xB2)).as_bytes());
    let toml = format!(
        "[[contract]]\ngeneration = 1\ncode_hash = \"{h1}\"\n\
         [[contract]]\ngeneration = 1\ncode_hash = \"{h2}\"\n"
    );
    let err = generate(&toml).expect_err("duplicate generations must fail");
    assert!(
        matches!(err, BuildError::DuplicateGeneration { .. }),
        "expected DuplicateGeneration, got: {err}"
    );
}
