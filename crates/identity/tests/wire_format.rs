//! Wire-format compatibility tests for the identity bundle.
//!
//! These tests open checked-in v1 bundle fixtures and assert they
//! deserialize to the expected identity contents. The fixtures must
//! NEVER be edited by hand -- they exist precisely to catch
//! accidental wire-format drift caused by:
//!
//! - serde attribute reorderings that change bincode field layout,
//! - bincode major-version bumps,
//! - KdfParams / Envelope struct field reordering,
//! - changes to the `BUNDLE_MAGIC` constant or `BUNDLE_VERSION`.
//!
//! If a wire-format change is intentional, both regenerate the
//! fixtures (via the `regenerate_wire_format_fixtures` ignored test
//! in `src/lib.rs`) AND add a legacy-aware migration path so
//! existing user bundles on disk continue to open.
//!
//! See `crates/freenet-git/legacy_contracts.toml` for the analogous
//! mechanism on the contract side.

use std::path::PathBuf;

use freenet_git_identity::read_bundle;

/// pubkey hex of the identity stored in the checked-in fixtures.
/// Update this constant when regenerating fixtures (the generator
/// prints the new value to stdout).
const EXPECTED_PUBKEY_HEX: &str =
    "a550729cf77e2d44da3665dbd4280c3f73ea1e4ba71914231dfd5d721f6cfa4c";

const EXPECTED_NAME: &str = "Fixture User";
const EXPECTED_EMAIL: &str = "fixture@example.com";
const EXPECTED_REPO_PREFIX: &str = "fixture-prefix";
const EXPECTED_REPO_DISPLAY_NAME: &str = "fixture-repo";

fn fixture_path(name: &str) -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests")
        .join("fixtures")
        .join(name)
}

fn pubkey_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn v1_encrypted_fixture_opens_with_correct_passphrase() {
    let bundle = read_bundle(&fixture_path("v1-encrypted.bundle"), "test-passphrase")
        .expect("v1-encrypted.bundle must open with the documented passphrase");

    assert_eq!(bundle.name, EXPECTED_NAME);
    assert_eq!(bundle.email, EXPECTED_EMAIL);
    assert_eq!(pubkey_hex(&bundle.public_key), EXPECTED_PUBKEY_HEX);
    assert_eq!(bundle.repos.len(), 1, "fixture has one registered repo");
    assert_eq!(bundle.repos[0].prefix, EXPECTED_REPO_PREFIX);
    assert_eq!(bundle.repos[0].display_name, EXPECTED_REPO_DISPLAY_NAME);
}

#[test]
fn v1_encrypted_fixture_rejects_wrong_passphrase() {
    let err = read_bundle(&fixture_path("v1-encrypted.bundle"), "wrong-passphrase")
        .expect_err("v1-encrypted.bundle must reject a wrong passphrase");
    let msg = format!("{err}");
    assert!(
        msg.contains("decryption failed") || msg.contains("Decryption"),
        "expected a decryption error, got: {msg}"
    );
}

#[test]
fn v1_encrypted_fixture_rejects_empty_passphrase() {
    // Defends against the inverse of #16's --no-passphrase fix:
    // an encrypted bundle must NOT silently open with the empty
    // passphrase (which is the unencrypted-mode sentinel).
    let err = read_bundle(&fixture_path("v1-encrypted.bundle"), "")
        .expect_err("encrypted bundle must reject empty passphrase");
    let msg = format!("{err}");
    assert!(
        msg.contains("decryption failed") || msg.contains("Decryption"),
        "expected a decryption error, got: {msg}"
    );
}

#[test]
fn v1_unencrypted_fixture_opens_with_empty_passphrase() {
    let bundle = read_bundle(&fixture_path("v1-unencrypted.bundle"), "")
        .expect("v1-unencrypted.bundle must open with empty passphrase");

    assert_eq!(bundle.name, EXPECTED_NAME);
    assert_eq!(bundle.email, EXPECTED_EMAIL);
    assert_eq!(pubkey_hex(&bundle.public_key), EXPECTED_PUBKEY_HEX);
    assert_eq!(bundle.repos.len(), 1);
    assert_eq!(bundle.repos[0].prefix, EXPECTED_REPO_PREFIX);
    assert_eq!(bundle.repos[0].display_name, EXPECTED_REPO_DISPLAY_NAME);
}

#[test]
fn v1_unencrypted_fixture_rejects_real_passphrase() {
    // Inverse of the empty-encrypted check: an unencrypted bundle
    // must NOT silently open if someone supplies a real passphrase.
    let err = read_bundle(&fixture_path("v1-unencrypted.bundle"), "test-passphrase")
        .expect_err("unencrypted bundle must reject a non-empty passphrase");
    let msg = format!("{err}");
    assert!(
        msg.contains("decryption failed") || msg.contains("Decryption"),
        "expected a decryption error, got: {msg}"
    );
}

#[test]
fn fixtures_have_distinct_bytes() {
    // Sanity: encrypted and unencrypted bundles for the same identity
    // produce different on-disk bytes. Otherwise the encryption layer
    // would be a no-op even with a real passphrase.
    let enc = std::fs::read(fixture_path("v1-encrypted.bundle")).unwrap();
    let unenc = std::fs::read(fixture_path("v1-unencrypted.bundle")).unwrap();
    assert_ne!(enc, unenc);
}
