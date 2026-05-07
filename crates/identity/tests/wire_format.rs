//! Wire-format compatibility tests for the identity bundle.
//!
//! These tests open checked-in v1 bundle fixtures and assert they
//! deserialize to the expected identity contents. The fixtures must
//! NEVER be edited by hand -- they exist precisely to catch
//! accidental wire-format drift caused by:
//!
//! - struct field reordering that changes bincode field layout
//!   (bincode is positional with default serde attrs);
//! - bincode major-version bumps;
//! - KdfParams / Envelope changes that shift byte layout;
//! - changes to the `BUNDLE_MAGIC` constant or `BUNDLE_VERSION`.
//!
//! What these tests do **NOT** catch:
//!
//! - Pure field renames on `#[derive(Serialize, Deserialize)]` types
//!   without `#[serde(rename = ...)]`. bincode is positional, so
//!   `salt: Vec<u8>` -> `nonce_seed: Vec<u8>` is wire-invisible if
//!   the type and order stay the same.
//! - Semantic changes that don't move bytes (e.g. tightening
//!   validation rules in a way that makes an existing valid bundle
//!   newly rejected at a higher layer).
//!
//! If a wire-format change is intentional, both regenerate the
//! fixtures (via the `regenerate_wire_format_fixtures` ignored test
//! in `src/lib.rs`) AND add a legacy-aware migration path so
//! existing user bundles on disk continue to open.
//!
//! See `crates/freenet-git/legacy_contracts.toml` for the analogous
//! mechanism on the contract side. Tracking issue for v2 read-side
//! migration: freenet/freenet-git#31.

use std::path::PathBuf;

use freenet_git_identity::{read_bundle, BundleError, BUNDLE_VERSION};

/// pubkey hex of the identity stored in the checked-in fixtures.
/// Derived from `FIXTURE_USER_SEED = [0x42; 32]` (see
/// `freenet_git_identity::tests::FIXTURE_USER_SEED`); the seed and
/// the resulting bytes are deterministic, so a regen run produces
/// this exact value. Anti-tamper: re-running
/// `regenerate_wire_format_fixtures` and comparing this hex to the
/// printed output verifies the fixtures were not hand-edited.
const EXPECTED_PUBKEY_HEX: &str =
    "2152f8d19b791d24453242e15f2eab6cb7cffa7b6a5ed30097960e069881db12";

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
    // Match on the variant rather than the Display string so a future
    // reword of `BundleError::Decrypt`'s message doesn't silently
    // break the test (or, worse, make it pass for the wrong reason).
    assert!(
        matches!(err, BundleError::Decrypt),
        "expected BundleError::Decrypt, got: {err:?}"
    );
}

#[test]
fn v1_encrypted_fixture_rejects_empty_passphrase() {
    // Defends against the inverse of #16's --no-passphrase fix:
    // an encrypted bundle must NOT silently open with the empty
    // passphrase (which is the unencrypted-mode sentinel).
    let err = read_bundle(&fixture_path("v1-encrypted.bundle"), "")
        .expect_err("encrypted bundle must reject empty passphrase");
    assert!(
        matches!(err, BundleError::Decrypt),
        "expected BundleError::Decrypt, got: {err:?}"
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
    assert!(
        matches!(err, BundleError::Decrypt),
        "expected BundleError::Decrypt, got: {err:?}"
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

/// Same value as `freenet_git_identity::tests::FIXTURE_USER_SEED`,
/// duplicated here because that module is `#[cfg(test)]` and so is
/// not visible to this integration test crate. Kept in sync by
/// `checked_in_pubkey_matches_deterministic_seed` below.
const FIXTURE_USER_SEED: [u8; 32] = [0x42; 32];

#[test]
fn future_version_bundle_is_rejected_at_public_api() {
    // Take a checked-in v1 bundle, bump the `version` field in the
    // header to BUNDLE_VERSION + 1, and confirm the public
    // `read_bundle` API hands back a structured `UnsupportedVersion`
    // error rather than choking on garbled ciphertext. This pins the
    // v1/v2 dispatch contract from freenet/freenet-git#31 at the
    // public-API boundary, complementing the in-crate
    // `rejects_future_bundle_version_with_structured_error` unit test.
    //
    // Using BUNDLE_VERSION + 1 (rather than a literal 2) keeps the
    // test self-healing: when v2 ships and BUNDLE_VERSION bumps to 2,
    // this test bumps the fixture's version field from 1 to 3, which
    // is still unsupported, and the dispatcher still rejects.
    let bytes = std::fs::read(fixture_path("v1-unencrypted.bundle")).unwrap();
    assert!(
        bytes.len() >= 12,
        "fixture is suspiciously short ({} bytes)",
        bytes.len()
    );

    // bincode 1.3 default config places the 8-byte magic at [0..8] and
    // the u32 version little-endian at [8..12]. Confirm we are about
    // to tamper with the version field (and not some other byte).
    let version_le = &bytes[8..12];
    assert_eq!(
        version_le,
        &1u32.to_le_bytes(),
        "v1 fixture must have version=1 at offset 8 in LE"
    );

    let future = BUNDLE_VERSION
        .checked_add(1)
        .expect("BUNDLE_VERSION + 1 must not overflow");
    let mut tampered = bytes.clone();
    tampered[8..12].copy_from_slice(&future.to_le_bytes());

    // Write the tampered bytes to a temp file so we exercise
    // `read_bundle` (the public API) rather than an internal helper.
    let dir = tempfile::tempdir().unwrap();
    let p = dir.path().join("future-version.bundle");
    std::fs::write(&p, &tampered).unwrap();

    let err = read_bundle(&p, "")
        .expect_err("synthetic future-version bundle must be rejected by the public API");
    match err {
        BundleError::UnsupportedVersion {
            found,
            max_supported,
        } => {
            assert_eq!(found, future);
            assert_eq!(max_supported, BUNDLE_VERSION);
        }
        other => panic!("expected UnsupportedVersion, got {other:?}"),
    }
}

#[test]
fn checked_in_pubkey_matches_deterministic_seed() {
    // Belt-and-braces anti-tamper check: derive the pubkey from the
    // documented seed and confirm it matches what's actually in the
    // checked-in encrypted fixture. If someone hand-edits the
    // fixture's identity but updates `EXPECTED_PUBKEY_HEX` to match,
    // the cross-check here against the seed-derived value catches it.
    use ed25519_dalek::SigningKey;

    let from_seed = SigningKey::from_bytes(&FIXTURE_USER_SEED)
        .verifying_key()
        .to_bytes();
    assert_eq!(
        pubkey_hex(&from_seed),
        EXPECTED_PUBKEY_HEX,
        "pubkey derived from FIXTURE_USER_SEED must match the constant"
    );

    let bundle = read_bundle(&fixture_path("v1-encrypted.bundle"), "test-passphrase").unwrap();
    assert_eq!(
        bundle.public_key,
        from_seed.to_vec(),
        "checked-in encrypted fixture's pubkey must equal the seed-derived pubkey"
    );

    let bundle = read_bundle(&fixture_path("v1-unencrypted.bundle"), "").unwrap();
    assert_eq!(
        bundle.public_key,
        from_seed.to_vec(),
        "checked-in unencrypted fixture's pubkey must equal the seed-derived pubkey"
    );
}
