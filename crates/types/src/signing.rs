//! Signing helpers used by the `freenet-git` and `git-remote-freenet`
//! binaries. Behind the `signing` feature flag because contract WASM does
//! not need a full ed25519 signing key (it only verifies).

use ed25519_dalek::{Signer, SigningKey};

use crate::{
    signature_domain_key, signed_payload_acl_field, signed_payload_bundle_record,
    signed_payload_extension, signed_payload_optional_repo_key_field, signed_payload_ref_entry,
    signed_payload_ref_list_field, signed_payload_string_field, AclState, CommitHash,
    ExtensionEntry, ObjectBundle, ObjectBundleRecord, RefEntry, RefName, RepoKey, RepoParams,
    Signature, SignedField,
};

/// Produce a [`SignedField<String>`] for the `name`, `description`, or
/// `default_branch` fields. The `field_name` argument MUST match what
/// [`crate::validate_state`] expects for the corresponding field.
pub fn sign_string_field(
    params: &RepoParams,
    key: &SigningKey,
    field_name: &str,
    value: String,
    update_seq: u64,
) -> SignedField<String> {
    let repo_key = signature_domain_key(params, &key.verifying_key().to_bytes());
    let payload = signed_payload_string_field(&repo_key, field_name, &value, update_seq);
    let sig = sign_to_array(key, &payload);
    SignedField {
        value,
        update_seq,
        signature: sig,
    }
}

/// Produce a [`SignedField<Vec<RefName>>`] for `force_push_allowed`.
pub fn sign_ref_list_field(
    params: &RepoParams,
    key: &SigningKey,
    field_name: &str,
    value: Vec<RefName>,
    update_seq: u64,
) -> SignedField<Vec<RefName>> {
    let repo_key = signature_domain_key(params, &key.verifying_key().to_bytes());
    let payload = signed_payload_ref_list_field(&repo_key, field_name, &value, update_seq);
    let sig = sign_to_array(key, &payload);
    SignedField {
        value,
        update_seq,
        signature: sig,
    }
}

/// Produce a [`SignedField<AclState>`].
pub fn sign_acl_field(
    params: &RepoParams,
    key: &SigningKey,
    field_name: &str,
    value: AclState,
    update_seq: u64,
) -> SignedField<AclState> {
    let repo_key = signature_domain_key(params, &key.verifying_key().to_bytes());
    let payload = signed_payload_acl_field(&repo_key, field_name, &value, update_seq);
    let sig = sign_to_array(key, &payload);
    SignedField {
        value,
        update_seq,
        signature: sig,
    }
}

/// Produce a [`SignedField<Option<RepoKey>>`] for `upgrade`.
pub fn sign_optional_repo_key_field(
    params: &RepoParams,
    key: &SigningKey,
    field_name: &str,
    value: Option<RepoKey>,
    update_seq: u64,
) -> SignedField<Option<RepoKey>> {
    let repo_key = signature_domain_key(params, &key.verifying_key().to_bytes());
    let payload =
        signed_payload_optional_repo_key_field(&repo_key, field_name, value.as_ref(), update_seq);
    let sig = sign_to_array(key, &payload);
    SignedField {
        value,
        update_seq,
        signature: sig,
    }
}

/// Produce a [`RefEntry`] signed by the given key. In Phase 1.0 this key
/// must be the owner's; the helper enforces that at construction time by
/// supplying `params.owner` as the public-key field.
pub fn sign_ref_entry(
    params: &RepoParams,
    key: &SigningKey,
    ref_name: &str,
    target: CommitHash,
    update_seq: u64,
    auth_epoch: u64,
) -> RefEntry {
    let repo_key = signature_domain_key(params, &key.verifying_key().to_bytes());
    let payload = signed_payload_ref_entry(&repo_key, ref_name, &target, update_seq, auth_epoch);
    let sig = sign_to_array(key, &payload);
    RefEntry {
        target,
        update_seq,
        updater: key.verifying_key().to_bytes(),
        auth_epoch,
        signature: sig,
    }
}

/// Produce an [`ObjectBundleRecord`] signed by the given key.
pub fn sign_bundle_record(
    params: &RepoParams,
    key: &SigningKey,
    bundle: ObjectBundle,
    auth_epoch: u64,
) -> ObjectBundleRecord {
    let repo_key = signature_domain_key(params, &key.verifying_key().to_bytes());
    let payload = signed_payload_bundle_record(&repo_key, &bundle, auth_epoch);
    let sig = sign_to_array(key, &payload);
    ObjectBundleRecord {
        bundle,
        added_by: key.verifying_key().to_bytes(),
        auth_epoch,
        signature: sig,
    }
}

/// Extension-key prefix used to advertise the "tip" commit of a
/// freshly-published [`ObjectBundle`]. The full key is
/// `bundle-tip:<hex-bundle-id>`. The signed value is the 20-byte
/// `CommitHash`. Readers (`git-remote-freenet handle_fetch`) use
/// this map to fetch only the bundles whose tips are reachable from
/// the wanted refs, instead of downloading every entry in
/// `object_index`. See issue #32.
///
/// Old contract states (pre-0.1.16) won't have these extensions;
/// readers fall back to "download all" for any bundle whose tip is
/// not advertised.
pub const BUNDLE_TIP_EXTENSION_PREFIX: &str = "bundle-tip:";

/// Extension key recording how the publisher mirrors content into
/// this contract. The signed value is the literal ASCII string
/// `"snapshot"` or `"history"`:
///
/// - `"snapshot"`: each push force-replaces the branch tip with a
///   fresh orphan commit. Older bundles in `object_index` are
///   dead-weight from rescue's perspective (no ref points at their
///   tip, no clone can be served from them). `freenet-git rescue`
///   automatically applies the `--only-current-tips` filter.
///
/// - `"history"`: each push extends the branch with a normal
///   fast-forward. Every bundle in `object_index` is reachable via
///   the parent chain. Rescue iterates all bundles.
///
/// Older contracts published before 0.1.19 don't have this
/// extension; rescue rescues everything (safe default). The
/// `mirror-repo.yml` reusable workflow sets the
/// `FREENET_GIT_MIRROR_MODE` env var on the push step so the
/// helper writes this extension automatically.
///
/// See freenet/freenet-git#43.
pub const MIRROR_MODE_EXTENSION_KEY: &str = "mirror-mode";

/// Canonical signed-value bytes for [`MIRROR_MODE_EXTENSION_KEY`]
/// when the publisher uses snapshot mode.
pub const MIRROR_MODE_VALUE_SNAPSHOT: &[u8] = b"snapshot";

/// Canonical signed-value bytes for [`MIRROR_MODE_EXTENSION_KEY`]
/// when the publisher uses history mode.
pub const MIRROR_MODE_VALUE_HISTORY: &[u8] = b"history";

/// Build the canonical extension key for a bundle's tip advertisement.
pub fn bundle_tip_extension_key(bundle_id: &crate::ObjectBundleId) -> String {
    let mut s = String::with_capacity(BUNDLE_TIP_EXTENSION_PREFIX.len() + 64);
    s.push_str(BUNDLE_TIP_EXTENSION_PREFIX);
    for b in bundle_id.iter() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// Produce a signed [`ExtensionEntry`] advertising that the given
/// `bundle_id` introduced `tip` as a reachable commit. Returns the
/// canonical extension key and the entry; callers insert into
/// `delta.extensions`. See [`BUNDLE_TIP_EXTENSION_PREFIX`].
pub fn sign_bundle_tip_extension(
    params: &RepoParams,
    key: &SigningKey,
    bundle_id: &crate::ObjectBundleId,
    tip: &CommitHash,
    update_seq: u64,
) -> (String, ExtensionEntry) {
    let ext_key = bundle_tip_extension_key(bundle_id);
    let entry = sign_extension(params, key, &ext_key, tip.to_vec(), update_seq);
    (ext_key, entry)
}

/// Parse a `bundle-tip:<hex>` extension key back to its
/// `ObjectBundleId`. Returns `None` for anything that doesn't match
/// the prefix or whose hex tail is not a valid 32-byte SHA.
pub fn parse_bundle_tip_extension_key(ext_key: &str) -> Option<crate::ObjectBundleId> {
    let hex = ext_key.strip_prefix(BUNDLE_TIP_EXTENSION_PREFIX)?;
    if hex.len() != 64 {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, byte) in out.iter_mut().enumerate() {
        let s = hex.get(i * 2..i * 2 + 2)?;
        *byte = u8::from_str_radix(s, 16).ok()?;
    }
    Some(out)
}

/// Produce an [`ExtensionEntry`] signed by the owner.
pub fn sign_extension(
    params: &RepoParams,
    key: &SigningKey,
    ext_key: &str,
    value: Vec<u8>,
    update_seq: u64,
) -> ExtensionEntry {
    let repo_key = signature_domain_key(params, &key.verifying_key().to_bytes());
    let payload = signed_payload_extension(&repo_key, ext_key, &value, update_seq);
    let sig = sign_to_array(key, &payload);
    ExtensionEntry {
        value,
        update_seq,
        signature: sig,
    }
}

fn sign_to_array(key: &SigningKey, payload: &[u8]) -> Signature {
    key.sign(payload).to_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn fixed_signing_key() -> SigningKey {
        SigningKey::from_bytes(&[0x42; 32])
    }

    #[test]
    fn bundle_tip_key_format_is_prefix_plus_hex() {
        let bundle_id: crate::ObjectBundleId = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b,
            0x1c, 0x1d, 0x1e, 0x1f,
        ];
        let key = bundle_tip_extension_key(&bundle_id);
        assert_eq!(
            key,
            "bundle-tip:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        );
    }

    #[test]
    fn parse_bundle_tip_round_trip() {
        let bundle_id: crate::ObjectBundleId = [0xab; 32];
        let key = bundle_tip_extension_key(&bundle_id);
        let parsed = parse_bundle_tip_extension_key(&key)
            .expect("key produced by bundle_tip_extension_key must round-trip");
        assert_eq!(parsed, bundle_id);
    }

    #[test]
    fn parse_bundle_tip_rejects_unknown_prefix() {
        assert!(parse_bundle_tip_extension_key(
            "name:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
        )
        .is_none());
        assert!(parse_bundle_tip_extension_key("plain-string").is_none());
        assert!(parse_bundle_tip_extension_key("").is_none());
    }

    #[test]
    fn parse_bundle_tip_rejects_wrong_length_hex() {
        // 63 chars (odd) -- not 64.
        let key = "bundle-tip:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1";
        assert!(parse_bundle_tip_extension_key(key).is_none());
        // 66 chars -- too long.
        let key = "bundle-tip:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1faa";
        assert!(parse_bundle_tip_extension_key(key).is_none());
    }

    #[test]
    fn parse_bundle_tip_rejects_non_hex() {
        let key = "bundle-tip:zz0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f";
        assert!(parse_bundle_tip_extension_key(key).is_none());
    }

    #[test]
    fn sign_bundle_tip_extension_produces_state_that_validates() {
        use crate::{validate_state, RepoParams, RepoState};

        let key = fixed_signing_key();
        let owner_pk = key.verifying_key().to_bytes();
        let prefix = bs58::encode(&owner_pk).into_string()[..12].to_string();
        let params = RepoParams { prefix };
        let bundle_id: crate::ObjectBundleId = [0x33; 32];
        let tip: CommitHash = [0x77; 20];

        let (ext_key, entry) = sign_bundle_tip_extension(&params, &key, &bundle_id, &tip, 0);
        assert!(ext_key.starts_with(BUNDLE_TIP_EXTENSION_PREFIX));
        assert_eq!(entry.value, tip.to_vec());
        assert_eq!(entry.update_seq, 0);

        // Drop into a minimal RepoState and run validate_state -- if
        // the signature didn't cover the right bytes the validator
        // would reject. This covers the full verify path through the
        // public API.
        let mut state = RepoState {
            owner: owner_pk,
            ..Default::default()
        };
        state.extensions.insert(ext_key, entry);
        validate_state(&params, &state).expect("freshly-signed bundle-tip extension must validate");
    }

    #[test]
    fn bundle_tip_key_under_extension_size_limit() {
        // bundle-tip:<64-char-hex> = 11 + 64 = 75 bytes, well under
        // the 256-byte MAX_EXTENSION_KEY_BYTES.
        let bundle_id: crate::ObjectBundleId = [0xff; 32];
        let key = bundle_tip_extension_key(&bundle_id);
        assert_eq!(key.len(), BUNDLE_TIP_EXTENSION_PREFIX.len() + 64);
        assert!(key.len() < crate::limits::MAX_EXTENSION_KEY_BYTES);
    }
}
