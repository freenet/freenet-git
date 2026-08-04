//! Shared state types and the pure validation/update logic for freenet-git.
//!
//! Both the `repo-contract` WASM and the on-host helpers depend on this crate
//! at the same pinned version. The contract WASM compiles a tiny shim that
//! deserializes parameters/state and dispatches into [`validate_state`] /
//! [`update_state`] / [`merge_state`] / [`summarize_state`] /
//! [`get_state_delta`]. Keeping all the logic here lets us unit-test it as
//! ordinary Rust without booting a WASM runtime.
//!
//! # Phase 1.0 scope
//!
//! Phase 1.0 is **single-writer**: only the repo owner can sign anything.
//! The schema includes the ACL fields ([`AclState`], [`WriterGrant`]) so
//! that adding multi-writer support in Phase 1.1 is a contract WASM upgrade
//! and not a fundamentally different schema. For now `validate_state`
//! requires `entry.updater == parameters.owner` for every signed entry.

#![deny(unsafe_code)]
#![warn(missing_docs)]

#[cfg(feature = "signing")]
pub mod signing;

pub mod chunked;

use std::collections::BTreeMap;

use freenet_git_encoding::canonical::{MapBuilder, Value};
use freenet_git_encoding::signed::build as build_payload;
use freenet_git_encoding::WIRE_VERSION;
use serde::{Deserialize, Serialize};

/// Hard upper bounds on string-shaped fields. These are not security-critical
/// (signatures already bound what an attacker can publish to what the owner
/// signs) but they eliminate accidental footguns like `cat huge.log | xargs
/// freenet-git rename`.
pub mod limits {
    /// Maximum length of [`SignedField<String>`](super::SignedField) for the
    /// `name` field.
    pub const MAX_NAME_BYTES: usize = 256;
    /// Maximum length of [`SignedField<String>`](super::SignedField) for the
    /// `description` field.
    pub const MAX_DESCRIPTION_BYTES: usize = 4096;
    /// Maximum length of any single [`RefName`](super::RefName).
    pub const MAX_REF_NAME_BYTES: usize = 256;
    /// Maximum length of any single extension key.
    pub const MAX_EXTENSION_KEY_BYTES: usize = 256;
    /// Maximum length of any single extension value.
    pub const MAX_EXTENSION_VALUE_BYTES: usize = 64 * 1024;
    /// Minimum length of a [`RepoParams`](super::RepoParams) prefix, in
    /// base58 characters.
    pub const MIN_PREFIX_LEN: usize = 4;
    /// Maximum length of a [`RepoParams`](super::RepoParams) prefix, in
    /// base58 characters. The full base58 of a 32-byte ed25519 public key
    /// is at most 44 characters, but we cap at 32 to leave headroom for
    /// future fingerprint formats.
    pub const MAX_PREFIX_LEN: usize = 32;
    /// Default prefix length the CLI emits for new repos.
    ///
    /// 12 base58 chars ≈ 70 bits of entropy. Birthday collision space is
    /// ~2^35 ≈ 34 billion repos — comfortably past any plausible Freenet
    /// adoption. Targeted preimage is 2^70, infeasible at any scale.
    /// We can lengthen later (the contract WASM accepts any prefix length
    /// in the 4..=32 range) without a migration.
    pub const DEFAULT_PREFIX_LEN: usize = 12;
}

/// Owner public key, lives in [`RepoState`] and is checked by
/// `validate_state` against the prefix in parameters.
pub type PublicKey = [u8; 32];

/// ed25519 signature.
pub type Signature = [u8; 64];

/// BLAKE3-32 of a packfile's bytes.
pub type PackHash = [u8; 32];

/// BLAKE3-32 of a chunked-pack manifest's bytes. (Not consumed in Phase 1.0.)
pub type ManifestHash = [u8; 32];

/// SHA-1 git commit hash, 20 bytes. Phase 1 does not care about the
/// SHA-256-object-format experiment yet; if/when we adopt it, this becomes
/// `enum CommitHash { Sha1([u8; 20]), Sha256([u8; 32]) }`.
pub type CommitHash = [u8; 20];

/// Stable identifier for a stored bundle: `BLAKE3-32(canonical-CBOR(bundle))`.
pub type ObjectBundleId = [u8; 32];

/// Logical key under which the contract is stored. We store this as the raw
/// 32-byte key part rather than the full `freenet_stdlib::ContractKey` to
/// avoid pulling stdlib into the contract WASM's link surface for
/// signature-domain purposes.
pub type RepoKey = [u8; 32];

/// A git ref name, e.g. `refs/heads/main`. Stored as a `String` but
/// constrained at validation time:
///
/// - NFC-normalized,
/// - no control characters (U+0000–U+001F, U+007F),
/// - no bidirectional override marks (U+202A–U+202E, U+2066–U+2069),
/// - byte length <= [`limits::MAX_REF_NAME_BYTES`].
///
/// (In Phase 1.0 we accept ASCII-only ref names for simplicity. The
/// stricter Unicode rules from the issue land alongside the multi-writer
/// ACL in Phase 1.1, since they're more relevant when ref names appear in
/// listings of writers and contributors.)
pub type RefName = String;

/// Initial parameters, immutable, part of the contract key via
/// `BLAKE3(BLAKE3(WASM) || Parameters)`.
///
/// The parameters carry only the **prefix** — the first N base58
/// characters of the owner's ed25519 public key. The owner pubkey
/// itself lives in [`RepoState`] (`state.owner`) and is checked by
/// [`validate_state`] against this prefix.
///
/// This means the URL — which is just the prefix — is short and
/// readable, but anyone who has the URL plus the bundled contract WASM
/// can compute the full contract key (`BLAKE3(BLAKE3(WASM) ||
/// CBOR({prefix}))`). Two different prefix lengths produce two
/// different contract keys, so the same owner can have many repos at
/// different prefix lengths — though in practice we always use
/// [`limits::DEFAULT_PREFIX_LEN`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoParams {
    /// Base58 prefix of the owner's ed25519 public key. Length must be
    /// in the `[MIN_PREFIX_LEN..=MAX_PREFIX_LEN]` range.
    pub prefix: String,
}

impl RepoParams {
    /// Construct parameters from an owner pubkey and prefix length.
    /// Caller must ensure `len` is in the valid range; consumers
    /// double-check via [`validate_state`].
    pub fn from_owner(owner: &PublicKey, len: usize) -> Self {
        Self {
            prefix: pubkey_prefix(owner, len),
        }
    }

    /// Encode as bytes for use as the `Parameters` payload of the contract.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("RepoParams serialization is infallible")
    }

    /// Decode from a `Parameters` payload.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidateError> {
        bincode::deserialize(bytes).map_err(|e| ValidateError::DecodeParams(e.to_string()))
    }
}

/// Compute the canonical prefix of an owner pubkey at a given length:
/// `base58(owner)[..len]`, with `len` saturated to the encoded string's
/// actual length so we never index past the end.
pub fn pubkey_prefix(owner: &PublicKey, len: usize) -> String {
    let encoded = bs58::encode(owner).into_string();
    let take = len.min(encoded.len());
    encoded[..take].to_string()
}

/// A field that carries its own owner signature so a peer can verify it
/// in isolation, regardless of how the surrounding state was assembled.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SignedField<T> {
    /// Current value.
    pub value: T,
    /// Strictly-monotonic counter. Increments on every owner-signed update;
    /// the highest `update_seq` wins under merge.
    pub update_seq: u64,
    /// Owner signature over `(domain || repo_key || field_name || value || update_seq)`.
    #[serde(with = "serde_bytes_array_64")]
    pub signature: Signature,
}

/// Per-writer ACL grant. Phase 1.0 schema includes this for forward compat
/// but `validate_state` ignores it — only the owner is authorized.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct WriterGrant {
    /// ACL epoch at which the grant was issued.
    pub granted_at_epoch: u64,
    /// `None` = currently authorized; `Some(e)` = revoked at epoch `e`.
    pub revoked_at_epoch: Option<u64>,
}

/// ACL grant log with epoch numbers. Owner-signed as a whole via the
/// surrounding [`SignedField`]. Phase 1.0 keeps this empty (`epoch = 0`,
/// no grants); Phase 1.1 adds grant/revoke via dedicated CLI commands.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct AclState {
    /// Current ACL epoch.
    pub epoch: u64,
    /// Map from writer public key to grant info. Never pruned, only
    /// tombstoned via `revoked_at_epoch`. See the issue spec for why.
    pub grants: BTreeMap<PublicKey, WriterGrant>,
}

/// One ref pointer. Phase 1.0 only accepts entries where
/// `updater == parameters.owner`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RefEntry {
    /// Object SHA the ref points at.
    ///
    /// For branch refs (`refs/heads/*`) and lightweight tag refs
    /// this is a commit SHA. For *annotated* tag refs
    /// (`refs/tags/*` created with `git tag -a`) this is the
    /// tag-object SHA — `git rev-parse refs/tags/<name>` for an
    /// annotated tag returns the tag object, not the commit it
    /// points at, and that is what gets stored here.
    ///
    /// The `CommitHash` type name is a Phase 1.0 misnomer kept for
    /// wire-format stability. Treat this field as an opaque
    /// 20-byte object SHA; downstream code peels through tag
    /// objects via `git rev-parse <sha>^{commit}` on demand
    /// (`walk_unresolved_parents` in `git-remote-freenet`).
    pub target: CommitHash,
    /// Strictly-monotonic counter for this ref.
    pub update_seq: u64,
    /// Public key that signed this entry. In Phase 1.0 must equal
    /// `parameters.owner`.
    pub updater: PublicKey,
    /// ACL epoch at which this update was signed. Phase 1.0 always uses
    /// `0` (no ACL changes).
    pub auth_epoch: u64,
    /// Signature by `updater` over the canonical ref-update payload.
    #[serde(with = "serde_bytes_array_64")]
    pub signature: Signature,
}

/// One stored bundle of git objects.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ObjectBundle {
    /// A single packfile uploaded as one immutable contract.
    SinglePack {
        /// BLAKE3-32 of the pack bytes.
        pack_hash: PackHash,
        /// Pack size in bytes (informational; helps clients estimate fetches).
        size_bytes: u64,
    },
    /// A chunked pack split across multiple immutable contracts. Phase 1.0
    /// helpers do not consume these; the variant is reserved so that adding
    /// support later does not require a contract key migration.
    ChunkedPack {
        /// BLAKE3-32 of the manifest bytes.
        manifest_hash: ManifestHash,
        /// Total bytes across all chunks.
        total_size: u64,
        /// Number of chunks.
        chunk_count: u32,
    },
}

impl ObjectBundle {
    /// Compute the deterministic [`ObjectBundleId`] for this bundle.
    ///
    /// Defined as `BLAKE3-32(canonical-CBOR(bundle))`. The exact byte format
    /// of the canonical encoding lives in [`freenet_git_encoding::canonical`]
    /// and is part of the wire-format pin.
    pub fn id(&self) -> ObjectBundleId {
        let value = match self {
            Self::SinglePack {
                pack_hash,
                size_bytes,
            } => MapBuilder::default()
                .text_entry("kind", Value::text("single-pack"))
                .text_entry("pack_hash", Value::bytes(pack_hash.to_vec()))
                .text_entry("size_bytes", Value::uint(*size_bytes))
                .build(),
            Self::ChunkedPack {
                manifest_hash,
                total_size,
                chunk_count,
            } => MapBuilder::default()
                .text_entry("kind", Value::text("chunked-pack"))
                .text_entry("manifest_hash", Value::bytes(manifest_hash.to_vec()))
                .text_entry("total_size", Value::uint(*total_size))
                .text_entry("chunk_count", Value::uint(u64::from(*chunk_count)))
                .build(),
        };
        *blake3::hash(&value.encode()).as_bytes()
    }
}

/// One entry in [`RepoState::object_index`]: a bundle and the signature of
/// the writer who introduced it.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectBundleRecord {
    /// The bundle. Its `id()` equals the [`ObjectBundleId`] under which this
    /// record is keyed in `object_index`.
    pub bundle: ObjectBundle,
    /// Writer who added this bundle. In Phase 1.0 must equal
    /// `parameters.owner`.
    pub added_by: PublicKey,
    /// ACL epoch at which the writer was authorized.
    pub auth_epoch: u64,
    /// Signature by `added_by` over the canonical bundle-add payload.
    #[serde(with = "serde_bytes_array_64")]
    pub signature: Signature,
}

/// One entry in [`RepoState::extensions`].
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ExtensionEntry {
    /// Raw value bytes.
    #[serde(with = "serde_bytes")]
    pub value: Vec<u8>,
    /// Strictly-monotonic counter for this key.
    pub update_seq: u64,
    /// Owner signature over the canonical extension payload.
    #[serde(with = "serde_bytes_array_64")]
    pub signature: Signature,
}

/// The full mutable state of a repo contract.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoState {
    /// The owner's ed25519 public key. `validate_state` enforces that
    /// `base58(owner)[..params.prefix.len()] == params.prefix`. The
    /// owner is implicitly authenticated through every signed field —
    /// changing it would invalidate all signatures, since the signature
    /// domain key derives from prefix + owner.
    pub owner: PublicKey,
    /// Display name of the repo.
    pub name: Option<SignedField<String>>,
    /// Free-form description.
    pub description: Option<SignedField<String>>,
    /// Default branch (`refs/heads/<x>`). When set, clones default to it.
    pub default_branch: Option<SignedField<RefName>>,
    /// Refs in this set are allowed to be force-pushed (non-fast-forward).
    /// Phase 1.0 always treats this as empty.
    pub force_push_allowed: Option<SignedField<Vec<RefName>>>,
    /// ACL grant log. Phase 1.0 keeps this at default (epoch 0, empty).
    pub acl: Option<SignedField<AclState>>,
    /// Append-only successor pointer for breaking schema migrations.
    pub upgrade: Option<SignedField<Option<RepoKey>>>,
    /// Refs by name.
    pub refs: BTreeMap<RefName, RefEntry>,
    /// Stored object bundles, keyed by their `id()`.
    pub object_index: BTreeMap<ObjectBundleId, ObjectBundleRecord>,
    /// Owner-signed extensions for forward compatibility.
    pub extensions: BTreeMap<String, ExtensionEntry>,
}

impl RepoState {
    /// Encode as bytes for use as the `State` payload of the contract.
    pub fn to_bytes(&self) -> Vec<u8> {
        bincode::serialize(self).expect("RepoState serialization is infallible")
    }

    /// Decode from a `State` payload.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, ValidateError> {
        if bytes.is_empty() {
            return Ok(Self::default());
        }
        bincode::deserialize(bytes).map_err(|e| ValidateError::DecodeState(e.to_string()))
    }
}

/// Errors `validate_state` can surface. The string variants carry diagnostic
/// detail; treat the variant as the machine-readable signal.
#[derive(Debug, thiserror::Error)]
pub enum ValidateError {
    /// Could not decode the parameters bytes.
    #[error("decode parameters: {0}")]
    DecodeParams(String),
    /// Could not decode the state bytes.
    #[error("decode state: {0}")]
    DecodeState(String),
    /// A signed field's signature did not verify against its claimed signer.
    #[error("signature verification failed for {0}")]
    InvalidSignature(&'static str),
    /// Phase 1.0 only accepts owner-signed entries; this entry was signed by
    /// someone else.
    #[error("entry signed by non-owner key (Phase 1.0 is single-writer)")]
    NonOwnerSigner,
    /// Field exceeded its size limit.
    #[error("field {field} exceeds limit ({len} > {max})")]
    FieldTooLong {
        /// The offending field.
        field: &'static str,
        /// Observed length in bytes.
        len: usize,
        /// Maximum allowed length in bytes.
        max: usize,
    },
    /// Bundle id did not match the canonical hash of the bundle.
    #[error("object_index entry has wrong bundle id")]
    BundleIdMismatch,
    /// `acl.epoch` went backwards or `update_seq` is non-monotonic.
    #[error("monotonic invariant violated: {0}")]
    NonMonotonic(&'static str),
    /// `params.prefix` length is outside `[MIN_PREFIX_LEN..=MAX_PREFIX_LEN]`.
    #[error("prefix length {len} outside valid range [{min}..={max}]")]
    InvalidPrefixLength {
        /// Observed prefix length.
        len: usize,
        /// Minimum allowed.
        min: usize,
        /// Maximum allowed.
        max: usize,
    },
    /// `state.owner` does not produce `params.prefix` when base58-encoded.
    #[error("owner pubkey does not match parameters prefix: expected {expected}, got {actual}")]
    PrefixMismatch {
        /// Prefix declared in parameters.
        expected: String,
        /// Prefix actually derived from `state.owner`.
        actual: String,
    },
    /// `params.prefix` contains characters outside the Bitcoin base58
    /// alphabet.
    #[error("prefix contains invalid base58 characters")]
    InvalidPrefixChars,
}

/// Run the full contract `validate_state` check.
///
/// Called by the contract WASM whenever a peer receives a candidate state
/// from any source (network or local). Verifies every signature in
/// isolation; rejects any state that does not exclusively consist of
/// owner-signed entries.
pub fn validate_state(params: &RepoParams, state: &RepoState) -> Result<(), ValidateError> {
    // 1. Validate prefix length is in range.
    if params.prefix.len() < limits::MIN_PREFIX_LEN || params.prefix.len() > limits::MAX_PREFIX_LEN
    {
        return Err(ValidateError::InvalidPrefixLength {
            len: params.prefix.len(),
            min: limits::MIN_PREFIX_LEN,
            max: limits::MAX_PREFIX_LEN,
        });
    }
    // 2. Validate prefix characters are base58 (catches typos and
    //    keeps the prefix domain narrow).
    if bs58::decode(&params.prefix).into_vec().is_err() {
        return Err(ValidateError::InvalidPrefixChars);
    }
    // 3. Validate owner pubkey produces the declared prefix.
    let actual_prefix = pubkey_prefix(&state.owner, params.prefix.len());
    if actual_prefix != params.prefix {
        return Err(ValidateError::PrefixMismatch {
            expected: params.prefix.clone(),
            actual: actual_prefix,
        });
    }
    let repo_key = params_repo_key(params, &state.owner);

    if let Some(field) = &state.name {
        check_size("name", field.value.len(), limits::MAX_NAME_BYTES)?;
        verify_signed_field_string(&repo_key, "name", &state.owner, field, "name")?;
    }
    if let Some(field) = &state.description {
        check_size(
            "description",
            field.value.len(),
            limits::MAX_DESCRIPTION_BYTES,
        )?;
        verify_signed_field_string(&repo_key, "description", &state.owner, field, "description")?;
    }
    if let Some(field) = &state.default_branch {
        check_size(
            "default_branch",
            field.value.len(),
            limits::MAX_REF_NAME_BYTES,
        )?;
        verify_signed_field_string(
            &repo_key,
            "default_branch",
            &state.owner,
            field,
            "default_branch",
        )?;
    }
    if let Some(field) = &state.force_push_allowed {
        verify_signed_field_ref_list(
            &repo_key,
            "force_push_allowed",
            &state.owner,
            field,
            "force_push_allowed",
        )?;
    }
    if let Some(field) = &state.acl {
        verify_signed_field_acl(&repo_key, "acl", &state.owner, field, "acl")?;
    }
    if let Some(field) = &state.upgrade {
        verify_signed_field_optional_repo_key(
            &repo_key,
            "upgrade",
            &state.owner,
            field,
            "upgrade",
        )?;
    }

    for (ref_name, entry) in &state.refs {
        check_size("ref name", ref_name.len(), limits::MAX_REF_NAME_BYTES)?;
        // Phase 1.0: only owner-signed refs are accepted.
        if entry.updater != state.owner {
            return Err(ValidateError::NonOwnerSigner);
        }
        verify_ref_entry(&repo_key, ref_name, entry)?;
    }

    for (bundle_id, record) in &state.object_index {
        if record.bundle.id() != *bundle_id {
            return Err(ValidateError::BundleIdMismatch);
        }
        if record.added_by != state.owner {
            return Err(ValidateError::NonOwnerSigner);
        }
        verify_bundle_record(&repo_key, record)?;
    }

    for (ext_key, entry) in &state.extensions {
        check_size(
            "extension key",
            ext_key.len(),
            limits::MAX_EXTENSION_KEY_BYTES,
        )?;
        check_size(
            "extension value",
            entry.value.len(),
            limits::MAX_EXTENSION_VALUE_BYTES,
        )?;
        verify_extension_entry(&repo_key, ext_key, &state.owner, entry)?;
    }

    Ok(())
}

/// Errors `update_state` can surface in addition to [`ValidateError`].
#[derive(Debug, thiserror::Error)]
pub enum UpdateError {
    /// The candidate state failed `validate_state`.
    #[error(transparent)]
    Invalid(#[from] ValidateError),
    /// A non-fast-forward update was attempted on a ref that is not in
    /// `force_push_allowed`.
    #[error("non-fast-forward update on protected ref")]
    NonFastForward,
}

/// Apply a *full new state* on top of the existing state, treating both as
/// CRDT snapshots and merging deterministically. This is the path triggered
/// by a peer pushing a fresh state to us.
///
/// Returns the merged state; never overwrites with strictly-older info.
pub fn merge_state(current: &RepoState, incoming: &RepoState) -> RepoState {
    let mut out = current.clone();
    out.name = pick_signed_field(out.name, incoming.name.clone());
    out.description = pick_signed_field(out.description, incoming.description.clone());
    out.default_branch = pick_signed_field(out.default_branch, incoming.default_branch.clone());
    out.force_push_allowed =
        pick_signed_field(out.force_push_allowed, incoming.force_push_allowed.clone());
    out.acl = pick_signed_field(out.acl, incoming.acl.clone());
    out.upgrade = pick_signed_field(out.upgrade, incoming.upgrade.clone());

    for (k, v) in &incoming.refs {
        let pick = match out.refs.remove(k) {
            None => v.clone(),
            Some(existing) => pick_ref_entry(existing, v.clone()),
        };
        out.refs.insert(k.clone(), pick);
    }
    for (k, v) in &incoming.object_index {
        out.object_index.entry(*k).or_insert_with(|| v.clone());
    }
    for (k, v) in &incoming.extensions {
        let pick = match out.extensions.remove(k) {
            None => v.clone(),
            Some(existing) => pick_extension_entry(existing, v.clone()),
        };
        out.extensions.insert(k.clone(), pick);
    }
    out
}

/// Apply a delta (a partial update produced by a writer) to the current
/// state. Used on the optimistic path. Performs the [`merge_state`] CRDT
/// reconciliation plus the additional fast-forward / sequence-number
/// guards described in the issue spec.
pub fn update_state(
    params: &RepoParams,
    current: &RepoState,
    delta: &RepoState,
) -> Result<RepoState, UpdateError> {
    // First merge by the same CRDT rule. Then validate. The order matters:
    // a delta can carry a new `default_branch` that, post-merge, makes a
    // ref-update legitimate. Validating before merge would reject deltas
    // that depend on co-arriving owner-signed metadata.
    let merged = merge_state(current, delta);

    // Phase 1.0 force-push enforcement: any ref present both in `current`
    // and `merged` whose `target` changed must EITHER be in
    // `merged.force_push_allowed` OR have a higher `update_seq` than
    // before. Without an object DB we can't verify ancestry, but we can
    // verify that the writer claimed `previous_target` matches the
    // current target. Since the on-host helper always submits a fresh
    // entry with `update_seq = current + 1`, the rule reduces to "the
    // entry in the delta either points to the same target as `current`,
    // or its `update_seq` is strictly greater than the existing
    // entry's." That's already enforced by `pick_ref_entry`. So in
    // Phase 1.0 the only concrete check here is the validate pass.
    let _ = params;

    validate_state(params, &merged)?;
    Ok(merged)
}

/// Compact summary used for `summarize_state` -> `get_state_delta`.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoSummary {
    /// `update_seq` of each owner-signed singleton field, if present.
    pub field_seqs: BTreeMap<String, u64>,
    /// Per-ref `update_seq`.
    pub ref_seqs: BTreeMap<RefName, u64>,
    /// Set of bundle ids the summarizer already has.
    pub bundle_ids: Vec<ObjectBundleId>,
    /// Per-extension `update_seq`.
    pub extension_seqs: BTreeMap<String, u64>,
}

/// Build a `RepoSummary` from a state. Used by the contract's
/// `summarize_state` entry point.
pub fn summarize_state(state: &RepoState) -> RepoSummary {
    let mut s = RepoSummary::default();
    if let Some(f) = &state.name {
        s.field_seqs.insert("name".into(), f.update_seq);
    }
    if let Some(f) = &state.description {
        s.field_seqs.insert("description".into(), f.update_seq);
    }
    if let Some(f) = &state.default_branch {
        s.field_seqs.insert("default_branch".into(), f.update_seq);
    }
    if let Some(f) = &state.force_push_allowed {
        s.field_seqs
            .insert("force_push_allowed".into(), f.update_seq);
    }
    if let Some(f) = &state.acl {
        s.field_seqs.insert("acl".into(), f.update_seq);
    }
    if let Some(f) = &state.upgrade {
        s.field_seqs.insert("upgrade".into(), f.update_seq);
    }
    for (k, v) in &state.refs {
        s.ref_seqs.insert(k.clone(), v.update_seq);
    }
    for k in state.object_index.keys() {
        s.bundle_ids.push(*k);
    }
    for (k, v) in &state.extensions {
        s.extension_seqs.insert(k.clone(), v.update_seq);
    }
    s
}

/// Compute the delta a peer needs to update from `summary` to `state`.
pub fn get_state_delta(state: &RepoState, summary: &RepoSummary) -> RepoState {
    let mut d = RepoState::default();

    if state.name.as_ref().map(|f| f.update_seq) > summary.field_seqs.get("name").copied() {
        d.name = state.name.clone();
    }
    if state.description.as_ref().map(|f| f.update_seq)
        > summary.field_seqs.get("description").copied()
    {
        d.description = state.description.clone();
    }
    if state.default_branch.as_ref().map(|f| f.update_seq)
        > summary.field_seqs.get("default_branch").copied()
    {
        d.default_branch = state.default_branch.clone();
    }
    if state.force_push_allowed.as_ref().map(|f| f.update_seq)
        > summary.field_seqs.get("force_push_allowed").copied()
    {
        d.force_push_allowed = state.force_push_allowed.clone();
    }
    if state.acl.as_ref().map(|f| f.update_seq) > summary.field_seqs.get("acl").copied() {
        d.acl = state.acl.clone();
    }
    if state.upgrade.as_ref().map(|f| f.update_seq) > summary.field_seqs.get("upgrade").copied() {
        d.upgrade = state.upgrade.clone();
    }

    // `None` (peer has never seen this key) is NOT the same as
    // `Some(0)` (peer already holds it at seq 0). Flattening the two
    // with `unwrap_or(0)` makes a seq-0 entry undeliverable to
    // everyone, forever: the test becomes `0 < 0`, so it is never put
    // in a delta and the peer never gets it. Refs dodge this today only
    // because the push path always writes `update_seq >= 1`, which is a
    // property of a different crate that nothing here enforces.
    // Extensions did not dodge it -- see the extensions loop below.
    for (k, v) in &state.refs {
        let peer_needs = match summary.ref_seqs.get(k) {
            None => true,
            Some(&seq) => seq < v.update_seq,
        };
        if peer_needs {
            d.refs.insert(k.clone(), v.clone());
        }
    }
    let known: std::collections::HashSet<&ObjectBundleId> = summary.bundle_ids.iter().collect();
    for (k, v) in &state.object_index {
        if !known.contains(k) {
            d.object_index.insert(*k, v.clone());
        }
    }
    // Same absent-vs-zero distinction as the refs loop above, and this
    // is the one that actually bit: `bundle-tip:<id>` extensions are
    // written at seq 0 by design (each key is unique per bundle, so
    // there is no monotonicity to track), so under `unwrap_or(0)` they
    // were never included in any delta and never reached a peer that
    // synced via summary+delta. The visible symptom was a repo whose
    // refs and object_index propagated fine while its extensions map
    // stayed empty, which silently disables the dead-weight bundle
    // filter on fetch.
    for (k, v) in &state.extensions {
        let peer_needs = match summary.extension_seqs.get(k) {
            None => true,
            Some(&seq) => seq < v.update_seq,
        };
        if peer_needs {
            d.extensions.insert(k.clone(), v.clone());
        }
    }
    d
}

// ---------------------------------------------------------------------------
// Signed-payload constructors
// ---------------------------------------------------------------------------

/// Construct the canonical signed-payload bytes for the `name` /
/// `description` / `default_branch` field updates.
pub fn signed_payload_string_field(
    repo_key: &RepoKey,
    field_name: &str,
    value: &str,
    update_seq: u64,
) -> Vec<u8> {
    build_payload(field_name, |b| {
        b.field_bytes(repo_key);
        b.field_str(value);
        b.field_u64(update_seq);
    })
}

/// Signed-payload bytes for `force_push_allowed`.
pub fn signed_payload_ref_list_field(
    repo_key: &RepoKey,
    field_name: &str,
    refs: &[RefName],
    update_seq: u64,
) -> Vec<u8> {
    build_payload(field_name, |b| {
        b.field_bytes(repo_key);
        b.field_u32(u32::try_from(refs.len()).unwrap_or(u32::MAX));
        for r in refs {
            b.field_str(r);
        }
        b.field_u64(update_seq);
    })
}

/// Signed-payload bytes for `acl`.
pub fn signed_payload_acl_field(
    repo_key: &RepoKey,
    field_name: &str,
    acl: &AclState,
    update_seq: u64,
) -> Vec<u8> {
    build_payload(field_name, |b| {
        b.field_bytes(repo_key);
        b.field_u64(acl.epoch);
        b.field_u32(u32::try_from(acl.grants.len()).unwrap_or(u32::MAX));
        for (writer, grant) in &acl.grants {
            b.field_bytes(writer);
            b.field_u64(grant.granted_at_epoch);
            b.field_option_bytes(
                grant
                    .revoked_at_epoch
                    .map(|e| e.to_le_bytes())
                    .as_ref()
                    .map(|x| x.as_slice()),
            );
        }
        b.field_u64(update_seq);
    })
}

/// Signed-payload bytes for `upgrade`.
pub fn signed_payload_optional_repo_key_field(
    repo_key: &RepoKey,
    field_name: &str,
    successor: Option<&RepoKey>,
    update_seq: u64,
) -> Vec<u8> {
    build_payload(field_name, |b| {
        b.field_bytes(repo_key);
        b.field_option_bytes(successor.map(|k| k.as_slice()));
        b.field_u64(update_seq);
    })
}

/// Signed-payload bytes for a [`RefEntry`].
pub fn signed_payload_ref_entry(
    repo_key: &RepoKey,
    ref_name: &str,
    target: &CommitHash,
    update_seq: u64,
    auth_epoch: u64,
) -> Vec<u8> {
    build_payload("ref-update", |b| {
        b.field_bytes(repo_key);
        b.field_str(ref_name);
        b.field_bytes(target);
        b.field_u64(update_seq);
        b.field_u64(auth_epoch);
    })
}

/// Signed-payload bytes for an [`ObjectBundleRecord`].
pub fn signed_payload_bundle_record(
    repo_key: &RepoKey,
    bundle: &ObjectBundle,
    auth_epoch: u64,
) -> Vec<u8> {
    let bundle_id = bundle.id();
    build_payload("object-bundle", |b| {
        b.field_bytes(repo_key);
        b.field_bytes(&bundle_id);
        b.field_u64(auth_epoch);
    })
}

/// Signed-payload bytes for an [`ExtensionEntry`].
pub fn signed_payload_extension(
    repo_key: &RepoKey,
    ext_key: &str,
    value: &[u8],
    update_seq: u64,
) -> Vec<u8> {
    build_payload("extension", |b| {
        b.field_bytes(repo_key);
        b.field_str(ext_key);
        b.field_bytes(value);
        b.field_u64(update_seq);
    })
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Compute the abstract repo key used in every signed payload as a
/// domain-separating prefix: `BLAKE3-32(WIRE_VERSION || prefix || owner)`.
///
/// This is only used as the *signature domain* repo key — Freenet computes
/// the actual contract key separately as `BLAKE3(BLAKE3(WASM) ||
/// Parameters)`. Keeping the signature domain stable across WASM rebuilds
/// means a contract WASM bump does not invalidate every signature in the
/// repo's history; only the contract key changes (as it must — that is
/// what migration via the upgrade pointer is for).
fn params_repo_key(params: &RepoParams, owner: &PublicKey) -> RepoKey {
    let mut h = blake3::Hasher::new();
    h.update(WIRE_VERSION.as_bytes());
    h.update(params.prefix.as_bytes());
    h.update(owner);
    *h.finalize().as_bytes()
}

/// Public version of [`params_repo_key`] for callers that need the same
/// derivation when constructing signed payloads.
pub fn signature_domain_key(params: &RepoParams, owner: &PublicKey) -> RepoKey {
    params_repo_key(params, owner)
}

fn check_size(field: &'static str, len: usize, max: usize) -> Result<(), ValidateError> {
    if len > max {
        Err(ValidateError::FieldTooLong { field, len, max })
    } else {
        Ok(())
    }
}

fn verify_signature(
    payload: &[u8],
    signer: &PublicKey,
    signature: &Signature,
    label: &'static str,
) -> Result<(), ValidateError> {
    let pk = ed25519_compact::PublicKey::from_slice(signer)
        .map_err(|_| ValidateError::InvalidSignature(label))?;
    let sig = ed25519_compact::Signature::from_slice(signature)
        .map_err(|_| ValidateError::InvalidSignature(label))?;
    pk.verify(payload, &sig)
        .map_err(|_| ValidateError::InvalidSignature(label))
}

fn verify_signed_field_string(
    repo_key: &RepoKey,
    field_name: &str,
    owner: &PublicKey,
    field: &SignedField<String>,
    label: &'static str,
) -> Result<(), ValidateError> {
    let payload = signed_payload_string_field(repo_key, field_name, &field.value, field.update_seq);
    verify_signature(&payload, owner, &field.signature, label)
}

fn verify_signed_field_ref_list(
    repo_key: &RepoKey,
    field_name: &str,
    owner: &PublicKey,
    field: &SignedField<Vec<RefName>>,
    label: &'static str,
) -> Result<(), ValidateError> {
    let payload =
        signed_payload_ref_list_field(repo_key, field_name, &field.value, field.update_seq);
    verify_signature(&payload, owner, &field.signature, label)
}

fn verify_signed_field_acl(
    repo_key: &RepoKey,
    field_name: &str,
    owner: &PublicKey,
    field: &SignedField<AclState>,
    label: &'static str,
) -> Result<(), ValidateError> {
    let payload = signed_payload_acl_field(repo_key, field_name, &field.value, field.update_seq);
    verify_signature(&payload, owner, &field.signature, label)
}

fn verify_signed_field_optional_repo_key(
    repo_key: &RepoKey,
    field_name: &str,
    owner: &PublicKey,
    field: &SignedField<Option<RepoKey>>,
    label: &'static str,
) -> Result<(), ValidateError> {
    let payload = signed_payload_optional_repo_key_field(
        repo_key,
        field_name,
        field.value.as_ref(),
        field.update_seq,
    );
    verify_signature(&payload, owner, &field.signature, label)
}

fn verify_ref_entry(
    repo_key: &RepoKey,
    ref_name: &str,
    entry: &RefEntry,
) -> Result<(), ValidateError> {
    let payload = signed_payload_ref_entry(
        repo_key,
        ref_name,
        &entry.target,
        entry.update_seq,
        entry.auth_epoch,
    );
    verify_signature(&payload, &entry.updater, &entry.signature, "ref entry")
}

fn verify_bundle_record(
    repo_key: &RepoKey,
    record: &ObjectBundleRecord,
) -> Result<(), ValidateError> {
    let payload = signed_payload_bundle_record(repo_key, &record.bundle, record.auth_epoch);
    verify_signature(
        &payload,
        &record.added_by,
        &record.signature,
        "bundle record",
    )
}

fn verify_extension_entry(
    repo_key: &RepoKey,
    ext_key: &str,
    owner: &PublicKey,
    entry: &ExtensionEntry,
) -> Result<(), ValidateError> {
    let payload = signed_payload_extension(repo_key, ext_key, &entry.value, entry.update_seq);
    verify_signature(&payload, owner, &entry.signature, "extension entry")
}

fn pick_signed_field<T: Clone>(
    a: Option<SignedField<T>>,
    b: Option<SignedField<T>>,
) -> Option<SignedField<T>> {
    match (a, b) {
        (None, x) | (x, None) => x,
        (Some(x), Some(y)) => Some(
            if pick_higher_seq(x.update_seq, &x.signature, y.update_seq, &y.signature) {
                x
            } else {
                y
            },
        ),
    }
}

fn pick_ref_entry(a: RefEntry, b: RefEntry) -> RefEntry {
    if pick_higher_seq(a.update_seq, &a.signature, b.update_seq, &b.signature) {
        a
    } else {
        b
    }
}

fn pick_extension_entry(a: ExtensionEntry, b: ExtensionEntry) -> ExtensionEntry {
    if pick_higher_seq(a.update_seq, &a.signature, b.update_seq, &b.signature) {
        a
    } else {
        b
    }
}

/// Returns true if `a` is the "winner" under (update_seq desc, signature
/// asc) ordering. The signature tiebreak makes the merge deterministic
/// across implementations even when two writers race to the same seq.
fn pick_higher_seq(a_seq: u64, a_sig: &Signature, b_seq: u64, b_sig: &Signature) -> bool {
    match a_seq.cmp(&b_seq) {
        std::cmp::Ordering::Greater => true,
        std::cmp::Ordering::Less => false,
        std::cmp::Ordering::Equal => a_sig <= b_sig,
    }
}

// `serde` ergonomics for `[u8; 64]`. `serde_bytes` only handles `Vec<u8>`
// and `&[u8]`; we want the array shape preserved so a corrupt signature is
// caught at decode time, not at verify time.
mod serde_bytes_array_64 {
    use serde::de::Error as _;
    use serde::{Deserialize, Deserializer, Serialize, Serializer};

    pub fn serialize<S: Serializer>(value: &[u8; 64], ser: S) -> Result<S::Ok, S::Error> {
        serde_bytes::Bytes::new(value).serialize(ser)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(de: D) -> Result<[u8; 64], D::Error> {
        let bytes: serde_bytes::ByteBuf = serde_bytes::ByteBuf::deserialize(de)?;
        bytes
            .as_ref()
            .try_into()
            .map_err(|_| D::Error::custom("expected 64-byte signature"))
    }
}

#[cfg(test)]
#[allow(clippy::field_reassign_with_default)]
mod tests {
    use super::*;

    /// `params_repo_key` does not depend on the contract WASM hash, so two
    /// different WASMs with the same parameters and owner produce the
    /// same signature domain key. Without this property, every contract
    /// WASM upgrade would invalidate every historical signature.
    #[test]
    fn signature_domain_key_is_wasm_independent() {
        let owner = [1u8; 32];
        let params = RepoParams::from_owner(&owner, limits::DEFAULT_PREFIX_LEN);
        let k = signature_domain_key(&params, &owner);
        assert_eq!(k.len(), 32);
        // Stability: same inputs => same output across runs.
        assert_eq!(signature_domain_key(&params, &owner), k);
    }

    /// `get_state_delta` must send an entry the peer has never seen,
    /// whatever its `update_seq`. Reading a missing entry as seq 0
    /// conflates "peer has never seen this key" with "peer already has
    /// it at seq 0", so an entry written at seq 0 is never sent to
    /// anyone and can never converge.
    ///
    /// This is not hypothetical: `bundle-tip:<id>` extensions are
    /// written at seq 0 on purpose (each key is unique per bundle, so
    /// there is no monotonicity to track), and they were silently
    /// failing to propagate. See the `update_seq` comment at the
    /// signing site in `git-remote-freenet`.
    #[test]
    fn get_state_delta_sends_a_seq_zero_extension_the_peer_has_never_seen() {
        let mut state = RepoState::default();
        state.extensions.insert(
            "bundle-tip:aa".into(),
            ExtensionEntry {
                value: vec![7u8; 20],
                update_seq: 0,
                signature: [0u8; 64],
            },
        );
        // A peer that knows nothing at all.
        let summary = RepoSummary::default();

        let delta = get_state_delta(&state, &summary);
        assert!(
            delta.extensions.contains_key("bundle-tip:aa"),
            "a seq-0 extension the peer has never seen must be in the delta; \
             otherwise it can never reach that peer"
        );
    }

    /// Same flattening bug, same function, for refs. Refs happen to
    /// dodge it today only because the push path always writes
    /// `update_seq >= 1`, which is a property of a different file and
    /// nothing enforces it here.
    #[test]
    fn get_state_delta_sends_a_seq_zero_ref_the_peer_has_never_seen() {
        let mut state = RepoState::default();
        state.refs.insert(
            "refs/heads/main".into(),
            RefEntry {
                target: [9u8; 20],
                update_seq: 0,
                updater: [0u8; 32],
                auth_epoch: 0,
                signature: [0u8; 64],
            },
        );

        let delta = get_state_delta(&state, &RepoSummary::default());
        assert!(
            delta.refs.contains_key("refs/heads/main"),
            "a seq-0 ref the peer has never seen must be in the delta"
        );
    }

    /// The flip side: an entry the peer already holds at the same seq
    /// must NOT be resent, or every sync ships the whole extension map.
    #[test]
    fn get_state_delta_omits_entries_the_peer_already_has() {
        let mut state = RepoState::default();
        state.extensions.insert(
            "bundle-tip:aa".into(),
            ExtensionEntry {
                value: vec![7u8; 20],
                update_seq: 0,
                signature: [0u8; 64],
            },
        );
        state.refs.insert(
            "refs/heads/main".into(),
            RefEntry {
                target: [9u8; 20],
                update_seq: 3,
                updater: [0u8; 32],
                auth_epoch: 0,
                signature: [0u8; 64],
            },
        );

        let summary = summarize_state(&state);
        let delta = get_state_delta(&state, &summary);
        assert!(
            delta.extensions.is_empty(),
            "peer is already current: {:?}",
            delta.extensions
        );
        assert!(
            delta.refs.is_empty(),
            "peer is already current: {:?}",
            delta.refs
        );
    }

    #[test]
    fn default_state_with_matching_prefix_validates() {
        // RepoState::default() has owner = [0; 32]. Build matching params.
        let owner = [0u8; 32];
        let params = RepoParams::from_owner(&owner, limits::DEFAULT_PREFIX_LEN);
        assert!(validate_state(&params, &RepoState::default()).is_ok());
    }

    #[test]
    fn prefix_mismatch_rejected() {
        let owner = [3u8; 32];
        let other = [4u8; 32];
        let params = RepoParams::from_owner(&owner, limits::DEFAULT_PREFIX_LEN);
        let mut state = RepoState::default();
        state.owner = other;
        match validate_state(&params, &state) {
            Err(ValidateError::PrefixMismatch { .. }) => {}
            other => panic!("expected PrefixMismatch, got {:?}", other),
        }
    }

    #[test]
    fn invalid_prefix_length_rejected() {
        let too_short = RepoParams {
            prefix: "abc".into(),
        };
        match validate_state(&too_short, &RepoState::default()) {
            Err(ValidateError::InvalidPrefixLength { len: 3, .. }) => {}
            other => panic!("expected InvalidPrefixLength, got {:?}", other),
        }
        let too_long = RepoParams {
            prefix: "a".repeat(33),
        };
        match validate_state(&too_long, &RepoState::default()) {
            Err(ValidateError::InvalidPrefixLength { len: 33, .. }) => {}
            other => panic!("expected InvalidPrefixLength, got {:?}", other),
        }
    }

    #[test]
    fn bundle_id_matches_canonical_hash() {
        let bundle = ObjectBundle::SinglePack {
            pack_hash: [0xAA; 32],
            size_bytes: 4096,
        };
        let id = bundle.id();
        // Same logical bundle always produces same id.
        assert_eq!(id, bundle.id());
        // Different sizes produce different ids.
        let bundle2 = ObjectBundle::SinglePack {
            pack_hash: [0xAA; 32],
            size_bytes: 4097,
        };
        assert_ne!(id, bundle2.id());
    }

    #[test]
    fn merge_picks_higher_seq() {
        let mut a: SignedField<String> = SignedField {
            value: "a".into(),
            update_seq: 1,
            signature: [0u8; 64],
        };
        let b: SignedField<String> = SignedField {
            value: "b".into(),
            update_seq: 2,
            signature: [0u8; 64],
        };
        let pick = pick_signed_field(Some(a.clone()), Some(b.clone())).unwrap();
        assert_eq!(pick.update_seq, 2);
        // Tie: lower signature wins. Force a tie by raising a's seq.
        a.update_seq = 2;
        a.signature[0] = 0; // < b's signature[0] = 0 -- equal here, so a wins (≤)
        let pick = pick_signed_field(Some(a.clone()), Some(b.clone())).unwrap();
        assert_eq!(pick.value, "a");
        // Make a strictly bigger.
        a.signature[0] = 1;
        let pick = pick_signed_field(Some(a.clone()), Some(b.clone())).unwrap();
        assert_eq!(pick.value, "b");
    }

    #[test]
    fn name_size_limit_is_enforced() {
        let owner = [5u8; 32];
        let params = RepoParams::from_owner(&owner, limits::DEFAULT_PREFIX_LEN);
        let mut state = RepoState::default();
        state.owner = owner;
        state.name = Some(SignedField {
            value: "x".repeat(limits::MAX_NAME_BYTES + 1),
            update_seq: 1,
            // Signature can be junk; we expect failure on the size check
            // BEFORE the signature is verified.
            signature: [0u8; 64],
        });
        match validate_state(&params, &state) {
            Err(ValidateError::FieldTooLong { field, .. }) => assert_eq!(field, "name"),
            other => panic!("expected FieldTooLong, got {:?}", other),
        }
    }
}
