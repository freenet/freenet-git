//! ed25519 identity bundle for freenet-git, optionally encrypted at rest.
//!
//! The bundle stores the user's signing key and a registry of repos they
//! have created. By default it is encrypted at rest with `scrypt`-derived
//! keys plus XChaCha20-Poly1305; the empty-passphrase mode described
//! under "Unencrypted bundles" below skips the encryption layer. Lives by
//! default at `~/.config/freenet/git-identity.bundle`.
//!
//! # Encryption is opt-in
//!
//! For passphrase-protected bundles, the threat model is identical to
//! SSH key material: a local attacker with disk access AND the
//! passphrase can sign as you; with disk access only they see
//! ciphertext and have to brute-force scrypt; a remote attacker never
//! sees the secret.
//!
//! For unencrypted bundles, the on-disk file alone holds the signing
//! authority. That's fine when the file itself is already protected
//! (CI secrets, an OS keychain, an encrypted volume) — adding a
//! passphrase on top under those conditions is redundant. See below.
//!
//! # Unencrypted bundles
//!
//! Calling [`seal`] (or [`write_bundle`]) with an empty passphrase
//! produces a bundle whose contents are recoverable by anyone holding
//! the file: the KDF step is skipped and a fixed all-zero key is used
//! in its place. Symmetrically, [`open`] (and [`read_bundle`]) with an
//! empty passphrase succeeds for unencrypted bundles and fails the AEAD
//! tag check for encrypted ones.
//!
//! The on-disk envelope still carries fresh `KdfParams` (salt, work
//! factors) for unencrypted bundles, even though they are unused in the
//! key-derivation step. This keeps the wire format unchanged so older
//! readers continue to deserialize the envelope (they will fail
//! decryption, since they have no empty-passphrase shortcut, but the
//! parse succeeds). Future "optimizations" that elide those fields
//! would be a wire-format break.
//!
//! # Wire format (v1)
//!
//! ```text
//! bundle = bincode<{
//!   magic: [u8; 8] = b"freegit\x01",
//!   version: u32   = 1,
//!   kdf: KdfParams { salt: [u8; 16], log_n: u8, r: u32, p: u32 },
//!   nonce: [u8; 24],   // XChaCha20-Poly1305 nonce
//!   ciphertext: Vec<u8>,
//! }>
//! ```
//!
//! `ciphertext` is XChaCha20-Poly1305 of `bincode<EncryptedPayload>`. AEAD
//! associated data is `magic || version || serialize(kdf)` so a downgrade
//! attack that swaps the KDF parameters in the header invalidates the tag.
//!
//! `EncryptedPayload` carries the secret key, public key, name, email, and
//! the per-repo nonce/url registry.
//!
//! # Forward compatibility (v2 and beyond)
//!
//! [`open`] peeks the first 12 bytes of the envelope (magic + version
//! field) before deserializing the rest, then dispatches to a
//! version-specific reader. Today only v1 exists; bundles whose
//! `version` field is anything other than [`BUNDLE_VERSION`] are
//! rejected with an actionable error telling the user to upgrade
//! `freenet-git`.
//!
//! When a v2 wire format ships:
//!
//! - bump [`BUNDLE_VERSION`] to 2 and update [`seal`] to write the new
//!   layout,
//! - add a `mod v2` reader alongside `mod v1` and add a new arm to the
//!   dispatch in [`open`],
//! - **keep `mod v1::open` for read-side back-compat** so existing
//!   bundles on user disks continue to open. v1 then becomes a legacy
//!   reader, analogous to the contract-side `legacy_contracts.toml`
//!   mechanism.
//!
//! See freenet/freenet-git#31 for the original tracking issue.

#![deny(unsafe_code)]
#![warn(missing_docs)]

use std::path::Path;

use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::aead::{Aead, KeyInit, Payload};
use chacha20poly1305::XChaCha20Poly1305;
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Bundle file magic. The byte `0x01` is the format version, separate from
/// the in-payload `version` field for early-out parsing.
pub const BUNDLE_MAGIC: [u8; 8] = *b"freegit\x01";

/// Wire-format version of the bundle envelope.
///
/// [`open`] dispatches to a version-specific reader based on the
/// `version` field. Bundles produced by a release that bumped this
/// constant past the running build's value are rejected with an
/// actionable error. See the module-level "Forward compatibility"
/// docs and freenet/freenet-git#31.
pub const BUNDLE_VERSION: u32 = 1;

/// Length in bytes of the envelope prefix that [`peek_envelope_header`]
/// inspects without committing to a full deserialize: 8-byte magic +
/// 4-byte little-endian `version`. Pinned here so a future format
/// change that moves the version field can update the dispatcher in
/// one place.
const ENVELOPE_HEADER_LEN: usize = 12;

/// Minimum scrypt work factors a bundle may declare. `import-identity`
/// rejects bundles that fall below these values.
///
/// The values are equivalent to age's default `scrypt-work-factor=18`
/// (i.e. N = 2^18) at r=8, p=1. We pin the floor here rather than in
/// downstream code so a future version can tighten the floor in one place.
pub mod kdf_min {
    /// Minimum log2(N).
    pub const LOG_N: u8 = 17;
    /// Minimum r.
    pub const R: u32 = 8;
    /// Minimum p.
    pub const P: u32 = 1;
}

/// Errors returned by the identity bundle code.
#[derive(Debug, thiserror::Error)]
pub enum BundleError {
    /// I/O failure reading or writing the bundle file.
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    /// Bytes do not parse as a bundle envelope.
    #[error("bundle decode: {0}")]
    Decode(String),
    /// Header magic or version did not match.
    #[error("not a freenet-git identity bundle")]
    BadMagic,
    /// KDF parameters fell below the security floor.
    #[error("bundle KDF parameters too weak: {0}")]
    WeakKdf(String),
    /// Decryption failed (wrong passphrase, corrupted ciphertext, or
    /// tampered associated data).
    #[error("decryption failed (wrong passphrase or corrupted bundle)")]
    Decrypt,
    /// Internal error from a crypto primitive.
    #[error("crypto: {0}")]
    Crypto(String),
}

/// scrypt parameters embedded in the bundle envelope.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    /// 16-byte random salt.
    #[serde(with = "serde_bytes")]
    pub salt: Vec<u8>,
    /// log2(N).
    pub log_n: u8,
    /// r.
    pub r: u32,
    /// p.
    pub p: u32,
}

impl KdfParams {
    /// Generate fresh KDF parameters with random salt at the minimum
    /// pinned work factors.
    pub fn fresh() -> Self {
        let mut salt = vec![0u8; 16];
        OsRng.fill_bytes(&mut salt);
        Self {
            salt,
            log_n: kdf_min::LOG_N,
            r: kdf_min::R,
            p: kdf_min::P,
        }
    }

    fn enforce_minimum(&self) -> Result<(), BundleError> {
        if self.log_n < kdf_min::LOG_N {
            return Err(BundleError::WeakKdf(format!(
                "log_n = {} < minimum {}",
                self.log_n,
                kdf_min::LOG_N
            )));
        }
        if self.r < kdf_min::R {
            return Err(BundleError::WeakKdf(format!(
                "r = {} < minimum {}",
                self.r,
                kdf_min::R
            )));
        }
        if self.p < kdf_min::P {
            return Err(BundleError::WeakKdf(format!(
                "p = {} < minimum {}",
                self.p,
                kdf_min::P
            )));
        }
        if self.salt.len() != 16 {
            return Err(BundleError::WeakKdf(format!(
                "salt must be 16 bytes, got {}",
                self.salt.len()
            )));
        }
        Ok(())
    }

    fn derive_key(&self, passphrase: &str) -> Result<[u8; 32], BundleError> {
        // Empty passphrase is a sentinel for "unencrypted at rest": the
        // key is publicly derivable (all zeros) so anyone with the file
        // can open it. Used when the bundle file itself lives in an
        // authenticated secret store (GitHub Actions secrets, OS
        // keychain) and the on-disk encryption layer is redundant.
        // Skips scrypt to keep CLI invocations snappy in CI.
        //
        // NOTE: this short-circuits before `enforce_minimum`, so weak
        // KdfParams in the envelope are ignored on the empty-passphrase
        // path. The KDF parameters are unused there anyway. If a future
        // change tightens the scrypt floor, the empty-passphrase
        // shortcut must remain exempt — otherwise existing unencrypted
        // bundles produced under the old floor would suddenly fail to
        // open after an upgrade.
        if passphrase.is_empty() {
            return Ok([0u8; 32]);
        }
        self.enforce_minimum()?;
        let params = scrypt::Params::new(self.log_n, self.r, self.p, 32)
            .map_err(|e| BundleError::Crypto(format!("scrypt params: {e}")))?;
        let mut out = [0u8; 32];
        scrypt::scrypt(passphrase.as_bytes(), &self.salt, &params, &mut out)
            .map_err(|e| BundleError::Crypto(format!("scrypt: {e}")))?;
        Ok(out)
    }
}

/// One row in the per-repo registry.
///
/// Each repo carries its own ed25519 keypair, mirroring the delta site
/// model: the URL prefix is derived from the per-repo public key, so a
/// fresh repo means a fresh keypair. The bundle's "default" identity
/// (`secret_key` / `public_key` at the top level) is reserved for
/// future per-user signing — PR comments and reviews in Phase 2.
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RepoRegistryEntry {
    /// ed25519 secret key for THIS repo.
    #[serde(with = "serde_bytes")]
    pub repo_secret: Vec<u8>,
    /// ed25519 public key for THIS repo.
    #[serde(with = "serde_bytes")]
    pub repo_public: Vec<u8>,
    /// The base58 prefix derived from `repo_public`. This IS the URL
    /// (modulo the `freenet:` scheme and an optional label). Cached
    /// here so we don't recompute on every CLI invocation.
    pub prefix: String,
    /// Display name (typically the repo name; used as the URL label).
    pub display_name: String,
}

impl std::fmt::Debug for RepoRegistryEntry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("RepoRegistryEntry")
            .field("prefix", &self.prefix)
            .field("display_name", &self.display_name)
            .field("repo_secret", &"<redacted>")
            .field(
                "repo_public",
                &format_args!("{}", hex_short(&self.repo_public)),
            )
            .finish()
    }
}

/// Decrypted bundle contents. Held in memory for the duration of one CLI
/// invocation, then dropped (which zeroizes the secret).
#[derive(Serialize, Deserialize, ZeroizeOnDrop)]
pub struct DecryptedBundle {
    /// ed25519 secret key bytes (32 bytes).
    #[serde(with = "serde_bytes")]
    pub secret_key: Vec<u8>,
    /// ed25519 public key bytes (32 bytes).
    #[serde(with = "serde_bytes")]
    pub public_key: Vec<u8>,
    /// Display name.
    #[zeroize(skip)]
    pub name: String,
    /// Email.
    #[zeroize(skip)]
    pub email: String,
    /// Repos this identity has created.
    #[zeroize(skip)]
    pub repos: Vec<RepoRegistryEntry>,
}

impl std::fmt::Debug for DecryptedBundle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DecryptedBundle")
            .field("name", &self.name)
            .field("email", &self.email)
            .field(
                "public_key",
                &format_args!("{}", hex_short(&self.public_key)),
            )
            .field("secret_key", &"<redacted>")
            .field("repos", &self.repos.len())
            .finish()
    }
}

impl DecryptedBundle {
    /// Generate a fresh keypair from OsRng and wrap it in a new bundle.
    pub fn new(name: String, email: String) -> Self {
        let signing = SigningKey::generate(&mut OsRng);
        let verifying = signing.verifying_key();
        Self {
            secret_key: signing.to_bytes().to_vec(),
            public_key: verifying.to_bytes().to_vec(),
            name,
            email,
            repos: Vec::new(),
        }
    }

    /// Reconstruct a `SigningKey` for use in signing operations. The
    /// returned key carries its own zero-on-drop semantics from
    /// ed25519-dalek.
    pub fn signing_key(&self) -> Result<SigningKey, BundleError> {
        let bytes: [u8; 32] = self
            .secret_key
            .as_slice()
            .try_into()
            .map_err(|_| BundleError::Decode("secret_key wrong length".into()))?;
        Ok(SigningKey::from_bytes(&bytes))
    }

    /// Reconstruct a `VerifyingKey` (the public part).
    pub fn verifying_key(&self) -> Result<VerifyingKey, BundleError> {
        let bytes: [u8; 32] = self
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| BundleError::Decode("public_key wrong length".into()))?;
        VerifyingKey::from_bytes(&bytes).map_err(|e| BundleError::Decode(e.to_string()))
    }

    /// Print-friendly identity string used in CLI output:
    /// `freenet:id:<base58 of pubkey>`.
    pub fn id_string(&self) -> String {
        format!(
            "freenet:id:{}",
            bs58::encode(&self.public_key).into_string()
        )
    }
}

/// Bundle envelope as it lives on disk for `version = 1`.
///
/// A future v2 will introduce its own struct (probably under
/// `mod v2`); the dispatch in [`open`] picks which one to deserialize
/// based on the version field peeked from the header. See module-level
/// "Forward compatibility" docs.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct Envelope {
    magic: [u8; 8],
    version: u32,
    kdf: KdfParams,
    #[serde(with = "serde_bytes")]
    nonce: Vec<u8>,
    #[serde(with = "serde_bytes")]
    ciphertext: Vec<u8>,
}

/// Lightweight view of the envelope's first 12 bytes, recovered without
/// committing to the rest of the layout. See [`peek_envelope_header`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct EnvelopeHeader {
    magic: [u8; 8],
    version: u32,
}

/// Inspect the first [`ENVELOPE_HEADER_LEN`] bytes of `bytes` to
/// recover the magic and version. Used by [`open`] to dispatch to a
/// version-specific reader before committing to a particular
/// `Envelope` layout. A future v2 may have a different post-header
/// struct, so we cannot do a full bincode deserialize up front.
fn peek_envelope_header(bytes: &[u8]) -> Result<EnvelopeHeader, BundleError> {
    if bytes.len() < ENVELOPE_HEADER_LEN {
        return Err(BundleError::Decode(format!(
            "bundle is too short to be a freenet-git identity bundle (got {} bytes, need at least {})",
            bytes.len(),
            ENVELOPE_HEADER_LEN
        )));
    }
    let mut magic = [0u8; 8];
    magic.copy_from_slice(&bytes[0..8]);
    // bincode 1.3 default config encodes `u32` as little-endian
    // fixed-size 4 bytes. The wire-format fixture tests would catch
    // a config change that moved this off the default, but pinning
    // the assumption here in a comment helps future readers.
    let version = u32::from_le_bytes([bytes[8], bytes[9], bytes[10], bytes[11]]);
    Ok(EnvelopeHeader { magic, version })
}

/// Encrypt a [`DecryptedBundle`] under a passphrase and return the
/// envelope bytes ready to be written to disk.
pub fn seal(bundle: &DecryptedBundle, passphrase: &str) -> Result<Vec<u8>, BundleError> {
    let kdf = KdfParams::fresh();
    let key_bytes = kdf.derive_key(passphrase)?;
    let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&key_bytes));

    let mut nonce = vec![0u8; 24];
    OsRng.fill_bytes(&mut nonce);

    let payload_bytes = bincode::serialize(bundle)
        .map_err(|e| BundleError::Crypto(format!("serialize bundle: {e}")))?;
    let aad = associated_data(&kdf)?;
    let ciphertext = cipher
        .encrypt(
            GenericArray::from_slice(&nonce),
            Payload {
                msg: &payload_bytes,
                aad: &aad,
            },
        )
        .map_err(|_| BundleError::Crypto("encrypt".into()))?;

    let mut key_zero = key_bytes;
    key_zero.zeroize();

    let envelope = Envelope {
        magic: BUNDLE_MAGIC,
        version: BUNDLE_VERSION,
        kdf,
        nonce,
        ciphertext,
    };
    bincode::serialize(&envelope)
        .map_err(|e| BundleError::Crypto(format!("serialize envelope: {e}")))
}

/// Decrypt a previously-sealed bundle.
///
/// Peeks the envelope header to recover the format version, then
/// dispatches to the version-specific reader. A bundle whose `version`
/// field is greater than [`BUNDLE_VERSION`] (i.e. produced by a newer
/// freenet-git release) is rejected with an actionable error telling
/// the user to upgrade. See the module-level "Forward compatibility"
/// docs.
pub fn open(bytes: &[u8], passphrase: &str) -> Result<DecryptedBundle, BundleError> {
    let header = peek_envelope_header(bytes)?;
    if header.magic != BUNDLE_MAGIC {
        return Err(BundleError::BadMagic);
    }
    match header.version {
        1 => v1::open(bytes, passphrase),
        v => Err(BundleError::Decode(format!(
            "unsupported bundle version {v}; this build of freenet-git supports versions up to {BUNDLE_VERSION}. Upgrade freenet-git to read this bundle."
        ))),
    }
}

/// v1 reader. Stays here as a legacy reader once a v2 layout ships;
/// see module-level "Forward compatibility" docs.
mod v1 {
    use super::{
        associated_data, BundleError, DecryptedBundle, Envelope, BUNDLE_MAGIC, BUNDLE_VERSION,
    };
    use chacha20poly1305::aead::generic_array::GenericArray;
    use chacha20poly1305::aead::{Aead, KeyInit, Payload};
    use chacha20poly1305::XChaCha20Poly1305;
    use zeroize::Zeroize;

    pub(super) fn open(bytes: &[u8], passphrase: &str) -> Result<DecryptedBundle, BundleError> {
        let envelope: Envelope =
            bincode::deserialize(bytes).map_err(|e| BundleError::Decode(e.to_string()))?;
        // The dispatcher in `super::open` already checked these, but
        // keep the guards so a future call site that bypasses dispatch
        // can't accidentally feed a non-v1 envelope into v1 logic.
        if envelope.magic != BUNDLE_MAGIC {
            return Err(BundleError::BadMagic);
        }
        if envelope.version != BUNDLE_VERSION {
            return Err(BundleError::Decode(format!(
                "v1 reader received version {} envelope",
                envelope.version
            )));
        }
        let key_bytes = envelope.kdf.derive_key(passphrase)?;
        let cipher = XChaCha20Poly1305::new(GenericArray::from_slice(&key_bytes));

        let aad = associated_data(&envelope.kdf)?;
        let plaintext = cipher
            .decrypt(
                GenericArray::from_slice(&envelope.nonce),
                Payload {
                    msg: &envelope.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| BundleError::Decrypt)?;

        let mut key_zero = key_bytes;
        key_zero.zeroize();

        bincode::deserialize::<DecryptedBundle>(&plaintext)
            .map_err(|e| BundleError::Decode(e.to_string()))
    }
}

/// Default bundle path: `~/.config/freenet/git-identity.bundle`.
///
/// Honors `$XDG_CONFIG_HOME` when set and otherwise falls back to
/// `$HOME/.config`.
pub fn default_bundle_path() -> std::path::PathBuf {
    if let Ok(xdg) = std::env::var("XDG_CONFIG_HOME") {
        return std::path::PathBuf::from(xdg)
            .join("freenet")
            .join("git-identity.bundle");
    }
    if let Ok(home) = std::env::var("HOME") {
        return std::path::PathBuf::from(home)
            .join(".config")
            .join("freenet")
            .join("git-identity.bundle");
    }
    std::path::PathBuf::from(".freenet-git-identity.bundle")
}

/// Convenience: write `bundle` encrypted under `passphrase` to `path`,
/// creating parent directories as needed and setting permissions to 0600
/// on Unix.
pub fn write_bundle(
    bundle: &DecryptedBundle,
    passphrase: &str,
    path: &Path,
) -> Result<(), BundleError> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = seal(bundle, passphrase)?;
    write_atomic(path, &bytes)
}

/// Convenience: read the bundle at `path` and decrypt it.
pub fn read_bundle(path: &Path, passphrase: &str) -> Result<DecryptedBundle, BundleError> {
    let bytes = std::fs::read(path)?;
    open(&bytes, passphrase)
}

fn write_atomic(path: &Path, bytes: &[u8]) -> Result<(), BundleError> {
    use std::io::Write;
    let parent = path.parent().unwrap_or(Path::new("."));
    let tmp = parent.join(format!(
        ".{}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    {
        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp)?;
        f.write_all(bytes)?;
        f.sync_all()?;
    }
    set_perms_0600(&tmp)?;
    std::fs::rename(&tmp, path)?;
    Ok(())
}

#[cfg(unix)]
fn set_perms_0600(path: &Path) -> Result<(), BundleError> {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path)?.permissions();
    perms.set_mode(0o600);
    std::fs::set_permissions(path, perms)?;
    Ok(())
}

#[cfg(not(unix))]
fn set_perms_0600(_path: &Path) -> Result<(), BundleError> {
    // On non-Unix, rely on the default ACLs. (Phase 1 ships Unix-first.)
    Ok(())
}

fn associated_data(kdf: &KdfParams) -> Result<Vec<u8>, BundleError> {
    let mut buf = Vec::with_capacity(8 + 4 + 32);
    buf.extend_from_slice(&BUNDLE_MAGIC);
    buf.extend_from_slice(&BUNDLE_VERSION.to_le_bytes());
    let kdf_bytes =
        bincode::serialize(kdf).map_err(|e| BundleError::Crypto(format!("serialize kdf: {e}")))?;
    buf.extend_from_slice(&kdf_bytes);
    Ok(buf)
}

fn hex_short(bytes: &[u8]) -> String {
    let mut out = String::new();
    for b in bytes.iter().take(4) {
        out.push_str(&format!("{b:02x}"));
    }
    out.push_str("..");
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_seal_and_open() {
        let bundle = DecryptedBundle::new("Tester".into(), "t@example.com".into());
        let sealed = seal(&bundle, "correct horse battery staple").unwrap();
        let opened = open(&sealed, "correct horse battery staple").unwrap();
        assert_eq!(opened.public_key, bundle.public_key);
        assert_eq!(opened.name, "Tester");
        assert_eq!(opened.email, "t@example.com");
    }

    #[test]
    fn wrong_passphrase_fails() {
        let bundle = DecryptedBundle::new("X".into(), "x@e.com".into());
        let sealed = seal(&bundle, "right").unwrap();
        match open(&sealed, "wrong") {
            Err(BundleError::Decrypt) => {}
            other => panic!("expected Decrypt, got {other:?}"),
        }
    }

    #[test]
    fn tampered_kdf_params_invalidate_tag() {
        let bundle = DecryptedBundle::new("X".into(), "x@e.com".into());
        let sealed = seal(&bundle, "pw").unwrap();
        let mut envelope: Envelope = bincode::deserialize(&sealed).unwrap();
        // Bump log_n by 1: AAD changes, AEAD tag fails.
        envelope.kdf.log_n += 1;
        let tampered = bincode::serialize(&envelope).unwrap();
        match open(&tampered, "pw") {
            Err(BundleError::Decrypt) => {}
            other => panic!("expected Decrypt, got {other:?}"),
        }
    }

    #[test]
    fn rejects_below_minimum_kdf() {
        // Construct a hand-rolled envelope with weak KDF params.
        let weak = KdfParams {
            salt: vec![0u8; 16],
            log_n: 8,
            r: 8,
            p: 1,
        };
        let result = weak.derive_key("pw");
        match result {
            Err(BundleError::WeakKdf(_)) => {}
            other => panic!("expected WeakKdf, got {other:?}"),
        }
    }

    #[test]
    fn round_trip_through_disk() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.bundle");
        let bundle = DecryptedBundle::new("Disk".into(), "d@e.com".into());
        write_bundle(&bundle, "pw", &path).unwrap();
        let opened = read_bundle(&path, "pw").unwrap();
        assert_eq!(opened.name, "Disk");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "bundle on disk must be 0600");
        }
    }

    #[test]
    fn id_string_uses_base58_pubkey() {
        let bundle = DecryptedBundle::new("X".into(), "x@e.com".into());
        let s = bundle.id_string();
        assert!(s.starts_with("freenet:id:"));
        // Decoded bytes must equal the public key.
        let decoded = bs58::decode(&s["freenet:id:".len()..]).into_vec().unwrap();
        assert_eq!(decoded, bundle.public_key);
    }

    #[test]
    fn empty_passphrase_round_trip() {
        let bundle = DecryptedBundle::new("None".into(), "n@e.com".into());
        let sealed = seal(&bundle, "").unwrap();
        let opened = open(&sealed, "").unwrap();
        assert_eq!(opened.public_key, bundle.public_key);
        assert_eq!(opened.name, "None");
    }

    #[test]
    fn empty_passphrase_does_not_open_encrypted_bundle() {
        let bundle = DecryptedBundle::new("X".into(), "x@e.com".into());
        let sealed = seal(&bundle, "real-passphrase").unwrap();
        match open(&sealed, "") {
            Err(BundleError::Decrypt) => {}
            other => panic!("expected Decrypt, got {other:?}"),
        }
    }

    #[test]
    fn real_passphrase_does_not_open_unencrypted_bundle() {
        let bundle = DecryptedBundle::new("X".into(), "x@e.com".into());
        let sealed = seal(&bundle, "").unwrap();
        match open(&sealed, "real-passphrase") {
            Err(BundleError::Decrypt) => {}
            other => panic!("expected Decrypt, got {other:?}"),
        }
    }

    /// Deterministic seed bytes for the fixture user's ed25519
    /// identity. Chosen as `[0x42; 32]` (no special meaning, just a
    /// recognisable nibble). The corresponding verifying-key bytes
    /// are pinned in `tests/wire_format.rs` so a regen produces a
    /// byte-identical pubkey -- enabling anti-tamper verification
    /// of the checked-in fixtures by re-running the generator.
    pub const FIXTURE_USER_SEED: [u8; 32] = [0x42; 32];

    /// One-shot generator for the on-disk wire-format fixtures used
    /// by `tests/wire_format.rs`. Marked `#[ignore]` so `cargo test`
    /// doesn't regenerate the fixtures on every run -- they are
    /// checked-in artifacts. To regenerate (e.g. after a known,
    /// intentional wire-format change), run:
    ///
    ///     cargo test -p freenet-git-identity \
    ///         regenerate_wire_format_fixtures -- --ignored --nocapture
    ///
    /// Uses `FIXTURE_USER_SEED` for the ed25519 keypair so the
    /// output is reproducible. The unencrypted fixture is fully
    /// byte-deterministic across regen runs (the empty-passphrase
    /// path skips both scrypt salt generation and AEAD nonce
    /// randomness... wait, actually `seal` still calls
    /// `KdfParams::fresh()` and a random nonce regardless of
    /// passphrase). The encrypted fixture's outer envelope has a
    /// fresh salt + nonce per regen, so its bytes differ each run --
    /// content-pinning happens via the round-trip test rather than
    /// byte equality. Anti-tamper for the unencrypted fixture is
    /// therefore "decrypt and verify identity content matches"
    /// rather than "byte-compare the file."
    #[test]
    #[ignore]
    fn regenerate_wire_format_fixtures() {
        use ed25519_dalek::SigningKey;

        let signing = SigningKey::from_bytes(&FIXTURE_USER_SEED);
        let bundle = DecryptedBundle {
            secret_key: signing.to_bytes().to_vec(),
            public_key: signing.verifying_key().to_bytes().to_vec(),
            name: "Fixture User".into(),
            email: "fixture@example.com".into(),
            // `prefix` and the per-repo keys are deliberately not
            // derived from a real per-repo keypair -- the fixture
            // is for deserialisation testing only, never for signing
            // or URL derivation. The literal `"fixture-prefix"`
            // exercises the `prefix` field's serde path without
            // committing to a particular pubkey-prefix scheme that
            // a future Phase 1.1 change might break.
            repos: vec![RepoRegistryEntry {
                repo_secret: vec![0u8; 32],
                repo_public: vec![0u8; 32],
                prefix: "fixture-prefix".to_string(),
                display_name: "fixture-repo".to_string(),
            }],
        };

        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests")
            .join("fixtures");
        std::fs::create_dir_all(&dir).unwrap();

        write_bundle(&bundle, "test-passphrase", &dir.join("v1-encrypted.bundle")).unwrap();
        write_bundle(&bundle, "", &dir.join("v1-unencrypted.bundle")).unwrap();

        let pubkey_hex: String = bundle
            .public_key
            .iter()
            .map(|b| format!("{b:02x}"))
            .collect();

        println!();
        println!("=== regenerated wire-format fixtures (deterministic seed) ===");
        println!("pubkey: {}", bundle.id_string());
        println!("pubkey hex: {pubkey_hex}");
    }

    #[test]
    fn rejects_future_bundle_version_with_actionable_error() {
        // Synthesise a "v2" bundle by sealing a v1 bundle and then
        // bumping the `version` field in the envelope. The dispatcher
        // in `open` should peek the version and reject with a message
        // that tells the user to upgrade. See freenet/freenet-git#31.
        let bundle = DecryptedBundle::new("X".into(), "x@e.com".into());
        let sealed = seal(&bundle, "pw").unwrap();
        let mut envelope: Envelope = bincode::deserialize(&sealed).unwrap();
        envelope.version = 2;
        let v2_synthetic = bincode::serialize(&envelope).unwrap();

        let err = open(&v2_synthetic, "pw")
            .expect_err("synthetic v2-version bundle must be rejected by dispatcher");
        match err {
            BundleError::Decode(msg) => {
                assert!(
                    msg.contains("unsupported bundle version 2"),
                    "error must name the offending version: {msg}"
                );
                assert!(
                    msg.contains("Upgrade") || msg.contains("upgrade"),
                    "error must tell the user to upgrade: {msg}"
                );
            }
            other => panic!("expected Decode, got {other:?}"),
        }
    }

    #[test]
    fn rejects_too_short_bundle() {
        // Anything shorter than the 12-byte header is not a bundle.
        // We must fail with Decode, not BadMagic, since we cannot even
        // check the magic on bytes this short.
        for len in [0usize, 1, 7, 11] {
            let bytes = vec![0u8; len];
            assert!(
                open(&bytes, "pw").is_err(),
                "len {len}: open must reject too-short input"
            );
        }
        let bytes = vec![0u8; 5];
        match open(&bytes, "pw") {
            Err(BundleError::Decode(msg)) => {
                assert!(
                    msg.contains("too short"),
                    "decode error should mention too-short: {msg}"
                );
            }
            other => panic!("expected Decode(too short), got {other:?}"),
        }
    }

    #[test]
    fn dispatcher_rejects_wrong_magic_before_version_check() {
        // 12 bytes of zeros: magic mismatches but length is enough to
        // peek the version. We must hit BadMagic, not the
        // "unsupported version" path -- a bundle from a different tool
        // entirely shouldn't be reported as a "future-version freenet
        // bundle."
        let mut bytes = vec![0u8; 64];
        // version field = 1 LE so we are sure version dispatch would
        // succeed if we got that far.
        bytes[8..12].copy_from_slice(&1u32.to_le_bytes());
        match open(&bytes, "pw") {
            Err(BundleError::BadMagic) => {}
            other => panic!("expected BadMagic, got {other:?}"),
        }
    }

    #[test]
    fn peek_envelope_header_recovers_magic_and_version() {
        let bundle = DecryptedBundle::new("X".into(), "x@e.com".into());
        let sealed = seal(&bundle, "pw").unwrap();
        let header = peek_envelope_header(&sealed)
            .expect("freshly-sealed bundle must have a peekable header");
        assert_eq!(header.magic, BUNDLE_MAGIC);
        assert_eq!(header.version, BUNDLE_VERSION);
    }

    #[test]
    fn unencrypted_bundle_round_trip_through_disk_with_0600_perms() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("id.bundle");
        let bundle = DecryptedBundle::new("Plain".into(), "p@e.com".into());
        write_bundle(&bundle, "", &path).unwrap();
        let opened = read_bundle(&path, "").unwrap();
        assert_eq!(opened.name, "Plain");

        // The whole point of the "Bundle is unencrypted at rest -- protect
        // the file accordingly" warning in the CLI is that 0600 is now the
        // only on-disk defense. Pin the contract.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "unencrypted bundle on disk must be 0600");
        }
    }
}
