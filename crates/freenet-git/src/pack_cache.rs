//! On-disk pack cache for `freenet-git`.
//!
//! Every successful pack GET (`wsclient::get_pack`) and pack PUT
//! (`wsclient::put_pack`) writes the raw pack bytes here, indexed by
//! their BLAKE3 content hash. Subsequent operations against the same
//! hash can short-circuit the network entirely. The cache is
//! content-addressed, so cache hits MUST verify the read bytes hash
//! to the requested key before returning -- a tampered cache file
//! cannot poison results.
//!
//! # Why this exists
//!
//! `freenet-git rescue` re-PUTs every bundle and chunk a repo
//! references back to the network -- but only what the local
//! Freenet node still has cached. If the gateway has already evicted
//! a chunk by the time the rescue cron fires, the rescue is a no-op
//! for that chunk. The pack cache lets a clone-holder rescue from
//! their own previously-fetched bytes even when the local node's
//! cache has rolled.
//!
//! It also helps clients: a re-clone after a partial-clone failure
//! reuses the chunks that already made it to disk, rather than
//! redoing the GET against a slow gateway. See
//! freenet/freenet-git#22 (Phase 1) for context.
//!
//! # Layout
//!
//! ```text
//! <root>/<lowercase-hex-hash>.pack
//! ```
//!
//! The default `<root>` (used by [`from_environment`]) is
//! `$XDG_CACHE_HOME/freenet-git/packs`, falling back to
//! `$HOME/.cache/freenet-git/packs`.
//!
//! # Disabling
//!
//! Setting `FREENET_GIT_PACK_CACHE=off` (or `0`/`false`) makes
//! [`from_environment`] return `None`. Callers fall through to a
//! no-op cache (every read misses, every write is dropped).
//! Setting `FREENET_GIT_PACK_CACHE_DIR=<path>` overrides the
//! default cache root.
//!
//! # Eviction
//!
//! None today. The cache grows monotonically and the user can
//! `rm -rf ~/.cache/freenet-git` to reclaim space. An LRU policy
//! is left as future work; pack files are immutable so eviction is
//! safe at any point.

use std::path::{Path, PathBuf};

/// Environment variable that disables the cache entirely when set
/// to `off`/`0`/`false`. Used by tests and by users who want to
/// force network round-trips for diagnostic purposes.
const ENV_TOGGLE: &str = "FREENET_GIT_PACK_CACHE";

/// Environment variable that overrides the cache root directory.
/// Users can point this at faster storage; tests should construct
/// a [`PackCache`] explicitly via [`PackCache::at`] instead of
/// relying on this (process-wide env vars race when cargo runs
/// tests in parallel).
const ENV_DIR: &str = "FREENET_GIT_PACK_CACHE_DIR";

/// Subdirectory under `$XDG_CACHE_HOME` (or `$HOME/.cache`) where
/// pack files live.
const SUBDIR: &str = "freenet-git/packs";

/// On-disk cache rooted at a specific directory.
///
/// Construct via [`PackCache::from_environment`] for the standard
/// XDG-resolved path, or [`PackCache::at`] for an explicit root
/// (used by tests).
#[derive(Debug, Clone)]
pub struct PackCache {
    root: PathBuf,
}

impl PackCache {
    /// Construct a cache rooted at an explicit directory. The
    /// directory is created lazily on first write.
    pub fn at(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    /// Resolve the default cache from environment:
    ///   1. `FREENET_GIT_PACK_CACHE_DIR` if set,
    ///   2. `$XDG_CACHE_HOME/freenet-git/packs` if `XDG_CACHE_HOME` set,
    ///   3. `$HOME/.cache/freenet-git/packs`.
    ///
    /// Returns `None` if `FREENET_GIT_PACK_CACHE` disables the cache,
    /// or if no usable home directory can be determined. A `None`
    /// here is safe: callers treat the absence of a cache as
    /// "every read misses, every write is dropped."
    pub fn from_environment() -> Option<Self> {
        if disabled_via_env() {
            return None;
        }
        if let Ok(custom) = std::env::var(ENV_DIR) {
            if !custom.is_empty() {
                return Some(Self::at(custom));
            }
        }
        if let Ok(xdg) = std::env::var("XDG_CACHE_HOME") {
            if !xdg.is_empty() {
                return Some(Self::at(PathBuf::from(xdg).join(SUBDIR)));
            }
        }
        if let Ok(home) = std::env::var("HOME") {
            if !home.is_empty() {
                return Some(Self::at(PathBuf::from(home).join(".cache").join(SUBDIR)));
            }
        }
        None
    }

    /// Cache root directory.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn path_for(&self, hash: &[u8; 32]) -> PathBuf {
        let mut name = String::with_capacity(64 + 5);
        for b in hash.iter() {
            use std::fmt::Write as _;
            let _ = write!(name, "{b:02x}");
        }
        name.push_str(".pack");
        self.root.join(name)
    }

    /// Read pack bytes for `hash`, verifying content addressing.
    /// Returns `None` for a miss, an unreadable file, or a
    /// content-hash mismatch (which removes the bad file). Errors
    /// are intentionally non-fatal: a cache fault must never break a
    /// fetch / rescue.
    pub fn read(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        let path = self.path_for(hash);
        let bytes = std::fs::read(&path).ok()?;
        let actual = *blake3::hash(&bytes).as_bytes();
        if actual != *hash {
            // File is content-addressed; a mismatch means the file
            // was tampered with or the storage corrupted it. Remove
            // so we don't keep returning poison on every read.
            let _ = std::fs::remove_file(&path);
            tracing::warn!(
                "pack cache: removing corrupted entry at {} (hash mismatch)",
                path.display()
            );
            return None;
        }
        Some(bytes)
    }

    /// Write pack bytes for `hash`. Best-effort: failures are
    /// logged at warn but do not propagate, because the surrounding
    /// network operation has already succeeded by the time we get
    /// here.
    pub fn write(&self, hash: &[u8; 32], bytes: &[u8]) {
        let path = self.path_for(hash);
        if let Err(e) = write_atomic(&path, bytes) {
            tracing::warn!("pack cache: failed to write {}: {e}", path.display());
        }
    }
}

fn disabled_via_env() -> bool {
    match std::env::var(ENV_TOGGLE) {
        Ok(v) => matches!(v.to_ascii_lowercase().as_str(), "off" | "0" | "false"),
        Err(_) => false,
    }
}

fn write_atomic(path: &Path, bytes: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    // tmp + rename so a partially-written file from a crashed
    // process doesn't surface as a "corrupted" entry on the next
    // read (which would silently drop the file -- correct, but
    // wasted work).
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
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
    std::fs::rename(&tmp, path)?;
    Ok(())
}

/// Convenience for the production path: try to resolve the default
/// cache from environment and call `read`. Returns `None` when the
/// cache is disabled or unavailable.
pub fn read(hash: &[u8; 32]) -> Option<Vec<u8>> {
    PackCache::from_environment().and_then(|c| c.read(hash))
}

/// Convenience for the production path: try to resolve the default
/// cache from environment and call `write`. No-op when the cache is
/// disabled or unavailable.
pub fn write(hash: &[u8; 32], bytes: &[u8]) {
    if let Some(c) = PackCache::from_environment() {
        c.write(hash, bytes);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unique_bytes(seed: u8) -> Vec<u8> {
        (0..1024u32).map(|i| (i & 0xFF) as u8 ^ seed).collect()
    }

    #[test]
    fn read_returns_none_on_miss() {
        let dir = tempfile::tempdir().unwrap();
        let cache = PackCache::at(dir.path());
        assert!(cache.read(&[0u8; 32]).is_none());
    }

    #[test]
    fn write_then_read_roundtrips() {
        let dir = tempfile::tempdir().unwrap();
        let cache = PackCache::at(dir.path());
        let bytes = unique_bytes(0x42);
        let hash = *blake3::hash(&bytes).as_bytes();
        cache.write(&hash, &bytes);
        let got = cache.read(&hash).expect("must read back what we wrote");
        assert_eq!(got, bytes);
    }

    #[test]
    fn read_rejects_and_removes_tampered_entry() {
        // Cache is content-addressed: if a file's bytes don't match
        // its key, we must NOT return them and we must remove the
        // poisoned file so the next read goes back to the network.
        let dir = tempfile::tempdir().unwrap();
        let cache = PackCache::at(dir.path());
        let claimed = [0xABu8; 32];
        let path = cache.path_for(&claimed);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, b"definitely not the right bytes").unwrap();

        assert!(cache.read(&claimed).is_none());
        assert!(
            !path.exists(),
            "tampered entry must be removed by read() at {}",
            path.display()
        );
    }

    #[test]
    fn write_overwrites_existing_entry_atomically() {
        // Two different writes for the same hash (e.g. a re-PUT)
        // should leave only the latest bytes on disk, never a
        // half-written tmpfile.
        let dir = tempfile::tempdir().unwrap();
        let cache = PackCache::at(dir.path());
        let bytes_a = unique_bytes(0x11);
        let hash = *blake3::hash(&bytes_a).as_bytes();
        cache.write(&hash, &bytes_a);
        let bytes_b = unique_bytes(0x22);
        // For the test, put bytes_b under the SAME hash to confirm
        // the overwrite path. (In production, a hash collision on
        // BLAKE3 is implausible; this test exercises the rename
        // semantics, not collision handling.)
        cache.write(&hash, &bytes_b);
        let path = cache.path_for(&hash);
        let on_disk = std::fs::read(&path).unwrap();
        assert_eq!(on_disk, bytes_b);

        // The .tmp file in the same directory must be gone.
        let tmp = path.parent().unwrap().join(format!(
            ".{}.tmp",
            path.file_name().unwrap().to_string_lossy()
        ));
        assert!(!tmp.exists(), "tmp file must be cleaned up after rename");
    }

    #[test]
    fn cache_creates_root_lazily() {
        // Cache root doesn't have to exist before write -- the
        // module creates it via create_dir_all. This is important
        // because a fresh user has no ~/.cache/freenet-git yet.
        let dir = tempfile::tempdir().unwrap();
        let nested = dir.path().join("sub/dir/that/doesnt/exist");
        let cache = PackCache::at(&nested);
        assert!(!nested.exists());

        let bytes = unique_bytes(0x33);
        let hash = *blake3::hash(&bytes).as_bytes();
        cache.write(&hash, &bytes);

        assert!(nested.exists(), "cache write must create root lazily");
        let got = cache.read(&hash).unwrap();
        assert_eq!(got, bytes);
    }

    #[test]
    fn distinct_hashes_have_distinct_paths() {
        let dir = tempfile::tempdir().unwrap();
        let cache = PackCache::at(dir.path());
        let p_a = cache.path_for(&[0x00; 32]);
        let p_b = cache.path_for(&[0xFF; 32]);
        assert_ne!(p_a, p_b);
        assert!(p_a.to_string_lossy().contains(&"00".repeat(32)));
        assert!(p_b.to_string_lossy().contains(&"ff".repeat(32)));
    }
}
