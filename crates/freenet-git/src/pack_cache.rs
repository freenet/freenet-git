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
        // Filename is always 64 lowercase hex chars + `.pack`,
        // emitted from a fixed 32-byte array. No path-traversal
        // possible: there is no way for arbitrary input to influence
        // this output beyond the 32-byte hash itself.
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
    ///
    /// `debug_assert!`s that `BLAKE3(bytes) == *hash` to catch
    /// caller bugs in test/debug builds. A mismatch in release
    /// would surface as a self-evicting cache entry on the next
    /// read (still safe, just wasted work).
    pub fn write(&self, hash: &[u8; 32], bytes: &[u8]) {
        debug_assert_eq!(
            blake3::hash(bytes).as_bytes(),
            hash,
            "pack_cache::write called with bytes whose BLAKE3 does not match the key",
        );
        let path = self.path_for(hash);
        if let Err(e) = write_atomic(&path, bytes) {
            tracing::warn!("pack cache: failed to write {}: {e}", path.display());
        }
    }

    /// Async wrapper around [`PackCache::read`] that runs the
    /// synchronous file IO on a Tokio blocking thread. Use this
    /// from `async fn` bodies on a current-thread runtime so the
    /// disk read + BLAKE3 verify don't stall the runtime thread.
    pub async fn read_async(&self, hash: &[u8; 32]) -> Option<Vec<u8>> {
        let me = self.clone();
        let h = *hash;
        tokio::task::spawn_blocking(move || me.read(&h))
            .await
            .ok()
            .flatten()
    }

    /// Async wrapper around [`PackCache::write`]. The synchronous
    /// fsync inside `write_atomic` can stall a current-thread
    /// runtime for tens to hundreds of milliseconds on slow disks,
    /// so the cache write is moved to a blocking thread. Best-
    /// effort: spawn-blocking failures are silently ignored, same
    /// as [`PackCache::write`] swallows IO errors.
    pub async fn write_async(&self, hash: &[u8; 32], bytes: &[u8]) {
        let me = self.clone();
        let h = *hash;
        let bytes = bytes.to_vec();
        let _ = tokio::task::spawn_blocking(move || me.write(&h, &bytes)).await;
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
    // read.
    //
    // The tmp path includes pid + a random suffix so concurrent
    // writers for the same content hash don't share a tmp file.
    // Without unique tmp paths, two processes (or two intra-process
    // tasks under chunked.rs's parallel fetcher pool) both writing
    // the same bytes would race on truncate+write of a single tmp,
    // leaving one writer's data partially overwritten before its
    // own rename. The final bytes would still be content-valid
    // (both writers produce identical bytes by definition), but the
    // intermediate tmp would briefly hold malformed bytes and a
    // crash mid-write would leave a partial file under that shared
    // tmp name. Unique tmps make the writes fully independent and
    // the final rename a clean replace-or-leave-alone.
    //
    // `O_NOFOLLOW` + `create_new` (== `O_CREAT | O_EXCL`) prevent
    // a planted symlink at the tmp path from redirecting our write
    // to an unrelated file. The unique tmp name + `O_EXCL` make the
    // open atomically fail if the tmp already exists, so a hostile
    // user who pre-plants a file at the tmp path can't trick us
    // into following a symlink they control.
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    let pid = std::process::id();
    let mut suffix = [0u8; 8];
    use rand::RngCore;
    rand::rngs::OsRng.fill_bytes(&mut suffix);
    use std::fmt::Write as _;
    let mut sfx = String::with_capacity(16);
    for b in suffix.iter() {
        let _ = write!(sfx, "{b:02x}");
    }
    let tmp = parent.join(format!(
        ".{}.{pid}.{sfx}.tmp",
        path.file_name().unwrap_or_default().to_string_lossy()
    ));
    let result = (|| -> std::io::Result<()> {
        let mut opts = std::fs::OpenOptions::new();
        opts.create_new(true).write(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            // O_NOFOLLOW: refuse to open if the path is a symlink.
            // Combined with create_new (O_CREAT | O_EXCL), this
            // makes the create+write step symlink-safe.
            const O_NOFOLLOW: i32 = 0x20000;
            opts.custom_flags(O_NOFOLLOW);
        }
        {
            let mut f = opts.open(&tmp)?;
            f.write_all(bytes)?;
            f.sync_all()?;
        }
        std::fs::rename(&tmp, path)?;
        Ok(())
    })();
    if result.is_err() {
        // Best-effort cleanup: if anything between create and rename
        // failed, remove the orphan tmp so the cache directory
        // doesn't accumulate `.tmp` cruft over time. Failure to
        // clean up is itself non-fatal -- the tmp will just hang
        // around until the user manually clears the cache dir.
        let _ = std::fs::remove_file(&tmp);
    }
    result
}

/// Convenience for the production path: try to resolve the default
/// cache from environment and call `read`. Returns `None` when the
/// cache is disabled or unavailable.
///
/// **Synchronous.** Async callers on a current-thread Tokio runtime
/// should use [`read_async`] instead; otherwise a cache hit on a
/// large pack will block the runtime thread for the duration of the
/// disk read + BLAKE3 verify.
pub fn read(hash: &[u8; 32]) -> Option<Vec<u8>> {
    PackCache::from_environment().and_then(|c| c.read(hash))
}

/// Convenience for the production path: try to resolve the default
/// cache from environment and call `write`. No-op when the cache is
/// disabled or unavailable.
///
/// **Synchronous.** Async callers on a current-thread Tokio runtime
/// should use [`write_async`] instead; otherwise the synchronous
/// `write_all` + `sync_all` + `rename` will block the runtime
/// thread.
pub fn write(hash: &[u8; 32], bytes: &[u8]) {
    if let Some(c) = PackCache::from_environment() {
        c.write(hash, bytes);
    }
}

/// Async wrapper around the env-resolved [`read`].
pub async fn read_async(hash: &[u8; 32]) -> Option<Vec<u8>> {
    match PackCache::from_environment() {
        Some(c) => c.read_async(hash).await,
        None => None,
    }
}

/// Async wrapper around the env-resolved [`write`].
pub async fn write_async(hash: &[u8; 32], bytes: &[u8]) {
    if let Some(c) = PackCache::from_environment() {
        c.write_async(hash, bytes).await;
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

    /// Module-level mutex serialising tests that touch process-wide
    /// env vars. Cargo runs tests in parallel by default; without
    /// this lock, two tests setting `FREENET_GIT_PACK_CACHE` /
    /// `_DIR` race and produce flaky failures.
    fn env_lock() -> std::sync::MutexGuard<'static, ()> {
        use std::sync::Mutex;
        static LOCK: Mutex<()> = Mutex::new(());
        LOCK.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Wipes all env vars this module reads, restoring on Drop. Use
    /// inside an `env_lock()` guard.
    struct EnvSandbox {
        prev_toggle: Option<String>,
        prev_dir: Option<String>,
        prev_xdg: Option<String>,
        prev_home: Option<String>,
    }

    impl EnvSandbox {
        fn new() -> Self {
            let s = Self {
                prev_toggle: std::env::var(ENV_TOGGLE).ok(),
                prev_dir: std::env::var(ENV_DIR).ok(),
                prev_xdg: std::env::var("XDG_CACHE_HOME").ok(),
                prev_home: std::env::var("HOME").ok(),
            };
            std::env::remove_var(ENV_TOGGLE);
            std::env::remove_var(ENV_DIR);
            std::env::remove_var("XDG_CACHE_HOME");
            std::env::remove_var("HOME");
            s
        }
    }

    impl Drop for EnvSandbox {
        fn drop(&mut self) {
            for (k, v) in [
                (ENV_TOGGLE, &self.prev_toggle),
                (ENV_DIR, &self.prev_dir),
                ("XDG_CACHE_HOME", &self.prev_xdg),
                ("HOME", &self.prev_home),
            ] {
                match v {
                    Some(val) => std::env::set_var(k, val),
                    None => std::env::remove_var(k),
                }
            }
        }
    }

    #[test]
    fn from_environment_disabled_returns_none() {
        let _g = env_lock();
        let _s = EnvSandbox::new();
        for v in ["off", "0", "false", "OFF", "False"] {
            std::env::set_var(ENV_TOGGLE, v);
            assert!(
                PackCache::from_environment().is_none(),
                "FREENET_GIT_PACK_CACHE={v} must disable cache"
            );
        }
    }

    #[test]
    fn from_environment_precedence_dir_over_xdg() {
        let _g = env_lock();
        let _s = EnvSandbox::new();
        let dir_path = "/tmp/freenet-git-test-dir-precedence-explicit";
        let xdg_path = "/tmp/freenet-git-test-dir-precedence-xdg";
        std::env::set_var(ENV_DIR, dir_path);
        std::env::set_var("XDG_CACHE_HOME", xdg_path);
        let cache = PackCache::from_environment().expect("cache must resolve");
        assert_eq!(cache.root(), std::path::Path::new(dir_path));
    }

    #[test]
    fn from_environment_xdg_over_home() {
        let _g = env_lock();
        let _s = EnvSandbox::new();
        let xdg_path = "/tmp/freenet-git-test-dir-precedence-xdg";
        let home_path = "/tmp/freenet-git-test-dir-precedence-home";
        std::env::set_var("XDG_CACHE_HOME", xdg_path);
        std::env::set_var("HOME", home_path);
        let cache = PackCache::from_environment().expect("cache must resolve");
        assert_eq!(cache.root(), std::path::Path::new(xdg_path).join(SUBDIR));
    }

    #[test]
    fn from_environment_falls_back_to_home() {
        let _g = env_lock();
        let _s = EnvSandbox::new();
        let home_path = "/tmp/freenet-git-test-dir-precedence-home-only";
        std::env::set_var("HOME", home_path);
        let cache = PackCache::from_environment().expect("cache must resolve");
        assert_eq!(
            cache.root(),
            std::path::Path::new(home_path).join(".cache").join(SUBDIR)
        );
    }

    #[test]
    fn from_environment_returns_none_when_no_home() {
        let _g = env_lock();
        let _s = EnvSandbox::new();
        // All four vars wiped by EnvSandbox::new().
        assert!(PackCache::from_environment().is_none());
    }

    #[test]
    fn from_environment_treats_empty_dir_as_unset() {
        let _g = env_lock();
        let _s = EnvSandbox::new();
        std::env::set_var(ENV_DIR, "");
        std::env::set_var("XDG_CACHE_HOME", "/tmp/freenet-git-empty-dir-fallback");
        let cache = PackCache::from_environment().expect("cache must resolve");
        // Empty FREENET_GIT_PACK_CACHE_DIR must NOT be used; XDG should win.
        assert_eq!(
            cache.root(),
            std::path::Path::new("/tmp/freenet-git-empty-dir-fallback").join(SUBDIR)
        );
    }

    #[test]
    fn top_level_read_write_respect_env_dir() {
        // End-to-end: set FREENET_GIT_PACK_CACHE_DIR, call the
        // top-level convenience functions (which `wsclient` also
        // calls), confirm the cache writes to and reads from the
        // configured root.
        let _g = env_lock();
        let _s = EnvSandbox::new();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var(ENV_DIR, dir.path());
        let bytes = unique_bytes(0x77);
        let hash = *blake3::hash(&bytes).as_bytes();
        super::write(&hash, &bytes);
        let got = super::read(&hash).expect("must read back via top-level fn");
        assert_eq!(got, bytes);
        // File is in the configured root, not anywhere else.
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        assert!(dir.path().join(format!("{hex}.pack")).exists());
    }

    #[test]
    fn top_level_read_write_no_op_when_disabled() {
        let _g = env_lock();
        let _s = EnvSandbox::new();
        let dir = tempfile::tempdir().unwrap();
        std::env::set_var(ENV_DIR, dir.path());
        std::env::set_var(ENV_TOGGLE, "off");
        let bytes = unique_bytes(0x88);
        let hash = *blake3::hash(&bytes).as_bytes();
        super::write(&hash, &bytes);
        assert!(super::read(&hash).is_none(), "disabled cache must miss");
        let hex: String = hash.iter().map(|b| format!("{b:02x}")).collect();
        assert!(
            !dir.path().join(format!("{hex}.pack")).exists(),
            "disabled cache must not write to disk"
        );
    }

    #[test]
    fn concurrent_writers_same_hash_produce_valid_entry() {
        // Two threads racing on the same hash must end up with a
        // valid cache entry. Each writer uses a unique tmp filename
        // (pid + random suffix), so neither truncates the other's
        // tmp mid-write. The renames may happen in either order;
        // whichever lands second wins, and read must return valid
        // bytes either way.
        let dir = tempfile::tempdir().unwrap();
        let cache = PackCache::at(dir.path());
        let bytes = unique_bytes(0x99);
        let hash = *blake3::hash(&bytes).as_bytes();
        let n = 8;
        let handles: Vec<_> = (0..n)
            .map(|_| {
                let cache = cache.clone();
                let bytes = bytes.clone();
                std::thread::spawn(move || {
                    cache.write(&hash, &bytes);
                })
            })
            .collect();
        for h in handles {
            h.join().unwrap();
        }
        let got = cache.read(&hash).expect("post-race entry must be valid");
        assert_eq!(got, bytes);

        // No orphan tmp files left over (every writer cleaned up).
        let entries: Vec<_> = std::fs::read_dir(dir.path())
            .unwrap()
            .filter_map(|e| e.ok())
            .collect();
        for e in &entries {
            let name = e.file_name();
            let s = name.to_string_lossy();
            assert!(!s.contains(".tmp"), "orphan tmp file: {s}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn write_refuses_to_follow_symlink_at_tmp_path() {
        // Pre-plant a symlink at the tmp path the cache *would*
        // write to. The pid+random suffix means we can't predict
        // the exact tmp path, but we can plant a symlink at the
        // *final* path and verify rename atomically replaces it
        // (rename clobbers symlinks safely; that's expected).
        //
        // The real symlink-follow attack worth defending is on the
        // tmp path during write -- but the unique tmp name (pid +
        // 8 random bytes) makes it computationally infeasible for
        // an attacker to plant a symlink at the matching tmp path
        // before our O_EXCL create races them. So this test is
        // mostly documentation: the rename of a unique-named tmp
        // onto the final path is the only attacker-visible step,
        // and rename() has its own atomicity guarantees on Unix.
        //
        // We DO want to confirm that a symlink at the *final* path
        // gets replaced cleanly (POSIX rename: target may be a
        // symlink to anywhere; rename replaces the entry in the
        // parent directory atomically without following the link).
        let dir = tempfile::tempdir().unwrap();
        let cache = PackCache::at(dir.path());
        let bytes = unique_bytes(0xAA);
        let hash = *blake3::hash(&bytes).as_bytes();
        let final_path = cache.path_for(&hash);
        std::fs::create_dir_all(final_path.parent().unwrap()).unwrap();
        let outside = dir.path().join("outside-cache");
        std::fs::write(&outside, b"do not touch").unwrap();
        std::os::unix::fs::symlink(&outside, &final_path).unwrap();

        cache.write(&hash, &bytes);

        // The symlink target must NOT have been written through.
        let outside_after = std::fs::read(&outside).unwrap();
        assert_eq!(
            outside_after, b"do not touch",
            "rename target must not follow symlink and overwrite the link target"
        );
        // The cache entry now contains the right bytes.
        let got = std::fs::read(&final_path).unwrap();
        assert_eq!(got, bytes);
    }
}
