//! Pack reconstruction from a local git clone.
//!
//! Powers `freenet-git rescue --from <git-dir>`: when a bundle's pack
//! has been evicted from the gateway AND from any peer reachable via
//! the ring, the rescue would otherwise be stuck (the previous behavior:
//! fail loudly, "1 bundle(s) failed to rescue"). With a local clone of
//! the same repo, we can rebuild the exact same pack bytes locally —
//! `git pack-objects` is byte-for-byte deterministic given the same
//! object set and same git version (verified empirically against the
//! freenet-git self-mirror, 2026-05-17, where pack
//! `7c30464721e743061a50a66fa21c57c9e25e2e57732046223554c28ffaad2c2a`
//! was reproduced from `000c4fde..c682079a` with matching BLAKE3).
//!
//! # Scope (initial implementation)
//!
//! - **History mode only**: snapshot-mode mirrors force-push fresh
//!   orphan commits per run, so the relationship between bundle tips
//!   and (prev, new) ranges is degenerate. Snapshot-mode contracts
//!   with missing data fall back to the existing GET-only path.
//! - **SinglePack only**: ChunkedPack reconstruction requires
//!   re-splitting the local pack into chunks of the same `chunk_size`
//!   that the original publish used; the chunk_size isn't stored in
//!   the contract metadata today. Tracked as follow-up.
//!
//! # Algorithm
//!
//! 1. Read every `bundle-tip:<id>` extension from the contract state
//!    (each value is a 20-byte commit SHA — the tip the bundle covers).
//! 2. Sort tips chronologically by commit timestamp (`git log -1
//!    --format=%ct`). Linear pushes produce a chain; out-of-order
//!    bundles (e.g. a force-push that wasn't reflected in main's
//!    ancestor chain) get whatever order their committer date puts
//!    them in — best-effort.
//! 3. For each consecutive (prev_tip, new_tip) pair, run
//!    `git pack-objects` on the symmetric difference, BLAKE3 the
//!    bytes, and store `(pack_hash -> pack_bytes)` in the lookup map.
//!    The first bundle's `prev_tip` is `None` (full history pack).
//! 4. At rescue time, when `wsclient::get_pack` fails for a bundle,
//!    look up the bundle's expected pack hash in the map; if present,
//!    PUT those bytes directly.

use anyhow::{anyhow, bail, Context, Result};
use freenet_git_types::signing::parse_bundle_tip_extension_key;
use freenet_git_types::{ObjectBundle, ObjectBundleId, RepoState};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Command, Stdio};

/// Map from expected pack BLAKE3 → reconstructed pack bytes. The
/// caller (rescue's per-bundle path) looks up the bundle's expected
/// pack_hash and PUTs the bytes when present.
pub type LocalPackMap = HashMap<[u8; 32], Vec<u8>>;

/// Build the local-pack map from a working git directory and the
/// contract's current `RepoState`.
///
/// Skips bundles that lack a `bundle-tip:<id>` extension (pre-0.1.16
/// mirrors don't record them) and bundles whose tip commit isn't
/// present in the local clone (the operator's clone is shallower than
/// the contract's history). Logs both cases at the `info` level so the
/// operator knows which bundles were skipped.
///
/// Returns a map keyed by reconstructed pack BLAKE3. Bundles whose
/// reconstructed pack hash matches the value stored in the contract's
/// object_index entry can be rescued from this map; bundles whose
/// reconstruction produces a different hash (shouldn't happen if pack
/// reproducibility holds) are silently dropped from the map and the
/// rescue falls back to the GET-only path.
pub fn build_local_pack_map(git_dir: &Path, state: &RepoState) -> Result<LocalPackMap> {
    // 1. Collect bundle-tip extensions: (bundle_id, tip_commit_sha)
    let mut tips: Vec<(ObjectBundleId, [u8; 20])> = Vec::new();
    for (ext_key, entry) in &state.extensions {
        let Some(bundle_id) = parse_bundle_tip_extension_key(ext_key) else {
            continue;
        };
        if entry.value.len() != 20 {
            // Malformed extension — skip with a debug log.
            tracing::debug!(
                "bundle-tip extension for {} has unexpected length {}; skipping",
                hex::encode(bundle_id),
                entry.value.len()
            );
            continue;
        }
        let mut tip = [0u8; 20];
        tip.copy_from_slice(&entry.value);
        tips.push((bundle_id, tip));
    }

    if tips.is_empty() {
        eprintln!(
            "info: no bundle-tip extensions in contract state; --from cannot \
             reconstruct any bundles (this is normal for pre-0.1.16 mirrors)"
        );
        return Ok(LocalPackMap::new());
    }

    // 2. Sort chronologically by commit timestamp. Bundles whose tip
    //    isn't in the local clone get filtered out here.
    let mut tips_with_time: Vec<(ObjectBundleId, [u8; 20], i64)> = Vec::with_capacity(tips.len());
    let mut skipped_missing = 0usize;
    for (bundle_id, tip) in &tips {
        match commit_timestamp(git_dir, tip) {
            Ok(ts) => tips_with_time.push((*bundle_id, *tip, ts)),
            Err(_) => skipped_missing += 1,
        }
    }
    if skipped_missing > 0 {
        eprintln!(
            "info: {skipped_missing} bundle tip commit(s) not present in local clone; \
             --from will not be able to reconstruct those bundles"
        );
    }
    tips_with_time.sort_by_key(|(_, _, t)| *t);

    // 3. For each consecutive (prev, new), build the pack and hash it.
    let mut map = LocalPackMap::new();
    let mut prev_tip: Option<[u8; 20]> = None;
    for (_bundle_id, new_tip, _) in &tips_with_time {
        let prev_hex = prev_tip.as_ref().map(hex::encode);
        let new_hex = hex::encode(new_tip);
        match build_pack_for_range(git_dir, prev_hex.as_deref(), &new_hex) {
            Ok(pack_bytes) => {
                let pack_hash: [u8; 32] = blake3::hash(&pack_bytes).as_bytes().to_owned();
                map.insert(pack_hash, pack_bytes);
            }
            Err(e) => {
                eprintln!(
                    "info: failed to reconstruct pack for tip {new_hex}: {e}; \
                     --from cannot rescue this bundle"
                );
            }
        }
        prev_tip = Some(*new_tip);
    }

    Ok(map)
}

/// Resolve the expected pack hash for a bundle, returning `None` for
/// non-`SinglePack` variants. Used by the rescue code to look up the
/// bundle's reconstructed bytes in [`LocalPackMap`].
pub fn expected_pack_hash(bundle: &ObjectBundle) -> Option<[u8; 32]> {
    match bundle {
        ObjectBundle::SinglePack { pack_hash, .. } => Some(*pack_hash),
        ObjectBundle::ChunkedPack { .. } => None,
    }
}

/// Build a pack for the symmetric difference `(prev..new]` from the
/// given git working directory. Equivalent to git-remote-freenet's
/// internal `build_pack` (no `--thin`, no `--no-reuse-delta`); using
/// the same flags is what gives byte-for-byte reproducibility against
/// the originally-pushed pack.
fn build_pack_for_range(git_dir: &Path, have: Option<&str>, want: &str) -> Result<Vec<u8>> {
    // git_dir may be either a `.git` directory or a working-tree path;
    // git accepts both via `--git-dir` (a working-tree path is treated
    // as if `.git` were appended).
    let mut rev_list = Command::new("git");
    rev_list.arg("--git-dir").arg(git_dir);
    rev_list.args(["rev-list", "--objects", want]);
    if let Some(h) = have {
        rev_list.arg(format!("^{h}"));
    }
    let rev_list_out = rev_list
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("spawn git rev-list")?;
    if !rev_list_out.status.success() {
        let stderr = String::from_utf8_lossy(&rev_list_out.stderr);
        bail!(
            "git rev-list failed for range {}..{want}: {} (stderr: {})",
            have.unwrap_or(""),
            rev_list_out.status,
            stderr.trim()
        );
    }

    let mut child = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args(["pack-objects", "--stdout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("spawn git pack-objects")?;
    {
        let mut stdin = child.stdin.take().ok_or_else(|| anyhow!("piped stdin"))?;
        for line in BufReader::new(rev_list_out.stdout.as_slice()).lines() {
            let line = line?;
            let sha = line.split(' ').next().unwrap_or("");
            if !sha.is_empty() {
                writeln!(stdin, "{sha}")?;
            }
        }
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!(
            "git pack-objects failed: {} (stderr: {})",
            out.status,
            stderr.trim()
        );
    }
    Ok(out.stdout)
}

/// Commit timestamp in seconds-since-epoch (committer date). Used to
/// chronologically order bundle tips before pairing them into push
/// ranges. Returns `Err` if the commit isn't in the local clone.
fn commit_timestamp(git_dir: &Path, commit_sha: &[u8; 20]) -> Result<i64> {
    let hex = hex::encode(commit_sha);
    let out = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args(["log", "-1", "--format=%ct", &hex])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("spawn git log")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("commit {hex} not in local clone: {}", stderr.trim());
    }
    let s = String::from_utf8(out.stdout).context("git log output not utf-8")?;
    s.trim()
        .parse::<i64>()
        .with_context(|| format!("parse timestamp from {s:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Pin: `expected_pack_hash` extracts the pack_hash for SinglePack
    /// and returns None for ChunkedPack. The rescue code's lookup gate
    /// depends on this distinction.
    #[test]
    fn expected_pack_hash_returns_singlepack_only() {
        let hash = [7u8; 32];
        let single = ObjectBundle::SinglePack {
            pack_hash: hash,
            size_bytes: 100,
        };
        let chunked = ObjectBundle::ChunkedPack {
            manifest_hash: hash,
            chunk_count: 3,
            total_size: 300,
        };
        assert_eq!(expected_pack_hash(&single), Some(hash));
        assert_eq!(expected_pack_hash(&chunked), None);
    }

    /// Pin: `build_local_pack_map` returns an empty map for a state
    /// with no bundle-tip extensions. Logs the situation but doesn't
    /// error — pre-0.1.16 mirrors legitimately don't have these.
    #[test]
    fn build_local_pack_map_empty_when_no_tip_extensions() {
        let state = RepoState::default();
        let result = build_local_pack_map(Path::new("/nonexistent/dir"), &state).unwrap();
        assert!(result.is_empty());
    }
}
