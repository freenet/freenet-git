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
use freenet_git_types::{ObjectBundleId, RepoState};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::Arc;

/// Map from expected pack BLAKE3 → reconstructed pack bytes. The
/// caller (rescue's per-bundle path) looks up the bundle's expected
/// pack_hash and PUTs the bytes when present. Bytes are `Arc`-wrapped
/// so parallel rescues don't deep-clone for each PUT.
pub type LocalPackMap = HashMap<[u8; 32], Arc<Vec<u8>>>;

/// Normalize a user-supplied `--from <path>` to the actual git
/// directory git's `--git-dir` flag expects. If `<path>/.git` is a
/// directory the user passed a worktree root → return `<path>/.git`.
/// Otherwise return `<path>` as-is (handles bare repos and explicit
/// `.git` directory paths).
///
/// Codex PR #55 P2 #2: without this, a user invoking `--from
/// /path/to/clone` would silently fail every reconstruction because
/// `git --git-dir /path/to/clone` treats the worktree as if it WERE
/// the git directory (no `.git` auto-append) and every command fails.
pub fn normalize_git_dir(path: &Path) -> PathBuf {
    let dot_git = path.join(".git");
    if dot_git.is_dir() {
        dot_git
    } else {
        path.to_path_buf()
    }
}

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
    let git_dir = normalize_git_dir(git_dir);
    let git_dir = git_dir.as_path();

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

    // 2. Order tips by ANCESTRY, not committer date. Each push's new
    //    tip is a descendant of the previous push's tip in a linear
    //    history-mode chain, so we can order by how many ancestors
    //    each tip has reachable in the local clone (more ancestors =
    //    later push). Codex/skeptical PR #55: committer-date sort can
    //    mis-pair (prev, new) when merge commits or imported history
    //    produce out-of-order timestamps.
    //
    //    Tips whose commit isn't in the local clone get filtered out.
    let mut tips_with_order: Vec<(ObjectBundleId, [u8; 20], u64)> = Vec::with_capacity(tips.len());
    let mut skipped_missing = 0usize;
    for (bundle_id, tip) in &tips {
        match ancestor_count(git_dir, tip) {
            Ok(n) => tips_with_order.push((*bundle_id, *tip, n)),
            Err(_) => skipped_missing += 1,
        }
    }
    if skipped_missing > 0 {
        eprintln!(
            "info: {skipped_missing} bundle tip commit(s) not present in local clone; \
             --from will not be able to reconstruct those bundles"
        );
    }
    // Two tips with the same reachable-commit count would be siblings
    // (neither an ancestor of the other) — shouldn't happen for linear
    // history-mode pushes. The tiebreak on tip bytes makes the order
    // deterministic across runs even if it occurs.
    tips_with_order.sort_by(|a, b| a.2.cmp(&b.2).then(a.1.cmp(&b.1)));

    // 3. For each consecutive (prev, new), build the pack and hash it.
    let mut map = LocalPackMap::new();
    let mut prev_tip: Option<[u8; 20]> = None;
    for (_bundle_id, new_tip, _) in &tips_with_order {
        let prev_hex = prev_tip.as_ref().map(hex::encode);
        let new_hex = hex::encode(new_tip);
        match build_pack_for_range(git_dir, prev_hex.as_deref(), &new_hex) {
            Ok(pack_bytes) => {
                let pack_hash: [u8; 32] = blake3::hash(&pack_bytes).as_bytes().to_owned();
                map.insert(pack_hash, Arc::new(pack_bytes));
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

/// Build a pack for the symmetric difference `(have..want]` from the
/// given git directory, with `pack.threads=1` so the delta search is
/// deterministic.
///
/// Skeptical-reviewer PR #55 H1: `git pack-objects` with the default
/// `pack.threads=auto` produces non-deterministic output because the
/// per-thread delta search races. Same object set → different deltas
/// → different pack bytes → different BLAKE3. Without `pack.threads=1`
/// the reconstructed map would lose half its entries on CI runners
/// with a different CPU count than the original publisher's machine,
/// silently degrading rescue success rate. Single-threaded delta
/// search trades wall-clock for bit-for-bit reproducibility (rescue
/// runs are not a hot path; correctness > speed here).
///
/// The original `build_pack` in git-remote-freenet.rs intentionally
/// doesn't carry this flag — push paths create fresh bundles whose
/// `pack_hash` is whatever the pack-objects run produced, so non-
/// determinism doesn't matter there.
fn build_pack_for_range(git_dir: &Path, have: Option<&str>, want: &str) -> Result<Vec<u8>> {
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
        // -c pack.threads=1: see fn-level docs (H1 fix).
        .args(["-c", "pack.threads=1", "pack-objects", "--stdout"])
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

/// Count of commits reachable from `commit_sha` in the local clone.
/// Used as a topological ordinal for sorting bundle tips by push
/// chronology — for a linear history-mode push chain, the Nth push's
/// tip has more reachable commits than the (N-1)th push's tip.
/// Returns `Err` if the commit isn't in the local clone.
fn ancestor_count(git_dir: &Path, commit_sha: &[u8; 20]) -> Result<u64> {
    let hex = hex::encode(commit_sha);
    let out = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args(["rev-list", "--count", &hex])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .context("spawn git rev-list --count")?;
    if !out.status.success() {
        let stderr = String::from_utf8_lossy(&out.stderr);
        bail!("commit {hex} not in local clone: {}", stderr.trim());
    }
    let s = String::from_utf8(out.stdout).context("git rev-list output not utf-8")?;
    s.trim()
        .parse::<u64>()
        .with_context(|| format!("parse ancestor count from {s:?}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::TempDir;

    /// Pin: `normalize_git_dir` returns `<path>/.git` when the user
    /// passes a worktree root (the documented invocation shape from
    /// `--from`'s help text). Codex PR #55 P2 #2 caught that without
    /// this, the user's literal `--from /path/to/clone` would silently
    /// produce a 0-pack map because `git --git-dir /path/to/clone`
    /// treats the worktree itself as the git directory.
    #[test]
    fn normalize_git_dir_appends_dot_git_for_worktree_root() {
        let tmp = TempDir::new().unwrap();
        let dot_git = tmp.path().join(".git");
        fs::create_dir(&dot_git).unwrap();
        assert_eq!(normalize_git_dir(tmp.path()), dot_git);
    }

    /// Pin: `normalize_git_dir` passes through paths that don't have a
    /// `.git` subdir (bare repos, or an explicit `.git` path).
    #[test]
    fn normalize_git_dir_passes_through_bare_or_dot_git() {
        let tmp = TempDir::new().unwrap();
        // No .git subdir → passed through as-is.
        assert_eq!(normalize_git_dir(tmp.path()), tmp.path());
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
