//! `git-remote-freenet` — Git remote helper for `freenet:` URLs.
//!
//! Drop this binary on `PATH` and `git clone freenet:<id>` works
//! natively. Git invokes us with two args (remote name, URL) and speaks
//! the [git-remote-helpers protocol] over stdin/stdout.
//!
//! [git-remote-helpers protocol]: https://git-scm.com/docs/gitremote-helpers
//!
//! # Phase 1.0 caveats
//!
//! - Single-writer only: only the repo owner can push. The helper loads
//!   the local identity bundle and uses its key to sign ref-updates and
//!   bundle-add records.
//! - SinglePack only: `ChunkedPack` records in `object_index` are
//!   reported as "this ref needs a newer freenet-git" and skipped.
//! - On push, the helper packs all new objects in one `git pack-objects`
//!   call. No incremental delta-pack optimization yet.
//! - Fetch downloads only bundles whose `bundle-tip:<id>` extension
//!   matches a current ref target. Bundles without a tip extension
//!   (legacy / pre-0.1.16 pushes) fall back to "must download" for
//!   safety. No per-object reachability shortcut yet, so history-mode
//!   pushes that introduce parents-of-parents still download every
//!   ancestor bundle. Snapshot-mode pushes get the full benefit:
//!   one bundle, regardless of how many earlier orphan force-pushes
//!   accumulated in `object_index`.
//! - Push semantics: a non-force push requires the remote tip to be
//!   in the local repo (so the helper can compute objects to send).
//!   A force push (`git push --force` or `+refspec`) replaces the
//!   remote tip even when the local has never seen it -- the natural
//!   case for snapshot mirroring of orphan commits.

#![deny(unsafe_code)]

use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::process::{Command, ExitCode, Stdio};
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use freenet_git_cli::ids::pack_contract_id;
use freenet_git_cli::url;
use freenet_git_cli::wsclient::{self, DEFAULT_WS_URL};
use freenet_git_identity::{self as identity, default_bundle_path, DecryptedBundle};
use freenet_git_types::signing::{
    parse_bundle_tip_extension_key, sign_bundle_record, sign_bundle_tip_extension, sign_extension,
    sign_ref_entry, MIRROR_MODE_EXTENSION_KEY,
};
use freenet_git_types::{update_state as ts_update_state, CommitHash, ObjectBundle, RepoState};
use freenet_stdlib::prelude::ContractInstanceId;

/// Shared fake-gateway harness, also used by `tests/legacy_fallback.rs`.
/// Lives under `tests/` because that is where its other consumer is;
/// pulled in here so the migration re-PUT in `fetch_repo_state_from_registry`
/// can be driven against it.
#[cfg(test)]
#[path = "../../tests/support/fake_gateway.rs"]
mod fake_gateway;

/// Default per-op WS timeout. A PUT confirmation can take ~60s
/// under network load (the local node has to forward to the peers
/// that subscribe to the contract's location and wait for them to
/// store and acknowledge); 180s gives 3x headroom. Override with
/// `FREENET_GIT_WS_TIMEOUT_SECS`.
fn ws_timeout() -> Duration {
    Duration::from_secs(
        std::env::var("FREENET_GIT_WS_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(180),
    )
}

/// Pack-size threshold above which we split into chunks. Override with
/// `FREENET_GIT_CHUNK_SIZE` (bytes). Default
/// [`freenet_git_types::chunked::DEFAULT_CHUNK_SIZE`] (1 MiB).
fn chunk_size_from_env() -> u32 {
    std::env::var("FREENET_GIT_CHUNK_SIZE")
        .ok()
        .and_then(|s| s.parse::<u32>().ok())
        .unwrap_or(freenet_git_types::chunked::DEFAULT_CHUNK_SIZE)
}

/// Decrypt the identity bundle from inside the helper, where prompting
/// is impossible (git owns stdin/stdout).
///
/// Resolution order matches the CLI's `open_bundle_remembering_passphrase`:
/// 1. If `FREENET_GIT_PASSPHRASE` is set and decrypts, use it.
/// 2. Otherwise try the empty passphrase (unencrypted bundle path).
/// 3. Otherwise surface a directed error.
fn read_identity_for_helper(path: &std::path::Path) -> Result<DecryptedBundle> {
    let bytes = std::fs::read(path)
        .with_context(|| format!("read identity bundle at {}", path.display()))?;
    let env_pw = std::env::var("FREENET_GIT_PASSPHRASE").ok();

    if let Some(pw) = &env_pw {
        if let Ok(b) = identity::open(&bytes, pw) {
            return Ok(b);
        }
    }

    if let Ok(b) = identity::open(&bytes, "") {
        return Ok(b);
    }

    if env_pw.is_some() {
        Err(anyhow!(
            "FREENET_GIT_PASSPHRASE was set but did not decrypt bundle at {} \
             (and the bundle is not unencrypted either)",
            path.display()
        ))
    } else {
        Err(anyhow!(
            "FREENET_GIT_PASSPHRASE must be set to push to an encrypted bundle \
             (the helper cannot prompt because git owns stdin/stdout). For an \
             unencrypted bundle, leave the variable unset."
        ))
    }
}

fn main() -> ExitCode {
    init_tracing();
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:?}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<()> {
    let args: Vec<String> = std::env::args().skip(1).collect();
    if args.len() != 2 {
        bail!(
            "git-remote-freenet expects exactly 2 arguments (remote name, URL); got {}",
            args.len()
        );
    }
    let _remote_name = &args[0];
    let url_str = &args[1];

    let parsed = url::parse(url_str).with_context(|| format!("parse remote URL {url_str}"))?;

    // Compute the contract instance id from the parsed prefix and the
    // bundled (or override) repo-contract WASM. This is delta-style
    // permissionless addressing: anyone with the URL plus the WASM
    // resolves the same key.
    let env = HelperEnv::from_env(parsed)?;

    let stdin = std::io::stdin();
    let mut stdin = stdin.lock();
    let stdout = std::io::stdout();
    let mut stdout = stdout.lock();

    let mut input = String::new();
    loop {
        input.clear();
        let n = stdin.read_line(&mut input)?;
        if n == 0 {
            // EOF — git closed the pipe.
            return Ok(());
        }
        let line = input.trim_end_matches('\n');

        if line.is_empty() {
            // git uses blank lines as command terminators; just loop.
            continue;
        }

        if line == "capabilities" {
            writeln!(stdout, "fetch")?;
            writeln!(stdout, "push")?;
            writeln!(stdout)?;
            stdout.flush()?;
            continue;
        }
        if line == "list" || line == "list for-push" {
            handle_list(&env, &mut stdout)?;
            continue;
        }
        if let Some(args) = line.strip_prefix("fetch ") {
            // Collect this fetch and any subsequent fetch lines until blank.
            let mut wants: Vec<(String, String)> = vec![split_fetch(args)?];
            loop {
                input.clear();
                let n = stdin.read_line(&mut input)?;
                if n == 0 {
                    break;
                }
                let line = input.trim_end_matches('\n');
                if line.is_empty() {
                    break;
                }
                let args = line
                    .strip_prefix("fetch ")
                    .ok_or_else(|| anyhow!("expected fetch line, got {line:?}"))?;
                wants.push(split_fetch(args)?);
            }
            handle_fetch(&env, &wants, &mut stdout)?;
            continue;
        }
        if let Some(args) = line.strip_prefix("push ") {
            let mut pushes: Vec<String> = vec![args.to_string()];
            loop {
                input.clear();
                let n = stdin.read_line(&mut input)?;
                if n == 0 {
                    break;
                }
                let line = input.trim_end_matches('\n');
                if line.is_empty() {
                    break;
                }
                let args = line
                    .strip_prefix("push ")
                    .ok_or_else(|| anyhow!("expected push line, got {line:?}"))?;
                pushes.push(args.to_string());
            }
            handle_push(&env, &pushes, &mut stdout)?;
            continue;
        }

        bail!("unknown remote helper command: {line:?}");
    }
}

fn split_fetch(args: &str) -> Result<(String, String)> {
    let mut parts = args.splitn(2, ' ');
    let sha = parts.next().ok_or_else(|| anyhow!("fetch missing sha"))?;
    let name = parts.next().ok_or_else(|| anyhow!("fetch missing name"))?;
    Ok((sha.to_string(), name.to_string()))
}

/// Read the repo-contract WASM. Defaults to the bytes bundled into this
/// binary by `freenet_git_cli::REPO_CONTRACT_WASM`; honors
/// `FREENET_GIT_REPO_WASM` for source-tree iteration.
fn load_repo_wasm(env: &HelperEnv) -> Result<Vec<u8>> {
    match env.repo_wasm_path.as_ref() {
        Some(path) => std::fs::read(path)
            .with_context(|| format!("read repo-contract wasm from {}", path.display())),
        None => Ok(freenet_git_cli::REPO_CONTRACT_WASM.to_vec()),
    }
}

/// Read the pack-contract WASM. Defaults to the bytes bundled into this
/// binary by `freenet_git_cli::PACK_CONTRACT_WASM`; honors
/// `FREENET_GIT_PACK_WASM` for source-tree iteration.
fn load_pack_wasm(env: &HelperEnv) -> Result<Vec<u8>> {
    match env.pack_wasm_path.as_ref() {
        Some(path) => std::fs::read(path)
            .with_context(|| format!("read pack-contract wasm from {}", path.display())),
        None => Ok(freenet_git_cli::PACK_CONTRACT_WASM.to_vec()),
    }
}

struct HelperEnv {
    /// URL prefix (the canonical identifier). Used as the lookup key in
    /// the bundle's per-repo registry.
    prefix: String,
    /// Contract instance id derived from the prefix + the bundled
    /// (or `--repo-wasm`-overridden) repo-contract WASM.
    contract_id: ContractInstanceId,
    ws_url: String,
    git_dir: PathBuf,
    identity_path: PathBuf,
    repo_wasm_path: Option<PathBuf>,
    pack_wasm_path: Option<PathBuf>,
}

impl HelperEnv {
    fn from_env(parsed: url::ParsedUrl) -> Result<Self> {
        let ws_url =
            std::env::var("FREENET_GIT_WS_URL").unwrap_or_else(|_| DEFAULT_WS_URL.to_string());
        let git_dir = PathBuf::from(std::env::var("GIT_DIR").unwrap_or_else(|_| ".git".into()));
        let identity_path = std::env::var("FREENET_GIT_IDENTITY")
            .map(PathBuf::from)
            .unwrap_or_else(|_| default_bundle_path());
        let repo_wasm_path = std::env::var("FREENET_GIT_REPO_WASM")
            .ok()
            .map(PathBuf::from);
        let pack_wasm_path = std::env::var("FREENET_GIT_PACK_WASM")
            .ok()
            .map(PathBuf::from);

        // Derive the contract instance id from the URL prefix and the
        // chosen repo-contract WASM bytes (env override or bundled).
        let repo_wasm: Vec<u8> = match repo_wasm_path.as_ref() {
            Some(path) => std::fs::read(path)
                .with_context(|| format!("read repo-contract wasm from {}", path.display()))?,
            None => freenet_git_cli::REPO_CONTRACT_WASM.to_vec(),
        };
        let contract_id =
            freenet_git_cli::ids::repo_contract_id_from_prefix(&repo_wasm, &parsed.prefix);

        Ok(Self {
            prefix: parsed.prefix,
            contract_id,
            ws_url,
            git_dir,
            identity_path,
            repo_wasm_path,
            pack_wasm_path,
        })
    }
}

/// GET the repo state, falling back through legacy contract hashes
/// if the current key returns nothing. When a legacy hit triggers a
/// migration, re-PUT the state to the current key (permissionless,
/// since the state is signed) so subsequent clients see it directly.
async fn fetch_repo_state(
    env: &HelperEnv,
    api: &mut freenet_stdlib::client_api::WebApi,
    repo_wasm: &[u8],
) -> Result<RepoState> {
    fetch_repo_state_from_registry(
        env,
        api,
        repo_wasm,
        freenet_git_cli::legacy::CONTRACT_LINEAGE,
    )
    .await
}

/// The body of [`fetch_repo_state`], with the legacy registry passed in
/// rather than read from the generated const.
///
/// The const is empty in every shipped build and can only be filled by
/// editing `legacy_contracts.toml` and rebuilding, so tests cannot
/// reach the migration branch without this seam. Nothing else changes:
/// production still passes `CONTRACT_LINEAGE`, and both the probe
/// hashes and the note used in the log line come from the same slice,
/// so they cannot disagree.
async fn fetch_repo_state_from_registry(
    env: &HelperEnv,
    api: &mut freenet_stdlib::client_api::WebApi,
    repo_wasm: &[u8],
    registry: &[freenet_git_cli::legacy::ContractLineageEntry],
) -> Result<RepoState> {
    use freenet_git_cli::wsclient::{GetSource, LegacyAwareGet};

    let params = freenet_git_types::RepoParams {
        prefix: env.prefix.clone(),
    };
    let params_bytes = params.to_bytes();

    let LegacyAwareGet { state, source } = wsclient::get_state_with_legacy_fallback(
        api,
        env.contract_id,
        &params_bytes,
        registry,
        ws_timeout(),
    )
    .await?;

    if let GetSource::Legacy { index, instance } = source {
        let entry = &registry[index];
        eprintln!(
            "info: state found at legacy contract {instance} (generation {}: {}); \
             migrating to current key",
            entry.generation, entry.note,
        );
        // Re-PUT to current key. We send the same state bytes — the
        // current contract's validate_state must accept them; if it
        // doesn't, the contract has a backwards-incompatible change
        // that needs a different migration strategy. We log and
        // continue in that case so the user can still read the
        // legacy state via the fallback path.
        match wsclient::put_contract(
            api,
            repo_wasm,
            params_bytes.clone(),
            state.clone(),
            ws_timeout(),
        )
        .await
        {
            Ok(_) => eprintln!("info: legacy state migrated to current contract key"),
            Err(e) => eprintln!(
                "warning: legacy state could not be migrated to current key: {e}; \
                 still serving from legacy"
            ),
        }
    }

    Ok(RepoState::from_bytes(&state)?)
}

/// Render the repos an identity bundle can sign pushes for, for use in
/// the "wrong identity" error.
///
/// Listing them turns "you don't own this" into something the user can
/// act on: nearly always they either mistyped the prefix in
/// `git remote add` or are pointed at the wrong bundle, and seeing the
/// prefixes side by side tells them which. Kept as a pure function over
/// the registry so the empty-bundle wording is unit-testable.
fn describe_pushable_repos(bundle: &DecryptedBundle) -> String {
    if bundle.repos.is_empty() {
        return "This identity has not created any repos, so there is nothing it \
                can push to yet."
            .to_string();
    }
    let mut out = String::from("Repos this identity can push to:");
    for repo in &bundle.repos {
        out.push_str(&format!("\n  {} ({})", repo.prefix, repo.display_name));
    }
    out
}

fn handle_list<W: Write>(env: &HelperEnv, out: &mut W) -> Result<()> {
    let runtime = build_runtime()?;
    let repo_wasm = load_repo_wasm(env)?;
    let state = runtime.block_on(async {
        let mut api = wsclient::connect(&env.ws_url).await?;
        fetch_repo_state(env, &mut api, &repo_wasm).await
    })?;

    // Emit refs.
    for (name, entry) in &state.refs {
        let hex = hex::encode(entry.target);
        writeln!(out, "{hex} {name}")?;
    }
    // Emit HEAD as a symref pointer if default_branch is set.
    if let Some(default) = &state.default_branch {
        writeln!(out, "@{} HEAD", default.value)?;
    }
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

fn handle_fetch<W: Write>(env: &HelperEnv, wants: &[(String, String)], out: &mut W) -> Result<()> {
    let pack_wasm = load_pack_wasm(env)?;
    let repo_wasm = load_repo_wasm(env)?;

    let runtime = build_runtime()?;
    runtime.block_on(async {
        let mut api = wsclient::connect(&env.ws_url).await?;

        eprintln!("==> reading repo state from Freenet");
        let state = fetch_repo_state(env, &mut api, &repo_wasm).await?;

        let pack_dir = env.git_dir.join("objects").join("pack");
        std::fs::create_dir_all(&pack_dir)?;

        // Filter the object_index down to bundles actually needed for
        // the wanted refs. See issue #32: every successful push appends
        // a bundle without GC, so contracts that have seen many pushes
        // accumulate dead-weight bundles that aren't reachable from any
        // current ref. We use the `bundle-tip:<id>` extensions
        // (populated by 0.1.16+ pushes) to identify which bundles are
        // reachable.
        //
        // Algorithm:
        // 1. Always download legacy (untipped) bundles upfront. They
        //    were pushed by pre-0.1.16 clients or the extension is
        //    missing; we have no metadata to filter them, so they go
        //    in for safety.
        // 2. Iteratively download tipped bundles whose tips are
        //    reachable from any current ref:
        //    - Start `wanted_commits` = current ref targets.
        //    - For each wanted commit, find the bundle whose tip ==
        //      that commit. Download + install.
        //    - After install, walk the local commit graph from each
        //      wanted commit to find unresolved parents (commits that
        //      aren't in the local objects yet). Add those parents to
        //      `wanted_commits`.
        //    - Repeat until no new bundles need downloading.
        //
        // For snapshot mode (orphan tip with no parents): one tipped
        // bundle, parents walk is empty, done.
        //
        // For history mode (each push appends commits to the same
        // ref): the wanted commit's bundle is downloaded first; its
        // pack contains commits since the previous push. Walking
        // parents finds the previous-push tip, which has its own
        // tipped bundle, and so on. Linear chain of bundles is
        // downloaded -- no missing ancestors.
        //
        // Bundles whose tips don't appear on any wanted-commit history
        // path (e.g. orphan force-push remnants) are correctly
        // skipped.
        let bundle_tips = collect_bundle_tip_extensions(&state);
        let tip_to_bundle: std::collections::HashMap<CommitHash, freenet_git_types::ObjectBundleId> =
            bundle_tips.iter().map(|(b, t)| (*t, *b)).collect();

        // Phase 1: legacy bundles (no tip extension). Must download.
        let legacy_ids: Vec<_> = state
            .object_index
            .keys()
            .filter(|id| !bundle_tips.contains_key(*id))
            .copied()
            .collect();
        let mut downloaded: std::collections::HashSet<freenet_git_types::ObjectBundleId> =
            std::collections::HashSet::new();
        let mut step = 1usize;

        for id in &legacy_ids {
            let record = state
                .object_index
                .get(id)
                .expect("id came from object_index keys");
            let label = format!("legacy bundle {step}/{}", legacy_ids.len());
            let pack_bytes =
                download_bundle(&mut api, &pack_wasm, &env.ws_url, &record.bundle, &label).await?;
            install_pack(&env.git_dir, &pack_bytes)?;
            downloaded.insert(*id);
            step += 1;
        }

        // Phase 2: iteratively download tipped bundles whose tips are
        // reachable from a wanted commit (or its already-walked
        // ancestor).
        //
        // Seeding policy: when git's remote-helper protocol passes
        // explicit `wants` (the SHAs from the `fetch <sha> <name>`
        // lines), seed `wanted_commits` from those. This handles two
        // cases the old "all current refs" seed got wrong:
        //  1. Partial fetches (`git fetch <remote> <single-ref>`) get
        //     the bundles for that single ref, not for every advertised
        //     ref.
        //  2. A ref moving between `list` and `fetch` (e.g. another
        //     pusher force-pushes during our fetch) doesn't make us
        //     skip the SHA git asked for. Git wants the SHA it saw at
        //     `list` time; we honor that.
        // When `wants` is empty (e.g. a no-op probe) fall back to the
        // current ref set so we don't accidentally do nothing.
        let mut wanted_commits: std::collections::HashSet<CommitHash> = wants
            .iter()
            .filter_map(|(sha_hex, _name)| parse_sha1(sha_hex).ok())
            .collect();
        if wanted_commits.is_empty() {
            wanted_commits = state.refs.values().map(|e| e.target).collect();
        }
        let mut walked: std::collections::HashSet<CommitHash> =
            std::collections::HashSet::new();

        loop {
            let to_download: Vec<_> = wanted_commits
                .iter()
                .filter_map(|c| tip_to_bundle.get(c))
                .copied()
                .filter(|id| !downloaded.contains(id))
                .collect();

            if to_download.is_empty() {
                // Even after all tipped bundles for current wanted set
                // are loaded, we may still have unresolved parents in
                // the commit graph. Walk them and check if any ARE
                // tipped on bundles we haven't yet downloaded.
                let new_wants =
                    walk_unresolved_parents(&env.git_dir, &wanted_commits, &mut walked)?;
                if new_wants.is_empty() {
                    break;
                }
                // Stuck-detection: if every unresolved commit lacks a
                // bundle-tip mapping, the next iteration would also
                // produce empty `to_download` and re-walk to the same
                // unresolved set forever. Bail with a directed error
                // pointing at the missing commits. This catches
                // contract states with malformed bundle-tip values,
                // missing legacy bundles, or any other inconsistency
                // where the wanted history simply isn't in any
                // available bundle.
                let any_resolvable =
                    new_wants.iter().any(|c| tip_to_bundle.contains_key(c));
                if !any_resolvable {
                    let sample: Vec<_> = new_wants
                        .iter()
                        .take(3)
                        .map(hex_encode_commit)
                        .collect();
                    bail!(
                        "fetch could not converge: {} commit(s) needed but no bundle in object_index advertises them. \
                         First missing: {}. The contract state may be inconsistent (missing bundles) \
                         or pre-0.1.16 bundles whose objects don't include the wanted history.",
                        new_wants.len(),
                        sample.join(", "),
                    );
                }
                wanted_commits.extend(new_wants);
                continue;
            }

            for id in &to_download {
                let record = state
                    .object_index
                    .get(id)
                    .expect("id came from tip_to_bundle which is built from object_index");
                let label = format!("bundle {step}");
                let pack_bytes =
                    download_bundle(&mut api, &pack_wasm, &env.ws_url, &record.bundle, &label)
                        .await?;
                install_pack(&env.git_dir, &pack_bytes)?;
                downloaded.insert(*id);
                step += 1;
            }
        }

        let total_in_index = state.object_index.len();
        let skipped = total_in_index - downloaded.len();
        if skipped > 0 {
            eprintln!(
                "==> downloaded {} bundle(s); skipped {skipped} dead-weight tipped bundle(s) of {total_in_index} in object_index",
                downloaded.len()
            );
        }
        eprintln!("==> done");
        Ok::<_, anyhow::Error>(())
    })?;

    // Empty line: success.
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

/// `update_seq` for `bundle-tip:<id>` extension entries.
///
/// Each key is unique per bundle, so nothing here needs monotonicity
/// and 0 would be the natural choice. It has to be **at least 1**
/// anyway, because of how the deployed repo contract computes deltas:
///
/// ```text
/// summary.extension_seqs.get(k).copied().unwrap_or(0) < v.update_seq
/// ```
///
/// That reads a key the peer has never seen as seq 0, which is
/// indistinguishable from a key it already holds at seq 0. For an entry
/// written at seq 0 the test is `0 < 0`, so it is never included in a
/// delta and never reaches a peer that syncs by summary+delta. The
/// symptom is a repo whose refs and object_index propagate normally
/// while `extensions` stays empty, which silently disables the
/// dead-weight bundle filter and makes every fetch download the whole
/// `object_index`.
///
/// `freenet_git_types::get_state_delta` has since been corrected to
/// distinguish absent from zero, but that lives in the contract WASM,
/// and `contracts/repo-contract.wasm` is a checked-in artifact that is
/// only rebuilt deliberately — rebuilding re-keys every repo and needs
/// a `legacy_contracts.toml` migration entry. So the source fix does
/// not reach the network until that happens, and writing seq 1 is what
/// actually makes tips propagate today. It stays correct after a
/// rebuild too: a peer missing the key still needs it, and a peer
/// holding it at 1 still does not.
const BUNDLE_TIP_UPDATE_SEQ: u64 = 1;

/// Build a `bundle_id -> tip_commit` map from the state's
/// `extensions`. Pushes from 0.1.16+ advertise their bundle's tip via
/// a `bundle-tip:<hex>` extension entry; this parses those back. See
/// issue #32 and `freenet_git_types::signing::sign_bundle_tip_extension`.
fn collect_bundle_tip_extensions(
    state: &RepoState,
) -> std::collections::HashMap<freenet_git_types::ObjectBundleId, CommitHash> {
    let mut out = std::collections::HashMap::new();
    for (key, entry) in &state.extensions {
        let Some(bundle_id) = parse_bundle_tip_extension_key(key) else {
            continue;
        };
        let tip: CommitHash = match entry.value.as_slice().try_into() {
            Ok(arr) => arr,
            Err(_) => continue, // value isn't a 20-byte sha; skip
        };
        out.insert(bundle_id, tip);
    }
    out
}

/// Download a single `ObjectBundle` from Freenet via the existing
/// pack/chunked-pack helpers. `label` is interpolated into the
/// progress messages.
async fn download_bundle(
    api: &mut freenet_stdlib::client_api::WebApi,
    pack_wasm: &[u8],
    ws_url: &str,
    bundle: &ObjectBundle,
    label: &str,
) -> Result<Vec<u8>> {
    match bundle {
        ObjectBundle::SinglePack {
            pack_hash,
            size_bytes,
        } => {
            eprintln!(
                "    [{label}] downloading pack ({})",
                human_bytes(*size_bytes),
            );
            let bytes = wsclient::get_pack(api, pack_wasm, *pack_hash, ws_timeout()).await?;
            Ok(bytes)
        }
        ObjectBundle::ChunkedPack {
            manifest_hash,
            total_size,
            chunk_count,
        } => {
            eprintln!(
                "    [{label}] downloading {chunk_count} chunks ({})",
                human_bytes(*total_size),
            );
            let bytes = freenet_git_cli::chunked::fetch_chunked_pack_with_progress(
                ws_url,
                pack_wasm,
                *manifest_hash,
                *total_size,
                *chunk_count,
                freenet_git_cli::chunked::parallelism_from_env(),
                ws_timeout(),
                |done, chunk_n| {
                    eprintln!("        chunk {done}/{chunk_n}");
                },
            )
            .await
            .with_context(|| format!("fetch ChunkedPack {}", hex::encode(manifest_hash)))?;
            Ok(bytes)
        }
    }
}

/// Walk the local commit graph from `wanted_commits` to find ancestor
/// commits that aren't yet present locally. For each `wanted` commit:
/// if it exists locally, its parents are recursively walked. If a
/// commit doesn't exist locally, it's added to the returned
/// "unresolved" set so the outer fetch loop knows to look for a
/// bundle whose tip matches it.
///
/// `walked` records commits we've already enumerated parents for, so
/// repeat invocations don't redo work for the resolvable portion of
/// the graph. **Unresolved commits are NOT added to `walked`**: once
/// a future iteration downloads their bundle, we'll come back and
/// walk through them properly. This is what lets multi-bundle
/// histories converge correctly -- without it, the second iteration
/// would skip the just-downloaded commit and never enumerate ITS
/// parents, leaving the older history forever unfetched.
fn walk_unresolved_parents(
    git_dir: &std::path::Path,
    wanted_commits: &std::collections::HashSet<CommitHash>,
    walked: &mut std::collections::HashSet<CommitHash>,
) -> Result<std::collections::HashSet<CommitHash>> {
    let mut unresolved = std::collections::HashSet::new();
    let mut to_visit: Vec<CommitHash> = wanted_commits.iter().copied().collect();

    while let Some(c) = to_visit.pop() {
        if walked.contains(&c) {
            continue;
        }
        let hex = hex_encode_commit(&c);
        if !commit_exists(git_dir, &hex)? {
            // commit_exists requires the SHA to peel through to a
            // commit. If the object is local but not a commit (e.g.
            // an annotated tag pointing at a tree, a blob ref),
            // there's no commit-graph to walk -- mark resolved and
            // move on. Without this, a tag-of-tree ref would keep
            // coming back as unresolved on every iteration even
            // after its bundle was downloaded.
            if any_object_exists(git_dir, &hex)? {
                walked.insert(c);
                continue;
            }
            // Truly missing -- a future bundle may carry it. DO NOT
            // add to `walked`; we want a future iteration (after the
            // bundle lands) to walk this commit's parents.
            unresolved.insert(c);
            continue;
        }
        // Commit IS local; mark as walked and enumerate parents.
        walked.insert(c);
        for parent in git_commit_parents(git_dir, &hex)? {
            if !walked.contains(&parent) {
                to_visit.push(parent);
            }
        }
    }
    Ok(unresolved)
}

fn hex_encode_commit(c: &CommitHash) -> String {
    let mut s = String::with_capacity(40);
    for b in c.iter() {
        s.push_str(&format!("{b:02x}"));
    }
    s
}

/// List a commit's immediate parents, reading only the commit object
/// itself. Returns parents as `CommitHash` (20-byte SHAs).
///
/// Uses `git cat-file commit <sha>` and parses the `parent` headers,
/// **not** `git rev-list --parents -n 1 <sha>`. The distinction is the
/// whole point (issue #60): `rev-list` traverses, so it fails with
/// `Could not read <parent>` when a parent object is absent — which is
/// precisely the case the sole caller, [`walk_unresolved_parents`],
/// exists to detect. Asking a traversal command to name objects it
/// cannot traverse to made the walk return `Err` exactly when it had
/// something useful to say, aborting the clone (`Failed to traverse
/// parents of commit <sha>`) instead of fetching the bundle carrying
/// that parent. `cat-file` reads one object and is therefore answerable
/// whether or not the parents are local.
///
/// `cat-file commit` peels an annotated tag to its commit, matching
/// [`commit_exists`]'s `<sha>^{commit}` and preserving the behaviour
/// `walk_unresolved_parents_walks_through_annotated_tag_of_commit`
/// pins.
///
/// Only the header is parsed. A commit object is headers, then a blank
/// line, then the free-form message — and a message body can easily
/// contain a line starting with "parent " (a quoted log, a review
/// note), so parsing past the blank line would invent parents out of
/// prose.
fn git_commit_parents(git_dir: &std::path::Path, sha_hex: &str) -> Result<Vec<CommitHash>> {
    let out = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args(["cat-file", "commit", sha_hex])
        .output()
        .context("spawn git cat-file commit")?;
    if !out.status.success() {
        bail!(
            "git cat-file commit {sha_hex} failed: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    let stdout = String::from_utf8_lossy(&out.stdout);
    let mut parents = Vec::new();
    for line in stdout.lines() {
        // Blank line ends the header block; everything after is the
        // commit message.
        if line.is_empty() {
            break;
        }
        let Some(sha) = line.strip_prefix("parent ") else {
            continue;
        };
        let sha = sha.trim();
        if sha.len() != 40 {
            bail!("git cat-file emitted a parent header with a non-40-char sha: {sha:?}");
        }
        let mut bytes = [0u8; 20];
        for (i, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&sha[i * 2..i * 2 + 2], 16)
                .map_err(|e| anyhow!("git cat-file emitted invalid parent hex {sha}: {e}"))?;
        }
        parents.push(bytes);
    }
    Ok(parents)
}

fn human_bytes(n: u64) -> String {
    const KIB: u64 = 1024;
    const MIB: u64 = 1024 * KIB;
    const GIB: u64 = 1024 * MIB;
    if n >= GIB {
        format!("{:.1} GiB", n as f64 / GIB as f64)
    } else if n >= MIB {
        format!("{:.1} MiB", n as f64 / MIB as f64)
    } else if n >= KIB {
        format!("{:.1} KiB", n as f64 / KIB as f64)
    } else {
        format!("{n} B")
    }
}

/// Returns true if the local git repo is a shallow clone. A shallow
/// repo has a `.git/shallow` file listing the boundary commits whose
/// parents are absent from the local object DB. Pushing from a shallow
/// repo produces packs that fail to clone on the receiver, so we
/// reject up front.
fn is_shallow_repo(git_dir: &std::path::Path) -> Result<bool> {
    Ok(git_dir.join("shallow").exists())
}

fn install_pack(git_dir: &std::path::Path, pack_bytes: &[u8]) -> Result<()> {
    // Hand the pack to git index-pack via stdin so it computes the
    // index and renames the files into place atomically.
    let mut child = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .arg("index-pack")
        .arg("--stdin")
        .arg("--keep")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawn git index-pack")?;
    {
        let mut stdin = child.stdin.take().expect("piped");
        stdin.write_all(pack_bytes)?;
    }
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("git index-pack failed: {}", out.status);
    }
    Ok(())
}

fn handle_push<W: Write>(env: &HelperEnv, pushes: &[String], out: &mut W) -> Result<()> {
    // Refuse to push from a shallow clone. A shallow source's HEAD
    // commit references a parent SHA that is NOT in the local object
    // DB; `git pack-objects` happily packs the commit (without the
    // missing parent), and the receiver fails with `Failed to traverse
    // parents of commit <sha>` during `git clone`. Surface this up
    // front with a clear remediation, rather than letting the user
    // discover it on the other end.
    if is_shallow_repo(&env.git_dir)? {
        bail!(
            "the local repo is a shallow clone (`.git/shallow` exists), so a \
             push from it would produce a pack referencing parent commits the \
             receiver cannot resolve.\n\n\
             Two ways to fix this:\n\n\
             1. Unshallow first (downloads full history):\n\
                  git fetch --unshallow\n\n\
             2. Push an orphan snapshot (no history, current source only):\n\
                  mkdir /tmp/snap && cd /tmp/snap && git init -b main\n\
                  cp -a $OLDPWD/. .\n\
                  git add . && git commit -m \"snapshot\"\n\
                  git remote add freenet <your-freenet-url>\n\
                  git push freenet main\n"
        );
    }

    let repo_wasm = load_repo_wasm(env)?;
    let pack_wasm = load_pack_wasm(env)?;

    // Decrypt identity once. The helper can't prompt because git owns
    // stdin/stdout, so for encrypted bundles the user must set
    // FREENET_GIT_PASSPHRASE up front. Unencrypted bundles (created with
    // `freenet-git init-identity --no-passphrase`) open silently here.
    let bundle = read_identity_for_helper(&env.identity_path)
        .with_context(|| format!("decrypt identity bundle at {}", env.identity_path.display()))?;

    // Find the per-repo signing key in the bundle by matching the URL
    // prefix. Each repo has its own keypair (delta-style); we never
    // reuse the bundle's "default" identity here.
    let registry_entry = bundle
        .repos
        .iter()
        .find(|r| r.prefix == env.prefix)
        .ok_or_else(|| {
            anyhow!(
                "this identity cannot sign pushes to {}: no entry for that prefix \
                 in the identity bundle at {}.\n\n{}\n\n\
                 If you created the repo with a different identity, point \
                 FREENET_GIT_IDENTITY at that bundle. If you have not created it \
                 yet, `freenet-git create --name <name>` makes a repo you own \
                 (you cannot push to someone else's repo — publish your own \
                 clone and send them the URL instead).",
                env.prefix,
                env.identity_path.display(),
                describe_pushable_repos(&bundle),
            )
        })?;
    let signing = {
        let bytes: [u8; 32] = registry_entry
            .repo_secret
            .as_slice()
            .try_into()
            .map_err(|_| {
                anyhow!(
                    "registry repo_secret is wrong length for prefix {}",
                    env.prefix
                )
            })?;
        ed25519_dalek::SigningKey::from_bytes(&bytes)
    };

    let chunk_size = chunk_size_from_env();
    let runtime = build_runtime()?;
    let result = runtime.block_on(async {
        let mut api = wsclient::connect(&env.ws_url).await?;

        // Use the legacy-aware fetch so push-from-old-version flows
        // discover the migrated state and don't try to push a fresh
        // ref-update onto an empty current contract.
        eprintln!("==> reading repo state from Freenet");
        let state = fetch_repo_state(env, &mut api, &repo_wasm).await?;

        let params = freenet_git_types::RepoParams {
            prefix: env.prefix.clone(),
        };

        let mut delta = RepoState::default();
        let mut ok_lines: Vec<String> = Vec::new();
        let mut error_lines: Vec<String> = Vec::new();

        for spec in pushes {
            // git sends `<src>:<dst>`; src may have a leading '+' for force.
            let (force, src, dst) = parse_push_spec(spec)?;
            if src.is_empty() {
                error_lines.push(format!("error {dst} delete-ref not supported in Phase 1.0"));
                continue;
            }
            let new_target = git_resolve_ref(&env.git_dir, &src)?;

            // Determine "have" = current target if any, so pack-objects
            // can produce a thin pack from <have>..<new_target>.
            let prev = state.refs.get(&dst).map(|e| hex::encode(e.target));

            // Idempotent short-circuit. See `is_already_up_to_date`
            // for the rationale and the cases this guards against.
            // Applies regardless of the force flag -- a `+` push of
            // an unchanged tip is also a no-op since the contract's
            // `update_seq` increment with identical target merges
            // to the same effective state.
            if is_already_up_to_date(prev.as_deref(), &new_target) {
                eprintln!("==> {dst} already at {new_target} on Freenet -- nothing to push");
                ok_lines.push(format!("ok {dst}"));
                continue;
            }

            let pack_bytes = match build_pack(&env.git_dir, prev.as_deref(), &new_target, force) {
                Ok(b) => b,
                Err(e) => {
                    error_lines.push(format!("error {dst} {e}"));
                    continue;
                }
            };

            // Decide SinglePack vs ChunkedPack. Rule (per design 0001):
            //   pack_size <= CHUNK_SIZE  -> SinglePack
            //   pack_size > CHUNK_SIZE   -> ChunkedPack
            let bundle_obj = if (pack_bytes.len() as u64) <= chunk_size as u64 {
                eprintln!(
                    "==> publishing {} pack as a single bundle",
                    human_bytes(pack_bytes.len() as u64),
                );
                let pack_key = wsclient::put_pack(
                    &mut api,
                    &pack_wasm,
                    pack_bytes.clone(),
                    ws_timeout(),
                )
                .await?;
                let pack_hash = *blake3::hash(&pack_bytes).as_bytes();
                let pack_id_check = pack_contract_id(&pack_wasm, &pack_bytes);
                debug_assert_eq!(pack_key.id(), &pack_id_check);
                ObjectBundle::SinglePack {
                    pack_hash,
                    size_bytes: pack_bytes.len() as u64,
                }
            } else {
                let total_chunks = (pack_bytes.len() as u64).div_ceil(chunk_size as u64);
                eprintln!(
                    "==> publishing {} pack as {total_chunks} chunks (~60s per chunk under load; up to {} in parallel)",
                    human_bytes(pack_bytes.len() as u64),
                    freenet_git_cli::chunked::parallelism_from_env(),
                );
                let published = freenet_git_cli::chunked::publish_chunked_pack_with_progress(
                    &env.ws_url,
                    &pack_wasm,
                    pack_bytes.clone(),
                    chunk_size,
                    freenet_git_cli::chunked::parallelism_from_env(),
                    ws_timeout(),
                    |phase, i, n| {
                        use freenet_git_cli::chunked::PublishPhase;
                        let label = match phase {
                            PublishPhase::PutChunk => "PUT chunk",
                            PublishPhase::VerifyChunk => "verify chunk",
                            PublishPhase::PutManifest => "PUT manifest",
                            PublishPhase::VerifyManifest => "verify manifest",
                        };
                        eprintln!("        {label} {i}/{n}");
                    },
                )
                .await?;
                eprintln!(
                    "==> published {} chunks, {} total",
                    published.chunk_count,
                    human_bytes(published.total_size),
                );
                published.bundle
            };

            let bundle_id = bundle_obj.id();
            let record = sign_bundle_record(&params, &signing, bundle_obj, 0);
            delta.object_index.insert(bundle_id, record);

            // Sign the ref update.
            //
            // `target_arr` is the 20-byte SHA the ref points at. For
            // branch refs and lightweight tags this is a commit SHA;
            // for annotated tags it is the tag *object's* SHA (which
            // git's `rev-parse refs/tags/<name>` returns). The
            // `CommitHash` type name is a historical misnomer — the
            // field semantically holds any object SHA the ref points
            // at. Downstream consumers (`reachable_bundle_ids`,
            // `bundle-tip:<id>` extensions, `walk_unresolved_parents`)
            // all treat this as an opaque object SHA and peel through
            // tag objects on demand, so the misnomer is contained.
            let new_seq = state.refs.get(&dst).map(|e| e.update_seq).unwrap_or(0) + 1;
            let target_arr: CommitHash = parse_sha1(&new_target)?;

            // Tag mutability advisory: git's "tags are immutable"
            // convention is enforced by the LOCAL git client (it
            // rejects non-fast-forward tag updates without `--force`).
            // The Freenet contract itself treats tag refs the same
            // as branch refs and accepts the bumped update_seq. A
            // force-push of a tag therefore quietly rewrites the
            // contract entry. Surface this so the operator notices
            // they are doing something unusual.
            if force && dst.starts_with("refs/tags/") {
                eprintln!(
                    "warning: force-pushing tag {dst} -- the previous target on the \
                     Freenet contract will be overwritten. Tags are conventionally \
                     immutable in git; the contract follows the same update_seq \
                     monotonicity as branch refs and does not enforce that convention. \
                     Consumers who fetched the old tag target keep their copy; future \
                     fetches see the new target."
                );
            }

            let entry = sign_ref_entry(&params, &signing, &dst, target_arr, new_seq, 0);
            delta.refs.insert(dst.clone(), entry);

            // Advertise the bundle's tip via a signed extension entry.
            // On fetch, readers consult these extensions to figure out
            // which bundles are reachable from the wanted refs and
            // which are dead weight from earlier force-pushes (issue
            // #32).
            let (tip_ext_key, tip_entry) = sign_bundle_tip_extension(
                &params,
                &signing,
                &bundle_id,
                &target_arr,
                BUNDLE_TIP_UPDATE_SEQ,
            );
            delta.extensions.insert(tip_ext_key, tip_entry);

            ok_lines.push(format!("ok {dst}"));
        }

        // Record the publisher's mirror mode as a signed extension
        // when `FREENET_GIT_MIRROR_MODE` is set. The mirror workflow
        // (`mirror-repo.yml`) is the only place that knows whether
        // it's running a snapshot-mode (force-push of an orphan
        // commit, all previous bundles become dead-weight) or
        // history-mode (incremental fast-forward, every ancestor
        // bundle is reachable) push. Recording it on the contract
        // lets `freenet-git rescue` auto-apply `--only-current-tips`
        // for snapshot-mode repos without the operator needing to
        // know the mode.
        //
        // Only re-signs when the value would change — saves an
        // extension entry write per push for the steady state. See
        // freenet-git#43.
        if let Ok(mode_raw) = std::env::var("FREENET_GIT_MIRROR_MODE") {
            let mode = mode_raw.trim();
            match mode {
                "snapshot" | "history" => {
                    let want = mode.as_bytes();
                    let current = state
                        .extensions
                        .get(MIRROR_MODE_EXTENSION_KEY)
                        .map(|e| e.value.as_slice());
                    if current != Some(want) {
                        let new_seq = state
                            .extensions
                            .get(MIRROR_MODE_EXTENSION_KEY)
                            .map(|e| e.update_seq)
                            .unwrap_or(0)
                            + 1;
                        let entry = sign_extension(
                            &params,
                            &signing,
                            MIRROR_MODE_EXTENSION_KEY,
                            want.to_vec(),
                            new_seq,
                        );
                        delta
                            .extensions
                            .insert(MIRROR_MODE_EXTENSION_KEY.to_string(), entry);
                    }
                }
                "" => {
                    // Empty / unset = no-op (legacy behaviour, no
                    // extension write). Pass through silently.
                }
                bad => {
                    // Non-empty invalid value: fail-loud. Silent skip
                    // would let the contract drift permanently
                    // mis-tagged after a workflow refactor or
                    // interpolation typo. Mirrors mirror-repo.yml's
                    // `exit 1` and rescue's `detect_mirror_mode`
                    // strict-equality check.
                    bail!(
                        "FREENET_GIT_MIRROR_MODE must be the literal \"snapshot\" or \"history\" (got {bad:?})"
                    );
                }
            }
        }

        if delta.object_index.is_empty()
            && delta.refs.is_empty()
            && delta.extensions.is_empty()
        {
            return Ok::<_, anyhow::Error>((ok_lines, error_lines));
        }

        // Local sanity: validate the merged state would pass before
        // committing it to the network.
        let merged = ts_update_state(&params, &state, &delta)
            .map_err(|e| anyhow!("local update_state rejected our delta: {e}"))?;
        let _ = merged;

        // UPDATE the repo contract with the signed delta.
        //
        // `update_state` derives the contract key's code hash from
        // `repo_wasm`, and that is load-bearing rather than cosmetic:
        // freenet-core resolves the contract for a delta update by
        // probing on the key's code hash, so a placeholder there fails
        // every push with `missing contract`. See
        // `wsclient::update_contract_key`.
        eprintln!("==> updating repo state on Freenet");
        wsclient::update_state(
            &mut api,
            env.contract_id,
            &repo_wasm,
            bincode::serialize(&delta)?,
            ws_timeout(),
        )
        .await?;
        eprintln!("==> done");

        Ok::<_, anyhow::Error>((ok_lines, error_lines))
    })?;

    let (ok_lines, error_lines) = result;
    for line in &ok_lines {
        writeln!(out, "{line}")?;
    }
    for line in &error_lines {
        writeln!(out, "{line}")?;
    }
    writeln!(out)?;
    out.flush()?;

    Ok(())
}

fn parse_push_spec(spec: &str) -> Result<(bool, String, String)> {
    let (force_stripped, force) = match spec.strip_prefix('+') {
        Some(rest) => (rest, true),
        None => (spec, false),
    };
    let mut parts = force_stripped.splitn(2, ':');
    let src = parts.next().unwrap_or("").to_string();
    let dst = parts
        .next()
        .ok_or_else(|| anyhow!("push spec missing destination"))?
        .to_string();
    Ok((force, src, dst))
}

/// Idempotent short-circuit predicate for `handle_push`. Returns
/// `true` if the contract's recorded ref target equals the local
/// commit we're about to push, in which case the push is a no-op
/// and should be skipped.
///
/// This is a defensive layer. Under normal `git push` flows, git
/// itself short-circuits a push of an unchanged ref ("Everything
/// up-to-date") before invoking the helper's `push` command --
/// it walks the remote's `list` output first and compares to local
/// refs. So this branch typically never fires in production. It
/// guards against:
///
/// 1. Hand-crafted helper drivers that bypass git's own up-to-date
///    check (e.g. a future `freenet-git rescue --push-from`).
/// 2. Future changes to git's protocol where the client no longer
///    pre-walks remote refs.
/// 3. A subtle bug where git's `list` parsing differs from ours.
///
/// Combined with PR #18's deterministic snapshot dates, this makes
/// daily safety-net cron runs against unchanged source no-op
/// end-to-end -- no contract write, no `update_seq` bump.
///
/// `prev` is the lowercase-hex SHA from `state.refs[dst].target`
/// (or `None` for first-push), and `new_target` is the lowercase-
/// hex SHA from `git_resolve_ref`. Both sides are normalised to
/// lowercase by their producers, so a direct `&str` comparison is
/// safe.
fn is_already_up_to_date(prev: Option<&str>, new_target: &str) -> bool {
    prev == Some(new_target)
}

/// Returns `Ok(true)` if `git_dir` has any object at `sha`, regardless
/// of kind (commit, tree, blob, tag). Used by `walk_unresolved_parents`
/// to distinguish "object truly missing" from "object present but not
/// a commit" (e.g. an annotated tag of a tree); the latter is
/// commit-graph-walked as a no-op rather than re-fetched indefinitely.
fn any_object_exists(git_dir: &std::path::Path, sha: &str) -> Result<bool> {
    let out = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args(["cat-file", "-e", sha])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("spawn git cat-file -e")?;
    if out.status.success() {
        return Ok(true);
    }
    match out.status.code() {
        Some(1) => Ok(false),
        other => bail!(
            "git cat-file -e {sha} failed (status={:?}): {}",
            other,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
    }
}

/// Returns `Ok(true)` if `git_dir` has a commit at `sha`, `Ok(false)`
/// if the SHA is missing or refers to a non-commit object (blob/tree/
/// tag), and `Err(...)` for any other failure (corrupt object DB,
/// invalid `.git`, missing `git` binary, etc.).
///
/// Used to gate the `^<have>` arg to `git rev-list`. The contract
/// state stores ref targets as `CommitHash`, so a `<have>` that
/// resolves to a non-commit means the local repo is in a
/// pathological state -- we should treat that the same as "missing"
/// rather than passing `^<have>` to rev-list and hitting the cryptic
/// `fatal: not a commit object`.
///
/// Implemented via `git rev-parse --verify --quiet <sha>^{commit}`:
/// - status 0 + stdout = full SHA: exists and is a commit.
/// - status 1: missing OR not a commit (with `--quiet`, no stderr).
/// - status 128: command-line / config error -- bubbled up.
fn commit_exists(git_dir: &std::path::Path, sha: &str) -> Result<bool> {
    let out = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args([
            "rev-parse",
            "--verify",
            "--quiet",
            &format!("{sha}^{{commit}}"),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::piped())
        .output()
        .context("spawn git rev-parse")?;
    if out.status.success() {
        return Ok(true);
    }
    match out.status.code() {
        Some(1) => Ok(false),
        other => bail!(
            "git rev-parse {sha}^{{commit}} failed (status={:?}): {}",
            other,
            String::from_utf8_lossy(&out.stderr).trim()
        ),
    }
}

fn git_resolve_ref(git_dir: &std::path::Path, refname: &str) -> Result<String> {
    let out = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args(["rev-parse", "--verify", refname])
        .output()
        .context("spawn git rev-parse")?;
    if !out.status.success() {
        bail!(
            "git rev-parse {refname} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(String::from_utf8(out.stdout)?.trim().to_string())
}

fn build_pack(
    git_dir: &std::path::Path,
    have: Option<&str>,
    want: &str,
    force: bool,
) -> Result<Vec<u8>> {
    // If `have` is set but the local repo doesn't actually have that
    // object, `git rev-list ^<have> <want>` will fail with "fatal: bad
    // object". The canonical case is force-pushing an orphan commit
    // (snapshot mode in the mirror workflow): the receiver knows about
    // the previous orphan tip but the local repo has never seen it.
    // For force pushes, drop `^<have>` and send everything reachable
    // from `want` -- that's the right semantic for "replace whatever
    // was there." For non-force pushes, surface a directed error
    // rather than the cryptic rev-list output.
    let effective_have = match have {
        Some(h) if !commit_exists(git_dir, h)? => {
            if force {
                None
            } else {
                bail!(
                    "remote tip {h} is not present (or not a commit) in the \
                     local repo. For snapshot/orphan-style pushes use \
                     `git push --force` (or prefix the refspec with `+`) to \
                     overwrite the remote tip's history. For regular \
                     fast-forward pushes, run `git fetch` to populate the \
                     missing tip first."
                );
            }
        }
        other => other,
    };

    // We pipe the rev-list into pack-objects --stdin --revs --thin so
    // git decides which objects need to be in the pack.
    let mut rev_list = Command::new("git");
    rev_list.arg("--git-dir").arg(git_dir);
    rev_list.args(["rev-list", "--objects", want]);
    if let Some(h) = effective_have {
        rev_list.arg(format!("^{h}"));
    }
    let rev_list_out = rev_list
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .output()
        .context("spawn git rev-list")?;
    if !rev_list_out.status.success() {
        bail!("git rev-list failed: {}", rev_list_out.status);
    }

    // `-c pack.threads=1`: the pack that lands on the contract here
    // is what `freenet-git rescue --from <git-dir>` will later try to
    // reconstruct byte-for-byte. Default `pack.threads=auto` races
    // delta search across cores → non-deterministic pack bytes →
    // future rescues' reconstructions silently miss the lookup map.
    // Pinning single-threaded is a small per-push wall-clock cost
    // for permanent rescue reproducibility. See PR #55 Codex P2 #2.
    let mut child = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args(["-c", "pack.threads=1", "pack-objects", "--stdout"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .context("spawn git pack-objects")?;
    {
        let mut stdin = child.stdin.take().expect("piped");
        // Strip the path part: pack-objects only wants the SHA on each line.
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
        bail!("git pack-objects failed: {}", out.status);
    }
    Ok(out.stdout)
}

fn parse_sha1(hex_str: &str) -> Result<CommitHash> {
    let bytes = hex::decode(hex_str).context("decode commit sha")?;
    let arr: [u8; 20] = bytes.as_slice().try_into().map_err(|_| {
        anyhow!(
            "commit sha must be 20 bytes (got {} hex chars)",
            hex_str.len()
        )
    })?;
    Ok(arr)
}

fn build_runtime() -> Result<tokio::runtime::Runtime> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")
}

fn init_tracing() {
    let _ = tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("warn")),
        )
        .with_writer(std::io::stderr)
        .try_init();
}

#[cfg(test)]
mod migration_tests {
    //! Drive the *forward* half of the legacy-contract migration: after
    //! `get_state_with_legacy_fallback` recovers a predecessor's state,
    //! `fetch_repo_state_from_registry` must re-PUT it to the current
    //! contract key so the next client finds it without falling back.
    //!
    //! `legacy_contracts.toml` is empty in every shipped build, so this
    //! branch has never executed. `tests/legacy_fallback.rs` covers the
    //! probe-and-recover half against the same fake gateway.

    use super::fake_gateway::{FakeGateway, Reply};
    use super::*;
    use freenet_git_cli::legacy::ContractLineageEntry;
    use freenet_stdlib::prelude::{ContractCode, Parameters};
    use std::collections::HashMap;

    /// Synthetic stand-in for a repo-contract WASM. Only its BLAKE3
    /// matters; each `tag` yields a distinct contract key.
    fn synthetic_wasm(tag: u8) -> Vec<u8> {
        let mut bytes = b"\0asm\x01\0\0\0synthetic-repo-contract-".to_vec();
        bytes.extend(std::iter::repeat_n(tag, 512));
        bytes
    }

    /// Oracle: derive the contract id the way `freenet-stdlib` does,
    /// independently of `wsclient::legacy_instance_id` (the
    /// freenet-migrate-backed derivation the migration probe uses).
    fn stdlib_id(wasm: &[u8], params_bytes: &[u8]) -> ContractInstanceId {
        ContractInstanceId::from_params_and_code(
            Parameters::from(params_bytes.to_vec()),
            ContractCode::from(wasm.to_vec()),
        )
    }

    struct Fixture {
        env: HelperEnv,
        current_wasm: Vec<u8>,
        current_id: ContractInstanceId,
        legacy_id: ContractInstanceId,
        legacy_hash: [u8; 32],
        state_bytes: Vec<u8>,
        gateway: FakeGateway,
    }

    /// A repo whose real, signed state sits at a predecessor key and
    /// nowhere else — the state of the world immediately after a
    /// release that re-keyed the repo contract.
    async fn stranded_repo() -> Fixture {
        let owner = ed25519_dalek::SigningKey::from_bytes(&[7u8; 32]);
        let owner_pk = owner.verifying_key().to_bytes();
        let params = freenet_git_types::RepoParams::from_owner(&owner_pk, 10);
        let params_bytes = params.to_bytes();

        // A real signed RepoState, not opaque bytes: the migration ends
        // in `RepoState::from_bytes`, so the recovered payload has to
        // survive a genuine round trip.
        let state = freenet_git_cli::state_init::initial_repo_state(
            &params,
            &owner,
            "stranded",
            "published before the re-key",
            "main",
        );
        let state_bytes = state.to_bytes();

        let current_wasm = synthetic_wasm(0xC0);
        let legacy_wasm = synthetic_wasm(0x1E);
        let current_id = stdlib_id(&current_wasm, &params_bytes);
        let legacy_id = stdlib_id(&legacy_wasm, &params_bytes);
        assert_ne!(current_id, legacy_id, "a WASM change must re-key the repo");

        let mut replies = HashMap::new();
        replies.insert(legacy_id, Reply::State(state_bytes.clone()));
        let gateway = FakeGateway::start(replies).await;

        let env = HelperEnv {
            prefix: params.prefix.clone(),
            contract_id: current_id,
            ws_url: gateway.url().to_string(),
            git_dir: PathBuf::from("/nonexistent/.git"),
            identity_path: PathBuf::from("/nonexistent/identity"),
            repo_wasm_path: None,
            pack_wasm_path: None,
        };

        Fixture {
            env,
            current_wasm,
            current_id,
            legacy_id,
            legacy_hash: *blake3::hash(&legacy_wasm).as_bytes(),
            state_bytes,
            gateway,
        }
    }

    /// Guard against a mutation turning a fast assertion failure into a
    /// 180-second `ws_timeout()` hang.
    async fn within<T>(fut: impl std::future::Future<Output = T>) -> T {
        tokio::time::timeout(Duration::from_secs(20), fut)
            .await
            .expect("migration should complete promptly against a loopback gateway")
    }

    /// The payoff of the whole mechanism: state stranded at a
    /// predecessor key is returned to the caller AND written forward to
    /// the current key, so the next client does not have to fall back.
    #[tokio::test]
    async fn recovered_predecessor_state_is_written_forward_to_the_current_key() {
        let f = stranded_repo().await;
        let registry = &[ContractLineageEntry {
            generation: 1,
            code_hash: f.legacy_hash,
            note: "0.1.3 repo-contract",
        }];

        let mut api = wsclient::connect(f.env.ws_url.as_str())
            .await
            .expect("connect");
        let recovered = within(fetch_repo_state_from_registry(
            &f.env,
            &mut api,
            &f.current_wasm,
            registry,
        ))
        .await
        .expect("state must be recovered from the predecessor key");

        assert_eq!(
            recovered.to_bytes(),
            f.state_bytes,
            "the caller must receive the predecessor's state, intact"
        );

        let puts = f.gateway.puts();
        assert_eq!(
            puts.len(),
            1,
            "exactly one migration PUT expected, got {puts:?}"
        );
        assert_eq!(
            puts[0].0, f.current_id,
            "the migration PUT must land on the CURRENT contract key; a PUT to \
             the legacy key would leave the repo stranded forever"
        );
        assert_eq!(
            puts[0].1, f.state_bytes,
            "the migrated bytes must be the recovered state, unaltered"
        );

        // And the migration must be durable from the network's point of
        // view: a second client with the same binary finds the state at
        // the current key and never probes the predecessor.
        let mut api2 = wsclient::connect(f.env.ws_url.as_str())
            .await
            .expect("reconnect");
        let gets_before = f.gateway.gets().len();
        let again = within(fetch_repo_state_from_registry(
            &f.env,
            &mut api2,
            &f.current_wasm,
            registry,
        ))
        .await
        .expect("post-migration fetch");
        assert_eq!(again.to_bytes(), f.state_bytes);
        assert_eq!(
            f.gateway.gets()[gets_before..],
            [f.current_id],
            "after migration the current key answers directly, with no fallback probe"
        );
        assert_eq!(
            f.gateway.puts().len(),
            1,
            "a fetch that hits the current key must not re-PUT"
        );
    }

    /// If the current contract rejects the migration PUT — the
    /// backwards-incompatible-state case the code comments call out —
    /// the user must still get their repo. Losing the read because the
    /// write failed would turn a degraded migration into an outage.
    #[tokio::test]
    async fn a_rejected_migration_put_still_returns_the_recovered_state() {
        let f = stranded_repo().await;
        f.gateway
            .reject_puts("state rejected by contract: validate_state failed");
        let registry = &[ContractLineageEntry {
            generation: 1,
            code_hash: f.legacy_hash,
            note: "0.1.3 repo-contract",
        }];

        let mut api = wsclient::connect(f.env.ws_url.as_str())
            .await
            .expect("connect");
        let recovered = within(fetch_repo_state_from_registry(
            &f.env,
            &mut api,
            &f.current_wasm,
            registry,
        ))
        .await
        .expect("a failed migration PUT must not fail the fetch");

        assert_eq!(recovered.to_bytes(), f.state_bytes);
        assert_eq!(
            f.gateway.puts().len(),
            1,
            "the migration must have been attempted before giving up on it"
        );
    }

    /// The note printed in the migration log line is indexed out of the
    /// same registry slice the hashes came from — and the reported index
    /// is a SLICE index even though probing is generation-descending.
    /// The decoy here is the NEWER generation (probed first, absent), so
    /// the hit is the second probe but slice entry 1; a fallback that
    /// reported probe position instead of slice position would mislabel
    /// the log line (or panic) on a real migration.
    #[tokio::test]
    async fn a_second_registry_entry_reports_the_right_index() {
        let f = stranded_repo().await;
        let decoy = *blake3::hash(&synthetic_wasm(0xDD)).as_bytes();
        let registry = &[
            ContractLineageEntry {
                generation: 2,
                code_hash: decoy,
                note: "0.1.4 repo-contract",
            },
            ContractLineageEntry {
                generation: 1,
                code_hash: f.legacy_hash,
                note: "0.1.3 repo-contract",
            },
        ];

        let mut api = wsclient::connect(f.env.ws_url.as_str())
            .await
            .expect("connect");
        let recovered = within(fetch_repo_state_from_registry(
            &f.env,
            &mut api,
            &f.current_wasm,
            registry,
        ))
        .await
        .expect("second registry entry holds the state");

        assert_eq!(recovered.to_bytes(), f.state_bytes);
        let gets = f.gateway.gets();
        assert_eq!(
            gets.len(),
            3,
            "current key, decoy predecessor, then the real one: {gets:?}"
        );
        assert_eq!(gets[2], f.legacy_id);
        assert_eq!(f.gateway.puts()[0].0, f.current_id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity_bundle(repos: &[(&str, &str)]) -> DecryptedBundle {
        DecryptedBundle {
            secret_key: vec![0u8; 32],
            public_key: vec![0u8; 32],
            name: "Test".into(),
            email: "test@example.com".into(),
            repos: repos
                .iter()
                .map(|(prefix, display_name)| identity::RepoRegistryEntry {
                    repo_secret: vec![0u8; 32],
                    repo_public: vec![0u8; 32],
                    prefix: (*prefix).to_string(),
                    display_name: (*display_name).to_string(),
                })
                .collect(),
        }
    }

    /// A bundle-tip extension must survive the **deployed** contract's
    /// delta rule, which is what decides whether the entry ever reaches
    /// a peer that syncs by summary+delta.
    ///
    /// The rule is replicated here on purpose rather than calling
    /// `freenet_git_types::get_state_delta`: that function has been
    /// corrected in source, but the correction only reaches the network
    /// when `contracts/repo-contract.wasm` is rebuilt, which re-keys
    /// every repo. Calling it would test the future and quietly stop
    /// testing what is actually running. Delete this replica when the
    /// contract is rebuilt, not before.
    #[test]
    fn bundle_tip_seq_survives_the_deployed_contracts_delta_rule() {
        fn deployed_peer_needs(peer_seq: Option<u64>, entry_seq: u64) -> bool {
            peer_seq.unwrap_or(0) < entry_seq
        }

        assert!(
            deployed_peer_needs(None, BUNDLE_TIP_UPDATE_SEQ),
            "a tip written at seq {BUNDLE_TIP_UPDATE_SEQ} must reach a peer \
             that has never seen it",
        );
        // Why 0 is not usable, pinned so nobody "simplifies" it back.
        assert!(
            !deployed_peer_needs(None, 0),
            "seq 0 is undeliverable under the deployed rule; that is the bug \
             BUNDLE_TIP_UPDATE_SEQ exists to avoid",
        );
        // And a peer that already has it must not be re-sent it.
        assert!(!deployed_peer_needs(
            Some(BUNDLE_TIP_UPDATE_SEQ),
            BUNDLE_TIP_UPDATE_SEQ
        ));
    }

    /// The "wrong identity" error lists what this bundle CAN push to,
    /// because the usual cause is a mistyped prefix or the wrong
    /// bundle — both obvious once the prefixes are shown side by side.
    #[test]
    fn describe_pushable_repos_lists_prefix_and_name() {
        let bundle = identity_bundle(&[("RtTzy58hMxAB", "my-project"), ("Aa12bc34De56", "other")]);
        let rendered = describe_pushable_repos(&bundle);
        assert!(rendered.contains("RtTzy58hMxAB (my-project)"), "{rendered}");
        assert!(rendered.contains("Aa12bc34De56 (other)"), "{rendered}");
    }

    /// An empty registry must not print an empty list under a
    /// "Repos this identity can push to:" heading — that reads like a
    /// rendering bug. Say plainly that there are none.
    #[test]
    fn describe_pushable_repos_handles_empty_registry() {
        let rendered = describe_pushable_repos(&identity_bundle(&[]));
        assert!(rendered.contains("has not created any repos"), "{rendered}");
        assert!(!rendered.contains("can push to:"), "{rendered}");
    }

    fn fake_bundle(pack_hash: [u8; 32]) -> ObjectBundle {
        ObjectBundle::SinglePack {
            pack_hash,
            size_bytes: 100,
        }
    }

    /// Build a minimal `RepoState` with the given ref targets and
    /// object_index entries (with optional bundle-tip extensions). All
    /// signatures are zero placeholders -- these tests exercise the
    /// pure filter logic which doesn't verify signatures.
    fn make_state(
        refs: &[(&str, [u8; 20])],
        bundles: &[(ObjectBundle, Option<[u8; 20]>)],
    ) -> RepoState {
        use freenet_git_types::{ObjectBundleRecord, RefEntry};

        let mut state = RepoState::default();
        for (name, target) in refs {
            state.refs.insert(
                (*name).to_string(),
                RefEntry {
                    target: *target,
                    update_seq: 1,
                    updater: [0u8; 32],
                    auth_epoch: 0,
                    signature: [0u8; 64],
                },
            );
        }
        for (bundle, tip) in bundles {
            let id = bundle.id();
            state.object_index.insert(
                id,
                ObjectBundleRecord {
                    bundle: bundle.clone(),
                    added_by: [0u8; 32],
                    auth_epoch: 0,
                    signature: [0u8; 64],
                },
            );
            if let Some(tip) = tip {
                let key = freenet_git_types::signing::bundle_tip_extension_key(&id);
                state.extensions.insert(
                    key,
                    freenet_git_types::ExtensionEntry {
                        value: tip.to_vec(),
                        update_seq: 0,
                        signature: [0u8; 64],
                    },
                );
            }
        }
        state
    }

    #[test]
    fn collect_bundle_tip_extensions_picks_only_bundle_tip_keys() {
        let bundle_a = fake_bundle([0x11; 32]);
        let bundle_b = fake_bundle([0x22; 32]);
        let mut state = make_state(
            &[("refs/heads/main", [0xaa; 20])],
            &[
                (bundle_a.clone(), Some([0xaa; 20])),
                (bundle_b.clone(), None), // legacy / no tip ext
            ],
        );
        // Add an unrelated extension (e.g. a hypothetical future
        // extension key) that must be ignored by the parser.
        state.extensions.insert(
            "some-other-extension".into(),
            freenet_git_types::ExtensionEntry {
                value: vec![1, 2, 3],
                update_seq: 0,
                signature: [0u8; 64],
            },
        );

        let tips = collect_bundle_tip_extensions(&state);
        assert_eq!(tips.len(), 1, "only one bundle has a tip extension");
        assert_eq!(tips.get(&bundle_a.id()), Some(&[0xaa_u8; 20]));
    }

    #[test]
    fn collect_bundle_tip_extensions_skips_malformed_value_length() {
        // A bundle-tip:* key whose value is the wrong length (not 20
        // bytes) must not be parsed as a tip. This covers the "value
        // tampered to non-CommitHash" case skeptical reviewer M4
        // flagged.
        let bundle_a = fake_bundle([0x11; 32]);
        let mut state = make_state(&[], &[(bundle_a.clone(), None)]);
        let key = freenet_git_types::signing::bundle_tip_extension_key(&bundle_a.id());
        state.extensions.insert(
            key,
            freenet_git_types::ExtensionEntry {
                value: vec![0u8; 10], // wrong length, not 20 bytes
                update_seq: 0,
                signature: [0u8; 64],
            },
        );

        let tips = collect_bundle_tip_extensions(&state);
        assert!(
            tips.is_empty(),
            "extension with wrong-length value must be skipped"
        );
    }

    /// Helper: build a tiny git repo with a linear history of the
    /// requested length and return the commit SHAs (oldest first).
    fn build_linear_history(dir: &std::path::Path, count: usize) -> Result<Vec<String>> {
        std::process::Command::new("git")
            .current_dir(dir)
            .args(["init", "-b", "main", "-q"])
            .status()?;
        for cmd in &[
            ["config", "user.email", "t@e.com"],
            ["config", "user.name", "Tester"],
            ["config", "commit.gpgsign", "false"],
        ] {
            std::process::Command::new("git")
                .current_dir(dir)
                .args(cmd)
                .status()?;
        }
        let mut shas = Vec::with_capacity(count);
        for i in 0..count {
            std::fs::write(dir.join("a.txt"), format!("contents-{i}\n"))?;
            std::process::Command::new("git")
                .current_dir(dir)
                .args(["add", "a.txt"])
                .status()?;
            std::process::Command::new("git")
                .current_dir(dir)
                .args(["commit", "-q", "-m", &format!("commit {i}")])
                .status()?;
            let out = std::process::Command::new("git")
                .current_dir(dir)
                .args(["rev-parse", "HEAD"])
                .output()?;
            shas.push(String::from_utf8(out.stdout)?.trim().to_string());
        }
        Ok(shas)
    }

    fn parse_hex_commit(hex: &str) -> CommitHash {
        let mut out = [0u8; 20];
        for (i, byte) in out.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&hex[i * 2..i * 2 + 2], 16).unwrap();
        }
        out
    }

    #[test]
    fn git_commit_parents_finds_immediate_parent() {
        let dir = tempfile::tempdir().unwrap();
        let shas = build_linear_history(dir.path(), 3).unwrap();
        let git_dir = dir.path().join(".git");

        // shas[0] is root (no parents); shas[1].parent == shas[0]; shas[2].parent == shas[1].
        assert!(git_commit_parents(&git_dir, &shas[0]).unwrap().is_empty());

        let parents_of_1 = git_commit_parents(&git_dir, &shas[1]).unwrap();
        assert_eq!(parents_of_1.len(), 1);
        assert_eq!(parents_of_1[0], parse_hex_commit(&shas[0]));

        let parents_of_2 = git_commit_parents(&git_dir, &shas[2]).unwrap();
        assert_eq!(parents_of_2.len(), 1);
        assert_eq!(parents_of_2[0], parse_hex_commit(&shas[1]));
    }

    #[test]
    fn walk_unresolved_parents_returns_missing_commits() {
        // Build a 3-commit history but only have the last commit
        // locally -- delete the older commit objects to simulate a
        // fetch that's only loaded the most recent bundle.
        let dir = tempfile::tempdir().unwrap();
        let shas = build_linear_history(dir.path(), 3).unwrap();

        // Clone shas[2]'s commit + tree + blob into a fresh repo so
        // its parents are NOT present (simulates "we have only the
        // tip"). Easier than doing pack-surgery on the original.
        let standalone = tempfile::tempdir().unwrap();
        let standalone_git = standalone.path().join(".git");
        std::process::Command::new("git")
            .current_dir(standalone.path())
            .args(["init", "-b", "main", "-q"])
            .status()
            .unwrap();
        // Copy ONLY the loose object for shas[2] (and its tree + blob)
        // from `dir`'s pack, by streaming its archive into a flat
        // single-commit history.
        let archive = std::process::Command::new("git")
            .current_dir(dir.path())
            .args(["archive", &shas[2]])
            .output()
            .unwrap();
        let tar_path = standalone.path().join("a.tar");
        std::fs::write(&tar_path, &archive.stdout).unwrap();
        std::process::Command::new("tar")
            .current_dir(standalone.path())
            .args(["-xf", "a.tar"])
            .status()
            .unwrap();
        std::fs::remove_file(&tar_path).unwrap();
        for cmd in &[
            vec!["config", "user.email", "t@e.com"],
            vec!["config", "user.name", "Tester"],
            vec!["config", "commit.gpgsign", "false"],
            vec!["add", "a.txt"],
        ] {
            std::process::Command::new("git")
                .current_dir(standalone.path())
                .args(cmd)
                .status()
                .unwrap();
        }
        // Make a synthetic orphan commit with the same tree as shas[2]
        // so the standalone repo contains shas[2]'s objects but NOT
        // shas[0]/shas[1].
        std::process::Command::new("git")
            .current_dir(standalone.path())
            .args(["commit", "-q", "-m", "synthetic"])
            .status()
            .unwrap();

        // Now walk parents starting from shas[1] (which doesn't exist
        // in `standalone_git`). Should report shas[1] as unresolved.
        let mut walked = std::collections::HashSet::new();
        let wanted: std::collections::HashSet<_> =
            std::iter::once(parse_hex_commit(&shas[1])).collect();
        let unresolved = walk_unresolved_parents(&standalone_git, &wanted, &mut walked).unwrap();
        assert!(
            unresolved.contains(&parse_hex_commit(&shas[1])),
            "missing commit must be in unresolved set"
        );
    }

    /// Write `commit_sha`'s raw commit object from `from` into `into`,
    /// and nothing else. The result is a repo where that commit is
    /// readable but its parents, tree, and blobs are absent.
    ///
    /// This is the state a clone is genuinely in partway through:
    /// the newest bundle's pack has been installed, so its tip commit
    /// is local, but the bundle carrying the tip's parent has not been
    /// downloaded yet. The pre-existing tests all build *orphan*
    /// commits instead, which is why none of them exercised
    /// [`git_commit_parents`] against a missing parent.
    fn copy_commit_object_only(from: &std::path::Path, into: &std::path::Path, commit_sha: &str) {
        let obj = std::process::Command::new("git")
            .current_dir(from)
            .args(["cat-file", "commit", commit_sha])
            .output()
            .unwrap();
        assert!(obj.status.success(), "read source commit object");
        let mut child = std::process::Command::new("git")
            .current_dir(into)
            .args(["hash-object", "-t", "commit", "-w", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(&obj.stdout)
            .unwrap();
        let written = child.wait_with_output().unwrap();
        assert!(written.status.success(), "write commit object into target");
    }

    /// Regression test for issue #60.
    ///
    /// A commit is local but its parent is not. The walk must report
    /// that parent as unresolved, so the caller knows to download the
    /// bundle carrying it. Before the fix, `git_commit_parents` shelled
    /// out to `git rev-list --parents -n 1`, which *errors* when a
    /// parent object is absent ("Could not read <parent>") — so the
    /// walk returned `Err` exactly when it had something to report, and
    /// the clone aborted instead of fetching the missing bundle.
    #[test]
    fn walk_unresolved_parents_reports_missing_parent_of_a_local_commit() {
        let full = tempfile::tempdir().unwrap();
        let shas = build_linear_history(full.path(), 3).unwrap();

        let partial = tempfile::tempdir().unwrap();
        std::process::Command::new("git")
            .current_dir(partial.path())
            .args(["init", "-b", "main", "-q"])
            .status()
            .unwrap();
        let partial_git = partial.path().join(".git");
        copy_commit_object_only(full.path(), partial.path(), &shas[2]);

        // Precondition: the tip IS local, its parent is NOT. If this
        // ever stops holding, the test is no longer exercising #60.
        assert!(
            commit_exists(&partial_git, &shas[2]).unwrap(),
            "tip commit should be readable in the partial repo"
        );
        assert!(
            !commit_exists(&partial_git, &shas[1]).unwrap(),
            "parent commit should be absent from the partial repo"
        );

        let mut walked = std::collections::HashSet::new();
        let wanted: std::collections::HashSet<_> =
            std::iter::once(parse_hex_commit(&shas[2])).collect();
        let unresolved = walk_unresolved_parents(&partial_git, &wanted, &mut walked).unwrap();

        assert!(
            unresolved.contains(&parse_hex_commit(&shas[1])),
            "the absent parent must be reported as unresolved so the \
             caller downloads its bundle; got {unresolved:?}"
        );
    }

    /// `git_commit_parents` must enumerate parents from the commit
    /// object alone, never requiring the parents themselves to be
    /// present. Pins the specific plumbing choice behind #60: the
    /// walk's whole job is to name absent parents.
    #[test]
    fn git_commit_parents_works_when_the_parent_object_is_absent() {
        let full = tempfile::tempdir().unwrap();
        let shas = build_linear_history(full.path(), 2).unwrap();

        let partial = tempfile::tempdir().unwrap();
        std::process::Command::new("git")
            .current_dir(partial.path())
            .args(["init", "-b", "main", "-q"])
            .status()
            .unwrap();
        let partial_git = partial.path().join(".git");
        copy_commit_object_only(full.path(), partial.path(), &shas[1]);

        let parents = git_commit_parents(&partial_git, &shas[1])
            .expect("enumerating parents must not require the parents to exist");
        assert_eq!(
            parents,
            vec![parse_hex_commit(&shas[0])],
            "should report exactly the one absent parent"
        );
    }

    /// A root commit has no parents. Guards against a parser that
    /// mistakes some other header (or the message body) for a parent.
    #[test]
    fn git_commit_parents_returns_empty_for_a_root_commit() {
        let dir = tempfile::tempdir().unwrap();
        let shas = build_linear_history(dir.path(), 1).unwrap();
        let parents = git_commit_parents(&dir.path().join(".git"), &shas[0]).unwrap();
        assert!(
            parents.is_empty(),
            "root commit has no parents: {parents:?}"
        );
    }

    /// Write a raw commit object into `dir` and return its sha. Lets a
    /// test pin an exact on-disk header layout that is awkward to
    /// produce with porcelain (a signature block, say).
    fn write_commit_object(dir: &std::path::Path, raw: &str) -> String {
        let mut child = std::process::Command::new("git")
            .current_dir(dir)
            .args(["hash-object", "-t", "commit", "-w", "--stdin"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .unwrap();
        child
            .stdin
            .as_mut()
            .unwrap()
            .write_all(raw.as_bytes())
            .unwrap();
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "write commit object");
        String::from_utf8(out.stdout).unwrap().trim().to_string()
    }

    /// A merge commit carries several `parent` headers and every one
    /// of them must come back, or the walk stops chasing a whole side
    /// of the history and the clone silently lacks those commits.
    #[test]
    fn git_commit_parents_returns_every_parent_of_a_merge_commit() {
        let dir = tempfile::tempdir().unwrap();
        build_linear_history(dir.path(), 1).unwrap();
        let git = |args: &[&str]| {
            std::process::Command::new("git")
                .current_dir(dir.path())
                .args(args)
                .status()
                .unwrap();
        };
        let rev_parse = |r: &str| {
            let o = std::process::Command::new("git")
                .current_dir(dir.path())
                .args(["rev-parse", r])
                .output()
                .unwrap();
            String::from_utf8(o.stdout).unwrap().trim().to_string()
        };

        git(&["checkout", "-q", "-b", "side"]);
        std::fs::write(dir.path().join("b.txt"), "side\n").unwrap();
        git(&["add", "b.txt"]);
        git(&["commit", "-q", "-m", "side"]);
        let side = rev_parse("HEAD");

        git(&["checkout", "-q", "main"]);
        std::fs::write(dir.path().join("c.txt"), "main\n").unwrap();
        git(&["add", "c.txt"]);
        git(&["commit", "-q", "-m", "main2"]);
        let mainline = rev_parse("HEAD");

        git(&["merge", "-q", "--no-ff", "side", "-m", "merge side"]);
        let merge = rev_parse("HEAD");

        let parents = git_commit_parents(&dir.path().join(".git"), &merge).unwrap();
        assert_eq!(
            parents,
            vec![parse_hex_commit(&mainline), parse_hex_commit(&side)],
            "both merge parents, first-parent first"
        );
    }

    /// A commit MESSAGE may contain a line that looks exactly like a
    /// `parent` header — quoting a log, pasting a review note. Parsing
    /// past the blank line would invent a parent out of prose, and the
    /// walk would then hunt forever for a bundle containing an object
    /// that does not exist. This is not hypothetical: `git commit -m`
    /// puts the body at column 0, same as a header.
    #[test]
    fn git_commit_parents_ignores_parent_lines_in_the_commit_message() {
        let dir = tempfile::tempdir().unwrap();
        let shas = build_linear_history(dir.path(), 1).unwrap();
        let tree = {
            let o = std::process::Command::new("git")
                .current_dir(dir.path())
                .args(["rev-parse", "HEAD^{tree}"])
                .output()
                .unwrap();
            String::from_utf8(o.stdout).unwrap().trim().to_string()
        };
        let bogus = "0000000000000000000000000000000000000000";
        let raw = format!(
            "tree {tree}\n\
             parent {}\n\
             author T <t@e.com> 1785815519 -0500\n\
             committer T <t@e.com> 1785815519 -0500\n\
             \n\
             subject\n\
             \n\
             parent {bogus}\n",
            shas[0]
        );
        let sha = write_commit_object(dir.path(), &raw);

        let parents = git_commit_parents(&dir.path().join(".git"), &sha).unwrap();
        assert_eq!(
            parents,
            vec![parse_hex_commit(&shas[0])],
            "only the header parent counts; the message line must be ignored"
        );
    }

    /// A signed commit's `gpgsig` header spans many continuation
    /// lines, and the blank line inside PGP armor is stored as a line
    /// containing a single space — not an empty line. Verify that does
    /// not end header parsing early or get misread, on a commit whose
    /// parent header is real.
    #[test]
    fn git_commit_parents_handles_a_multiline_gpgsig_header() {
        let dir = tempfile::tempdir().unwrap();
        let shas = build_linear_history(dir.path(), 1).unwrap();
        let tree = {
            let o = std::process::Command::new("git")
                .current_dir(dir.path())
                .args(["rev-parse", "HEAD^{tree}"])
                .output()
                .unwrap();
            String::from_utf8(o.stdout).unwrap().trim().to_string()
        };
        let raw = format!(
            "tree {tree}\n\
             parent {}\n\
             author T <t@e.com> 1785815519 -0500\n\
             committer T <t@e.com> 1785815519 -0500\n\
             gpgsig -----BEGIN PGP SIGNATURE-----\n\
             \x20\n\
             \x20iQIzBAABCgAdFiEEnotarealsignature\n\
             \x20=abcd\n\
             \x20-----END PGP SIGNATURE-----\n\
             \n\
             signed commit\n",
            shas[0]
        );
        let sha = write_commit_object(dir.path(), &raw);

        let parents = git_commit_parents(&dir.path().join(".git"), &sha).unwrap();
        assert_eq!(
            parents,
            vec![parse_hex_commit(&shas[0])],
            "signature continuation lines must not disturb parent parsing"
        );
    }

    #[test]
    fn walk_unresolved_parents_does_not_short_circuit_after_download() {
        // Regression test for Codex P1 on PR #33: when a parent commit
        // is reported as unresolved on iteration N, it must NOT be
        // marked as walked -- otherwise iteration N+1 (after that
        // parent's bundle is downloaded and the parent becomes local)
        // would skip it and never enumerate ITS parents.
        //
        // Setup: two-step history. Iteration 1 simulates "we have C2
        // but not C1" (C2 standalone repo). walk_unresolved_parents
        // returns C1 as unresolved; `walked` must NOT contain C1.
        // Then iteration 2 simulates "we have both C1 and C2" (full
        // repo); walk_unresolved_parents on the same wanted set and
        // SAME `walked` should return empty AND visit C1 to enumerate
        // its parents (it's the root, so no further unresolved).
        let full_dir = tempfile::tempdir().unwrap();
        let shas = build_linear_history(full_dir.path(), 2).unwrap();
        let full_git = full_dir.path().join(".git");

        // Iteration-1 simulator: a repo with only C2's tree as a
        // synthetic orphan.
        let part_dir = tempfile::tempdir().unwrap();
        std::process::Command::new("git")
            .current_dir(part_dir.path())
            .args(["init", "-b", "main", "-q"])
            .status()
            .unwrap();
        let archive = std::process::Command::new("git")
            .current_dir(full_dir.path())
            .args(["archive", &shas[1]])
            .output()
            .unwrap();
        let tar_path = part_dir.path().join("a.tar");
        std::fs::write(&tar_path, &archive.stdout).unwrap();
        std::process::Command::new("tar")
            .current_dir(part_dir.path())
            .args(["-xf", "a.tar"])
            .status()
            .unwrap();
        std::fs::remove_file(&tar_path).unwrap();
        for cmd in &[
            vec!["config", "user.email", "t@e.com"],
            vec!["config", "user.name", "Tester"],
            vec!["config", "commit.gpgsign", "false"],
            vec!["add", "a.txt"],
            vec!["commit", "-q", "-m", "synthetic"],
        ] {
            std::process::Command::new("git")
                .current_dir(part_dir.path())
                .args(cmd)
                .status()
                .unwrap();
        }
        let part_git = part_dir.path().join(".git");

        let mut walked = std::collections::HashSet::new();
        let wanted: std::collections::HashSet<_> =
            std::iter::once(parse_hex_commit(&shas[0])).collect();

        // Iter 1: C1 missing in part_git, must be returned as unresolved.
        let unresolved = walk_unresolved_parents(&part_git, &wanted, &mut walked).unwrap();
        assert!(
            unresolved.contains(&parse_hex_commit(&shas[0])),
            "C1 must be unresolved against part_git"
        );
        assert!(
            !walked.contains(&parse_hex_commit(&shas[0])),
            "unresolved commits MUST NOT be added to walked -- otherwise the next iteration would skip them"
        );

        // Iter 2: same `walked`, but now run against full_git
        // (simulates "we just downloaded the bundle that contains
        // C1"). Walker should re-visit C1, see it's local, enumerate
        // its parents (none, it's the root), and return empty.
        let unresolved = walk_unresolved_parents(&full_git, &wanted, &mut walked).unwrap();
        assert!(
            unresolved.is_empty(),
            "after downloading C1's bundle, the walk should converge"
        );
        assert!(
            walked.contains(&parse_hex_commit(&shas[0])),
            "C1 should now be walked"
        );
    }

    #[test]
    fn walk_unresolved_parents_returns_empty_for_complete_history() {
        // All commits are local -> walk produces no unresolved.
        let dir = tempfile::tempdir().unwrap();
        let shas = build_linear_history(dir.path(), 3).unwrap();
        let git_dir = dir.path().join(".git");

        let mut walked = std::collections::HashSet::new();
        let wanted: std::collections::HashSet<_> =
            std::iter::once(parse_hex_commit(&shas[2])).collect();
        let unresolved = walk_unresolved_parents(&git_dir, &wanted, &mut walked).unwrap();
        assert!(
            unresolved.is_empty(),
            "complete history should have no unresolved commits, got: {unresolved:?}"
        );
        // We should have visited every commit in the chain.
        assert_eq!(walked.len(), 3);
    }

    #[test]
    fn walk_unresolved_parents_walks_through_annotated_tag_of_commit() {
        // Pin the round-4 push-back: an annotated tag pointing at a
        // commit must NOT take the `any_object_exists` short-circuit
        // because `commit_exists` peels through tag->commit via
        // `<tag>^{commit}` and returns true. The walk then enumerates
        // the underlying commit's parents via `git rev-list --parents
        // -n 1 <tag>` which also peels.
        let dir = tempfile::tempdir().unwrap();
        let shas = build_linear_history(dir.path(), 2).unwrap();
        // shas[0] is root, shas[1] is its child.
        // Create an annotated tag pointing at shas[1] (the child commit).
        std::process::Command::new("git")
            .current_dir(dir.path())
            .args(["tag", "-a", "v1", "-m", "annotated", &shas[1]])
            .status()
            .unwrap();
        let tag_sha_hex = String::from_utf8(
            std::process::Command::new("git")
                .current_dir(dir.path())
                .args(["rev-parse", "v1"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        let tag_sha: CommitHash = parse_hex_commit(&tag_sha_hex);
        let git_dir = dir.path().join(".git");

        // commit_exists must succeed (peels through to the commit).
        assert!(
            commit_exists(&git_dir, &tag_sha_hex).unwrap(),
            "tag-of-commit must satisfy commit_exists (rev-parse peels)"
        );

        // Walk should visit the underlying commit's parents -- ie. the
        // root commit shas[0] -- and end up with both the tag SHA and
        // the root commit in `walked` (no unresolved).
        let mut walked = std::collections::HashSet::new();
        let wanted: std::collections::HashSet<_> = std::iter::once(tag_sha).collect();
        let unresolved = walk_unresolved_parents(&git_dir, &wanted, &mut walked).unwrap();
        assert!(unresolved.is_empty(), "tag-of-commit's history is local");
        assert!(walked.contains(&tag_sha), "tag SHA must be walked");
        assert!(
            walked.contains(&parse_hex_commit(&shas[0])),
            "underlying commit's parent (root) must also be walked"
        );
    }

    #[test]
    fn walk_unresolved_parents_treats_tag_of_tree_as_resolved() {
        // Regression test for Codex P1 (round 3): a ref pointing at a
        // tag-of-tree (or any non-commit object) must NOT be reported
        // as unresolved on every iteration -- once the bundle is
        // downloaded the object IS local, just not a commit. Without
        // the `any_object_exists` fallback, `commit_exists` returns
        // false (can't peel through to a commit) and the outer loop
        // would spin forever re-requesting the same already-downloaded
        // bundle.
        let dir = tempfile::tempdir().unwrap();
        std::process::Command::new("git")
            .current_dir(dir.path())
            .args(["init", "-b", "main", "-q"])
            .status()
            .unwrap();
        for cmd in &[
            ["config", "user.email", "t@e.com"],
            ["config", "user.name", "Tester"],
            ["config", "commit.gpgsign", "false"],
        ] {
            std::process::Command::new("git")
                .current_dir(dir.path())
                .args(cmd)
                .status()
                .unwrap();
        }
        std::fs::write(dir.path().join("a.txt"), "hello\n").unwrap();
        std::process::Command::new("git")
            .current_dir(dir.path())
            .args(["add", "a.txt"])
            .status()
            .unwrap();
        std::process::Command::new("git")
            .current_dir(dir.path())
            .args(["commit", "-q", "-m", "c1"])
            .status()
            .unwrap();
        // Get the tree's SHA; create an annotated tag of the tree.
        let tree_sha = String::from_utf8(
            std::process::Command::new("git")
                .current_dir(dir.path())
                .args(["rev-parse", "HEAD^{tree}"])
                .output()
                .unwrap()
                .stdout,
        )
        .unwrap()
        .trim()
        .to_string();
        // mktag is the lower-level way to create a tag of a non-commit.
        let tag_input = format!(
            "object {tree_sha}\ntype tree\ntag tree-tag\ntagger T <t@e.com> 0 +0000\n\nmsg\n"
        );
        std::fs::write(dir.path().join("tag.txt"), &tag_input).unwrap();
        let tag_out = std::process::Command::new("sh")
            .current_dir(dir.path())
            .arg("-c")
            .arg("git mktag < tag.txt")
            .output()
            .unwrap();
        assert!(
            tag_out.status.success(),
            "mktag failed: {}",
            String::from_utf8_lossy(&tag_out.stderr)
        );
        let tag_sha_hex = String::from_utf8(tag_out.stdout)
            .unwrap()
            .trim()
            .to_string();
        let tag_sha: CommitHash = parse_hex_commit(&tag_sha_hex);

        // commit_exists(tag_sha) should be false (can't peel tree-tag
        // to a commit).
        let git_dir = dir.path().join(".git");
        assert!(
            !commit_exists(&git_dir, &tag_sha_hex).unwrap(),
            "tag-of-tree must not satisfy commit_exists"
        );
        // any_object_exists should be true.
        assert!(
            any_object_exists(&git_dir, &tag_sha_hex).unwrap(),
            "tag-of-tree object IS local"
        );

        // Walk should treat the tag-of-tree as resolved (mark walked,
        // return empty unresolved).
        let mut walked = std::collections::HashSet::new();
        let wanted: std::collections::HashSet<_> = std::iter::once(tag_sha).collect();
        let unresolved = walk_unresolved_parents(&git_dir, &wanted, &mut walked).unwrap();
        assert!(
            unresolved.is_empty(),
            "tag-of-tree must NOT be returned as unresolved -- it's local, just not a commit"
        );
        assert!(walked.contains(&tag_sha), "tag-of-tree must be in walked");
    }

    #[test]
    fn hex_encode_commit_round_trips_through_parse() {
        let original: CommitHash = [
            0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
            0x0e, 0x0f, 0xfe, 0xed, 0xfa, 0xce,
        ];
        let hex = hex_encode_commit(&original);
        assert_eq!(hex.len(), 40);
        assert_eq!(hex, "000102030405060708090a0b0c0d0e0ffeedface");
        // Round-trip via the parse path used by `git_commit_parents`.
        assert_eq!(parse_hex_commit(&hex), original);
    }

    #[test]
    fn is_already_up_to_date_first_push_is_not_uptodate() {
        // No prior remote tip -> we genuinely have something to push.
        assert!(!is_already_up_to_date(
            None,
            "0123456789abcdef0123456789abcdef01234567"
        ));
    }

    #[test]
    fn is_already_up_to_date_matching_sha_is_uptodate() {
        // Snapshot mode with deterministic dates produces the same
        // SHA across runs against unchanged source; this is the path
        // we want to short-circuit.
        let sha = "0123456789abcdef0123456789abcdef01234567";
        assert!(is_already_up_to_date(Some(sha), sha));
    }

    #[test]
    fn is_already_up_to_date_different_sha_is_not_uptodate() {
        // Source moved -> remote target differs from local. Must
        // proceed with the push.
        assert!(!is_already_up_to_date(
            Some("0123456789abcdef0123456789abcdef01234567"),
            "fedcba9876543210fedcba9876543210fedcba98"
        ));
    }

    #[test]
    fn is_already_up_to_date_case_sensitive_no_uppercase_drift() {
        // Both producers (`hex::encode` and `git rev-parse`) emit
        // lowercase. If a future change introduces uppercase on one
        // side, the comparison would silently miss the short-circuit
        // and we'd waste a contract write -- not a correctness bug
        // but a perf regression. Pin the lowercase contract.
        let lower = "0123456789abcdef0123456789abcdef01234567";
        let upper = "0123456789ABCDEF0123456789ABCDEF01234567";
        assert!(!is_already_up_to_date(Some(lower), upper));
        assert!(!is_already_up_to_date(Some(upper), lower));
    }

    #[test]
    fn parse_push_spec_force_flag() {
        let (force, src, dst) = parse_push_spec("+main:main").unwrap();
        assert!(force, "leading + means force");
        assert_eq!(src, "main");
        assert_eq!(dst, "main");

        let (force, src, dst) = parse_push_spec("main:main").unwrap();
        assert!(!force, "no + means non-force");
        assert_eq!(src, "main");
        assert_eq!(dst, "main");

        let (force, src, dst) = parse_push_spec("+refs/heads/main:refs/heads/main").unwrap();
        assert!(force);
        assert_eq!(src, "refs/heads/main");
        assert_eq!(dst, "refs/heads/main");
    }

    /// Initialize a fresh git repo in `dir` with a single commit and
    /// return its SHA. Used by build_pack tests to have a real
    /// reachable object on the `want` side without needing the network.
    ///
    /// `commit.gpgsign=false` and `tag.gpgsign=false` are forced
    /// per-invocation so a developer with global GPG signing on
    /// doesn't trip a passphrase prompt in the test.
    ///
    /// Tests assume `git` is on PATH. GitHub Actions Linux/macOS/Windows
    /// runners all have it preinstalled.
    fn init_repo_with_commit(dir: &std::path::Path) -> Result<String> {
        commit_in(dir, "init", "a.txt", "hello\n", &[])
    }

    /// Add a commit on top of the current HEAD with the given file
    /// contents, returning the new SHA. `parents` is left empty for
    /// `init_repo_with_commit`'s first commit.
    fn commit_in(
        dir: &std::path::Path,
        message: &str,
        file: &str,
        contents: &str,
        _parents: &[&str],
    ) -> Result<String> {
        let run = |args: &[&str]| -> Result<()> {
            let status = Command::new("git").current_dir(dir).args(args).status()?;
            if !status.success() {
                bail!("git {} failed: {status}", args.join(" "));
            }
            Ok(())
        };
        if !dir.join(".git").exists() {
            run(&["init", "-b", "main", "-q"])?;
            run(&["config", "user.email", "t@e.com"])?;
            run(&["config", "user.name", "Tester"])?;
            run(&["config", "commit.gpgsign", "false"])?;
            run(&["config", "tag.gpgsign", "false"])?;
        }
        std::fs::write(dir.join(file), contents)?;
        run(&["add", file])?;
        run(&["commit", "-q", "-m", message])?;
        let out = Command::new("git")
            .current_dir(dir)
            .args(["rev-parse", "HEAD"])
            .output()?;
        Ok(String::from_utf8(out.stdout)?.trim().to_string())
    }

    #[test]
    fn build_pack_no_have_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let sha = init_repo_with_commit(dir.path()).unwrap();
        let git_dir = dir.path().join(".git");
        let pack = build_pack(&git_dir, None, &sha, false).unwrap();
        assert!(
            !pack.is_empty(),
            "empty have should produce a non-empty pack"
        );
    }

    #[test]
    fn build_pack_have_equal_to_want_emits_empty_pack() {
        // `have == want` means git rev-list emits zero objects. The
        // pack pack-objects produces is structural-only (a pack
        // header + empty body). It should be much smaller than a
        // pack containing real objects.
        let dir = tempfile::tempdir().unwrap();
        let sha = init_repo_with_commit(dir.path()).unwrap();
        let git_dir = dir.path().join(".git");
        let pack = build_pack(&git_dir, Some(&sha), &sha, false).unwrap();
        let no_have = build_pack(&git_dir, None, &sha, false).unwrap();
        assert!(
            pack.len() < no_have.len(),
            "have==want pack ({} B) should be smaller than full pack ({} B)",
            pack.len(),
            no_have.len()
        );
    }

    #[test]
    fn build_pack_fast_forward_have_is_real_ancestor() {
        // The production happy path: `have` is the parent commit,
        // `want` is the child. Pack should contain only the child's
        // new objects, not the parent's.
        let dir = tempfile::tempdir().unwrap();
        let parent = init_repo_with_commit(dir.path()).unwrap();
        let child = commit_in(dir.path(), "second", "b.txt", "world\n", &[&parent]).unwrap();
        let git_dir = dir.path().join(".git");

        let incremental = build_pack(&git_dir, Some(&parent), &child, false).unwrap();
        let full = build_pack(&git_dir, None, &child, false).unwrap();

        assert!(
            !incremental.is_empty(),
            "fast-forward pack should contain the new commit + tree + blob"
        );
        assert!(
            incremental.len() < full.len(),
            "fast-forward pack ({} B) should be smaller than full pack ({} B) \
             since the parent commit's objects are excluded",
            incremental.len(),
            full.len()
        );
    }

    #[test]
    fn build_pack_missing_have_non_force_fails_with_directed_error() {
        let dir = tempfile::tempdir().unwrap();
        let sha = init_repo_with_commit(dir.path()).unwrap();
        let git_dir = dir.path().join(".git");
        // 40-char hex that is definitely not in the new repo.
        let bogus = "0123456789abcdef0123456789abcdef01234567";
        let err = build_pack(&git_dir, Some(bogus), &sha, false).unwrap_err();
        let msg = format!("{err:#}");
        // Pin the user-visible payload of the directed error message.
        // Future cleanups must keep the actionable bits (the SHA, the
        // git fetch hint, the --force hint) so users can recover
        // without having to read the source.
        assert!(
            msg.contains("not present") && msg.contains("local repo"),
            "expected 'not present' and 'local repo'; got: {msg}"
        );
        assert!(
            msg.contains("git fetch"),
            "expected 'git fetch' hint; got: {msg}"
        );
        assert!(
            msg.contains("--force"),
            "expected '--force' hint; got: {msg}"
        );
        assert!(
            msg.contains(bogus),
            "expected the SHA in the error; got: {msg}"
        );
    }

    #[test]
    fn build_pack_missing_have_force_drops_have_and_succeeds() {
        let dir = tempfile::tempdir().unwrap();
        let sha = init_repo_with_commit(dir.path()).unwrap();
        let git_dir = dir.path().join(".git");
        let bogus = "0123456789abcdef0123456789abcdef01234567";
        // Force=true should make build_pack treat the missing have as
        // a request to send everything reachable from `want`.
        let pack = build_pack(&git_dir, Some(bogus), &sha, true).unwrap();
        assert!(
            !pack.is_empty(),
            "force-push of a fresh repo should produce a non-empty pack"
        );
    }

    #[test]
    fn commit_exists_distinguishes_commit_from_bogus() {
        let dir = tempfile::tempdir().unwrap();
        let sha = init_repo_with_commit(dir.path()).unwrap();
        let git_dir = dir.path().join(".git");
        assert!(commit_exists(&git_dir, &sha).unwrap());
        let bogus = "0123456789abcdef0123456789abcdef01234567";
        assert!(!commit_exists(&git_dir, bogus).unwrap());
    }

    /// Helper: create a lightweight tag on the given commit.
    fn lightweight_tag(dir: &std::path::Path, name: &str, target: &str) -> Result<()> {
        let status = Command::new("git")
            .current_dir(dir)
            .args(["tag", name, target])
            .status()?;
        if !status.success() {
            bail!("git tag {name} {target} failed: {status}");
        }
        Ok(())
    }

    /// Helper: create an annotated tag on the given commit. Returns
    /// the tag object's SHA (distinct from the commit SHA).
    fn annotated_tag(dir: &std::path::Path, name: &str, target: &str) -> Result<String> {
        let status = Command::new("git")
            .current_dir(dir)
            .args([
                "tag",
                "-a",
                name,
                "-m",
                &format!("annotated {name}"),
                target,
            ])
            .status()?;
        if !status.success() {
            bail!("git tag -a {name} {target} failed: {status}");
        }
        let out = Command::new("git")
            .current_dir(dir)
            .args(["rev-parse", &format!("refs/tags/{name}")])
            .output()?;
        Ok(String::from_utf8(out.stdout)?.trim().to_string())
    }

    #[test]
    fn git_resolve_ref_returns_commit_sha_for_lightweight_tag() {
        // Lightweight tag is just a ref pointing at a commit -- no
        // separate tag object. `git rev-parse refs/tags/<name>`
        // returns the commit SHA directly.
        let dir = tempfile::tempdir().unwrap();
        let commit = init_repo_with_commit(dir.path()).unwrap();
        lightweight_tag(dir.path(), "v0.1.0", &commit).unwrap();
        let git_dir = dir.path().join(".git");
        let resolved = git_resolve_ref(&git_dir, "refs/tags/v0.1.0").unwrap();
        assert_eq!(
            resolved, commit,
            "lightweight tag resolves to the commit SHA"
        );
    }

    #[test]
    fn git_resolve_ref_returns_tag_object_sha_for_annotated_tag() {
        // Annotated tag has its own object in the database; rev-parse
        // returns the tag object's SHA, NOT the commit's. The bundle
        // built from this SHA must include both the tag object and
        // the commit it points at (verified separately by build_pack).
        let dir = tempfile::tempdir().unwrap();
        let commit = init_repo_with_commit(dir.path()).unwrap();
        let tag_sha = annotated_tag(dir.path(), "v0.1.0", &commit).unwrap();
        assert_ne!(tag_sha, commit, "annotated tag SHA differs from commit SHA");
        let git_dir = dir.path().join(".git");
        let resolved = git_resolve_ref(&git_dir, "refs/tags/v0.1.0").unwrap();
        assert_eq!(
            resolved, tag_sha,
            "annotated tag resolves to the tag-object SHA, not the commit"
        );
    }

    #[test]
    fn build_pack_includes_annotated_tag_object_and_target_commit() {
        // Critical correctness check for freenet-git#40: when the
        // push refspec is `refs/tags/v0.1.0:refs/tags/v0.1.0` and
        // the tag is annotated, the pack MUST include BOTH the tag
        // object AND the commit it points at, so the receiver can
        // dereference the ref. Without the commit the bundle would
        // land on the contract pointing at an object whose target
        // the receiver can't resolve.
        //
        // We verify by feeding the pack to `git index-pack -v` and
        // asserting BOTH SHAs appear in its enumeration. This is
        // stronger than just "pack is larger than commit-only" —
        // that weaker assertion would pass if pack-objects emitted
        // just the tag header without the underlying commit.
        let dir = tempfile::tempdir().unwrap();
        let commit = init_repo_with_commit(dir.path()).unwrap();
        let tag_sha = annotated_tag(dir.path(), "v0.1.0", &commit).unwrap();
        assert_ne!(
            tag_sha, commit,
            "test sanity: tag SHA must differ from commit SHA"
        );
        let git_dir = dir.path().join(".git");

        let pack_via_tag = build_pack(&git_dir, None, &tag_sha, false).unwrap();

        // Parse pack via `git index-pack --stdin -v`. The `-v`
        // output is enumerated SHAs, one per line, with type/size
        // metadata. Init a fresh empty repo to host the index so
        // we don't accidentally read from the source repo's
        // object DB.
        let dst_repo = tempfile::tempdir().unwrap();
        let dst_git_dir = dst_repo.path().join(".git");
        let init_status = Command::new("git")
            .arg("--git-dir")
            .arg(&dst_git_dir)
            .args(["init", "--bare", "-q"])
            .status()
            .unwrap();
        assert!(init_status.success(), "git init --bare failed");

        let mut child = Command::new("git")
            .arg("--git-dir")
            .arg(&dst_git_dir)
            .args(["index-pack", "--stdin", "-v"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        std::io::Write::write_all(&mut child.stdin.take().unwrap(), &pack_via_tag).unwrap();
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "git index-pack failed: stdout={}, stderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        );
        // index-pack prints object stats on stderr; the resulting
        // .idx lives in the bare repo. Inspect with `git verify-pack`
        // to enumerate every SHA in the pack.
        let idx_files: Vec<_> = std::fs::read_dir(dst_git_dir.join("objects").join("pack"))
            .unwrap()
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|s| s.to_str()) == Some("idx"))
            .collect();
        assert_eq!(idx_files.len(), 1, "expected exactly one .idx file");

        let verify = Command::new("git")
            .arg("--git-dir")
            .arg(&dst_git_dir)
            .args(["verify-pack", "-v"])
            .arg(&idx_files[0])
            .output()
            .unwrap();
        assert!(verify.status.success(), "git verify-pack failed");
        let listing = String::from_utf8_lossy(&verify.stdout);
        assert!(
            listing.contains(&tag_sha),
            "annotated tag object SHA {tag_sha} must appear in pack listing:\n{listing}"
        );
        assert!(
            listing.contains(&commit),
            "underlying commit SHA {commit} must appear in pack listing \
             (regression guard: pack-objects must peel tag→commit):\n{listing}"
        );
    }

    #[test]
    fn build_pack_lightweight_tag_equals_pack_from_commit() {
        // Lightweight tag has no tag object; pushing the tag ref
        // produces the same pack as pushing the commit directly.
        let dir = tempfile::tempdir().unwrap();
        let commit = init_repo_with_commit(dir.path()).unwrap();
        lightweight_tag(dir.path(), "v0.1.0", &commit).unwrap();
        let git_dir = dir.path().join(".git");
        let tag_sha = git_resolve_ref(&git_dir, "refs/tags/v0.1.0").unwrap();
        // (already proven by git_resolve_ref_returns_commit_sha_for_lightweight_tag,
        // but worth restating in this test's context)
        assert_eq!(tag_sha, commit);
        let pack_via_tag = build_pack(&git_dir, None, &tag_sha, false).unwrap();
        let pack_via_commit = build_pack(&git_dir, None, &commit, false).unwrap();
        assert_eq!(
            pack_via_tag.len(),
            pack_via_commit.len(),
            "lightweight tag pack should match commit pack byte-for-byte size"
        );
    }

    #[test]
    fn commit_exists_rejects_blob_and_tree() {
        // Edge case from the skeptical reviewer: if a SHA exists in
        // the object store but is a blob or tree rather than a commit
        // (corrupt repo or partial fetch), passing it as `^<have>` to
        // rev-list would fail with `fatal: not a commit object` --
        // back to the cryptic error this PR aims to eliminate.
        // commit_exists must treat non-commits as "not present" so
        // the directed-error path fires.
        let dir = tempfile::tempdir().unwrap();
        let _commit_sha = init_repo_with_commit(dir.path()).unwrap();
        let git_dir = dir.path().join(".git");

        // Get the SHA of the file blob (tracked file written by
        // init_repo_with_commit).
        let blob_out = Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["rev-parse", "HEAD:a.txt"])
            .output()
            .unwrap();
        let blob_sha = String::from_utf8(blob_out.stdout)
            .unwrap()
            .trim()
            .to_string();
        assert!(!blob_sha.is_empty(), "expected a blob sha");
        assert!(
            !commit_exists(&git_dir, &blob_sha).unwrap(),
            "a blob SHA must NOT count as a commit"
        );

        // Same for the root tree.
        let tree_out = Command::new("git")
            .arg("--git-dir")
            .arg(&git_dir)
            .args(["rev-parse", "HEAD^{tree}"])
            .output()
            .unwrap();
        let tree_sha = String::from_utf8(tree_out.stdout)
            .unwrap()
            .trim()
            .to_string();
        assert!(
            !commit_exists(&git_dir, &tree_sha).unwrap(),
            "a tree SHA must NOT count as a commit"
        );
    }
}
