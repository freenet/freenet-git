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
//! - Fetch downloads every pack referenced in `object_index`. No
//!   per-object reachability shortcut yet.
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
use freenet_git_types::signing::{sign_bundle_record, sign_ref_entry};
use freenet_git_types::{update_state as ts_update_state, CommitHash, ObjectBundle, RepoState};
use freenet_stdlib::prelude::ContractInstanceId;

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
    use freenet_git_cli::wsclient::{GetSource, LegacyAwareGet};

    let params = freenet_git_types::RepoParams {
        prefix: env.prefix.clone(),
    };
    let params_bytes = params.to_bytes();
    let legacy_hashes: Vec<&[u8; 32]> = freenet_git_cli::legacy::LEGACY_REPO_CONTRACT_WASM_HASHES
        .iter()
        .map(|(h, _)| *h)
        .collect();

    let LegacyAwareGet { state, source } = wsclient::get_state_with_legacy_fallback(
        api,
        env.contract_id,
        &params_bytes,
        &legacy_hashes,
        ws_timeout(),
    )
    .await?;

    if let GetSource::Legacy { index, instance } = source {
        let (_, desc) = freenet_git_cli::legacy::LEGACY_REPO_CONTRACT_WASM_HASHES[index];
        eprintln!(
            "info: state found at legacy contract {instance} ({desc}); migrating to current key",
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

        let total_bundles = state.object_index.len();
        let total_size: u64 = state.object_index.values().map(bundle_size).sum();
        eprintln!(
            "==> {total_bundles} bundle(s), {} total (~60s per chunk under load; up to {} in parallel)",
            human_bytes(total_size),
            freenet_git_cli::chunked::parallelism_from_env(),
        );

        for (i, record) in state.object_index.values().enumerate() {
            let n = i + 1;
            let pack_bytes = match &record.bundle {
                ObjectBundle::SinglePack {
                    pack_hash,
                    size_bytes,
                } => {
                    eprintln!(
                        "    [{n}/{total_bundles}] downloading pack ({})",
                        human_bytes(*size_bytes),
                    );
                    wsclient::get_pack(&mut api, &pack_wasm, *pack_hash, ws_timeout()).await?
                }
                ObjectBundle::ChunkedPack {
                    manifest_hash,
                    total_size,
                    chunk_count,
                } => {
                    eprintln!(
                        "    [{n}/{total_bundles}] downloading {chunk_count} chunks ({})",
                        human_bytes(*total_size),
                    );
                    let bytes = freenet_git_cli::chunked::fetch_chunked_pack_with_progress(
                        &env.ws_url,
                        &pack_wasm,
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
                    bytes
                }
            };
            install_pack(&env.git_dir, &pack_bytes)?;
        }

        let _ = wants;
        eprintln!("==> done");
        Ok::<_, anyhow::Error>(())
    })?;

    // Empty line: success.
    writeln!(out)?;
    out.flush()?;
    Ok(())
}

fn bundle_size(record: &freenet_git_types::ObjectBundleRecord) -> u64 {
    match &record.bundle {
        ObjectBundle::SinglePack { size_bytes, .. } => *size_bytes,
        ObjectBundle::ChunkedPack { total_size, .. } => *total_size,
    }
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
                "no entry for prefix {} in identity bundle registry — was this \
                 repo created with this identity?",
                env.prefix,
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

            // Idempotent short-circuit: if the new local commit
            // equals the existing remote tip, there's nothing to
            // send. Defensive layer -- git itself already short-
            // circuits a push of unchanged refs ("Everything
            // up-to-date") before reaching the helper's `push`
            // command, so this branch typically never fires under
            // normal `git push` flows. It guards against:
            // 1. Hand-crafted helper drivers that bypass git's
            //    own up-to-date check.
            // 2. Future changes to git's protocol where the client
            //    no longer pre-walks remote refs.
            // 3. A subtle bug where git's `list` parsing differs
            //    from ours.
            // Combined with H3's deterministic snapshot dates, this
            // makes daily safety-net cron runs against unchanged
            // source genuinely no-op end-to-end -- no contract
            // write, no `update_seq` bump.
            if prev.as_deref() == Some(new_target.as_str()) {
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
            let new_seq = state.refs.get(&dst).map(|e| e.update_seq).unwrap_or(0) + 1;
            let target_arr: CommitHash = parse_sha1(&new_target)?;
            let entry = sign_ref_entry(&params, &signing, &dst, target_arr, new_seq, 0);
            delta.refs.insert(dst.clone(), entry);
            ok_lines.push(format!("ok {dst}"));
        }

        if delta.object_index.is_empty() && delta.refs.is_empty() {
            return Ok::<_, anyhow::Error>((ok_lines, error_lines));
        }

        // Local sanity: validate the merged state would pass before
        // committing it to the network.
        let merged = ts_update_state(&params, &state, &delta)
            .map_err(|e| anyhow!("local update_state rejected our delta: {e}"))?;
        let _ = merged;

        // UPDATE the repo contract with the signed delta.
        eprintln!("==> updating repo state on Freenet");
        wsclient::update_state(
            &mut api,
            env.contract_id,
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

    let mut child = Command::new("git")
        .arg("--git-dir")
        .arg(git_dir)
        .args(["pack-objects", "--stdout"])
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
mod tests {
    use super::*;

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
