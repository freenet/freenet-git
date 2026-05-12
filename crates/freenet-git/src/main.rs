//! `freenet-git` companion CLI. Phase 1.0 commands:
//!
//! - `init-identity` / `whoami` / `export-identity` / `import-identity`
//!   — work today (offline; just bundle management).
//! - `create` — derives the repo contract id locally, builds the initial
//!   signed state, and prints the URL. Network publish is gated on the
//!   `--publish-to <ws-url>` flag (TODO: implement WS API call).
//! - `info` — prints the contents of a repo's signed state (TODO: needs
//!   WS API GET).
//! - `subscribe`, `subscriptions`, `status`, `rename`, `rescue` — coming
//!   in follow-up commits once the WS API plumbing lands.

#![deny(unsafe_code)]

use std::path::PathBuf;
use std::process::ExitCode;

use std::time::Duration;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use freenet_git_cli::ids::repo_contract_id_from_prefix;
use freenet_git_cli::state_init::initial_repo_state;
use freenet_git_cli::url;
use freenet_git_cli::wsclient::{self, DEFAULT_WS_URL};
use freenet_git_identity::{
    self as identity, default_bundle_path, write_bundle, DecryptedBundle, RepoRegistryEntry,
};
use freenet_git_types::{limits, pubkey_prefix, RepoParams};
use rand::rngs::OsRng;

#[derive(Debug, Parser)]
#[command(
    name = "freenet-git",
    version,
    about = "Companion CLI for hosting and consuming git repositories on Freenet"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,

    /// Path to the identity bundle. Defaults to
    /// `$XDG_CONFIG_HOME/freenet/git-identity.bundle` (or `~/.config/...`).
    #[arg(long, env = "FREENET_GIT_IDENTITY", global = true)]
    identity_path: Option<PathBuf>,
}

#[derive(Debug, Subcommand)]
enum Cmd {
    /// Generate a fresh ed25519 identity and write it to a passphrase-
    /// encrypted bundle on disk.
    InitIdentity {
        /// Display name to embed in the bundle.
        #[arg(long)]
        name: String,
        /// Email to embed in the bundle.
        #[arg(long)]
        email: String,
        /// Skip passphrase encryption. The bundle file becomes recoverable
        /// by anyone who can read it. Use only when the file itself lives
        /// in an authenticated secret store (CI secrets, OS keychain,
        /// encrypted volume) — the on-disk encryption layer is then
        /// redundant.
        #[arg(long)]
        no_passphrase: bool,
    },
    /// Print the identity stored in the bundle.
    Whoami,
    /// Re-encrypt the bundle to the given output path. Useful for moving
    /// the identity to a new machine.
    ExportIdentity {
        /// Path to write the exported bundle.
        out: PathBuf,
        /// Write the exported bundle without passphrase encryption. See
        /// the equivalent flag on `init-identity` for when this is safe.
        #[arg(long)]
        no_passphrase: bool,
    },
    /// Replace the local bundle with the one at `from` (decrypted with the
    /// supplied passphrase, re-encrypted in place).
    ImportIdentity {
        /// Path to read the source bundle.
        from: PathBuf,
        /// Write the new local bundle without passphrase encryption. See
        /// the equivalent flag on `init-identity` for when this is safe.
        #[arg(long)]
        no_passphrase: bool,
    },
    /// Derive the contract URL for a brand-new repo, build its initial
    /// signed state, and publish it to a local Freenet node.
    Create {
        /// Display name for the repo.
        #[arg(long)]
        name: String,
        /// Description.
        #[arg(long, default_value = "")]
        description: String,
        /// Default branch.
        #[arg(long, default_value = "refs/heads/main")]
        default_branch: String,
        /// Override the bundled repo-contract WASM. Normally you do not
        /// need this — `cargo install freenet-git` ships the right bytes.
        /// Useful when iterating on the contract from source.
        #[arg(long)]
        repo_wasm: Option<PathBuf>,
        /// WebSocket URL of a local Freenet node. Defaults to the
        /// stdlib's standard endpoint
        /// (`ws://127.0.0.1:7509/v1/contract/command?encodingProtocol=native`).
        /// Pass `--no-publish` to skip the network call and just print
        /// the would-be URL.
        #[arg(long)]
        publish_to: Option<String>,
        /// Skip the network PUT entirely. Useful for `--dry-run`-style
        /// previews or for hand-off to `fdev publish`.
        #[arg(long, conflicts_with = "publish_to")]
        no_publish: bool,
        /// Override the default 180-second confirmation timeout. First-PUT
        /// under network load can take ~60s for the local node to forward
        /// to subscribing peers and collect confirmation; 180s gives 3x
        /// headroom.
        #[arg(long, default_value = "180")]
        publish_timeout_secs: u64,
    },
    /// Re-PUT every bundle a repo references, refreshing the network's
    /// hot copy. Use when chunks have been evicted from the wider
    /// network (`exhausted all peers` errors during clone).
    ///
    /// MVP behaviour: connects to the local Freenet node, GETs each
    /// bundle (and chunks) via the local node's cache or the network,
    /// then PUTs each one back. This re-broadcasts to whichever peers
    /// subscribe to each contract's location and bumps the bytes back
    /// to the top of their LRU cache.
    ///
    /// Future versions will reconstruct missing bytes from a local
    /// clone (`--from <path>`) when the local node's cache no longer
    /// has them either.
    Rescue {
        /// Repo URL, e.g. `freenet:RtTzy58hMxAB/my-project`.
        url: String,
        /// WebSocket URL of a local Freenet node. Defaults to the
        /// standard local endpoint.
        #[arg(long)]
        ws_url: Option<String>,
        /// Override the default 180-second per-operation timeout.
        #[arg(long, default_value = "180")]
        timeout_secs: u64,
        /// Only rescue bundles whose `bundle-tip:<id>` extension
        /// points at a commit that is currently in some `refs/*`
        /// entry of the repo state.
        ///
        /// **Use this for snapshot-mode mirrors only.** Snapshot
        /// mirrors force-push a fresh orphan commit on every run, so
        /// older bundles in `object_index` are dead-weight from
        /// rescue's perspective — no current ref points at their tip
        /// and the network can't serve a clone from them. Skipping
        /// them drops freenet-core's rescue from 15+ bundles to 1.
        ///
        /// **Do NOT use this for history-mode mirrors.** In history
        /// mode every bundle's tip is a real commit in the parent
        /// chain. Only the most recent push's bundle has a tip that
        /// equals a current ref value; older bundles' tips are
        /// ancestor commits, no longer in `refs.values()`. This flag
        /// would incorrectly skip them and the network would lose
        /// cache pressure on the bulk of the history.
        ///
        /// See freenet/freenet-git#41 for the rescue-time-budget
        /// motivation. Default `false` keeps existing behaviour
        /// (rescue everything).
        #[arg(long)]
        only_current_tips: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    init_tracing();

    match run(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("error: {e:?}");
            ExitCode::FAILURE
        }
    }
}

fn run(cli: Cli) -> Result<()> {
    let bundle_path = cli.identity_path.unwrap_or_else(default_bundle_path);
    match cli.cmd {
        Cmd::InitIdentity {
            name,
            email,
            no_passphrase,
        } => init_identity(&bundle_path, name, email, no_passphrase),
        Cmd::Whoami => whoami(&bundle_path),
        Cmd::ExportIdentity { out, no_passphrase } => {
            export_identity(&bundle_path, &out, no_passphrase)
        }
        Cmd::ImportIdentity {
            from,
            no_passphrase,
        } => import_identity(&bundle_path, &from, no_passphrase),
        Cmd::Create {
            name,
            description,
            default_branch,
            repo_wasm,
            publish_to,
            no_publish,
            publish_timeout_secs,
        } => create_repo(
            &bundle_path,
            &name,
            &description,
            &default_branch,
            repo_wasm.as_deref(),
            publish_to.as_deref(),
            no_publish,
            Duration::from_secs(publish_timeout_secs),
        ),
        Cmd::Rescue {
            url,
            ws_url,
            timeout_secs,
            only_current_tips,
        } => rescue(
            &url,
            ws_url.as_deref(),
            Duration::from_secs(timeout_secs),
            only_current_tips,
        ),
    }
}

fn init_identity(
    path: &std::path::Path,
    name: String,
    email: String,
    no_passphrase: bool,
) -> Result<()> {
    if path.exists() {
        bail!(
            "identity bundle already exists at {} -- refusing to overwrite. \
             Move or delete it first if you really want a new identity.",
            path.display()
        );
    }

    let pw = if no_passphrase {
        String::new()
    } else {
        prompt_passphrase_with_confirm("Passphrase for new identity")?
    };
    let bundle = DecryptedBundle::new(name, email);
    write_bundle(&bundle, &pw, path).with_context(|| format!("write {}", path.display()))?;
    println!("Generated ed25519 keypair.");
    println!("Public key: {}", bundle.id_string());
    println!("Bundle written to: {}", path.display());
    if no_passphrase {
        println!("Bundle is unencrypted at rest -- protect the file accordingly.");
    }
    Ok(())
}

fn whoami(path: &std::path::Path) -> Result<()> {
    let (bundle, passphrase) = open_bundle_remembering_passphrase(path)?;
    println!("{} <{}>", bundle.name, bundle.email);
    println!("{}", bundle.id_string());
    println!(
        "Encryption: {}",
        if passphrase.is_empty() {
            "none (unencrypted at rest)"
        } else {
            "passphrase-protected"
        }
    );
    if !bundle.repos.is_empty() {
        println!();
        println!("Repos in registry:");
        for r in &bundle.repos {
            let label = if r.display_name.is_empty() {
                None
            } else {
                Some(r.display_name.as_str())
            };
            println!("  {}", url::format_with_label(&r.prefix, label));
        }
    }
    Ok(())
}

fn export_identity(
    path: &std::path::Path,
    out: &std::path::Path,
    no_passphrase: bool,
) -> Result<()> {
    let bundle = open_bundle_with_prompt(path)?;
    let pw = if no_passphrase {
        String::new()
    } else {
        prompt_passphrase_with_confirm("Passphrase for exported bundle")?
    };
    // Use write_bundle to get atomic-rename + 0600 permissions on Unix.
    // Plain `std::fs::write` would leave the bundle world-readable
    // depending on the user's umask.
    write_bundle(&bundle, &pw, out)
        .with_context(|| format!("write exported bundle to {}", out.display()))?;
    println!("Wrote bundle to {}", out.display());
    if no_passphrase {
        println!("Exported bundle is unencrypted at rest -- protect the file accordingly.");
    }
    Ok(())
}

fn import_identity(
    local_path: &std::path::Path,
    from: &std::path::Path,
    no_passphrase: bool,
) -> Result<()> {
    let bundle = open_bundle_with_prompt(from)
        .with_context(|| format!("read source bundle at {}", from.display()))?;
    if local_path.exists() {
        bail!(
            "local identity bundle already exists at {} -- refusing to overwrite",
            local_path.display()
        );
    }
    let pw_out = if no_passphrase {
        String::new()
    } else {
        prompt_passphrase_with_confirm("Passphrase for new local bundle")?
    };
    write_bundle(&bundle, &pw_out, local_path)?;
    println!(
        "Imported identity {} into {}",
        bundle.id_string(),
        local_path.display()
    );
    if no_passphrase {
        println!("Local bundle is unencrypted at rest.");
    }
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn create_repo(
    bundle_path: &std::path::Path,
    name: &str,
    description: &str,
    default_branch: &str,
    repo_wasm_path: Option<&std::path::Path>,
    publish_to: Option<&str>,
    no_publish: bool,
    publish_timeout: Duration,
) -> Result<()> {
    let (bundle, bundle_passphrase) = open_bundle_remembering_passphrase(bundle_path)?;

    let repo_wasm: Vec<u8> = match repo_wasm_path {
        Some(path) => std::fs::read(path)
            .with_context(|| format!("read repo-contract wasm from {}", path.display()))?,
        None => freenet_git_cli::REPO_CONTRACT_WASM.to_vec(),
    };

    // Generate a fresh per-repo keypair. The URL prefix is derived
    // from this key, so a fresh repo means a fresh keypair (this is
    // the delta site model).
    let repo_signing = SigningKey::generate(&mut OsRng);
    let repo_owner = repo_signing.verifying_key().to_bytes();
    let prefix = pubkey_prefix(&repo_owner, limits::DEFAULT_PREFIX_LEN);
    let params = RepoParams {
        prefix: prefix.clone(),
    };
    let initial_state =
        initial_repo_state(&params, &repo_signing, name, description, default_branch);

    let contract_id = repo_contract_id_from_prefix(&repo_wasm, &prefix);
    // Use the repo name as the URL label so `git clone` produces a
    // human-friendly directory name. The label is purely cosmetic; the
    // prefix is the only authoritative identifier.
    let label = if name.is_empty() { None } else { Some(name) };
    let repo_url = url::format_with_label(&prefix, label);
    let git_url = url::format_git_url_with_label(&prefix, label);
    println!("Repo prepared:");
    println!("  Name:        {name}");
    println!("  Description: {description}");
    println!("  Default ref: {default_branch}");
    println!("  Identity:    {} (this user)", bundle.id_string());
    println!("  Owner:       {} (this repo)", repo_id_string(&repo_owner));
    println!("  URL:         {repo_url}");
    println!("  git URL:     {git_url}");
    println!("  Contract id: {contract_id}");
    println!();
    println!(
        "Initial signed state size: {} bytes",
        initial_state.to_bytes().len()
    );

    if no_publish {
        // Hand-off mode: write artefacts for fdev publish.
        let parameters_path = format!("/tmp/freenet-git-params-{prefix}.bin");
        let state_path = format!("/tmp/freenet-git-state-{prefix}.bin");
        std::fs::write(&parameters_path, params.to_bytes())?;
        std::fs::write(&state_path, initial_state.to_bytes())?;
        println!();
        println!("--no-publish: skipped network PUT.");
        println!("  parameters: {parameters_path}");
        println!("  state:      {state_path}");
        println!();
        let repo_wasm_path_str = match repo_wasm_path {
            Some(p) => p.display().to_string(),
            None => "<bundled-repo-contract.wasm>".to_string(),
        };
        println!("To publish manually, e.g. with fdev:");
        println!(
            "  fdev publish --code {repo_wasm_path_str} --parameters {parameters_path} contract --state {state_path}",
        );
        return register_in_bundle(
            bundle,
            &bundle_passphrase,
            bundle_path,
            &repo_signing,
            &prefix,
            name,
        );
    }

    let ws_url = publish_to.unwrap_or(DEFAULT_WS_URL).to_string();
    println!();
    println!("Publishing to {ws_url} ...");

    let key = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?
        .block_on(async {
            let mut api = wsclient::connect(&ws_url).await?;
            wsclient::put_contract(
                &mut api,
                &repo_wasm,
                params.to_bytes(),
                initial_state.to_bytes(),
                publish_timeout,
            )
            .await
        })
        .with_context(|| format!("PUT to {ws_url}"))?;

    println!("PUT confirmed by host. Contract key: {}", key.id());

    register_in_bundle(
        bundle,
        &bundle_passphrase,
        bundle_path,
        &repo_signing,
        &prefix,
        name,
    )
}

fn register_in_bundle(
    bundle: DecryptedBundle,
    passphrase: &str,
    bundle_path: &std::path::Path,
    repo_signing: &SigningKey,
    prefix: &str,
    name: &str,
) -> Result<()> {
    let mut bundle_with_repo = bundle;
    bundle_with_repo.repos.push(RepoRegistryEntry {
        repo_secret: repo_signing.to_bytes().to_vec(),
        repo_public: repo_signing.verifying_key().to_bytes().to_vec(),
        prefix: prefix.to_string(),
        display_name: name.to_string(),
    });
    write_bundle(&bundle_with_repo, passphrase, bundle_path)?;
    println!();
    println!("Registered repo in identity bundle.");
    Ok(())
}

fn repo_id_string(pubkey: &[u8]) -> String {
    format!("freenet:id:{}", bs58::encode(pubkey).into_string())
}

/// Re-PUT every bundle (and chunk) a repo references back to the
/// network, refreshing the hot copy. The local Freenet node serves
/// as the byte source: each bundle is GET'd (which pulls from local
/// cache if hosted, or from the wider network if not), then PUT
/// back, which broadcasts to whichever peers subscribe to that
/// contract's location and bumps the bytes back to the top of their
/// LRU cache.
///
/// When `only_current_tips` is true, bundles whose `bundle-tip:<id>`
/// extension does NOT point at a commit currently in `state.refs.*`
/// are skipped. Intended for snapshot-mode mirrors where each push
/// force-replaces the branch tip with a fresh orphan commit and all
/// previous bundles become dead-weight (no current ref points at
/// their tip, so the network can't serve a clone from them). See the
/// flag's docstring on `Cmd::Rescue` for the constraint on history
/// mode.
fn rescue(
    url_str: &str,
    ws_url: Option<&str>,
    timeout: Duration,
    only_current_tips: bool,
) -> Result<()> {
    let parsed = url::parse(url_str).with_context(|| format!("parse {url_str}"))?;
    let ws = ws_url.unwrap_or(DEFAULT_WS_URL).to_string();
    println!("Rescuing {} via {ws}", url::format(&parsed.prefix));

    let repo_wasm = freenet_git_cli::REPO_CONTRACT_WASM.to_vec();
    let pack_wasm = freenet_git_cli::PACK_CONTRACT_WASM.to_vec();
    let contract_id =
        freenet_git_cli::ids::repo_contract_id_from_prefix(&repo_wasm, &parsed.prefix);

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .context("build tokio runtime")?;

    runtime.block_on(async {
        let mut api = wsclient::connect(&ws).await?;

        // Pull the repo state. legacy_aware_get uses fallback so a
        // post-WASM-bump rescue still finds the predecessor's state.
        let params = freenet_git_types::RepoParams {
            prefix: parsed.prefix.clone(),
        };
        let params_bytes = params.to_bytes();
        let legacy_hashes: Vec<&[u8; 32]> =
            freenet_git_cli::legacy::LEGACY_REPO_CONTRACT_WASM_HASHES
                .iter()
                .map(|(h, _)| *h)
                .collect();
        let result = wsclient::get_state_with_legacy_fallback(
            &mut api,
            contract_id,
            &params_bytes,
            &legacy_hashes,
            timeout,
        )
        .await?;
        let state = freenet_git_types::RepoState::from_bytes(&result.state)?;

        // We deliberately do NOT re-PUT the repo state itself here.
        // Rescue's job is to refresh the *chunks* the network has
        // forgotten. The repo contract has natural subscription
        // pressure from any active reader and tends to stay alive,
        // and re-PUTting it triggers a host-side broadcast cycle
        // that is much slower than refreshing pack contracts. If
        // the legacy-fallback path activated, fetch_repo_state in
        // git-remote-freenet handles the migration re-PUT during
        // a normal fetch.
        let _ = (repo_wasm, params_bytes);

        let mut bundle_count = 0usize;
        let mut chunk_count = 0usize;
        let mut skipped_count = 0usize;
        let mut errors: Vec<String> = Vec::new();

        let reachable = if only_current_tips {
            Some(reachable_bundle_ids(&state))
        } else {
            None
        };

        for (id, record) in &state.object_index {
            if let Some(set) = reachable.as_ref() {
                if !set.contains(id) {
                    skipped_count += 1;
                    continue;
                }
            }
            bundle_count += 1;
            let bundle_label = format!("bundle {}", hex::encode(id));
            match &record.bundle {
                freenet_git_types::ObjectBundle::SinglePack { pack_hash, .. } => {
                    if let Err(e) = rescue_pack(&mut api, &pack_wasm, *pack_hash, timeout).await {
                        errors.push(format!("  {bundle_label} (SinglePack): {e}"));
                    } else {
                        println!("ok {bundle_label} (SinglePack)");
                    }
                }
                freenet_git_types::ObjectBundle::ChunkedPack {
                    manifest_hash,
                    total_size: _,
                    chunk_count: declared_count,
                } => match rescue_chunked(&ws, &pack_wasm, *manifest_hash, timeout).await {
                    Ok(n) => {
                        chunk_count += n;
                        println!("ok {bundle_label} (ChunkedPack, {n}/{declared_count} chunks)",);
                    }
                    Err(e) => errors.push(format!("  {bundle_label} (ChunkedPack): {e}")),
                },
            }
        }

        println!();
        if only_current_tips {
            println!(
                "rescued {} bundle(s), {} chunk(s); skipped {} dead-weight bundle(s); {} failure(s)",
                bundle_count,
                chunk_count,
                skipped_count,
                errors.len()
            );
        } else {
            println!(
                "rescued {} bundle(s), {} chunk(s); {} failure(s)",
                bundle_count,
                chunk_count,
                errors.len()
            );
        }
        for line in &errors {
            eprintln!("{line}");
        }
        if errors.is_empty() {
            Ok::<_, anyhow::Error>(())
        } else {
            Err(anyhow::anyhow!(
                "{} bundle(s) failed to rescue",
                errors.len()
            ))
        }
    })
}

/// Return the subset of bundle IDs in `state.object_index` whose
/// `bundle-tip:<id>` extension points at a commit that is currently
/// in some `state.refs.*` entry.
///
/// Snapshot-mode mirrors emit one bundle per push and force-update
/// the branch ref to that bundle's tip; old bundles still live in
/// `object_index` but no ref points at them anymore, so this set is
/// "current bundle(s) the network must keep serving."
///
/// Bundles without a tip extension (legacy pre-0.1.16 pushes) are
/// considered unreachable here: there is no signal that any ref
/// points at them. Safe for snapshot mode (legacy + current-but-
/// re-pushed bundles are dead-weight); unsafe for history mode where
/// every ancestor bundle is reachable via the commit graph but never
/// equal to a ref value. See `Cmd::Rescue::only_current_tips`'s
/// docstring for the mode constraint.
fn reachable_bundle_ids(
    state: &freenet_git_types::RepoState,
) -> std::collections::HashSet<freenet_git_types::ObjectBundleId> {
    use freenet_git_types::signing::bundle_tip_extension_key;

    let current_tips: std::collections::HashSet<&[u8]> = state
        .refs
        .values()
        .map(|entry| entry.target.as_slice())
        .collect();

    state
        .object_index
        .keys()
        .copied()
        .filter(|id| {
            let key = bundle_tip_extension_key(id);
            let Some(ext) = state.extensions.get(&key) else {
                return false;
            };
            current_tips.contains(ext.value.as_slice())
        })
        .collect()
}

async fn rescue_pack(
    api: &mut freenet_stdlib::client_api::WebApi,
    pack_wasm: &[u8],
    pack_hash: [u8; 32],
    timeout: Duration,
) -> Result<()> {
    let bytes = wsclient::get_pack(api, pack_wasm, pack_hash, timeout)
        .await
        .with_context(|| format!("GET pack {}", hex::encode(pack_hash)))?;
    wsclient::put_pack(api, pack_wasm, bytes, timeout)
        .await
        .with_context(|| format!("PUT pack {}", hex::encode(pack_hash)))?;
    Ok(())
}

/// Rescue a chunked-pack bundle. Each chunk is GET'd then re-PUT;
/// chunks run in parallel across a small pool of WS connections
/// (default 8, override via `FREENET_GIT_PARALLEL_OPS`) so a
/// hundreds-of-chunks rescue is hours instead of overnight.
///
/// A separate one-shot bootstrap connection handles the manifest GET
/// (we need the chunk count to size the pool, and re-using this
/// connection as pool member 0 would require pool-construction API
/// contortion; one extra round-trip per bundle is cheap). The chunk
/// pool then drives the per-chunk GET-then-PUT pairs in parallel,
/// and the manifest re-PUT lands on the first chunk-pool connection
/// at the end. Each chunk task takes exclusive use of one connection
/// for the duration of its GET-then-PUT pair, so the host's
/// per-connection request order is preserved.
async fn rescue_chunked(
    ws_url: &str,
    pack_wasm: &[u8],
    manifest_hash: [u8; 32],
    timeout: Duration,
) -> Result<usize> {
    use futures::stream::StreamExt;
    use std::sync::Arc;
    use tokio::sync::Mutex;

    // Open one connection up front to fetch the manifest. We need the
    // chunk count to pick the pool size, and re-using this connection
    // as the first pool member would require a different pool API; the
    // manifest GET is one round-trip so a separate connection is cheap.
    let mut bootstrap = wsclient::connect(ws_url)
        .await
        .context("connect to local node")?;
    let manifest_bytes = wsclient::get_pack(&mut bootstrap, pack_wasm, manifest_hash, timeout)
        .await
        .with_context(|| format!("GET manifest {}", hex::encode(manifest_hash)))?;
    drop(bootstrap);

    let manifest = freenet_git_types::chunked::ChunkedPackManifestV1::from_bytes(&manifest_bytes)
        .context("decode manifest")?;

    let n = manifest.chunk_count;
    let parallelism = freenet_git_cli::chunked::parallelism_from_env();
    let want = parallelism.min((n as usize).max(1));

    // Open the chunk pool. Same graceful-degradation policy as
    // chunked.rs: if the local node refuses extras we proceed with
    // however many we got.
    let mut pool: Vec<Arc<Mutex<freenet_stdlib::client_api::WebApi>>> = Vec::with_capacity(want);
    for _ in 0..want {
        match wsclient::connect(ws_url).await {
            Ok(c) => pool.push(Arc::new(Mutex::new(c))),
            Err(e) if !pool.is_empty() => {
                tracing::warn!(
                    "opened {}/{} parallel WS connections for rescue; falling back: {e:#}",
                    pool.len(),
                    want,
                );
                break;
            }
            Err(e) => return Err(e).context("open at least one WS connection for rescue"),
        }
    }
    let actual_parallelism = pool.len();

    // Each task GETs then PUTs one chunk on its assigned connection.
    let pack_wasm: Arc<Vec<u8>> = Arc::new(pack_wasm.to_vec());
    let mut stream = futures::stream::iter(manifest.chunk_hashes.iter().copied().enumerate())
        .map(|(i, chunk_hash)| {
            let conn = pool[i % pool.len()].clone();
            let pack_wasm = pack_wasm.clone();
            async move {
                let mut conn = conn.lock().await;
                let bytes = wsclient::get_pack(&mut conn, &pack_wasm, chunk_hash, timeout)
                    .await
                    .with_context(|| {
                        format!("GET chunk {}/{} ({})", i + 1, n, hex::encode(chunk_hash))
                    })?;
                wsclient::put_pack(&mut conn, &pack_wasm, bytes, timeout)
                    .await
                    .with_context(|| format!("PUT chunk {}/{}", i + 1, n))?;
                anyhow::Ok(())
            }
        })
        .buffer_unordered(actual_parallelism);

    let mut rescued = 0usize;
    while let Some(result) = stream.next().await {
        result?;
        rescued += 1;
    }
    drop(stream);

    // Re-PUT the manifest itself on the first connection.
    {
        let mut conn = pool[0].lock().await;
        wsclient::put_pack(&mut conn, &pack_wasm, manifest_bytes, timeout)
            .await
            .context("PUT manifest")?;
    }
    Ok(rescued)
}

fn open_bundle_with_prompt(path: &std::path::Path) -> Result<DecryptedBundle> {
    Ok(open_bundle_remembering_passphrase(path)?.0)
}

/// Read a bundle that may or may not be passphrase-encrypted, prompting
/// only when we actually need a passphrase. Returns the passphrase that
/// was used so the caller can re-seal the bundle later (e.g. after
/// updating the repo registry) without re-prompting.
///
/// Resolution order:
/// 1. If `FREENET_GIT_PASSPHRASE` is set, try it. If it decrypts, use it.
///    Otherwise fall through (the env var may be stale and the bundle
///    actually unencrypted, or vice versa).
/// 2. Try the empty passphrase. Unencrypted bundles open here.
/// 3. Fall back to a TTY prompt for an encrypted bundle.
/// 4. If the env var was set but neither it nor empty decrypted, surface
///    a directed error rather than the generic "decrypt bundle" message.
fn open_bundle_remembering_passphrase(path: &std::path::Path) -> Result<(DecryptedBundle, String)> {
    if !path.exists() {
        bail!(
            "no identity bundle at {} -- run `freenet-git init-identity` first",
            path.display()
        );
    }
    let bytes = std::fs::read(path)?;
    let env_pw = std::env::var("FREENET_GIT_PASSPHRASE").ok();

    if let Some(pw) = &env_pw {
        if let Ok(bundle) = identity::open(&bytes, pw) {
            return Ok((bundle, pw.clone()));
        }
    }

    if let Ok(b) = identity::open(&bytes, "") {
        return Ok((b, String::new()));
    }

    if env_pw.is_some() {
        bail!(
            "FREENET_GIT_PASSPHRASE was set but did not decrypt bundle at {} \
             (and the bundle is not unencrypted either)",
            path.display()
        );
    }

    let pw = rpassword::prompt_password("Passphrase: ")?;
    if pw.is_empty() {
        bail!("empty passphrase");
    }
    let bundle = identity::open(&bytes, &pw)
        .with_context(|| format!("decrypt bundle at {}", path.display()))?;
    Ok((bundle, pw))
}

/// Prompt for a NEW passphrase (with confirmation) when creating or
/// re-encrypting a bundle. Honors `FREENET_GIT_PASSPHRASE` for
/// non-interactive use; an empty value is rejected here because the
/// `--no-passphrase` flag is the explicit way to opt out of encryption.
fn prompt_passphrase_with_confirm(prompt: &str) -> Result<String> {
    if let Ok(pw) = std::env::var("FREENET_GIT_PASSPHRASE") {
        if pw.is_empty() {
            bail!(
                "FREENET_GIT_PASSPHRASE is empty -- pass --no-passphrase \
                 to create an unencrypted bundle"
            );
        }
        return Ok(pw);
    }
    let pw = rpassword::prompt_password(format!("{prompt}: "))?;
    if pw.is_empty() {
        bail!("empty passphrase -- pass --no-passphrase to opt out of encryption");
    }
    let confirm = rpassword::prompt_password("Confirm passphrase: ")?;
    if pw != confirm {
        bail!("passphrases did not match");
    }
    Ok(pw)
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
    use freenet_git_types::signing::sign_bundle_tip_extension;
    use freenet_git_types::{
        ObjectBundle, ObjectBundleId, ObjectBundleRecord, RefEntry, RefName, RepoParams, RepoState,
    };

    fn dummy_record(seed: u8) -> ObjectBundleRecord {
        ObjectBundleRecord {
            bundle: ObjectBundle::SinglePack {
                pack_hash: [seed; 32],
                size_bytes: 0,
            },
            added_by: [seed; 32],
            auth_epoch: 0,
            signature: [0u8; 64],
        }
    }

    /// Helper to make a RefEntry pointing at a given commit.
    fn ref_entry(commit: [u8; 20]) -> RefEntry {
        RefEntry {
            target: commit,
            update_seq: 0,
            updater: [0u8; 32],
            auth_epoch: 0,
            signature: [0u8; 64],
        }
    }

    #[test]
    fn reachable_returns_only_bundles_whose_tip_is_in_refs() {
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x11; 32]);
        let owner_pk = key.verifying_key().to_bytes();
        let prefix = bs58::encode(&owner_pk).into_string()[..12].to_string();
        let params = RepoParams { prefix };

        let mut state = RepoState {
            owner: owner_pk,
            ..Default::default()
        };

        // Three bundles. Bundle A has tip == current ref. Bundles
        // B and C have tips not in any ref (dead-weight from
        // snapshot-mode rescue's perspective). Bundle D has no tip
        // extension at all (legacy pre-0.1.16).
        let id_a: ObjectBundleId = [0xAA; 32];
        let id_b: ObjectBundleId = [0xBB; 32];
        let id_c: ObjectBundleId = [0xCC; 32];
        let id_d: ObjectBundleId = [0xDD; 32];
        let tip_a = [0x01u8; 20];
        let tip_b = [0x02u8; 20];
        let tip_c = [0x03u8; 20];

        state.object_index.insert(id_a, dummy_record(0xAA));
        state.object_index.insert(id_b, dummy_record(0xBB));
        state.object_index.insert(id_c, dummy_record(0xCC));
        state.object_index.insert(id_d, dummy_record(0xDD));

        let (k_a, e_a) = sign_bundle_tip_extension(&params, &key, &id_a, &tip_a, 0);
        let (k_b, e_b) = sign_bundle_tip_extension(&params, &key, &id_b, &tip_b, 0);
        let (k_c, e_c) = sign_bundle_tip_extension(&params, &key, &id_c, &tip_c, 0);
        state.extensions.insert(k_a, e_a);
        state.extensions.insert(k_b, e_b);
        state.extensions.insert(k_c, e_c);
        // id_d intentionally has no tip extension.

        // Current ref points at tip_a only.
        state
            .refs
            .insert(RefName::from("refs/heads/main"), ref_entry(tip_a));

        let reachable = reachable_bundle_ids(&state);
        assert_eq!(reachable.len(), 1, "only bundle A is reachable");
        assert!(reachable.contains(&id_a));
        assert!(
            !reachable.contains(&id_b),
            "B has tip ext but tip not in refs"
        );
        assert!(
            !reachable.contains(&id_c),
            "C has tip ext but tip not in refs"
        );
        assert!(
            !reachable.contains(&id_d),
            "D has no tip ext -- treated as unreachable"
        );
    }

    #[test]
    fn reachable_handles_multiple_refs() {
        // Multi-branch repo: each branch's latest bundle is
        // reachable; bundles whose tips are no branch's head are
        // skipped.
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x22; 32]);
        let owner_pk = key.verifying_key().to_bytes();
        let prefix = bs58::encode(&owner_pk).into_string()[..12].to_string();
        let params = RepoParams { prefix };

        let mut state = RepoState {
            owner: owner_pk,
            ..Default::default()
        };

        let id_main: ObjectBundleId = [0x11; 32];
        let id_dev: ObjectBundleId = [0x22; 32];
        let id_orphan: ObjectBundleId = [0x33; 32];
        let tip_main = [0xAA; 20];
        let tip_dev = [0xBB; 20];
        let tip_orphan = [0xCC; 20];

        state.object_index.insert(id_main, dummy_record(0x11));
        state.object_index.insert(id_dev, dummy_record(0x22));
        state.object_index.insert(id_orphan, dummy_record(0x33));

        let (k_m, e_m) = sign_bundle_tip_extension(&params, &key, &id_main, &tip_main, 0);
        let (k_d, e_d) = sign_bundle_tip_extension(&params, &key, &id_dev, &tip_dev, 0);
        let (k_o, e_o) = sign_bundle_tip_extension(&params, &key, &id_orphan, &tip_orphan, 0);
        state.extensions.insert(k_m, e_m);
        state.extensions.insert(k_d, e_d);
        state.extensions.insert(k_o, e_o);

        state
            .refs
            .insert(RefName::from("refs/heads/main"), ref_entry(tip_main));
        state
            .refs
            .insert(RefName::from("refs/heads/dev"), ref_entry(tip_dev));

        let reachable = reachable_bundle_ids(&state);
        assert_eq!(reachable.len(), 2);
        assert!(reachable.contains(&id_main));
        assert!(reachable.contains(&id_dev));
        assert!(!reachable.contains(&id_orphan));
    }

    #[test]
    fn reachable_empty_when_no_extensions_and_no_refs_match() {
        // Pre-0.1.16 contract: bundles in object_index, no tip
        // extensions, refs may or may not exist. Result: no bundle
        // is considered reachable. (Workflow should not pass
        // --only-current-tips in this case; this test pins the
        // safe-degrade behavior if someone does.)
        let mut state = RepoState {
            owner: [0; 32],
            ..Default::default()
        };
        state.object_index.insert([0xEE; 32], dummy_record(0xEE));
        state
            .refs
            .insert(RefName::from("refs/heads/main"), ref_entry([0xFF; 20]));

        assert!(reachable_bundle_ids(&state).is_empty());
    }
}
