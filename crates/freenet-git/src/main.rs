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
        /// Force the tip-reachability filter on: only rescue bundles
        /// whose `bundle-tip:<id>` extension points at a commit
        /// currently in some `refs/*` entry of the repo state.
        ///
        /// **Usually you don't need this.** Since 0.1.19 the helper
        /// records a `mirror-mode` extension on the contract at
        /// push time (snapshot or history), and rescue auto-applies
        /// this filter when the extension says snapshot. The flag
        /// is the manual override for one-off use against
        /// pre-0.1.19 snapshot contracts or for diagnostic re-runs
        /// without trusting the on-contract metadata.
        ///
        /// **Use this for snapshot-mode mirrors only.** Snapshot
        /// mirrors force-push a fresh orphan commit on every run, so
        /// older bundles in `object_index` are dead-weight from
        /// rescue's perspective — no current ref points at their tip
        /// and the network can't serve a clone from them.
        ///
        /// **Do NOT use this for history-mode mirrors.** In history
        /// mode every bundle's tip is a real commit in the parent
        /// chain. Only the most recent push's bundle has a tip that
        /// equals a current ref value; older bundles' tips are
        /// ancestor commits, no longer in `refs.values()`. This flag
        /// would incorrectly skip them and the network would lose
        /// cache pressure on the bulk of the history.
        ///
        /// See freenet-git#41 and freenet-git#43.
        #[arg(long)]
        only_current_tips: bool,
        /// How many bundles to rescue in parallel. Each parallel
        /// bundle opens its own WebSocket connection (SinglePack)
        /// or delegates to a chunked-pack driver that opens its
        /// own pool of up to `FREENET_GIT_PARALLEL_OPS` chunk
        /// connections (default 8, see `chunked::parallelism_from_env`).
        /// Peak concurrent WebSocket connections under load is
        /// `parallel_bundles * chunk_pool`, so 2 parallel bundles
        /// against the default chunk pool means up to 16 concurrent
        /// PUTs to the local node.
        ///
        /// Default of 2 is conservative against the gateway's
        /// per-handler scheduler — see freenet-core#4056 for what
        /// happens when concurrent multi-PUT traffic overruns the
        /// `wait_for_res_tx` priority (fixed in v0.2.56 via #4059,
        /// but the ceiling is empirical not pinned). Bump cautiously
        /// on a healthy gateway via `FREENET_GIT_RESCUE_PARALLEL`
        /// or this flag.
        ///
        /// `1` returns the outer-loop work to the pre-#44 serial
        /// shape. Full serial behaviour (including chunks) also
        /// requires `FREENET_GIT_PARALLEL_OPS=1`. Values of `0` are
        /// clamped up to `1`.
        #[arg(long, env = "FREENET_GIT_RESCUE_PARALLEL", default_value = "2")]
        parallel_bundles: usize,
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
            parallel_bundles,
        } => rescue(
            &url,
            ws_url.as_deref(),
            Duration::from_secs(timeout_secs),
            only_current_tips,
            parallel_bundles,
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
    parallel_bundles: usize,
) -> Result<()> {
    let parallel_bundles = parallel_bundles.max(1);
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
        let mut errors: Vec<String> = Vec::new();

        // Resolve the effective filter: explicit --only-current-tips
        // wins. Otherwise auto-detect from the publisher-supplied
        // `mirror-mode` extension (snapshot → filter, history →
        // no filter, missing/unknown → no filter, preserving the
        // historical "rescue everything" default for pre-0.1.19
        // contracts). See freenet-git#43.
        let effective_only_current_tips = if only_current_tips {
            true
        } else {
            match detect_mirror_mode(&state) {
                Some(DetectedMirrorMode::Snapshot) => {
                    println!(
                        "note: contract advertises mirror-mode=snapshot; \
                         filtering rescue to bundles whose tip is reachable \
                         from a current ref (auto-detect from extension)"
                    );
                    true
                }
                Some(DetectedMirrorMode::History) | None => false,
            }
        };

        let (rescue_set, skipped_count) =
            partition_bundles_for_rescue(&state, effective_only_current_tips);

        // Bail-with-direction guard: if the filter was active
        // (explicit or auto-detected) and skipped EVERY bundle in a
        // non-empty object_index, the contract is in a state that
        // doesn't match the assumptions (empty refs, every tip
        // extension malformed, accidental flag-against-history-mode,
        // or stale mirror-mode=snapshot extension on a contract
        // that's actually history-mode now). Exit non-zero with a
        // directed message so CI alerts on it rather than printing
        // "rescued 0 bundles" and returning success.
        if effective_only_current_tips
            && !state.object_index.is_empty()
            && rescue_set.is_empty()
        {
            bail!(
                "tip-reachability filter skipped all {} bundle(s) in this \
                 contract; no bundle's tip extension matches a current ref. \
                 Either the contract has no refs (empty state.refs), every \
                 tip extension is malformed, this is a history-mode contract \
                 where the filter is unsafe, or the contract advertises \
                 mirror-mode=snapshot but no bundle currently matches a ref. \
                 Re-run with --only-current-tips=false (or unset \
                 FREENET_GIT_MIRROR_MODE) to rescue everything.",
                state.object_index.len()
            );
        }

        // Drop the bootstrap connection before spawning per-bundle
        // tasks. Each task opens its own fresh connection so the
        // outer loop never contends with itself on a shared `&mut
        // api`. ChunkedPack rescues additionally open their own
        // 8-way chunk pool internally; combined concurrency at peak
        // is roughly `parallel_bundles + parallel_bundles*8`.
        drop(api);

        // FuturesUnordered with admission control: keep at most
        // `parallel_bundles` rescue tasks in flight; backfill as
        // each one completes. The driver runs on a current-thread
        // runtime (per `tokio::runtime::Builder::new_current_thread`
        // above), so the parallelism is purely IO-overlap — the
        // CPU work of each task is negligible compared to its
        // network round-trips.
        use futures::stream::{FuturesUnordered, StreamExt};
        use std::sync::Arc;

        // Tasks run via `tokio::spawn` so a panic inside
        // `rescue_one_bundle` becomes a `JoinError` rather than
        // unwinding through `next().await` and aborting the whole
        // rescue. We lose the label on panic (it's captured by the
        // closure, not surfaced through JoinError), so the failure
        // line uses a generic placeholder — but the user still gets
        // a count and the panic message via RUST_BACKTRACE.
        let pack_wasm = Arc::new(pack_wasm);
        let ws = Arc::new(ws);
        let mut iter = rescue_set.into_iter();
        let mut in_flight: FuturesUnordered<tokio::task::JoinHandle<BundleOutcome>> =
            FuturesUnordered::new();

        loop {
            while in_flight.len() < parallel_bundles {
                let Some((id, record)) = iter.next() else {
                    break;
                };
                let pack_wasm = pack_wasm.clone();
                let ws = ws.clone();
                let id_owned = *id;
                let bundle = record.bundle.clone();
                in_flight.push(tokio::spawn(async move {
                    let label = format!("bundle {}", hex::encode(id_owned));
                    rescue_one_bundle(&ws, &pack_wasm, bundle, timeout, label).await
                }));
            }
            let Some(join_result) = in_flight.next().await else {
                break;
            };
            let outcome = match join_result {
                Ok(outcome) => outcome,
                Err(join_err) if join_err.is_panic() => BundleOutcome::Err {
                    label: "<bundle-unknown>".to_string(),
                    kind: "panic",
                    error: anyhow::anyhow!(
                        "rescue task panicked: {join_err}. Re-run with RUST_BACKTRACE=1 to identify the bundle."
                    ),
                },
                Err(join_err) => BundleOutcome::Err {
                    label: "<bundle-unknown>".to_string(),
                    kind: "cancelled",
                    error: anyhow::anyhow!("rescue task cancelled: {join_err}"),
                },
            };
            match outcome {
                BundleOutcome::Ok {
                    label,
                    kind_label,
                    chunks_rescued,
                } => {
                    bundle_count += 1;
                    chunk_count += chunks_rescued;
                    println!("ok {label} ({kind_label})");
                }
                BundleOutcome::Err { label, kind, error } => {
                    errors.push(format!("  {label} ({kind}): {error}"));
                }
            }
        }

        println!();
        if effective_only_current_tips {
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
/// Decide which bundles in `state.object_index` to rescue. Returns
/// (kept, skipped_count) so the caller can iterate the kept set and
/// print a summary line with the dropped count.
///
/// When `only_current_tips` is false, every bundle is kept and the
/// skipped count is zero — the historical default.
///
/// When true, the kept set is restricted to bundles whose
/// `bundle-tip:<id>` extension points at a commit currently in
/// `state.refs.values()`. See [`reachable_bundle_ids`] for the
/// definition and the snapshot-vs-history mode constraint.
/// Decoded `mirror-mode` extension value from a `RepoState`. Returned
/// by [`detect_mirror_mode`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DetectedMirrorMode {
    /// Publisher uses snapshot mode (force-push of orphan commits).
    /// Old bundles in `object_index` are dead-weight; rescue should
    /// apply the tip-reachability filter.
    Snapshot,
    /// Publisher uses history mode (incremental fast-forward).
    /// Every bundle is reachable via the parent chain; rescue
    /// iterates all bundles.
    History,
}

/// Read the publisher-recorded `mirror-mode` extension from a
/// `RepoState`. Returns `None` if the extension is absent (pre-0.1.19
/// contracts) or has an unknown / malformed value. Callers default
/// to "rescue everything" on `None`.
///
/// The value comparison is exact — `b"snapshot"` or `b"history"`,
/// no whitespace tolerance, no case folding. Mirror workflows write
/// the canonical bytes via `git-remote-freenet handle_push`'s env-
/// var path; manual contract surgery is the only way to land
/// something else here.
fn detect_mirror_mode(state: &freenet_git_types::RepoState) -> Option<DetectedMirrorMode> {
    use freenet_git_types::signing::{
        MIRROR_MODE_EXTENSION_KEY, MIRROR_MODE_VALUE_HISTORY, MIRROR_MODE_VALUE_SNAPSHOT,
    };
    let ext = state.extensions.get(MIRROR_MODE_EXTENSION_KEY)?;
    match ext.value.as_slice() {
        v if v == MIRROR_MODE_VALUE_SNAPSHOT => Some(DetectedMirrorMode::Snapshot),
        v if v == MIRROR_MODE_VALUE_HISTORY => Some(DetectedMirrorMode::History),
        _ => None,
    }
}

fn partition_bundles_for_rescue(
    state: &freenet_git_types::RepoState,
    only_current_tips: bool,
) -> (
    Vec<(
        &freenet_git_types::ObjectBundleId,
        &freenet_git_types::ObjectBundleRecord,
    )>,
    usize,
) {
    if !only_current_tips {
        return (state.object_index.iter().collect(), 0);
    }
    let reachable = reachable_bundle_ids(state);
    let mut kept = Vec::with_capacity(reachable.len());
    let mut skipped = 0usize;
    for (id, record) in &state.object_index {
        if reachable.contains(id) {
            kept.push((id, record));
        } else {
            skipped += 1;
        }
    }
    (kept, skipped)
}

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
            // Tolerate cross-bundle tip aliasing (multiple bundles
            // with the same tip extension value): both pass the
            // filter, both get rescued. Wasted work, not wrong, and
            // the idempotent-short-circuit on push (PR #29) prevents
            // it in practice.
            //
            // Malformed extension values (length != 20) fall through
            // `contains()` as false and the bundle is treated as
            // unreachable. Safe degrade: a contract emitting bad
            // tip extensions is broken at a layer above rescue;
            // silently skipping beats panicking. The caller in
            // `rescue()` checks for the "all bundles skipped"
            // pathology and bails with an explicit error so an
            // empty-refs / fully-malformed contract doesn't pass
            // CI as success.
            current_tips.contains(ext.value.as_slice())
        })
        .collect()
}

/// Outcome of a single bundle rescue, returned by `rescue_one_bundle`
/// for the parallel driver in `rescue()` to accumulate.
enum BundleOutcome {
    Ok {
        label: String,
        kind_label: String,
        chunks_rescued: usize,
    },
    Err {
        label: String,
        kind: &'static str,
        error: anyhow::Error,
    },
}

/// Drive a single bundle's GET-then-PUT cycle. Opens a fresh
/// WebSocket connection for SinglePack rescues (the parallel driver
/// in `rescue()` cannot share `&mut api` across bundles).
/// ChunkedPack bundles delegate to `rescue_chunked` which manages
/// its own connection pool internally.
async fn rescue_one_bundle(
    ws: &str,
    pack_wasm: &[u8],
    bundle: freenet_git_types::ObjectBundle,
    timeout: Duration,
    label: String,
) -> BundleOutcome {
    match bundle {
        freenet_git_types::ObjectBundle::SinglePack { pack_hash, .. } => {
            let mut api = match wsclient::connect(ws).await {
                Ok(api) => api,
                Err(e) => {
                    return BundleOutcome::Err {
                        label,
                        kind: "SinglePack",
                        error: e.context("open per-bundle WS connection"),
                    };
                }
            };
            match rescue_pack(&mut api, pack_wasm, pack_hash, timeout).await {
                Ok(()) => BundleOutcome::Ok {
                    label,
                    kind_label: "SinglePack".to_string(),
                    chunks_rescued: 0,
                },
                Err(e) => BundleOutcome::Err {
                    label,
                    kind: "SinglePack",
                    error: e,
                },
            }
        }
        freenet_git_types::ObjectBundle::ChunkedPack {
            manifest_hash,
            chunk_count: declared_count,
            ..
        } => match rescue_chunked(ws, pack_wasm, manifest_hash, timeout).await {
            Ok(n) => BundleOutcome::Ok {
                label,
                kind_label: format!("ChunkedPack, {n}/{declared_count} chunks"),
                chunks_rescued: n,
            },
            Err(e) => BundleOutcome::Err {
                label,
                kind: "ChunkedPack",
                error: e,
            },
        },
    }
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
        // is considered reachable. The caller in rescue() converts
        // this into a hard error rather than silently rescuing zero
        // bundles — that's the bail-with-direction guard.
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

    #[test]
    fn reachable_keeps_multiple_bundles_sharing_a_tip() {
        // Cross-bundle tip aliasing: two bundles whose tip
        // extensions point at the same commit. Both pass the
        // filter. In practice the idempotent-push short-circuit
        // from PR #29 prevents the contract from getting into this
        // state, but the filter must tolerate it without dropping
        // either bundle.
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x33; 32]);
        let owner_pk = key.verifying_key().to_bytes();
        let prefix = bs58::encode(&owner_pk).into_string()[..12].to_string();
        let params = RepoParams { prefix };

        let mut state = RepoState {
            owner: owner_pk,
            ..Default::default()
        };

        let id_a: ObjectBundleId = [0x11; 32];
        let id_b: ObjectBundleId = [0x22; 32];
        let shared_tip = [0x88; 20];

        state.object_index.insert(id_a, dummy_record(0x11));
        state.object_index.insert(id_b, dummy_record(0x22));

        let (k_a, e_a) = sign_bundle_tip_extension(&params, &key, &id_a, &shared_tip, 0);
        let (k_b, e_b) = sign_bundle_tip_extension(&params, &key, &id_b, &shared_tip, 1);
        state.extensions.insert(k_a, e_a);
        state.extensions.insert(k_b, e_b);

        state
            .refs
            .insert(RefName::from("refs/heads/main"), ref_entry(shared_tip));

        let reachable = reachable_bundle_ids(&state);
        assert_eq!(reachable.len(), 2, "both aliased bundles must be kept");
        assert!(reachable.contains(&id_a));
        assert!(reachable.contains(&id_b));
    }

    #[test]
    fn reachable_skips_bundle_with_wrong_length_tip_value() {
        // Malformed tip extension: a contract bug emits an extension
        // with a `value` that isn't 20 bytes (CommitHash length).
        // The filter must not panic and must treat the bundle as
        // unreachable. Hand-rolled extension entry — sign_extension
        // would have validated length downstream, but the contract
        // itself doesn't enforce a length on extension values.
        use freenet_git_types::{ExtensionEntry, RepoState};

        let mut state = RepoState {
            owner: [0; 32],
            ..Default::default()
        };
        let id: ObjectBundleId = [0xAA; 32];
        state.object_index.insert(id, dummy_record(0xAA));

        let bad_value = vec![0xFFu8; 32]; // 32 bytes, not 20
        let key = freenet_git_types::signing::bundle_tip_extension_key(&id);
        state.extensions.insert(
            key,
            ExtensionEntry {
                value: bad_value,
                update_seq: 0,
                signature: [0u8; 64],
            },
        );
        state
            .refs
            .insert(RefName::from("refs/heads/main"), ref_entry([0xFF; 20]));

        let reachable = reachable_bundle_ids(&state);
        assert!(
            reachable.is_empty(),
            "malformed tip value must not match any ref"
        );
    }

    #[test]
    fn partition_with_filter_off_keeps_all_with_zero_skipped() {
        // Historical default path: --only-current-tips not set.
        // Every bundle in object_index is kept and skipped_count is 0.
        let mut state = RepoState {
            owner: [0; 32],
            ..Default::default()
        };
        state.object_index.insert([0x01; 32], dummy_record(0x01));
        state.object_index.insert([0x02; 32], dummy_record(0x02));
        state.object_index.insert([0x03; 32], dummy_record(0x03));

        let (kept, skipped) = partition_bundles_for_rescue(&state, false);
        assert_eq!(kept.len(), 3);
        assert_eq!(skipped, 0);
    }

    #[test]
    fn partition_with_filter_on_counts_skipped() {
        // Snapshot-mode flow: three bundles, only one has a tip
        // extension matching a current ref. Filter keeps that one,
        // counts the other two as skipped.
        let key = ed25519_dalek::SigningKey::from_bytes(&[0x44; 32]);
        let owner_pk = key.verifying_key().to_bytes();
        let prefix = bs58::encode(&owner_pk).into_string()[..12].to_string();
        let params = RepoParams { prefix };

        let mut state = RepoState {
            owner: owner_pk,
            ..Default::default()
        };

        let id_keep: ObjectBundleId = [0x10; 32];
        let id_skip_1: ObjectBundleId = [0x20; 32];
        let id_skip_2: ObjectBundleId = [0x30; 32];
        let tip_keep = [0xAA; 20];
        let tip_old_1 = [0xBB; 20];
        let tip_old_2 = [0xCC; 20];

        state.object_index.insert(id_keep, dummy_record(0x10));
        state.object_index.insert(id_skip_1, dummy_record(0x20));
        state.object_index.insert(id_skip_2, dummy_record(0x30));

        let (k1, e1) = sign_bundle_tip_extension(&params, &key, &id_keep, &tip_keep, 0);
        let (k2, e2) = sign_bundle_tip_extension(&params, &key, &id_skip_1, &tip_old_1, 0);
        let (k3, e3) = sign_bundle_tip_extension(&params, &key, &id_skip_2, &tip_old_2, 0);
        state.extensions.insert(k1, e1);
        state.extensions.insert(k2, e2);
        state.extensions.insert(k3, e3);

        state
            .refs
            .insert(RefName::from("refs/heads/main"), ref_entry(tip_keep));

        let (kept, skipped) = partition_bundles_for_rescue(&state, true);
        assert_eq!(kept.len(), 1);
        assert_eq!(skipped, 2);
        assert_eq!(kept[0].0, &id_keep);
    }

    #[test]
    fn partition_with_filter_on_empty_object_index_returns_empty() {
        // Pin: an empty contract doesn't trigger the bail-with-
        // direction guard in rescue() (that fires only when
        // object_index is non-empty but every bundle skipped). Pure
        // partition output is (empty, 0).
        let state = RepoState {
            owner: [0; 32],
            ..Default::default()
        };
        let (kept, skipped) = partition_bundles_for_rescue(&state, true);
        assert!(kept.is_empty());
        assert_eq!(skipped, 0);
    }

    #[test]
    fn detect_mirror_mode_reads_snapshot_value() {
        use freenet_git_types::signing::{MIRROR_MODE_EXTENSION_KEY, MIRROR_MODE_VALUE_SNAPSHOT};
        use freenet_git_types::ExtensionEntry;
        let mut state = RepoState {
            owner: [0; 32],
            ..Default::default()
        };
        state.extensions.insert(
            MIRROR_MODE_EXTENSION_KEY.to_string(),
            ExtensionEntry {
                value: MIRROR_MODE_VALUE_SNAPSHOT.to_vec(),
                update_seq: 1,
                signature: [0u8; 64],
            },
        );
        assert_eq!(
            detect_mirror_mode(&state),
            Some(DetectedMirrorMode::Snapshot)
        );
    }

    #[test]
    fn detect_mirror_mode_reads_history_value() {
        use freenet_git_types::signing::{MIRROR_MODE_EXTENSION_KEY, MIRROR_MODE_VALUE_HISTORY};
        use freenet_git_types::ExtensionEntry;
        let mut state = RepoState {
            owner: [0; 32],
            ..Default::default()
        };
        state.extensions.insert(
            MIRROR_MODE_EXTENSION_KEY.to_string(),
            ExtensionEntry {
                value: MIRROR_MODE_VALUE_HISTORY.to_vec(),
                update_seq: 1,
                signature: [0u8; 64],
            },
        );
        assert_eq!(
            detect_mirror_mode(&state),
            Some(DetectedMirrorMode::History)
        );
    }

    #[test]
    fn detect_mirror_mode_returns_none_for_missing_extension() {
        let state = RepoState {
            owner: [0; 32],
            ..Default::default()
        };
        assert_eq!(detect_mirror_mode(&state), None);
    }

    #[test]
    fn detect_mirror_mode_returns_none_for_unknown_value() {
        // A malformed contract or a future mode the current build
        // doesn't recognise. Safe-degrade: returns None, caller
        // defaults to "rescue everything."
        use freenet_git_types::signing::MIRROR_MODE_EXTENSION_KEY;
        use freenet_git_types::ExtensionEntry;
        let mut state = RepoState {
            owner: [0; 32],
            ..Default::default()
        };
        state.extensions.insert(
            MIRROR_MODE_EXTENSION_KEY.to_string(),
            ExtensionEntry {
                value: b"shallow".to_vec(),
                update_seq: 1,
                signature: [0u8; 64],
            },
        );
        assert_eq!(detect_mirror_mode(&state), None);
    }

    #[test]
    fn detect_mirror_mode_does_not_match_partial_or_extra_bytes() {
        // Exact equality only — no whitespace stripping, no case
        // folding, no prefix-match. A real publisher writes
        // `b"snapshot"` exactly; anything else is treated as
        // unknown.
        use freenet_git_types::signing::MIRROR_MODE_EXTENSION_KEY;
        use freenet_git_types::ExtensionEntry;
        for v in [
            b"snapshot\n".to_vec(),
            b"Snapshot".to_vec(),
            b" snapshot".to_vec(),
            b"snapshots".to_vec(),
            b"".to_vec(),
        ] {
            let mut state = RepoState {
                owner: [0; 32],
                ..Default::default()
            };
            state.extensions.insert(
                MIRROR_MODE_EXTENSION_KEY.to_string(),
                ExtensionEntry {
                    value: v.clone(),
                    update_seq: 1,
                    signature: [0u8; 64],
                },
            );
            assert_eq!(
                detect_mirror_mode(&state),
                None,
                "value {v:?} should not match"
            );
        }
    }
}
