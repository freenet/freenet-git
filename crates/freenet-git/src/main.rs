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
    default_bundle_path, read_bundle, write_bundle, DecryptedBundle, RepoRegistryEntry,
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
    },
    /// Print the identity stored in the bundle.
    Whoami,
    /// Re-encrypt the bundle to the given output path. Useful for moving
    /// the identity to a new machine.
    ExportIdentity {
        /// Path to write the exported bundle.
        out: PathBuf,
    },
    /// Replace the local bundle with the one at `from` (decrypted with the
    /// supplied passphrase, re-encrypted in place).
    ImportIdentity {
        /// Path to read the source bundle.
        from: PathBuf,
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
        Cmd::InitIdentity { name, email } => init_identity(&bundle_path, name, email),
        Cmd::Whoami => whoami(&bundle_path),
        Cmd::ExportIdentity { out } => export_identity(&bundle_path, &out),
        Cmd::ImportIdentity { from } => import_identity(&bundle_path, &from),
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
        } => rescue(&url, ws_url.as_deref(), Duration::from_secs(timeout_secs)),
    }
}

fn init_identity(path: &std::path::Path, name: String, email: String) -> Result<()> {
    if path.exists() {
        bail!(
            "identity bundle already exists at {} -- refusing to overwrite. \
             Move or delete it first if you really want a new identity.",
            path.display()
        );
    }

    let pw = prompt_passphrase_with_confirm("Passphrase for new identity")?;
    let bundle = DecryptedBundle::new(name, email);
    write_bundle(&bundle, &pw, path).with_context(|| format!("write {}", path.display()))?;
    println!("Generated ed25519 keypair.");
    println!("Public key: {}", bundle.id_string());
    println!("Bundle written to: {}", path.display());
    Ok(())
}

fn whoami(path: &std::path::Path) -> Result<()> {
    let bundle = open_bundle_with_prompt(path)?;
    println!("{} <{}>", bundle.name, bundle.email);
    println!("{}", bundle.id_string());
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

fn export_identity(path: &std::path::Path, out: &std::path::Path) -> Result<()> {
    let bundle = open_bundle_with_prompt(path)?;
    let pw = prompt_passphrase_with_confirm("Passphrase for exported bundle")?;
    // Use write_bundle to get atomic-rename + 0600 permissions on Unix.
    // Plain `std::fs::write` would leave the bundle world-readable
    // depending on the user's umask.
    write_bundle(&bundle, &pw, out)
        .with_context(|| format!("write exported bundle to {}", out.display()))?;
    println!("Wrote bundle to {}", out.display());
    Ok(())
}

fn import_identity(local_path: &std::path::Path, from: &std::path::Path) -> Result<()> {
    let pw_in = prompt_passphrase("Passphrase for source bundle")?;
    let bundle = read_bundle(from, &pw_in)
        .with_context(|| format!("read source bundle at {}", from.display()))?;
    if local_path.exists() {
        bail!(
            "local identity bundle already exists at {} -- refusing to overwrite",
            local_path.display()
        );
    }
    let pw_out = prompt_passphrase_with_confirm("Passphrase for new local bundle")?;
    write_bundle(&bundle, &pw_out, local_path)?;
    println!(
        "Imported identity {} into {}",
        bundle.id_string(),
        local_path.display()
    );
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
    let bundle = open_bundle_with_prompt(bundle_path)?;

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
        return register_in_bundle(bundle, bundle_path, &repo_signing, &prefix, name);
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
                repo_wasm,
                params.to_bytes(),
                initial_state.to_bytes(),
                publish_timeout,
            )
            .await
        })
        .with_context(|| format!("PUT to {ws_url}"))?;

    println!("PUT confirmed by host. Contract key: {}", key.id());

    register_in_bundle(bundle, bundle_path, &repo_signing, &prefix, name)
}

fn register_in_bundle(
    bundle: DecryptedBundle,
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
    let pw = prompt_passphrase("Passphrase to update bundle (registry entry)")?;
    write_bundle(&bundle_with_repo, &pw, bundle_path)?;
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
fn rescue(url_str: &str, ws_url: Option<&str>, timeout: Duration) -> Result<()> {
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

        for (id, record) in &state.object_index {
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
        println!(
            "rescued {} bundle(s), {} chunk(s); {} failure(s)",
            bundle_count,
            chunk_count,
            errors.len()
        );
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

async fn rescue_pack(
    api: &mut freenet_stdlib::client_api::WebApi,
    pack_wasm: &[u8],
    pack_hash: [u8; 32],
    timeout: Duration,
) -> Result<()> {
    let bytes = wsclient::get_pack(api, pack_wasm, pack_hash, timeout)
        .await
        .with_context(|| format!("GET pack {}", hex::encode(pack_hash)))?;
    wsclient::put_pack(api, pack_wasm.to_vec(), bytes, timeout)
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
                wsclient::put_pack(&mut conn, (*pack_wasm).clone(), bytes, timeout)
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
        wsclient::put_pack(&mut conn, (*pack_wasm).clone(), manifest_bytes, timeout)
            .await
            .context("PUT manifest")?;
    }
    Ok(rescued)
}

fn open_bundle_with_prompt(path: &std::path::Path) -> Result<DecryptedBundle> {
    if !path.exists() {
        bail!(
            "no identity bundle at {} -- run `freenet-git init-identity` first",
            path.display()
        );
    }
    let pw = prompt_passphrase("Passphrase")?;
    let bundle =
        read_bundle(path, &pw).with_context(|| format!("decrypt bundle at {}", path.display()))?;
    Ok(bundle)
}

/// Read a passphrase. For interactive use, prompts on the controlling
/// TTY via `rpassword`. For non-interactive use (CI, tests, scripts),
/// `FREENET_GIT_PASSPHRASE` short-circuits the prompt — required because
/// rpassword fails outright when no TTY is attached.
fn prompt_passphrase(prompt: &str) -> Result<String> {
    if let Ok(pw) = std::env::var("FREENET_GIT_PASSPHRASE") {
        if pw.is_empty() {
            bail!("empty FREENET_GIT_PASSPHRASE");
        }
        return Ok(pw);
    }
    let pw = rpassword::prompt_password(format!("{prompt}: "))?;
    if pw.is_empty() {
        bail!("empty passphrase");
    }
    Ok(pw)
}

fn prompt_passphrase_with_confirm(prompt: &str) -> Result<String> {
    // Single env var fills both prompts in non-interactive mode.
    let pw = prompt_passphrase(prompt)?;
    if std::env::var("FREENET_GIT_PASSPHRASE").is_ok() {
        return Ok(pw);
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
