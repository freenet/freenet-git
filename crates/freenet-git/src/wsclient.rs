//! Thin wrapper around `freenet-stdlib`'s `WebApi` for the operations the
//! `freenet-git` CLI needs: connect, PUT a contract, GET a state.
//!
//! The complexity in this file is mostly about *waiting for the right
//! response*: when we PUT with `subscribe: true`, the host can respond
//! with either a `PutResponse` or an `UpdateNotification` first, and we
//! need to accept either as success while ignoring unrelated notifications
//! that may interleave.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{anyhow, bail, Context, Result};
use freenet_stdlib::client_api::{
    ClientRequest, ContractRequest, ContractResponse, HostResponse, WebApi,
};
use freenet_stdlib::prelude::{
    ContractCode, ContractContainer, ContractInstanceId, ContractKey, ContractWasmAPIVersion,
    Parameters, RelatedContracts, WrappedContract, WrappedState,
};
use tokio_tungstenite::connect_async;

/// Default WebSocket endpoint for a local Freenet node. The path is the
/// stdlib's contract command socket; `?encodingProtocol=native` matches
/// what `riverctl` and `fdev` use.
pub const DEFAULT_WS_URL: &str = "ws://127.0.0.1:7509/v1/contract/command?encodingProtocol=native";

/// Open a `WebApi` connection to a local Freenet node.
///
/// `url` should look like `ws://127.0.0.1:7509/v1/contract/command?encodingProtocol=native`.
/// If you want the default, pass [`DEFAULT_WS_URL`].
pub async fn connect(url: &str) -> Result<WebApi> {
    let (ws_stream, _) = connect_async(url)
        .await
        .with_context(|| format!("connect to Freenet node WS at {url}"))?;
    Ok(WebApi::start(ws_stream))
}

/// PUT a contract: upload the WASM, parameters, and signed initial state to
/// the local node, with `subscribe: true` so we get propagation
/// notifications. Returns the [`ContractKey`] confirmed by the host.
///
/// Note: we use `subscribe: true` (not `blocking_subscribe`) because the
/// host returns `PutResponse` as soon as it has accepted the PUT; for a
/// real network we'd then wait for downstream propagation evidence, but
/// for the Phase 1 single-node demo `PutResponse` is the success signal.
pub async fn put_contract(
    web_api: &mut WebApi,
    wasm_bytes: &[u8],
    parameters_bytes: Vec<u8>,
    state_bytes: Vec<u8>,
    timeout: Duration,
) -> Result<ContractKey> {
    let parameters = Parameters::from(parameters_bytes);
    // Clone the WASM bytes once at the boundary into the owned
    // ContractCode the host wire format requires. Callers therefore
    // hand us a borrow and we pay one allocation per attempt
    // (matches the historical retry loop's clone-per-attempt cost,
    // and lets parallel-chunked publish/fetch share one Arc<Vec<u8>>
    // across N chunk tasks instead of deep-cloning per chunk).
    let code = ContractCode::from(wasm_bytes.to_vec());
    let expected_key = ContractKey::from_params_and_code(parameters.clone(), &code);

    let contract_container = ContractContainer::from(ContractWasmAPIVersion::V1(
        WrappedContract::new(Arc::new(code), parameters),
    ));
    let wrapped_state = WrappedState::new(state_bytes);

    let req = ContractRequest::Put {
        contract: contract_container,
        state: wrapped_state,
        related_contracts: RelatedContracts::default(),
        subscribe: true,
        blocking_subscribe: false,
    };
    web_api
        .send(ClientRequest::ContractOp(req))
        .await
        .map_err(|e| anyhow!("send PUT: {e}"))?;

    // The host can respond with `PutResponse` or `UpdateNotification`
    // (when subscribe=true the same key starts streaming back to us as
    // soon as the PUT is accepted). Accept either as success; ignore
    // notifications for unrelated keys (none should arrive on a fresh
    // connection, but be defensive).
    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            bail!("timed out waiting for PUT confirmation after {timeout:?}");
        }
        let response = match tokio::time::timeout(remaining, web_api.recv()).await {
            Ok(r) => r.map_err(|e| anyhow!("recv: {e}"))?,
            Err(_) => bail!("timed out waiting for PUT confirmation after {timeout:?}"),
        };
        match dispatch_put_response(response, &expected_key) {
            PutDispatch::Success(key) => return Ok(key),
            PutDispatch::Continue => {}
        }
    }
}

/// Outcome of inspecting one [`HostResponse`] against a Put's
/// expected key. Pulled out so the per-message dispatch is unit
/// testable without spinning up a real WebApi.
#[derive(Debug)]
enum PutDispatch {
    /// Caller should return `Ok(key)` immediately.
    Success(ContractKey),
    /// Caller should skip and keep waiting on the recv loop.
    Continue,
}

/// Decide what to do with the next message arriving on a put_contract
/// recv loop. Skipping mismatched PutResponses (rather than bailing)
/// handles the cross-op stale-response case (issue #9): if a previous
/// put_pack on this same connection had to retry, the original
/// attempt's response can arrive late and sit in the queue. The next
/// put_contract on the connection would otherwise read that stale
/// buffered message. The other recv loops in this file (get_state,
/// update_state) already skip on key mismatch; this branch used to
/// bail and produce "host returned key X for PUT but we computed Y"
/// errors that looked like host bugs but were actually our own
/// queue residue.
///
/// Comparison is by `ContractKey::id()` only, matching the convention
/// in `get_state` / `update_state`. `ContractKey`'s own `PartialEq`
/// is also id-only (the `code: CodeHash` field is ignored), so this
/// is the same equality the original `key != expected_key` check used.
///
/// Tradeoff: silently continuing on mismatch turns the rare "wrong
/// key" case into a slower "wait for the real response, possibly
/// timeout" path. If the real response truly never arrives, the
/// caller hits its `timeout` deadline rather than a fast-fail bail.
/// We accept this for parity with the get/update loops.
fn dispatch_put_response(response: HostResponse, expected_key: &ContractKey) -> PutDispatch {
    match response {
        HostResponse::ContractResponse(ContractResponse::PutResponse { key }) => {
            if key.id() != expected_key.id() {
                tracing::debug!(
                    "ignoring stale PutResponse for unrelated key {} while waiting for {}",
                    key.id(),
                    expected_key.id(),
                );
                PutDispatch::Continue
            } else {
                PutDispatch::Success(key)
            }
        }
        HostResponse::ContractResponse(ContractResponse::UpdateNotification { key, .. }) => {
            if key.id() == expected_key.id() {
                // Subscribe path: PUT was accepted, this is our own
                // initial state being relayed back. Treat as success.
                PutDispatch::Success(key)
            } else {
                PutDispatch::Continue
            }
        }
        HostResponse::Ok => {
            // Pre-existing arm: the host may emit a bare Ok rather
            // than a typed response in some edge paths. We treat it
            // as success because the original put_contract did, but
            // this is the one branch where we can't verify the Ok
            // belongs to *our* request (it has no key). If the queue
            // had a stale Ok from a prior unrelated op, that would
            // produce a false success here. Tightening to require a
            // typed PutResponse/UpdateNotification with key match
            // would need a survey of host code paths to confirm
            // PUTs never legitimately resolve via bare Ok; deferred
            // until we have txn-id correlation (the stdlib-side fix).
            PutDispatch::Success(*expected_key)
        }
        other => {
            tracing::debug!(?other, "ignoring non-PUT response while waiting");
            PutDispatch::Continue
        }
    }
}

/// Convert a [`ContractKey`] to the `ContractInstanceId` we embed in
/// `freenet:` URLs. The instance id is just the Bitcoin-base58-encoded
/// 32-byte key.
pub fn instance_id(key: &ContractKey) -> ContractInstanceId {
    *key.id()
}

/// Compute a contract instance id from a precomputed WASM hash and
/// parameters bytes, without needing the full WASM. Used for the
/// legacy-contract probe path during migration: we don't ship the old
/// WASM bytes (just their hashes), but we can still derive what the
/// old contract key would have been for the same prefix.
///
/// This duplicates the derivation `freenet_stdlib` does internally
/// (`BLAKE3(BLAKE3(code) || params)`) but skips the
/// `BLAKE3(code)` step since we already have it.
pub fn contract_id_from_wasm_hash(wasm_hash: &[u8; 32], params_bytes: &[u8]) -> ContractInstanceId {
    let mut hasher = blake3::Hasher::new();
    hasher.update(wasm_hash);
    hasher.update(params_bytes);
    let full = hasher.finalize();
    let mut spec = [0u8; 32];
    spec.copy_from_slice(full.as_bytes());
    ContractInstanceId::new(spec)
}

/// GET the repo state at `current_id`; if not found, walk
/// `legacy_wasm_hashes`, computing the legacy contract key for the
/// same `params_bytes` and probing each. Returns the first state we
/// can find, plus an indicator of whether it came from a legacy key
/// (so the caller can re-PUT it to the current key for migration).
///
/// `timeout` is per-probe, not total — a long list of legacy hashes
/// can take O(N × timeout) in the worst case.
pub async fn get_state_with_legacy_fallback(
    web_api: &mut WebApi,
    current_id: ContractInstanceId,
    params_bytes: &[u8],
    legacy_wasm_hashes: &[&[u8; 32]],
    timeout: Duration,
) -> Result<LegacyAwareGet> {
    // Fast path: try the current key first.
    match get_state(web_api, current_id, false, timeout).await {
        Ok(state) if !state.is_empty() => {
            return Ok(LegacyAwareGet {
                state,
                source: GetSource::Current,
            });
        }
        Ok(_) => {
            // Empty state: treat as "not found" for migration purposes.
        }
        Err(e) => {
            // Network error or contract not found. Don't propagate yet
            // -- legacy probes might find data.
            tracing::debug!("current-key GET failed: {e}; trying legacy fallback");
        }
    }

    // Legacy probes.
    for (idx, legacy_hash) in legacy_wasm_hashes.iter().enumerate() {
        let legacy_id = contract_id_from_wasm_hash(legacy_hash, params_bytes);
        match get_state(web_api, legacy_id, false, timeout).await {
            Ok(state) if !state.is_empty() => {
                return Ok(LegacyAwareGet {
                    state,
                    source: GetSource::Legacy {
                        index: idx,
                        instance: legacy_id,
                    },
                });
            }
            Ok(_) => {}
            Err(e) => {
                tracing::debug!("legacy probe {idx} failed: {e}");
            }
        }
    }

    bail!(
        "no state found at current contract key or any of {} legacy keys",
        legacy_wasm_hashes.len()
    );
}

/// Result of [`get_state_with_legacy_fallback`].
pub struct LegacyAwareGet {
    /// The retrieved state bytes.
    pub state: Vec<u8>,
    /// Where the state came from.
    pub source: GetSource,
}

/// Where a [`get_state_with_legacy_fallback`] result came from.
pub enum GetSource {
    /// The current contract key.
    Current,
    /// A legacy contract key, indexed into `legacy_wasm_hashes`.
    Legacy {
        /// Index in the legacy hash array.
        index: usize,
        /// The legacy contract instance id (so the caller can log it).
        instance: ContractInstanceId,
    },
}

/// Outcome of inspecting one [`HostResponse`] against a Get's expected
/// instance_id. Pulled out so the per-message dispatch is unit testable
/// without spinning up a real WebApi (mirrors `dispatch_put_response`).
#[derive(Debug)]
enum GetDispatch {
    /// Caller should return `Ok(bytes)` immediately — either real state
    /// bytes (matching `GetResponse`) or an empty `Vec` (`NotFound` for
    /// our instance_id). The empty-bytes channel preserves
    /// `get_state_with_legacy_fallback`'s "fall through to the next
    /// legacy key" semantics.
    Terminal(Vec<u8>),
    /// Caller should skip and keep waiting on the recv loop.
    Continue,
}

/// Decide what to do with the next message arriving on a `get_state`
/// recv loop.
///
/// `NotFound` for our key is treated as `Terminal(Vec::new())` because
/// freenet-core v0.2.56+ emits `ContractResponse::NotFound` as the
/// terminal response when the task-per-tx GET driver exhausts every
/// peer reachable from the gateway's ring (see freenet-core PR #4076).
/// Pre-#4076 the legacy state machine never surfaced `NotFound` on the
/// WS API, so this client used to deadlock the recv loop until the
/// outer rescue timeout fired (see matrix dev-channel report
/// 2026-05-15: "rescue-demos failure" recurring every 12h after the
/// gateway upgrade to v0.2.57).
///
/// Empty bytes are valid for the "not found" channel because the only
/// caller, `get_state_with_legacy_fallback`, already treats `Ok(empty)`
/// as "try the next legacy key, then bail with 'no state found at
/// current contract key or any of N legacy keys'".
fn dispatch_get_response(response: HostResponse, id: ContractInstanceId) -> GetDispatch {
    match response {
        HostResponse::ContractResponse(ContractResponse::GetResponse {
            key: got_key,
            state,
            ..
        }) => {
            if got_key.id() != &id {
                tracing::debug!("ignoring GetResponse for unrelated key {}", got_key.id());
                GetDispatch::Continue
            } else {
                GetDispatch::Terminal(state.as_ref().to_vec())
            }
        }
        HostResponse::ContractResponse(ContractResponse::NotFound {
            instance_id: nf_id,
        }) => {
            if nf_id != id {
                tracing::debug!("ignoring NotFound for unrelated key {nf_id}");
                GetDispatch::Continue
            } else {
                GetDispatch::Terminal(Vec::new())
            }
        }
        HostResponse::ContractResponse(ContractResponse::UpdateNotification {
            key: notif_key,
            ..
        }) => {
            // Subscription noise; ignore until our GetResponse arrives.
            tracing::debug!(
                "got UpdateNotification for {} while waiting for GET",
                notif_key.id()
            );
            GetDispatch::Continue
        }
        other => {
            tracing::debug!(?other, "ignoring non-GET response while waiting");
            GetDispatch::Continue
        }
    }
}

/// GET the current state of a contract by its instance id. Returns the
/// raw state bytes — caller decodes (e.g. via `RepoState::from_bytes`).
///
/// An empty `Vec` return value means the host responded with
/// `ContractResponse::NotFound` for `id`; the legacy-fallback caller
/// uses that signal to try the next legacy key.
///
/// Setting `subscribe: true` is intentional: we want the local node to
/// keep the contract live for us so subsequent pushes/fetches don't have
/// to re-discover peers from cold.
pub async fn get_state(
    web_api: &mut WebApi,
    id: ContractInstanceId,
    subscribe: bool,
    timeout: Duration,
) -> Result<Vec<u8>> {
    let req = ContractRequest::Get {
        key: id,
        return_contract_code: false,
        subscribe,
        blocking_subscribe: false,
    };
    web_api
        .send(ClientRequest::ContractOp(req))
        .await
        .map_err(|e| anyhow!("send GET: {e}"))?;

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            bail!("timed out waiting for GET response after {timeout:?}");
        }
        let response = match tokio::time::timeout(remaining, web_api.recv()).await {
            Ok(r) => r.map_err(|e| anyhow!("recv: {e}"))?,
            Err(_) => bail!("timed out waiting for GET response after {timeout:?}"),
        };
        match dispatch_get_response(response, id) {
            GetDispatch::Terminal(bytes) => return Ok(bytes),
            GetDispatch::Continue => {}
        }
    }
}

/// Send an UPDATE for a contract. The bytes given are interpreted by the
/// contract's `update_state` (for the repo contract that's a serialized
/// `RepoState` interpreted as a delta). Returns when the host confirms
/// the update was applied (`UpdateResponse`) or an UpdateNotification for
/// our key arrives.
pub async fn update_state(
    web_api: &mut WebApi,
    id: ContractInstanceId,
    delta_bytes: Vec<u8>,
    timeout: Duration,
) -> Result<()> {
    use freenet_stdlib::prelude::{CodeHash, StateDelta, UpdateData};
    // Update needs a full ContractKey (instance id + code hash). We don't
    // know the code hash from the instance id alone, but the host does
    // not actually re-derive it from the request — it uses the key only
    // for routing. A zero CodeHash works as a placeholder; downstream
    // matching is by `ContractKey::id()` only.
    let key = ContractKey::from_id_and_code(id, CodeHash::new([0u8; 32]));
    let req = ContractRequest::Update {
        key,
        data: UpdateData::Delta(StateDelta::from(delta_bytes)),
    };
    web_api
        .send(ClientRequest::ContractOp(req))
        .await
        .map_err(|e| anyhow!("send UPDATE: {e}"))?;

    let deadline = tokio::time::Instant::now() + timeout;
    loop {
        let remaining = deadline.saturating_duration_since(tokio::time::Instant::now());
        if remaining.is_zero() {
            bail!("timed out waiting for UPDATE response after {timeout:?}");
        }
        let response = match tokio::time::timeout(remaining, web_api.recv()).await {
            Ok(r) => r.map_err(|e| anyhow!("recv: {e}"))?,
            Err(_) => bail!("timed out waiting for UPDATE response after {timeout:?}"),
        };
        match response {
            HostResponse::ContractResponse(ContractResponse::UpdateResponse {
                key: got_key,
                ..
            }) => {
                if got_key.id() == &id {
                    return Ok(());
                }
                tracing::debug!("ignoring UpdateResponse for unrelated key {}", got_key.id());
            }
            HostResponse::ContractResponse(ContractResponse::UpdateNotification {
                key: notif_key,
                ..
            }) => {
                if notif_key.id() == &id {
                    // Update echoed back means it was applied.
                    return Ok(());
                }
                tracing::debug!("ignoring unrelated UpdateNotification");
            }
            HostResponse::Ok => return Ok(()),
            other => {
                tracing::debug!(?other, "ignoring non-UPDATE response while waiting");
            }
        }
    }
}

/// PUT a pack contract. Uses the universal pack-contract WASM (passed in)
/// and the BLAKE3-32 of the pack bytes as the parameters; the contract's
/// `validate_state` enforces `BLAKE3(state) == parameters` so any peer
/// can verify content addressing without a signature.
///
/// Retries up to 3 times with exponential backoff on transient host
/// errors. Pack contracts are content-addressed, so retries are
/// idempotent: a second PUT of the same bytes resolves to the same
/// contract key, and the contract's `update_state` accepts a no-op
/// re-PUT of identical canonical bytes.
pub async fn put_pack(
    web_api: &mut WebApi,
    pack_wasm: &[u8],
    pack_bytes: Vec<u8>,
    timeout: Duration,
) -> Result<ContractKey> {
    const MAX_ATTEMPTS: u32 = 3;
    let pack_hash = *blake3::hash(&pack_bytes).as_bytes();
    let mut last_err: Option<anyhow::Error> = None;
    for attempt in 1..=MAX_ATTEMPTS {
        match put_contract(
            web_api,
            pack_wasm,
            pack_hash.to_vec(),
            pack_bytes.clone(),
            timeout,
        )
        .await
        {
            Ok(key) => {
                // Cache the bytes we just successfully PUT so a
                // later rescue can re-PUT from the cache without
                // having to network-GET them back. See pack_cache
                // module docs and freenet/freenet-git#22.
                crate::pack_cache::write_async(&pack_hash, &pack_bytes).await;
                return Ok(key);
            }
            Err(e) => {
                let msg = format!("{e}");
                tracing::warn!(
                    "put_pack attempt {attempt}/{MAX_ATTEMPTS} failed: {msg}; will retry"
                );
                last_err = Some(e);
                if attempt < MAX_ATTEMPTS {
                    let backoff = Duration::from_secs(2u64.pow(attempt));
                    tokio::time::sleep(backoff).await;
                }
            }
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("put_pack failed (no error captured)")))
}

/// GET a pack contract's bytes by computing its instance id from the
/// pack-contract WASM and the pack hash. Verifies content-addressing
/// (`BLAKE3(returned_bytes) == pack_hash`) before returning so a
/// pathological host cannot hand us bytes claiming to be a specific
/// pack.
///
/// Consults the on-disk pack cache before going to the network. Cache
/// hits skip the network entirely; cache misses (or a missing /
/// disabled cache) fall through to the WS GET, and the returned
/// bytes are written back to the cache. The cache is a hard offline
/// shortcut for re-clones / retries against a slow gateway -- see
/// freenet/freenet-git#22.
pub async fn get_pack(
    web_api: &mut WebApi,
    pack_wasm: &[u8],
    pack_hash: [u8; 32],
    timeout: Duration,
) -> Result<Vec<u8>> {
    let parameters = Parameters::from(pack_hash.to_vec());
    let code = ContractCode::from(pack_wasm.to_vec());
    let key = ContractKey::from_params_and_code(parameters, &code);
    let id = *key.id();
    let cache = crate::pack_cache::PackCache::from_environment();
    get_pack_with_fetcher(cache.as_ref(), pack_hash, move |_hash| async move {
        get_state(web_api, id, false, timeout).await
    })
    .await
}

/// Inner cache-aware GET. Factored out from `get_pack` so the
/// cache-hit / cache-miss / verify / cache-write branches are
/// unit-testable without a live `WebApi` or environment-variable
/// manipulation. Production passes a cache resolved from
/// environment; tests pass an explicit `PackCache::at(tempdir)` so
/// they don't race other tests on shared env vars.
///
/// `cache: None` disables the cache for this call entirely (the
/// fetcher is always invoked, no read or write happens). That's
/// also the path taken when the user sets
/// `FREENET_GIT_PACK_CACHE=off` in production, since
/// `PackCache::from_environment` returns `None` in that case.
///
/// **Defense in depth:** even though `PackCache::read_async`
/// already verifies BLAKE3 on every cache hit, this function
/// re-verifies after the read. Belt-and-braces because a future
/// refactor of `PackCache::read` that drops verification (e.g.
/// "for performance") would silently turn the GET path into a
/// poison vector.
async fn get_pack_with_fetcher<F, Fut>(
    cache: Option<&crate::pack_cache::PackCache>,
    pack_hash: [u8; 32],
    fetcher: F,
) -> Result<Vec<u8>>
where
    F: FnOnce([u8; 32]) -> Fut,
    Fut: std::future::Future<Output = Result<Vec<u8>>>,
{
    if let Some(cache) = cache {
        if let Some(bytes) = cache.read_async(&pack_hash).await {
            let actual = *blake3::hash(&bytes).as_bytes();
            if actual == pack_hash {
                tracing::debug!(
                    "pack cache hit for {} ({} bytes)",
                    hex_lower(&pack_hash),
                    bytes.len()
                );
                return Ok(bytes);
            }
            tracing::warn!(
                "pack cache returned bytes whose BLAKE3 does not match key {}; falling through to network",
                hex_lower(&pack_hash),
            );
        }
    }
    let bytes = fetcher(pack_hash).await?;
    let actual = *blake3::hash(&bytes).as_bytes();
    if actual != pack_hash {
        bail!(
            "pack content hash mismatch: got {} expected {}",
            hex_lower(&actual),
            hex_lower(&pack_hash),
        );
    }
    // Cache the bytes we just verified. Writes are best-effort and
    // never fail the surrounding GET.
    if let Some(cache) = cache {
        cache.write_async(&pack_hash, &bytes).await;
    }
    Ok(bytes)
}

fn hex_lower(b: &[u8]) -> String {
    use std::fmt::Write as _;
    let mut s = String::with_capacity(b.len() * 2);
    for byte in b {
        let _ = write!(s, "{byte:02x}");
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use freenet_stdlib::prelude::{ContractCode, Parameters};

    /// `contract_id_from_wasm_hash` must produce exactly the same id
    /// as `ContractInstanceId::from_params_and_code` would, given the
    /// matching WASM bytes whose BLAKE3 we're shortcutting.
    #[test]
    fn legacy_id_derivation_matches_full_derivation() {
        let fake_wasm: Vec<u8> = (0..1024u32).map(|i| (i & 0xFF) as u8).collect();
        let wasm_hash = *blake3::hash(&fake_wasm).as_bytes();
        let params_bytes: Vec<u8> = b"test-params".to_vec();

        let full = ContractInstanceId::from_params_and_code(
            Parameters::from(params_bytes.clone()),
            ContractCode::from(fake_wasm),
        );
        let shortcut = contract_id_from_wasm_hash(&wasm_hash, &params_bytes);
        assert_eq!(full, shortcut);
    }

    /// Build a fresh ContractKey from a unique seed for tests.
    fn test_key(seed: u8) -> ContractKey {
        let wasm: Vec<u8> = vec![seed; 64];
        let params: Vec<u8> = vec![seed ^ 0x55; 32];
        ContractKey::from_params_and_code(Parameters::from(params), ContractCode::from(wasm))
    }

    #[test]
    fn dispatch_put_response_returns_success_for_matching_put_response() {
        let key = test_key(1);
        let response = HostResponse::ContractResponse(ContractResponse::PutResponse { key });
        match dispatch_put_response(response, &key) {
            PutDispatch::Success(got) => assert_eq!(got.id(), key.id()),
            PutDispatch::Continue => panic!("expected Success on matching PutResponse"),
        }
    }

    #[test]
    fn dispatch_put_response_continues_on_stale_put_response() {
        // The regression case for #9: an earlier PutResponse for a
        // different key sitting in the queue must not be mistaken for
        // ours and must not error. The recv loop just keeps waiting.
        let stale_key = test_key(1);
        let our_key = test_key(2);
        let response =
            HostResponse::ContractResponse(ContractResponse::PutResponse { key: stale_key });
        assert!(matches!(
            dispatch_put_response(response, &our_key),
            PutDispatch::Continue,
        ));
    }

    #[test]
    fn dispatch_put_response_treats_matching_update_notification_as_success() {
        let key = test_key(3);
        let response = HostResponse::ContractResponse(ContractResponse::UpdateNotification {
            key,
            update: freenet_stdlib::prelude::UpdateData::State(
                freenet_stdlib::prelude::State::from(vec![]).into_owned(),
            ),
        });
        assert!(matches!(
            dispatch_put_response(response, &key),
            PutDispatch::Success(_),
        ));
    }

    #[test]
    fn dispatch_put_response_skips_unrelated_update_notification() {
        let our_key = test_key(4);
        let other_key = test_key(5);
        let response = HostResponse::ContractResponse(ContractResponse::UpdateNotification {
            key: other_key,
            update: freenet_stdlib::prelude::UpdateData::State(
                freenet_stdlib::prelude::State::from(vec![]).into_owned(),
            ),
        });
        assert!(matches!(
            dispatch_put_response(response, &our_key),
            PutDispatch::Continue,
        ));
    }

    #[test]
    fn dispatch_put_response_treats_host_ok_as_success() {
        let key = test_key(6);
        assert!(matches!(
            dispatch_put_response(HostResponse::Ok, &key),
            PutDispatch::Success(_),
        ));
    }

    #[test]
    fn dispatch_get_response_returns_state_for_matching_get_response() {
        let key = test_key(10);
        let response = HostResponse::ContractResponse(ContractResponse::GetResponse {
            key,
            state: freenet_stdlib::prelude::WrappedState::new(b"hello".to_vec()),
            contract: None,
        });
        match dispatch_get_response(response, *key.id()) {
            GetDispatch::Terminal(bytes) => assert_eq!(bytes, b"hello"),
            GetDispatch::Continue => panic!("expected Terminal on matching GetResponse"),
        }
    }

    #[test]
    fn dispatch_get_response_continues_on_unrelated_get_response() {
        // A GetResponse for some other instance_id (e.g. from a prior
        // subscription's race or a multiplexed connection) must be
        // skipped, not mistaken for ours.
        let our_id = *test_key(11).id();
        let other_key = test_key(12);
        let response = HostResponse::ContractResponse(ContractResponse::GetResponse {
            key: other_key,
            state: freenet_stdlib::prelude::WrappedState::new(b"stale".to_vec()),
            contract: None,
        });
        assert!(matches!(
            dispatch_get_response(response, our_id),
            GetDispatch::Continue,
        ));
    }

    /// Regression for matrix dev-channel report 2026-05-15: the
    /// freenet-git rescue workflow hangs for the full per-op timeout
    /// (180s default) on contracts the gateway can't find on the
    /// network. Root cause is freenet-core PR #4076 (in v0.2.56)
    /// adding `ContractResponse::NotFound` as the terminal response
    /// from the task-per-tx GET driver on retry exhaustion; this
    /// client used to ignore that arm via the `_ =>` fallback.
    ///
    /// Treating `NotFound` for our key as `Terminal(empty)` lets
    /// `get_state_with_legacy_fallback` move on to the next legacy
    /// probe — or bail with "no state found at current contract key
    /// …" if none remain — instead of deadlocking the recv loop.
    #[test]
    fn dispatch_get_response_treats_not_found_as_terminal_for_our_key() {
        let our_id = *test_key(13).id();
        let response =
            HostResponse::ContractResponse(ContractResponse::NotFound { instance_id: our_id });
        match dispatch_get_response(response, our_id) {
            GetDispatch::Terminal(bytes) => assert!(
                bytes.is_empty(),
                "NotFound must surface as empty bytes so the legacy-fallback caller \
                 distinguishes it from a real GetResponse with state"
            ),
            GetDispatch::Continue => panic!(
                "regression: NotFound for our key must be a terminal outcome, \
                 not Continue (would deadlock the recv loop until rescue timeout)"
            ),
        }
    }

    #[test]
    fn dispatch_get_response_skips_not_found_for_unrelated_key() {
        // NotFound for a different contract (e.g. a sub-operation or a
        // multiplexed legacy-probe race) must not be mistaken for ours.
        let our_id = *test_key(14).id();
        let other_id = *test_key(15).id();
        let response = HostResponse::ContractResponse(ContractResponse::NotFound {
            instance_id: other_id,
        });
        assert!(matches!(
            dispatch_get_response(response, our_id),
            GetDispatch::Continue,
        ));
    }

    #[test]
    fn dispatch_get_response_skips_update_notification() {
        let our_id = *test_key(16).id();
        let other_key = test_key(17);
        let response = HostResponse::ContractResponse(ContractResponse::UpdateNotification {
            key: other_key,
            update: freenet_stdlib::prelude::UpdateData::State(
                freenet_stdlib::prelude::State::from(vec![]).into_owned(),
            ),
        });
        assert!(matches!(
            dispatch_get_response(response, our_id),
            GetDispatch::Continue,
        ));
    }

    #[test]
    fn dispatch_get_response_continues_on_unrelated_contract_response() {
        // Defends against silently swallowing a brand-new ContractResponse
        // variant. SubscribeResponse for an unrelated key should be
        // skipped, not mistaken for our GET.
        let our_id = *test_key(18).id();
        let other_key = test_key(19);
        let response = HostResponse::ContractResponse(ContractResponse::SubscribeResponse {
            key: other_key,
            subscribed: true,
        });
        assert!(matches!(
            dispatch_get_response(response, our_id),
            GetDispatch::Continue,
        ));
    }

    #[test]
    fn dispatch_put_response_continues_on_unrelated_contract_response() {
        // Defends against silently swallowing a brand-new ContractResponse
        // variant. SubscribeResponse for an unrelated key should be
        // skipped, not mistaken for our PUT confirmation.
        let our_key = test_key(7);
        let other_key = test_key(8);
        let response = HostResponse::ContractResponse(ContractResponse::SubscribeResponse {
            key: other_key,
            subscribed: true,
        });
        assert!(matches!(
            dispatch_put_response(response, &our_key),
            PutDispatch::Continue,
        ));
    }

    /// Regression guard: `get_pack` MUST consult the pack cache
    /// before doing the network GET, and a cache hit MUST NOT
    /// invoke the network fetcher. If a future refactor drops
    /// `cache.read_async` from `get_pack_with_fetcher`, this test
    /// fails because the panicking fetcher will fire.
    ///
    /// Uses an explicit `PackCache::at(tempdir)` so the test does
    /// not touch process-wide env vars and does not race the
    /// pack_cache module's own env-var tests.
    #[tokio::test]
    async fn get_pack_short_circuits_on_cache_hit() {
        let dir = tempfile::tempdir().unwrap();
        let cache = crate::pack_cache::PackCache::at(dir.path());

        let bytes: Vec<u8> = (0..2048u32).map(|i| (i & 0xFF) as u8).collect();
        let hash = *blake3::hash(&bytes).as_bytes();
        cache.write(&hash, &bytes);

        let got = super::get_pack_with_fetcher(Some(&cache), hash, |_h| async move {
            panic!("cache hit must short-circuit before fetcher fires");
        })
        .await
        .expect("cache hit must succeed");
        assert_eq!(got, bytes);
    }

    /// On a cache MISS, `get_pack_with_fetcher` must call the
    /// network fetcher, verify content addressing, and write the
    /// result back to the cache.
    #[tokio::test]
    async fn get_pack_falls_through_to_fetcher_on_miss() {
        let dir = tempfile::tempdir().unwrap();
        let cache = crate::pack_cache::PackCache::at(dir.path());

        let bytes: Vec<u8> = (0..512u32).map(|i| (i & 0xFF) as u8).collect();
        let hash = *blake3::hash(&bytes).as_bytes();
        let bytes_for_closure = bytes.clone();
        let got = super::get_pack_with_fetcher(Some(&cache), hash, |_h| async move {
            Ok::<Vec<u8>, anyhow::Error>(bytes_for_closure)
        })
        .await
        .expect("miss + fetcher success must return bytes");
        assert_eq!(got, bytes);

        // Post-miss: cache populated.
        let cached = cache
            .read(&hash)
            .expect("cache must be populated after miss");
        assert_eq!(cached, bytes);
    }

    /// A fetcher returning bytes whose BLAKE3 doesn't match the
    /// requested hash MUST surface as an error (`bail!`) and MUST
    /// NOT poison the cache. This is the host-tampering defence.
    #[tokio::test]
    async fn get_pack_rejects_fetcher_bytes_with_wrong_hash() {
        let dir = tempfile::tempdir().unwrap();
        let cache = crate::pack_cache::PackCache::at(dir.path());

        let claimed_hash = [0xCDu8; 32];
        let err = super::get_pack_with_fetcher(Some(&cache), claimed_hash, |_h| async move {
            // Bytes that obviously don't hash to claimed_hash.
            Ok::<Vec<u8>, anyhow::Error>(b"wrong bytes for this hash".to_vec())
        })
        .await
        .expect_err("hash mismatch must surface as error");
        assert!(
            err.to_string().contains("pack content hash mismatch"),
            "error must name the mismatch: {err}"
        );
        // Cache must NOT be populated with the bad bytes.
        assert!(
            cache.read(&claimed_hash).is_none(),
            "cache must NOT be populated when fetcher returns wrong bytes"
        );
    }

    /// `cache: None` (cache disabled / unavailable) must always
    /// hit the fetcher; no cache-related branching at all.
    #[tokio::test]
    async fn get_pack_with_no_cache_always_calls_fetcher() {
        let bytes: Vec<u8> = (0..256u32).map(|i| (i & 0xFF) as u8).collect();
        let hash = *blake3::hash(&bytes).as_bytes();
        let bytes_for_closure = bytes.clone();
        let got = super::get_pack_with_fetcher(None, hash, |_h| async move {
            Ok::<Vec<u8>, anyhow::Error>(bytes_for_closure)
        })
        .await
        .expect("no-cache + fetcher success must return bytes");
        assert_eq!(got, bytes);
    }
}
