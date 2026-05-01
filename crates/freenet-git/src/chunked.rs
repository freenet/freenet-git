//! ChunkedPack publish and fetch flows for the on-host helper.
//!
//! Chunked-pack publish is a four-phase commit:
//!
//! ```text
//! 1. PUT every chunk contract.
//! 2. Re-GET each chunk; verify BLAKE3(bytes) == declared hash.
//! 3. PUT the manifest contract.
//! 4. Re-GET the manifest; verify BLAKE3(manifest_bytes) == manifest_hash.
//! 5. (Caller) Sign and submit the BundleAdd delta to the repo contract.
//! ```
//!
//! The forbidden case (the repo state advancing while the chunks or
//! manifest are not yet remotely retrievable) is impossible because
//! step 5 only runs after step 2 and step 4 have re-GET-verified.
//! Crashes between steps 1 and 5 produce harmless orphan contracts on
//! the network; the next push does not reference them and they evict
//! naturally.
//!
//! ## Parallelism
//!
//! Chunk PUTs and chunk GETs run concurrently across a small pool of
//! WebSocket connections to the local Freenet node (see
//! [`DEFAULT_PARALLEL_OPS`] and [`parallelism_from_env`]). The pool
//! size is bounded so the local node and the wider network are not
//! flooded; each chunk is dispatched to one of N connections via
//! round-robin (`chunk_index % N`). The manifest PUT and re-GET use
//! the first connection because they are single-shot.
//!
//! The round-robin assignment assumes per-chunk latency is roughly
//! uniform. If one chunk on connection `k` takes much longer than
//! its siblings, every chunk where `i % N == k` queues behind it,
//! so the realized speedup degrades from N-way toward 1-way for
//! that subset. This is acceptable for content-addressed PUT/GET
//! (where most chunks are similar size and the bottleneck is per-op
//! network confirmation) but worth noting if a future change makes
//! per-chunk costs more variable.
//!
//! See [`docs/0001-large-repos.md`](../../../../docs/0001-large-repos.md)
//! for the full design.

use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context, Result};
use freenet_git_types::chunked::{split_pack, ChunkedPackManifestV1};
use freenet_git_types::ObjectBundle;
use freenet_stdlib::client_api::WebApi;
use futures::stream::StreamExt;
use tokio::sync::Mutex;

use crate::wsclient;

/// Default number of parallel chunk operations (PUTs / GETs). 8 was
/// chosen as a balance between speedup and avoiding flood-load on the
/// local node and the wider network. Override with
/// [`parallelism_from_env`] reading `FREENET_GIT_PARALLEL_OPS`.
pub const DEFAULT_PARALLEL_OPS: usize = 8;

/// Read the parallel-ops setting from `FREENET_GIT_PARALLEL_OPS`,
/// falling back to [`DEFAULT_PARALLEL_OPS`]. A value of 0 or a
/// non-integer falls back to the default; a serial run can be forced
/// with `FREENET_GIT_PARALLEL_OPS=1`.
pub fn parallelism_from_env() -> usize {
    parse_parallelism(std::env::var("FREENET_GIT_PARALLEL_OPS").as_deref().ok())
}

/// Pure parser for `FREENET_GIT_PARALLEL_OPS`. Split out from
/// [`parallelism_from_env`] so unit tests can exercise it without
/// mutating process-wide environment variables (which is `unsafe` to
/// do concurrently).
fn parse_parallelism(value: Option<&str>) -> usize {
    value
        .and_then(|s| s.parse::<usize>().ok())
        .filter(|&n| n > 0)
        .unwrap_or(DEFAULT_PARALLEL_OPS)
}

/// Result of a chunked-pack publish: the [`ObjectBundle`] the caller
/// should reference in its `BundleAdd` delta to the repo contract.
#[derive(Debug, Clone)]
pub struct PublishedChunkedPack {
    /// The bundle entry to drop into `RepoState.object_index`.
    pub bundle: ObjectBundle,
    /// Number of chunks actually PUT (== `manifest.chunk_count`).
    pub chunk_count: u32,
    /// Total bytes published (== `manifest.total_size`, == original pack size).
    pub total_size: u64,
}

/// Phase that the publish state machine is in. The CLI uses this
/// to emit user-visible progress lines.
#[derive(Debug, Clone, Copy)]
pub enum PublishPhase {
    /// A chunk PUT just completed. `i` is the count of chunks PUT so
    /// far including the just-completed one (1-indexed); `n` is the
    /// total. Chunk PUTs run in parallel so completion order is not
    /// the index order.
    PutChunk,
    /// A chunk verification re-GET just completed. Same indexing
    /// semantics as [`PutChunk`](PublishPhase::PutChunk).
    VerifyChunk,
    /// PUTting the manifest. Fired once before the manifest PUT
    /// starts. `i` is 1, `n` is 1.
    PutManifest,
    /// Re-GETting the manifest for verification. Fired once before
    /// the manifest re-GET starts. `i` is 1, `n` is 1.
    VerifyManifest,
}

/// Publish a packfile as a [`ObjectBundle::ChunkedPack`].
///
/// Splits `pack_bytes` into chunks of `chunk_size`, PUTs each chunk
/// as a `pack-contract` instance (in parallel across N connections),
/// builds the manifest, PUTs the manifest, and re-GET-verifies
/// everything before returning. The caller is responsible for signing
/// and submitting the resulting [`PublishedChunkedPack::bundle`] in a
/// `BundleAdd` delta to the repo contract, only after this function
/// returns successfully.
///
/// `parallelism` defaults to [`parallelism_from_env`] which honors
/// `FREENET_GIT_PARALLEL_OPS`. The caller can also pass a fixed value
/// via [`publish_chunked_pack_with_progress`].
pub async fn publish_chunked_pack(
    ws_url: &str,
    pack_wasm: Vec<u8>,
    pack_bytes: Vec<u8>,
    chunk_size: u32,
    timeout_per_op: Duration,
) -> Result<PublishedChunkedPack> {
    publish_chunked_pack_with_progress(
        ws_url,
        pack_wasm,
        pack_bytes,
        chunk_size,
        parallelism_from_env(),
        timeout_per_op,
        |_, _, _| {},
    )
    .await
}

/// Publish a packfile as a [`ObjectBundle::ChunkedPack`] with
/// per-step progress callbacks. Same semantics as
/// [`publish_chunked_pack`]; the callback fires once per completed
/// chunk PUT, once per completed verification re-GET, and once each
/// at the start of the manifest PUT and verification.
#[allow(clippy::too_many_arguments)]
pub async fn publish_chunked_pack_with_progress<F>(
    ws_url: &str,
    pack_wasm: Vec<u8>,
    pack_bytes: Vec<u8>,
    chunk_size: u32,
    parallelism: usize,
    timeout_per_op: Duration,
    mut on_step: F,
) -> Result<PublishedChunkedPack>
where
    F: FnMut(PublishPhase, u32, u32),
{
    if pack_bytes.is_empty() {
        bail!("publish_chunked_pack: empty pack");
    }
    if chunk_size == 0 {
        bail!("publish_chunked_pack: zero chunk_size");
    }
    if parallelism == 0 {
        bail!("publish_chunked_pack: zero parallelism");
    }

    let chunks = split_pack(&pack_bytes, chunk_size);
    let manifest = ChunkedPackManifestV1::from_chunks(chunk_size, &chunks);
    manifest
        .validate()
        .context("manifest self-check before publish")?;

    let n = manifest.chunk_count;
    // Open the pool first; `open_pool` may return fewer connections
    // than requested (graceful degradation). Use the actual pool size
    // as the parallelism for `buffer_unordered` so we never schedule
    // more concurrent ops than connections.
    let conns = open_pool(ws_url, parallelism.min((n as usize).max(1))).await?;
    let actual_parallelism = conns.len();

    // INVARIANT: chunks are dispatched to connections by `i % conns.len()`,
    // and `buffer_unordered(actual_parallelism)` schedules at most
    // `conns.len()` futures concurrently while pulling from the iterator
    // in strict order. Together these guarantee that the first `N` futures
    // map 1:1 to the `N` connections, and each subsequent future does not
    // start until a sibling on its assigned connection has finished and
    // released the mutex. So the round-robin gives us full parallelism
    // without inter-chunk contention as long as `buffer_unordered`'s
    // concurrency cap matches `conns.len()`.

    // Wrap the WASM blob in Arc so chunk tasks share one allocation
    // across both phases (refcount bump per task instead of deep
    // clone). Both put_pack and get_pack take `&[u8]`, so the Arc
    // hands out `&pack_wasm` directly. The wsclient layer clones
    // internally only on retry, scoped to put_contract's lifetime.
    let pack_wasm = Arc::new(pack_wasm);

    // Phase 1: PUT every chunk in parallel.
    let mut puts_completed: u32 = 0;
    let mut put_stream = futures::stream::iter(chunks.into_iter().enumerate())
        .map(|(i, chunk)| {
            let conn = conns[i % conns.len()].clone();
            let pack_wasm = pack_wasm.clone();
            async move {
                let mut conn = conn.lock().await;
                wsclient::put_pack(&mut conn, &pack_wasm, chunk, timeout_per_op)
                    .await
                    .with_context(|| format!("PUT chunk {i}"))?;
                anyhow::Ok(())
            }
        })
        .buffer_unordered(actual_parallelism);
    while let Some(result) = put_stream.next().await {
        result?;
        puts_completed += 1;
        on_step(PublishPhase::PutChunk, puts_completed, n);
    }

    // Phase 2: re-GET every chunk in parallel and verify BLAKE3.
    // (The BLAKE3 check inside `wsclient::get_pack` already enforces
    // content-addressing, so the explicit `got_hash != expected_hash`
    // check below is belt-and-braces; we keep it because the
    // post-publish verification phase is the one place where a
    // host-level bug should not silently slip through.)
    let mut verifies_completed: u32 = 0;
    let mut verify_stream =
        futures::stream::iter(manifest.chunk_hashes.iter().copied().enumerate())
            .map(|(i, expected_hash)| {
                let conn = conns[i % conns.len()].clone();
                let pack_wasm = pack_wasm.clone();
                async move {
                    let mut conn = conn.lock().await;
                    let got =
                        wsclient::get_pack(&mut conn, &pack_wasm, expected_hash, timeout_per_op)
                            .await
                            .with_context(|| format!("re-GET chunk {i} for verification"))?;
                    let got_hash = *blake3::hash(&got).as_bytes();
                    if got_hash != expected_hash {
                        bail!(
                            "chunk {i} verification failed: got {} expected {}",
                            hex_lower(&got_hash),
                            hex_lower(&expected_hash),
                        );
                    }
                    anyhow::Ok(())
                }
            })
            .buffer_unordered(actual_parallelism);
    while let Some(result) = verify_stream.next().await {
        result?;
        verifies_completed += 1;
        on_step(PublishPhase::VerifyChunk, verifies_completed, n);
    }

    // Phase 3: PUT the manifest as a pack-contract (single connection).
    on_step(PublishPhase::PutManifest, 1, 1);
    let manifest_bytes = manifest.to_bytes();
    let manifest_hash = *blake3::hash(&manifest_bytes).as_bytes();
    {
        let mut conn = conns[0].lock().await;
        wsclient::put_pack(
            &mut conn,
            &pack_wasm,
            manifest_bytes.clone(),
            timeout_per_op,
        )
        .await
        .context("PUT manifest")?;
    }

    // Phase 4: re-GET the manifest and verify byte-for-byte.
    on_step(PublishPhase::VerifyManifest, 1, 1);
    let got_manifest = {
        let mut conn = conns[0].lock().await;
        wsclient::get_pack(&mut conn, &pack_wasm, manifest_hash, timeout_per_op)
            .await
            .context("re-GET manifest for verification")?
    };
    if got_manifest != manifest_bytes {
        bail!("manifest re-GET returned different bytes");
    }

    Ok(PublishedChunkedPack {
        bundle: ObjectBundle::ChunkedPack {
            manifest_hash,
            total_size: manifest.total_size,
            chunk_count: manifest.chunk_count,
        },
        chunk_count: manifest.chunk_count,
        total_size: manifest.total_size,
    })
}

/// Fetch and reassemble a [`ObjectBundle::ChunkedPack`] without
/// progress feedback. See [`fetch_chunked_pack_with_progress`] for
/// the variant that calls back per chunk for CLI feedback.
pub async fn fetch_chunked_pack(
    ws_url: &str,
    pack_wasm: &[u8],
    manifest_hash: [u8; 32],
    expected_total_size: u64,
    expected_chunk_count: u32,
    timeout_per_op: Duration,
) -> Result<Vec<u8>> {
    fetch_chunked_pack_with_progress(
        ws_url,
        pack_wasm,
        manifest_hash,
        expected_total_size,
        expected_chunk_count,
        parallelism_from_env(),
        timeout_per_op,
        |_, _| {},
    )
    .await
}

/// Fetch and reassemble a [`ObjectBundle::ChunkedPack`] with
/// per-chunk progress callbacks. The callback fires once per chunk
/// when the GET completes; with `parallelism > 1` the calls fire in
/// completion order, not in chunk-index order. The first argument is
/// the count of chunks completed so far including this one
/// (1-indexed), the second is the total.
///
/// 1. GET the manifest by `manifest_hash`. Verify
///    `BLAKE3 == manifest_hash`.
/// 2. Decode the manifest. Re-validate internal consistency rules.
/// 3. Verify `total_size` and `chunk_count` from the bundle entry
///    match the manifest. **Mismatch fails hard.**
/// 4. GET each chunk in parallel across `parallelism` connections.
///    Verify `BLAKE3(chunk_i) == manifest.chunk_hashes[i]`. Verify
///    chunk length matches the manifest's expectation (`chunk_size`
///    for non-final, computed remainder for final).
/// 5. Concatenate in **manifest order** (not completion order) and
///    return.
#[allow(clippy::too_many_arguments)]
pub async fn fetch_chunked_pack_with_progress<F>(
    ws_url: &str,
    pack_wasm: &[u8],
    manifest_hash: [u8; 32],
    expected_total_size: u64,
    expected_chunk_count: u32,
    parallelism: usize,
    timeout_per_op: Duration,
    on_chunk: F,
) -> Result<Vec<u8>>
where
    F: FnMut(u32, u32),
{
    if parallelism == 0 {
        bail!("fetch_chunked_pack: zero parallelism");
    }

    // Phase 1: open the connection pool, GET the manifest on conn 0.
    // We open up to `parallelism` connections, capped at the expected
    // chunk count; `open_pool` may also return fewer if the node
    // refuses extras (graceful degradation). The actual pool size is
    // then used for `buffer_unordered` so chunk dispatch never
    // exceeds connection availability.
    let conns = open_pool(
        ws_url,
        parallelism.min(expected_chunk_count.max(1) as usize),
    )
    .await?;
    let actual_parallelism = conns.len();

    let manifest_bytes = {
        let mut conn = conns[0].lock().await;
        wsclient::get_pack(&mut conn, pack_wasm, manifest_hash, timeout_per_op)
            .await
            .context("GET manifest")?
    };

    // Phase 2: decode and re-validate.
    let manifest = ChunkedPackManifestV1::from_bytes(&manifest_bytes).context("decode manifest")?;

    // Phase 3: authority check. Bundle entry must agree with manifest.
    if manifest.total_size != expected_total_size {
        bail!(
            "object_index entry total_size {} disagrees with manifest {}",
            expected_total_size,
            manifest.total_size,
        );
    }
    if manifest.chunk_count != expected_chunk_count {
        bail!(
            "object_index entry chunk_count {} disagrees with manifest {}",
            expected_chunk_count,
            manifest.chunk_count,
        );
    }

    // Phase 4: parallel chunk GETs. Reassemble in manifest order via
    // `collect_chunks_into_slots`, which is split out so the slot-by-
    // index reassembly is unit-testable without spinning up real WS
    // connections.
    let n = manifest.chunk_count;
    let chunk_lens: Vec<u64> = (0..n).map(|i| manifest.chunk_len(i)).collect();
    // Share the WASM blob across chunk tasks via Arc so each task only
    // bumps a refcount instead of deep-cloning the WASM bytes.
    let pack_wasm: Arc<Vec<u8>> = Arc::new(pack_wasm.to_vec());
    let get_stream = futures::stream::iter(manifest.chunk_hashes.iter().copied().enumerate())
        .map(|(i, expected_hash)| {
            let conn = conns[i % conns.len()].clone();
            let pack_wasm = pack_wasm.clone();
            let expected_len = chunk_lens[i];
            async move {
                let mut conn = conn.lock().await;
                let chunk =
                    wsclient::get_pack(&mut conn, &pack_wasm, expected_hash, timeout_per_op)
                        .await
                        .with_context(|| format!("GET chunk {i}"))?;
                if (chunk.len() as u64) != expected_len {
                    bail!(
                        "chunk {i} length {} disagrees with manifest expectation {}",
                        chunk.len(),
                        expected_len,
                    );
                }
                anyhow::Ok((i, chunk))
            }
        })
        .buffer_unordered(actual_parallelism);
    let received = collect_chunks_into_slots(get_stream, n, on_chunk).await?;
    assemble_chunks(received, manifest.total_size)
}

/// Drain a stream of `(chunk_index, chunk_bytes)` results into a
/// `Vec<Option<Vec<u8>>>` indexed by manifest position. Fires
/// `on_chunk(completed_count, total)` on each successful completion.
/// This is the consumer half of the parallel fetch path; pulling it
/// out lets us unit-test the "completion order does not affect slot
/// placement" invariant without a real `WebApi`.
async fn collect_chunks_into_slots<S, F>(
    stream: S,
    n: u32,
    mut on_chunk: F,
) -> Result<Vec<Option<Vec<u8>>>>
where
    S: futures::Stream<Item = Result<(usize, Vec<u8>)>>,
    F: FnMut(u32, u32),
{
    use futures::pin_mut;
    pin_mut!(stream);
    let mut received: Vec<Option<Vec<u8>>> = vec![None; n as usize];
    let mut completed: u32 = 0;
    while let Some(result) = stream.next().await {
        let (i, chunk) = result?;
        received[i] = Some(chunk);
        completed += 1;
        on_chunk(completed, n);
    }
    Ok(received)
}

/// Concatenate per-chunk byte vectors in manifest order. Errors if any
/// slot is `None` (a chunk failed to arrive), which should be
/// unreachable when called after a successful parallel-GET stream.
/// Errors if the assembled length disagrees with `expected_total_size`.
fn assemble_chunks(received: Vec<Option<Vec<u8>>>, expected_total_size: u64) -> Result<Vec<u8>> {
    let mut assembled = Vec::with_capacity(expected_total_size as usize);
    for (i, slot) in received.into_iter().enumerate() {
        let chunk = slot.ok_or_else(|| anyhow::anyhow!("chunk {i} missing during reassembly"))?;
        assembled.extend_from_slice(&chunk);
    }
    if (assembled.len() as u64) != expected_total_size {
        bail!(
            "assembled length {} disagrees with manifest total_size {}",
            assembled.len(),
            expected_total_size,
        );
    }
    Ok(assembled)
}

/// Open up to `n` parallel WebSocket connections to the Freenet
/// node. **Degrades gracefully**: if the node refuses additional
/// connections (e.g. it caps the per-client limit) we proceed with
/// however many we did get, so a parallelism setting that the host
/// can't honor produces a slower run rather than an outright
/// failure. We only error if we cannot open even one connection,
/// since the pre-parallel implementation managed with one.
///
/// All connections are wrapped in `Arc<Mutex<...>>` so chunk futures
/// can take exclusive access for the duration of one PUT or GET.
async fn open_pool(ws_url: &str, n: usize) -> Result<Vec<Arc<Mutex<WebApi>>>> {
    let mut pool = Vec::with_capacity(n);
    for _ in 0..n {
        match wsclient::connect(ws_url).await {
            Ok(conn) => pool.push(Arc::new(Mutex::new(conn))),
            Err(e) if !pool.is_empty() => {
                tracing::warn!(
                    "opened {}/{} parallel WS connections; falling back: {e:#}",
                    pool.len(),
                    n,
                );
                break;
            }
            Err(e) => return Err(e).context("open at least one WS connection"),
        }
    }
    Ok(pool)
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

    #[test]
    fn assemble_chunks_concatenates_in_slot_order() {
        let in_order: Vec<Option<Vec<u8>>> = vec![
            Some(vec![1, 2, 3]),
            Some(vec![4, 5]),
            Some(vec![6, 7, 8, 9]),
        ];
        assert_eq!(
            assemble_chunks(in_order, 9).unwrap(),
            vec![1, 2, 3, 4, 5, 6, 7, 8, 9],
        );
    }

    #[test]
    fn assemble_chunks_errors_on_missing_slot() {
        let received: Vec<Option<Vec<u8>>> = vec![Some(vec![1, 2]), None, Some(vec![3, 4])];
        let err = assemble_chunks(received, 4).unwrap_err();
        assert!(err.to_string().contains("chunk 1 missing"), "got: {err}");
    }

    #[test]
    fn assemble_chunks_errors_on_total_size_mismatch() {
        let received: Vec<Option<Vec<u8>>> = vec![Some(vec![1, 2]), Some(vec![3])];
        let err = assemble_chunks(received, 99).unwrap_err();
        assert!(
            err.to_string()
                .contains("disagrees with manifest total_size"),
            "got: {err}",
        );
    }

    #[tokio::test]
    async fn collect_chunks_lands_in_correct_slots_regardless_of_completion_order() {
        // Drive the consumer with chunks finishing in a deliberately
        // wrong order. Slot 0 must end up holding chunk-index-0's
        // bytes regardless of when it arrived.
        let items: Vec<Result<(usize, Vec<u8>)>> = vec![
            Ok((2, vec![6, 7, 8, 9])), // chunk index 2 arrives first
            Ok((0, vec![1, 2, 3])),    // chunk index 0 arrives second
            Ok((1, vec![4, 5])),       // chunk index 1 arrives last
        ];
        let stream = futures::stream::iter(items);
        let mut progress: Vec<(u32, u32)> = Vec::new();
        let received = collect_chunks_into_slots(stream, 3, |done, total| {
            progress.push((done, total));
        })
        .await
        .unwrap();
        assert_eq!(received[0], Some(vec![1, 2, 3]));
        assert_eq!(received[1], Some(vec![4, 5]));
        assert_eq!(received[2], Some(vec![6, 7, 8, 9]));
        // Progress fires in completion order with monotonic count.
        assert_eq!(progress, vec![(1, 3), (2, 3), (3, 3)]);
    }

    #[tokio::test]
    async fn collect_chunks_propagates_errors_and_does_not_advance_progress() {
        let items: Vec<Result<(usize, Vec<u8>)>> = vec![
            Ok((0, vec![1])),
            Err(anyhow::anyhow!("simulated chunk failure")),
            Ok((2, vec![3])),
        ];
        let stream = futures::stream::iter(items);
        let mut progress: Vec<(u32, u32)> = Vec::new();
        let result = collect_chunks_into_slots(stream, 3, |done, total| {
            progress.push((done, total));
        })
        .await;
        assert!(result.is_err());
        // Progress fired only for the successful first chunk; the
        // error short-circuits before the callback fires for the
        // second item.
        assert_eq!(progress, vec![(1, 3)]);
    }

    #[test]
    fn parse_parallelism_handles_all_inputs() {
        assert_eq!(parse_parallelism(None), DEFAULT_PARALLEL_OPS);
        assert_eq!(parse_parallelism(Some("1")), 1);
        assert_eq!(parse_parallelism(Some("16")), 16);
        assert_eq!(parse_parallelism(Some("0")), DEFAULT_PARALLEL_OPS);
        assert_eq!(parse_parallelism(Some("")), DEFAULT_PARALLEL_OPS);
        assert_eq!(
            parse_parallelism(Some("not-a-number")),
            DEFAULT_PARALLEL_OPS
        );
        assert_eq!(parse_parallelism(Some("-1")), DEFAULT_PARALLEL_OPS);
    }
}
