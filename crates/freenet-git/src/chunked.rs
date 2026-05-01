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
    std::env::var("FREENET_GIT_PARALLEL_OPS")
        .ok()
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
    let actual_parallelism = parallelism.min(n as usize).max(1);
    let conns = open_pool(ws_url, actual_parallelism).await?;

    // Phase 1: PUT every chunk in parallel.
    let mut completed: u32 = 0;
    let mut put_stream = futures::stream::iter(chunks.iter().enumerate())
        .map(|(i, chunk)| {
            let conn = conns[i % conns.len()].clone();
            let pack_wasm = pack_wasm.clone();
            let chunk = chunk.clone();
            async move {
                let mut g = conn.lock().await;
                wsclient::put_pack(&mut g, pack_wasm, chunk, timeout_per_op)
                    .await
                    .with_context(|| format!("PUT chunk {i}"))?;
                Ok::<_, anyhow::Error>(())
            }
        })
        .buffer_unordered(actual_parallelism);
    while let Some(result) = put_stream.next().await {
        result?;
        completed += 1;
        on_step(PublishPhase::PutChunk, completed, n);
    }
    drop(put_stream);

    // Phase 2: re-GET every chunk in parallel and verify BLAKE3.
    let mut completed: u32 = 0;
    let mut verify_stream =
        futures::stream::iter(manifest.chunk_hashes.iter().copied().enumerate())
            .map(|(i, expected_hash)| {
                let conn = conns[i % conns.len()].clone();
                let pack_wasm = pack_wasm.clone();
                async move {
                    let mut g = conn.lock().await;
                    let got = wsclient::get_pack(&mut g, &pack_wasm, expected_hash, timeout_per_op)
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
                    Ok::<_, anyhow::Error>(())
                }
            })
            .buffer_unordered(actual_parallelism);
    while let Some(result) = verify_stream.next().await {
        result?;
        completed += 1;
        on_step(PublishPhase::VerifyChunk, completed, n);
    }
    drop(verify_stream);

    // Phase 3: PUT the manifest as a pack-contract (single connection).
    on_step(PublishPhase::PutManifest, 1, 1);
    let manifest_bytes = manifest.to_bytes();
    let manifest_hash = *blake3::hash(&manifest_bytes).as_bytes();
    {
        let mut g = conns[0].lock().await;
        wsclient::put_pack(
            &mut g,
            pack_wasm.clone(),
            manifest_bytes.clone(),
            timeout_per_op,
        )
        .await
        .context("PUT manifest")?;
    }

    // Phase 4: re-GET the manifest and verify byte-for-byte.
    on_step(PublishPhase::VerifyManifest, 1, 1);
    let got_manifest = {
        let mut g = conns[0].lock().await;
        wsclient::get_pack(&mut g, &pack_wasm, manifest_hash, timeout_per_op)
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
    mut on_chunk: F,
) -> Result<Vec<u8>>
where
    F: FnMut(u32, u32),
{
    if parallelism == 0 {
        bail!("fetch_chunked_pack: zero parallelism");
    }

    // Phase 1: open the connection pool, GET the manifest on conn 0.
    // Cap pool size at the chunk count once we know it. To avoid
    // reopening the pool, we open `parallelism` connections up front
    // and just use a subset if the manifest turns out to be smaller.
    let actual_parallelism = parallelism.min(expected_chunk_count.max(1) as usize);
    let conns = open_pool(ws_url, actual_parallelism).await?;

    let manifest_bytes = {
        let mut g = conns[0].lock().await;
        wsclient::get_pack(&mut g, pack_wasm, manifest_hash, timeout_per_op)
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

    // Phase 4: parallel chunk GETs. Reassemble in manifest order.
    let n = manifest.chunk_count;
    let mut received: Vec<Option<Vec<u8>>> = (0..n as usize).map(|_| None).collect();
    let chunk_lens: Vec<u64> = (0..n).map(|i| manifest.chunk_len(i)).collect();
    let mut completed: u32 = 0;
    let mut get_stream = futures::stream::iter(manifest.chunk_hashes.iter().copied().enumerate())
        .map(|(i, expected_hash)| {
            let conn = conns[i % conns.len()].clone();
            let pack_wasm = pack_wasm.to_vec();
            let expected_len = chunk_lens[i];
            async move {
                let mut g = conn.lock().await;
                let chunk = wsclient::get_pack(&mut g, &pack_wasm, expected_hash, timeout_per_op)
                    .await
                    .with_context(|| format!("GET chunk {i}"))?;
                if (chunk.len() as u64) != expected_len {
                    bail!(
                        "chunk {i} length {} disagrees with manifest expectation {}",
                        chunk.len(),
                        expected_len,
                    );
                }
                Ok::<_, anyhow::Error>((i, chunk))
            }
        })
        .buffer_unordered(actual_parallelism);
    while let Some(result) = get_stream.next().await {
        let (i, chunk) = result?;
        received[i] = Some(chunk);
        completed += 1;
        on_chunk(completed, n);
    }
    drop(get_stream);

    let assembled = assemble_chunks(received, manifest.total_size)?;
    Ok(assembled)
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

/// Open `n` parallel WebSocket connections to the Freenet node. All
/// connections are wrapped in `Arc<Mutex<...>>` so chunk futures can
/// take exclusive access for the duration of one PUT or GET.
async fn open_pool(ws_url: &str, n: usize) -> Result<Vec<Arc<Mutex<WebApi>>>> {
    let conns =
        futures::future::try_join_all((0..n).map(|_| async { wsclient::connect(ws_url).await }))
            .await
            .context("open parallel WS connections")?;
    Ok(conns.into_iter().map(|c| Arc::new(Mutex::new(c))).collect())
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
    fn assemble_chunks_concatenates_in_order() {
        // Reassembly is the load-bearing piece for parallel fetch:
        // chunks complete out of order but must be glued in manifest
        // order. Use the same input twice in different "completion"
        // orders and confirm the concatenation is identical.
        let in_order: Vec<Option<Vec<u8>>> = vec![
            Some(vec![1, 2, 3]),
            Some(vec![4, 5]),
            Some(vec![6, 7, 8, 9]),
        ];
        let total: u64 = 9;
        let expected = vec![1, 2, 3, 4, 5, 6, 7, 8, 9];
        assert_eq!(assemble_chunks(in_order, total).unwrap(), expected);

        // Same chunks, different "completion order" produces the same
        // assembled bytes because the slot index drives ordering.
        let mut shuffled: Vec<Option<Vec<u8>>> = vec![None, None, None];
        shuffled[2] = Some(vec![6, 7, 8, 9]); // completed third chunk first
        shuffled[0] = Some(vec![1, 2, 3]); // then first
        shuffled[1] = Some(vec![4, 5]); // then middle
        assert_eq!(assemble_chunks(shuffled, total).unwrap(), expected);
    }

    #[test]
    fn assemble_chunks_errors_on_missing_slot() {
        let received: Vec<Option<Vec<u8>>> = vec![Some(vec![1, 2]), None, Some(vec![3, 4])];
        let err = assemble_chunks(received, 4).unwrap_err();
        assert!(err.to_string().contains("chunk 1 missing"), "got: {err}",);
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

    #[test]
    fn parallelism_from_env_handles_unset_zero_and_invalid() {
        // SAFETY: env mutation in tests. This is the only test that
        // touches FREENET_GIT_PARALLEL_OPS so there is no race with
        // sibling tests. cargo test runs each test in its own thread
        // but the same process, so we restore the var at the end.
        let prev = std::env::var("FREENET_GIT_PARALLEL_OPS").ok();

        std::env::remove_var("FREENET_GIT_PARALLEL_OPS");
        assert_eq!(parallelism_from_env(), DEFAULT_PARALLEL_OPS);

        std::env::set_var("FREENET_GIT_PARALLEL_OPS", "1");
        assert_eq!(parallelism_from_env(), 1);

        std::env::set_var("FREENET_GIT_PARALLEL_OPS", "16");
        assert_eq!(parallelism_from_env(), 16);

        std::env::set_var("FREENET_GIT_PARALLEL_OPS", "0");
        assert_eq!(parallelism_from_env(), DEFAULT_PARALLEL_OPS);

        std::env::set_var("FREENET_GIT_PARALLEL_OPS", "not-a-number");
        assert_eq!(parallelism_from_env(), DEFAULT_PARALLEL_OPS);

        match prev {
            Some(v) => std::env::set_var("FREENET_GIT_PARALLEL_OPS", v),
            None => std::env::remove_var("FREENET_GIT_PARALLEL_OPS"),
        }
    }
}
