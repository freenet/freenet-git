//! End-to-end exercise of the legacy-contract migration fallback.
//!
//! Freenet contract keys are content-addressed
//! (`BLAKE3(BLAKE3(wasm) || params)`), so any change to the
//! repo-contract WASM re-keys every repo and orphans the state stored
//! under the old key. `legacy_contracts.toml` plus
//! [`wsclient::get_state_with_legacy_fallback`] is this crate's remedy:
//! record the predecessor WASM hashes, and on a miss at the current key
//! walk backwards through them.
//!
//! That registry has been empty since it was introduced (2026-04-30),
//! legitimately so — the committed contract WASM has not changed since,
//! so no re-key has happened. The consequence is that the fallback's
//! *sequencing* has never executed with a non-empty legacy list, in
//! production or in CI. The existing unit tests all cover pieces in
//! isolation (`dispatch_get_response`, `ProbeOutcome`,
//! `outcomes_worth_retrying`, `format_fallback_failure`,
//! `contract_id_from_wasm_hash`); none of them makes the code walk a
//! predecessor key and hand back what it found.
//!
//! These tests close that gap by driving the real client against a fake
//! gateway over a real loopback WebSocket (see `support/fake_gateway`).
//!
//! ## Oracle independence
//!
//! Every legacy instance id these tests expect is derived with the
//! *stdlib's* `ContractInstanceId::from_params_and_code` over synthetic
//! predecessor WASM bytes. The code under test derives the same id via
//! `wsclient::contract_id_from_wasm_hash`, which shortcuts the
//! `BLAKE3(code)` step. Deriving the expectation with the shortcut
//! would make the test self-consistent rather than correct: it would
//! keep passing if the shortcut drifted from the real key derivation
//! and every migration probed the wrong key. The gateway stores state
//! under the stdlib-derived id, so a drifted shortcut probes an id the
//! gateway does not know and the test fails.

#[path = "support/fake_gateway.rs"]
mod fake_gateway;

use std::collections::HashMap;

use fake_gateway::{FakeGateway, Reply, FAST_PROBE_TIMEOUT};
use freenet_git_cli::wsclient::{self, GetSource};
use freenet_stdlib::prelude::{ContractCode, ContractInstanceId, Parameters};

/// Synthetic stand-in for the repo-contract WASM of some freenet-git
/// release. Content is irrelevant; only its BLAKE3 matters, and each
/// `tag` yields a distinct hash and therefore a distinct contract key.
fn synthetic_wasm(tag: u8) -> Vec<u8> {
    let mut bytes = b"\0asm\x01\0\0\0synthetic-repo-contract-".to_vec();
    bytes.extend(std::iter::repeat_n(tag, 512));
    bytes
}

/// Derive a contract instance id the way `freenet-stdlib` does, from
/// full WASM bytes. This is the tests' oracle; see the module docs on
/// why it must not be `wsclient::contract_id_from_wasm_hash`.
fn stdlib_id(wasm: &[u8], params_bytes: &[u8]) -> ContractInstanceId {
    ContractInstanceId::from_params_and_code(
        Parameters::from(params_bytes.to_vec()),
        ContractCode::from(wasm.to_vec()),
    )
}

fn params_for(prefix: &str) -> Vec<u8> {
    freenet_git_types::RepoParams {
        prefix: prefix.to_string(),
    }
    .to_bytes()
}

fn blake3_of(wasm: &[u8]) -> [u8; 32] {
    *blake3::hash(wasm).as_bytes()
}

/// State bytes standing in for a serialized `RepoState`. The fallback
/// is agnostic to their content — it hands the caller whatever the
/// contract returned — so opaque bytes keep the test focused on the
/// probe/recover sequencing.
const PREDECESSOR_STATE: &[u8] = b"state-published-by-the-old-contract";

/// How long the retry test waits for the first predecessor probe
/// before giving up. Generous compared to the milliseconds a loopback
/// probe actually takes; its job is only to bound the wait so a broken
/// fallback fails the test instead of hanging it.
const HEAL_DEADLINE: std::time::Duration = std::time::Duration::from_secs(5);

/// The core claim: when the current contract key has nothing and a
/// registered predecessor key does, the fallback recovers the
/// predecessor's state and reports where it came from.
#[tokio::test]
async fn recovers_state_from_a_predecessor_contract_key() {
    let params = params_for("abc1234567");
    let current_wasm = synthetic_wasm(0xC0);
    let legacy_wasm = synthetic_wasm(0x1E);

    let current_id = stdlib_id(&current_wasm, &params);
    let legacy_id = stdlib_id(&legacy_wasm, &params);
    assert_ne!(
        current_id, legacy_id,
        "test setup: a WASM change must re-key the contract, else this proves nothing"
    );

    // Only the predecessor key holds state. The current key is absent,
    // exactly as it would be immediately after a re-keying release.
    let mut replies = HashMap::new();
    replies.insert(legacy_id, Reply::State(PREDECESSOR_STATE.to_vec()));
    let gateway = FakeGateway::start(replies).await;

    let mut api = wsclient::connect(gateway.url()).await.expect("connect");
    let legacy_hash = blake3_of(&legacy_wasm);
    let found = wsclient::get_state_with_legacy_fallback(
        &mut api,
        current_id,
        &params,
        &[&legacy_hash],
        FAST_PROBE_TIMEOUT,
    )
    .await
    .expect("fallback should recover state from the predecessor key");

    assert_eq!(
        found.state, PREDECESSOR_STATE,
        "recovered bytes must be the predecessor's state, verbatim"
    );
    match found.source {
        GetSource::Legacy { index, instance } => {
            assert_eq!(index, 0, "the hit was registry entry 0");
            assert_eq!(
                instance, legacy_id,
                "reported instance must be the stdlib-derived predecessor key"
            );
        }
        GetSource::Current => panic!(
            "state came back tagged as Current, so the caller would skip the \
             migration re-PUT and the recovered state would never move forward"
        ),
    }

    assert_eq!(
        gateway.gets(),
        vec![current_id, legacy_id],
        "must probe the current key first, then fall back to the predecessor"
    );
}

/// The current key wins when it has state, and no predecessor is
/// probed. Guards against a fallback that always walks the registry
/// (O(N) wasted round trips on every fetch, and a stale predecessor
/// could shadow current state).
#[tokio::test]
async fn current_key_wins_and_no_predecessor_is_probed() {
    let params = params_for("abc1234567");
    let current_wasm = synthetic_wasm(0xC0);
    let legacy_wasm = synthetic_wasm(0x1E);
    let current_id = stdlib_id(&current_wasm, &params);
    let legacy_id = stdlib_id(&legacy_wasm, &params);

    let mut replies = HashMap::new();
    replies.insert(current_id, Reply::State(b"fresh-current-state".to_vec()));
    replies.insert(legacy_id, Reply::State(PREDECESSOR_STATE.to_vec()));
    let gateway = FakeGateway::start(replies).await;

    let mut api = wsclient::connect(gateway.url()).await.expect("connect");
    let legacy_hash = blake3_of(&legacy_wasm);
    let found = wsclient::get_state_with_legacy_fallback(
        &mut api,
        current_id,
        &params,
        &[&legacy_hash],
        FAST_PROBE_TIMEOUT,
    )
    .await
    .expect("current key has state");

    assert_eq!(found.state, b"fresh-current-state");
    assert!(
        matches!(found.source, GetSource::Current),
        "state at the current key must be reported as Current, not as a migration"
    );
    assert_eq!(
        gateway.gets(),
        vec![current_id],
        "a hit at the current key must not probe any predecessor"
    );
}

/// Predecessors are walked oldest-registered-first, in registry order,
/// and the reported index identifies which one hit. The index is not
/// cosmetic: `fetch_repo_state` uses it to index back into
/// `LEGACY_REPO_CONTRACT_WASM_HASHES` for the log line, so an off-by-one
/// would panic on a real migration.
#[tokio::test]
async fn walks_predecessors_in_registry_order_and_reports_the_index() {
    let params = params_for("abc1234567");
    let current_id = stdlib_id(&synthetic_wasm(0xC0), &params);

    let legacy_wasms: Vec<Vec<u8>> = (0..3).map(|i| synthetic_wasm(0xA0 + i)).collect();
    let legacy_ids: Vec<ContractInstanceId> =
        legacy_wasms.iter().map(|w| stdlib_id(w, &params)).collect();

    // Only the LAST registered predecessor holds state, so a fallback
    // that stops early or probes in the wrong order fails.
    let mut replies = HashMap::new();
    replies.insert(legacy_ids[2], Reply::State(PREDECESSOR_STATE.to_vec()));
    let gateway = FakeGateway::start(replies).await;

    let mut api = wsclient::connect(gateway.url()).await.expect("connect");
    let hashes: Vec<[u8; 32]> = legacy_wasms.iter().map(|w| blake3_of(w)).collect();
    let hash_refs: Vec<&[u8; 32]> = hashes.iter().collect();

    let found = wsclient::get_state_with_legacy_fallback(
        &mut api,
        current_id,
        &params,
        &hash_refs,
        FAST_PROBE_TIMEOUT,
    )
    .await
    .expect("third predecessor holds the state");

    assert_eq!(found.state, PREDECESSOR_STATE);
    match found.source {
        GetSource::Legacy { index, instance } => {
            assert_eq!(index, 2, "the hit was registry entry 2");
            assert_eq!(instance, legacy_ids[2]);
        }
        GetSource::Current => panic!("state came from a predecessor, not the current key"),
    }

    let mut expected = vec![current_id];
    expected.extend(legacy_ids.iter().copied());
    assert_eq!(
        gateway.gets(),
        expected,
        "probe order must be current key, then predecessors in registry order"
    );
}

/// A predecessor that answers with zero-length state is a miss, not a
/// recovery. `RepoState::from_bytes(&[])` would fail downstream, and
/// worse, `fetch_repo_state` would re-PUT empty state over the current
/// key. The `!state.is_empty()` guard in `probe_all_keys` is what
/// prevents that; this pins it.
#[tokio::test]
async fn empty_state_at_a_predecessor_is_not_mistaken_for_recovery() {
    let params = params_for("abc1234567");
    let current_id = stdlib_id(&synthetic_wasm(0xC0), &params);
    let empty_wasm = synthetic_wasm(0xE1);
    let real_wasm = synthetic_wasm(0xE2);
    let empty_id = stdlib_id(&empty_wasm, &params);
    let real_id = stdlib_id(&real_wasm, &params);

    let mut replies = HashMap::new();
    replies.insert(empty_id, Reply::Empty);
    replies.insert(real_id, Reply::State(PREDECESSOR_STATE.to_vec()));
    let gateway = FakeGateway::start(replies).await;

    let mut api = wsclient::connect(gateway.url()).await.expect("connect");
    let hashes = [blake3_of(&empty_wasm), blake3_of(&real_wasm)];
    let hash_refs: Vec<&[u8; 32]> = hashes.iter().collect();

    let found = wsclient::get_state_with_legacy_fallback(
        &mut api,
        current_id,
        &params,
        &hash_refs,
        FAST_PROBE_TIMEOUT,
    )
    .await
    .expect("second predecessor holds real state");

    assert_eq!(found.state, PREDECESSOR_STATE);
    match found.source {
        GetSource::Legacy { index, .. } => assert_eq!(
            index, 1,
            "an empty response must be skipped, not returned as recovered state"
        ),
        GetSource::Current => panic!("state came from a predecessor"),
    }
}

/// A predecessor probe that times out is transient, not authoritative:
/// the whole sequence is retried, and the retry recovers the state.
///
/// This is the one path where the current key being authoritatively
/// absent must NOT suppress the retry — an all-authoritative outcome
/// set fails fast. `outcomes_worth_retrying_retries_transient_legacy_after_current_not_found`
/// unit-tests that decision; this test proves the loop around it
/// actually re-probes and recovers.
#[tokio::test]
async fn transient_predecessor_timeout_is_retried_and_then_recovers() {
    let params = params_for("abc1234567");
    let current_id = stdlib_id(&synthetic_wasm(0xC0), &params);
    let legacy_wasm = synthetic_wasm(0x7A);
    let legacy_id = stdlib_id(&legacy_wasm, &params);

    let mut replies = HashMap::new();
    replies.insert(legacy_id, Reply::Silence);
    let gateway = FakeGateway::start(replies).await;

    // Heal the predecessor as soon as the first probe reaches it, so
    // attempt 2 (after the 2s backoff) finds state. Polling on the
    // observed-request log rather than a fixed sleep keeps this
    // deterministic regardless of machine speed.
    //
    // The deadline matters: if the predecessor is never probed at all
    // (the shape of a broken fallback) this loop would otherwise spin
    // forever and `tokio::join!` below would hang instead of failing.
    // A test that hangs on a regression is barely better than one that
    // passes — CI reports a timeout, not a diagnosis.
    let healer = async {
        let deadline = tokio::time::Instant::now() + HEAL_DEADLINE;
        while tokio::time::Instant::now() < deadline {
            if gateway.gets().contains(&legacy_id) {
                gateway.set_reply(legacy_id, Reply::State(PREDECESSOR_STATE.to_vec()));
                return;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    };

    let mut api = wsclient::connect(gateway.url()).await.expect("connect");
    let legacy_hash = blake3_of(&legacy_wasm);
    let hash_refs = [&legacy_hash];
    let probe = wsclient::get_state_with_legacy_fallback(
        &mut api,
        current_id,
        &params,
        &hash_refs,
        FAST_PROBE_TIMEOUT,
    );

    let (found, ()) = tokio::join!(probe, healer);
    let found = found.expect("retry after a transient timeout should recover the state");

    assert_eq!(found.state, PREDECESSOR_STATE);
    assert!(
        matches!(found.source, GetSource::Legacy { index: 0, .. }),
        "recovered state must still be attributed to the predecessor key"
    );
    assert!(
        gateway.gets().iter().filter(|id| **id == legacy_id).count() >= 2,
        "the predecessor must have been re-probed after the transient timeout"
    );
}

/// Production must hand the *real* registry to the seam.
///
/// Everything downstream of that argument is covered by the tests
/// above, because they inject their own registry. The one line those
/// tests cannot observe is the wrapper's: while
/// `legacy_contracts.toml` is empty, passing `&[]`, or the wrong
/// constant, or dropping the argument's meaning entirely produces
/// behaviour identical to passing the real thing. A regression there
/// would surface only at the first genuine re-key — the exact scenario
/// this file exists to de-risk.
///
/// So it is pinned by scraping the source. A source pin is a blunt
/// instrument, but it is the right shape here: the property is "this
/// call site names this constant", which is a fact about the text.
///
/// Three anti-vacuity guards, because a source pin that stops matching
/// anything passes silently:
///   * the wrapper must be found at all, else fail loudly;
///   * the needle is compared whitespace-stripped, so `cargo fmt`
///     rewrapping the call cannot disarm it;
///   * this test lives in an integration file and scrapes a *different*
///     file, so it can neither match its own text nor be switched off
///     by deleting a `#[cfg(test)] mod tests` block.
#[test]
fn production_fetch_repo_state_passes_the_generated_registry() {
    const BIN_SRC: &str = include_str!("../src/bin/git-remote-freenet.rs");

    let start = BIN_SRC
        .find("async fn fetch_repo_state(")
        .expect("fn fetch_repo_state was renamed or removed; this pin is now testing nothing");
    let body = &BIN_SRC[start..];
    let end = body
        .find("\n}\n")
        .expect("could not find the end of fetch_repo_state");
    let wrapper: String = body[..end].chars().filter(|c| !c.is_whitespace()).collect();

    assert!(
        wrapper.contains("freenet_git_cli::legacy::LEGACY_REPO_CONTRACT_WASM_HASHES"),
        "fetch_repo_state must pass the generated registry to \
         fetch_repo_state_from_registry. Passing anything else is invisible to \
         every other test while legacy_contracts.toml is empty, and would only \
         be discovered at the first real re-key. Wrapper body was:\n{wrapper}"
    );
    assert!(
        !wrapper.contains("&[]"),
        "fetch_repo_state must not pass an empty registry:\n{wrapper}"
    );
}

/// Negative control. If nothing exists anywhere, the fallback must fail
/// — and say so in terms that distinguish absence from a sick gateway.
///
/// Without this, a fallback that fabricated empty state on a total miss
/// would still satisfy the positive tests above.
#[tokio::test]
async fn reports_absence_when_neither_current_nor_predecessor_has_state() {
    let params = params_for("abc1234567");
    let current_id = stdlib_id(&synthetic_wasm(0xC0), &params);
    let legacy_wasm = synthetic_wasm(0x1E);

    // Empty reply map: the gateway answers NotFound for everything.
    let gateway = FakeGateway::start(HashMap::new()).await;
    let mut api = wsclient::connect(gateway.url()).await.expect("connect");
    let legacy_hash = blake3_of(&legacy_wasm);

    // `LegacyAwareGet` has no `Debug`, so unwrap the error by hand
    // rather than reaching for `expect_err`.
    let msg = match wsclient::get_state_with_legacy_fallback(
        &mut api,
        current_id,
        &params,
        &[&legacy_hash],
        FAST_PROBE_TIMEOUT,
    )
    .await
    {
        Ok(found) => panic!(
            "nothing is published anywhere, yet the fallback returned {} byte(s) \
             of state — a fabricated success would migrate garbage onto the \
             current key",
            found.state.len()
        ),
        Err(e) => e.to_string(),
    };
    assert!(
        msg.contains("no state found"),
        "an all-absent result must read as absence, not as a transport problem: {msg}"
    );
    assert!(
        msg.contains("1 legacy key"),
        "the message should say how many predecessors were tried: {msg}"
    );
    assert_eq!(
        gateway.gets(),
        vec![current_id, stdlib_id(&legacy_wasm, &params)],
        "an authoritative absence everywhere must fail fast, without retrying"
    );
}
