//! An in-process fake Freenet gateway, spoken to over a real loopback
//! WebSocket by a real `freenet_stdlib::client_api::WebApi`.
//!
//! Why this exists: the legacy-contract migration path
//! (`wsclient::get_state_with_legacy_fallback` and its caller
//! `fetch_repo_state`) can only be exercised end to end against
//! *something* that answers GETs. Every existing test in this crate
//! covers the path's individual pure functions (response dispatch,
//! outcome classification, retry decisions, error formatting) but
//! nothing drives the sequencing: probe the current key, then walk the
//! legacy keys in registry order, then re-PUT what a legacy key
//! returned. Because `legacy_contracts.toml` is empty in every shipped
//! build, that sequencing has never executed with a non-empty legacy
//! list, in production or in CI.
//!
//! A real Freenet node is far too heavy (and per this repo's testing
//! philosophy, reserved for transport concerns). This gateway is not a
//! transport test: it is the smallest thing that lets the *real* client
//! code run its *real* recv loop against *real* bincode wire frames.
//!
//! Wire contract, mirroring `freenet_stdlib::client_api::regular`:
//!   * client → server: `Message::Binary(bincode(ClientRequest))`
//!   * server → client: `Message::Binary(bincode(Result<HostResponse, ClientError>))`

#![allow(dead_code)] // Each test file uses a different subset.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use freenet_stdlib::client_api::{
    ClientError, ClientRequest, ContractRequest, ContractResponse, HostResponse,
};
use freenet_stdlib::prelude::{CodeHash, ContractInstanceId, ContractKey, WrappedState};
use futures::{SinkExt, StreamExt};
use tokio::net::TcpListener;
use tokio_tungstenite::tungstenite::Message;

/// How the fake gateway answers a GET for one particular instance id.
#[derive(Clone, Debug)]
pub enum Reply {
    /// Answer `GetResponse` carrying these state bytes.
    State(Vec<u8>),
    /// Answer `GetResponse` with zero-length state — the
    /// "initialised but empty" case the client treats as a miss but
    /// distinguishes from an authoritative absence.
    Empty,
    /// Answer `ContractResponse::NotFound` — authoritative absence.
    NotFound,
    /// Answer nothing at all, so the client's per-probe timeout fires.
    /// Used to exercise the transient/retry classification.
    Silence,
}

/// One request the gateway observed, in arrival order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Observed {
    Get(ContractInstanceId),
    Put {
        instance: ContractInstanceId,
        state: Vec<u8>,
    },
    Update(ContractInstanceId),
}

/// Shared, inspectable gateway state.
#[derive(Default)]
struct Inner {
    replies: HashMap<ContractInstanceId, Reply>,
    observed: Vec<Observed>,
    /// When set, every PUT is answered with this host error instead of
    /// a `PutResponse` — used to exercise "the migration re-PUT was
    /// rejected, but the user must still get their state".
    put_error: Option<String>,
}

/// A running fake gateway. Drop it and the listener task goes away.
pub struct FakeGateway {
    url: String,
    inner: Arc<Mutex<Inner>>,
    _task: tokio::task::JoinHandle<()>,
}

impl FakeGateway {
    /// Bind on an ephemeral loopback port and start serving.
    ///
    /// `replies` maps instance id → canned answer. Any id not in the
    /// map is answered `NotFound`, which is what a real gateway does
    /// for a contract nobody has published.
    pub async fn start(replies: HashMap<ContractInstanceId, Reply>) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind loopback listener");
        let port = listener.local_addr().expect("local_addr").port();
        let inner = Arc::new(Mutex::new(Inner {
            replies,
            observed: Vec::new(),
            put_error: None,
        }));

        let task_inner = Arc::clone(&inner);
        let task = tokio::spawn(async move {
            // One connection per test is enough; loop so a client that
            // reconnects is still served.
            while let Ok((stream, _)) = listener.accept().await {
                let conn_inner = Arc::clone(&task_inner);
                tokio::spawn(async move {
                    serve_connection(stream, conn_inner).await;
                });
            }
        });

        Self {
            // The path and query mirror what `wsclient::DEFAULT_WS_URL`
            // uses, so the client code under test builds its request
            // exactly as it would against a real node.
            url: format!("ws://127.0.0.1:{port}/v1/contract/command?encodingProtocol=native"),
            inner,
            _task: task,
        }
    }

    /// WebSocket URL to hand to `wsclient::connect`.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Every request the gateway has seen so far, in arrival order.
    pub fn observed(&self) -> Vec<Observed> {
        self.inner.lock().expect("gateway mutex").observed.clone()
    }

    /// Just the GET probes, in arrival order.
    pub fn gets(&self) -> Vec<ContractInstanceId> {
        self.observed()
            .into_iter()
            .filter_map(|o| match o {
                Observed::Get(id) => Some(id),
                _ => None,
            })
            .collect()
    }

    /// Just the PUTs, in arrival order.
    pub fn puts(&self) -> Vec<(ContractInstanceId, Vec<u8>)> {
        self.observed()
            .into_iter()
            .filter_map(|o| match o {
                Observed::Put { instance, state } => Some((instance, state)),
                _ => None,
            })
            .collect()
    }

    /// Make every PUT fail with this host error.
    pub fn reject_puts(&self, message: &str) {
        self.inner.lock().expect("gateway mutex").put_error = Some(message.to_string());
    }

    /// Swap the canned answer for one instance id mid-test (used to
    /// make a probe that timed out once succeed on a retry).
    pub fn set_reply(&self, id: ContractInstanceId, reply: Reply) {
        self.inner
            .lock()
            .expect("gateway mutex")
            .replies
            .insert(id, reply);
    }
}

async fn serve_connection(stream: tokio::net::TcpStream, inner: Arc<Mutex<Inner>>) {
    let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
        return;
    };

    while let Some(Ok(msg)) = ws.next().await {
        let bytes = match msg {
            Message::Binary(b) => b,
            Message::Close(_) => break,
            _ => continue,
        };
        let Ok(request) = bincode::deserialize::<ClientRequest<'_>>(&bytes) else {
            continue;
        };

        let response = match request {
            ClientRequest::ContractOp(ContractRequest::Get { key, .. }) => {
                let reply = {
                    let mut guard = inner.lock().expect("gateway mutex");
                    guard.observed.push(Observed::Get(key));
                    guard.replies.get(&key).cloned().unwrap_or(Reply::NotFound)
                };
                match reply {
                    Reply::State(state) => Some(Ok(HostResponse::ContractResponse(
                        ContractResponse::GetResponse {
                            key: key_for(key),
                            state: WrappedState::new(state),
                            contract: None,
                        },
                    ))),
                    Reply::Empty => Some(Ok(HostResponse::ContractResponse(
                        ContractResponse::GetResponse {
                            key: key_for(key),
                            state: WrappedState::new(Vec::new()),
                            contract: None,
                        },
                    ))),
                    Reply::NotFound => Some(Ok(HostResponse::ContractResponse(
                        ContractResponse::NotFound { instance_id: key },
                    ))),
                    // Deliberately answer nothing: the client should
                    // hit its own per-probe timeout.
                    Reply::Silence => None,
                }
            }
            ClientRequest::ContractOp(ContractRequest::Put {
                contract, state, ..
            }) => {
                let instance = *contract.key().id();
                let state_bytes = state.as_ref().to_vec();
                let rejection = {
                    let mut guard = inner.lock().expect("gateway mutex");
                    guard.observed.push(Observed::Put {
                        instance,
                        state: state_bytes.clone(),
                    });
                    match guard.put_error.clone() {
                        Some(msg) => Some(msg),
                        None => {
                            // A PUT makes the contract readable at that
                            // key, so a later GET in the same test sees
                            // the migration.
                            guard.replies.insert(instance, Reply::State(state_bytes));
                            None
                        }
                    }
                };
                match rejection {
                    Some(msg) => Some(Err(ClientError::from(msg))),
                    None => Some(Ok(HostResponse::ContractResponse(
                        ContractResponse::PutResponse {
                            key: contract.key(),
                        },
                    ))),
                }
            }
            ClientRequest::ContractOp(ContractRequest::Update { key, .. }) => {
                inner
                    .lock()
                    .expect("gateway mutex")
                    .observed
                    .push(Observed::Update(*key.id()));
                Some(Ok(HostResponse::ContractResponse(
                    ContractResponse::UpdateResponse {
                        key,
                        summary: freenet_stdlib::prelude::StateSummary::from(Vec::new()),
                    },
                )))
            }
            ClientRequest::Disconnect { .. } | ClientRequest::Close => break,
            _ => None,
        };

        if let Some(payload) = response {
            let payload: Result<HostResponse, ClientError> = payload;
            let Ok(encoded) = bincode::serialize(&payload) else {
                continue;
            };
            if ws.send(Message::Binary(encoded.into())).await.is_err() {
                break;
            }
        }
    }
}

/// Build a `ContractKey` for a `GetResponse`/`PutResponse` envelope.
///
/// The client only ever compares `key.id()` against the instance id it
/// asked for, so the code-hash half is irrelevant here; a real gateway
/// would carry the true one.
fn key_for(instance: ContractInstanceId) -> ContractKey {
    ContractKey::from_id_and_code(instance, CodeHash::from_code(b"fake-gateway-code"))
}

/// Convenience: a per-probe timeout short enough to keep
/// `Reply::Silence` tests fast, long enough that a loopback round trip
/// never races it.
pub const FAST_PROBE_TIMEOUT: Duration = Duration::from_millis(600);
