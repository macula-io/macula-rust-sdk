//! Direct-dial resolve-and-call: resolving a signed `procedure_advertisement`
//! DHT record and its serving station's own signed `station_endpoint`, then
//! dialing that station in one hop — instead of depending on ordinary
//! advertise-gossip having propagated a route between whichever two
//! stations happen to be involved.
//!
//! Ported from `macula-io/macula`'s `macula_direct_dial.erl`, cross-checked
//! against `macula-go-sdk`'s own port of the same reference
//! (`directdial/directdial.go`) — see that file's doc for the fuller
//! reasoning behind each design choice made here.
//!
//! **Trust model** (see `macula_direct_dial.erl`'s module doc for the full
//! reasoning): every candidate `procedure_advertisement` must carry a valid
//! Ed25519 signature before its `serving_station` is trusted at all, and
//! the resolved `station_endpoint` must be signed by the station itself.
//! The actual QUIC dial trusts neither the TLS certificate (a production
//! station's TLS is terminated by an unrelated PKI) nor nothing — trust is
//! enforced at the application layer, by checking the freshly dialed
//! session's own signature-verified HELLO identity against the exact
//! pubkey the signed DHT chain resolved.
//!
//! `cert_chain`-based org/realm authorization (Slice 7c Direction B,
//! `macula_record:verify_advertisement_cert_chain/3` on the Erlang side) is
//! NOT ported here — it is opt-in even in the reference implementation,
//! and blocked behind direct-dial itself existing at all in this SDK, same
//! call `macula-go-sdk` made.

use std::future::Future;
use std::time::Duration;

use crate::cbor::Value;
use crate::connection::{self, Session};
use crate::dht::{self, DhtError, Record};
use crate::frame::CallResponse;
use crate::identity::KeyPair;
use crate::transport::Trust;

fn now_ms() -> i128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_millis() as i128
}

/// Matches `macula_direct_dial.erl`'s `?RESOLVE_RETRIES`/`?RESOLVE_RETRY_MS`
/// — a record just published on the provider's station has not necessarily
/// replicated to the resolving station yet, so the first miss is not
/// treated as failure.
const RESOLVE_RETRIES: u32 = 50;
const RESOLVE_RETRY_DELAY: Duration = Duration::from_millis(100);

#[derive(Debug)]
pub enum ResolveError {
    /// Every `find_records` attempt came back empty after retrying past
    /// DHT propagation lag.
    ProcedureNotAdvertised,
    /// Records were found, but none had a valid signature.
    NoTrustedAdvertisement,
    /// A resolved station published no reachable (or no longer valid)
    /// `station_endpoint` after retrying.
    StationEndpointNotFound,
    /// A `station_endpoint` record was found under the right key, but its
    /// signer didn't match the station it's supposed to describe.
    StationEndpointSignerMismatch,
    Dht(DhtError),
}

impl std::fmt::Display for ResolveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ResolveError::ProcedureNotAdvertised => {
                write!(
                    f,
                    "direct_dial: procedure has no direct-dial advertisement in the DHT"
                )
            }
            ResolveError::NoTrustedAdvertisement => write!(
                f,
                "direct_dial: every candidate advertisement failed signature verification"
            ),
            ResolveError::StationEndpointNotFound => write!(
                f,
                "direct_dial: resolved station published no reachable station_endpoint"
            ),
            ResolveError::StationEndpointSignerMismatch => {
                write!(f, "direct_dial: station_endpoint signer mismatch")
            }
            ResolveError::Dht(e) => write!(f, "direct_dial: {e}"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// One resolved direct-dial target: the station's own node id plus a
/// dialable host/port.
#[derive(Debug, Clone)]
pub struct Resolved {
    pub station: [u8; 32],
    pub host: String,
    pub port: u16,
}

/// Finds `procedure`'s currently-advertised serving station and its
/// dialable host/port, retrying past DHT propagation lag. `realm` and
/// `procedure` must match exactly what the provider passed to
/// [`advertise_direct`] (or the Erlang equivalent) — the discovery URI they
/// derive must agree. `session` is used only to query the DHT; it does not
/// need to be connected to the same station that will end up serving the
/// call.
pub async fn resolve(
    session: &mut Session,
    id: &KeyPair,
    realm: [u8; 32],
    procedure: &str,
) -> Result<Resolved, ResolveError> {
    let uri = dht::discovery_uri(realm, procedure);
    let key = dht::procedure_key(&uri);

    let mut recs: Vec<Record> = Vec::new();
    for _ in 0..RESOLVE_RETRIES {
        match dht::find_records(session, id, key).await {
            Ok(found) if !found.is_empty() => {
                recs = found;
                break;
            }
            Ok(_) => {}
            Err(e) => return Err(ResolveError::Dht(e)),
        }
        tokio::time::sleep(RESOLVE_RETRY_DELAY).await;
    }
    if recs.is_empty() {
        return Err(ResolveError::ProcedureNotAdvertised);
    }

    let adv = first_trusted_advertisement(&recs).ok_or(ResolveError::NoTrustedAdvertisement)?;
    resolve_station_endpoint(session, id, adv.serving_station).await
}

fn first_trusted_advertisement(recs: &[Record]) -> Option<dht::ProcedureAdvertisement> {
    recs.iter().find_map(|rec| {
        dht::verify(rec).ok()?;
        dht::read_procedure_advertisement(rec).ok()
    })
}

/// Retries past a resolved-but-stale record, not just an absent one — the
/// DHT can hand back a replica that hasn't been evicted yet even though the
/// station's own current publish is live. Giving up on the first stale hit
/// would make an otherwise healthy station unreachable via direct-dial
/// until that one replica ages out.
async fn resolve_station_endpoint(
    session: &mut Session,
    id: &KeyPair,
    station: [u8; 32],
) -> Result<Resolved, ResolveError> {
    let key = dht::station_endpoint_key(station);
    for _ in 0..RESOLVE_RETRIES {
        let rec = match dht::find_record(session, id, key).await {
            Ok(rec) => rec,
            Err(DhtError::NotFound) => {
                tokio::time::sleep(RESOLVE_RETRY_DELAY).await;
                continue;
            }
            Err(e) => return Err(ResolveError::Dht(e)),
        };
        // The station_endpoint record for `station` must be SIGNED BY
        // `station` itself — checking the signature and that the signer is
        // exactly `station`, not just any valid signature, is what makes
        // pinning the dial's expected identity meaningful below.
        if rec.key != station {
            return Err(ResolveError::StationEndpointSignerMismatch);
        }
        match dht::verify(&rec) {
            Ok(()) => {}
            Err(dht::VerifyError::Expired) => {
                tokio::time::sleep(RESOLVE_RETRY_DELAY).await;
                continue;
            }
            Err(_) => return Err(ResolveError::NoTrustedAdvertisement),
        }
        let ep =
            dht::read_station_endpoint(&rec).map_err(|_| ResolveError::StationEndpointNotFound)?;
        let Some(host) = ep.host_advertised.into_iter().next() else {
            return Err(ResolveError::StationEndpointNotFound);
        };
        return Ok(Resolved {
            station,
            host,
            port: ep.quic_port,
        });
    }
    Err(ResolveError::StationEndpointNotFound)
}

#[derive(Debug)]
pub enum CallError {
    Resolve(ResolveError),
    Dial(connection::HandshakeError),
    /// The dialed peer's own signature-verified HELLO identity didn't
    /// match the pubkey the signed DHT chain resolved — a trust violation,
    /// not a retryable error.
    TrustViolation {
        resolved: [u8; 32],
        dialed: [u8; 32],
    },
    Call(connection::CallError),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Resolve(e) => write!(f, "{e}"),
            CallError::Dial(e) => write!(f, "direct_dial: dialing resolved station: {e}"),
            CallError::TrustViolation { resolved, dialed } => write!(
                f,
                "direct_dial: trust violation -- resolved station {} but the dialed peer proved identity {}",
                hex_of(resolved),
                hex_of(dialed)
            ),
            CallError::Call(e) => write!(f, "direct_dial: {e}"),
        }
    }
}

impl std::error::Error for CallError {}

fn hex_of(b: &[u8; 32]) -> String {
    b.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Resolves `procedure`'s provider via direct-dial (through `resolve_via`,
/// used only to query the DHT) and calls it there, in one hop, in a
/// SEPARATE connection from `resolve_via`. The provider must have
/// advertised via [`advertise_direct`] (or the Erlang
/// `macula_response:advertise_direct/6,7`) — a plain `advertise` publishes
/// no discoverable record and [`resolve`] will return
/// [`ResolveError::ProcedureNotAdvertised`].
///
/// The dial itself uses [`Trust::Insecure`] (no TLS verification) because
/// trust is enforced at the application layer instead — see the module
/// doc's "Trust model". After the dial, the freshly connected session's own
/// signature-verified HELLO identity is checked against the exact pubkey
/// the signed DHT chain resolved; a mismatch is
/// [`CallError::TrustViolation`], and the call is refused.
pub async fn call(
    resolve_via: &mut Session,
    id: &KeyPair,
    realm: [u8; 32],
    procedure: &str,
    payload: Value,
    timeout: Duration,
) -> Result<CallResponse, CallError> {
    let resolved = resolve(resolve_via, id, realm, procedure)
        .await
        .map_err(CallError::Resolve)?;

    let mut target = tokio::time::timeout(
        timeout,
        connection::connect(&resolved.host, resolved.port, Trust::Insecure, id),
    )
    .await
    .unwrap_or(Err(connection::HandshakeError::Timeout))
    .map_err(CallError::Dial)?;

    if target.station.node_id != resolved.station {
        let dialed = target.station.node_id;
        target.close("trust_violation", None, id).await;
        return Err(CallError::TrustViolation {
            resolved: resolved.station,
            dialed,
        });
    }

    let deadline_ms = now_ms() + timeout.as_millis() as i128;
    let result = target
        .call(procedure, realm, payload, deadline_ms, id, timeout)
        .await
        .map_err(CallError::Call);
    target.close("normal", None, id).await;
    result
}

/// Publishes a signed `procedure_advertisement` naming `session`'s own
/// currently-connected station (`session.station.node_id`) as `procedure`'s
/// server, discoverable by any caller's [`resolve`]/[`call`]. Mirrors
/// `macula_response:advertise_direct/6,7` +
/// `macula_direct_dial:publish_advertisement/4,5` — unlike the Erlang
/// reference's pool (many links, one chosen by `connected_station/1`), a
/// [`Session`] is always exactly one connection, so there is no
/// link-selection step: the session's own verified HELLO identity IS the
/// serving station.
///
/// **Sends the ordinary ADVERTISE frame first, then publishes the DHT
/// record** — matching `macula_response:advertise_direct/7`'s own body
/// exactly (`case advertise(Pool, Realm, Procedure, Module, Args, Opts) of
/// {ok, Sup} -> ... macula_direct_dial:publish_advertisement(...)`). The
/// DHT record is an ADDITIONAL discovery path for a caller on a different
/// station to skip inter-station gossip propagation — it is not a
/// substitute for the station actually knowing to route inbound CALLs
/// here. **Found live, 2026-08-30**: an earlier version of this function
/// (and its `macula-go-sdk` port, same gap, not yet fixed there as of this
/// writing) published only the DHT record — a direct-dial caller could
/// resolve and dial the right station, but the station itself had never
/// been told to route the call anywhere, so every call still failed with
/// `unknown_next_peer` despite a perfectly valid, resolvable, trusted
/// advertisement. Caught by a live test that, unlike the earlier
/// direct-dial verification, actually tried to get a real RESULT back
/// instead of accepting `unknown_next_peer` as the expected terminal state.
///
/// Unlike the Erlang SDK's supervised `macula_response`, this does not
/// itself keep anything alive — it does not spawn a responder process, so
/// a caller still needs its own [`Session::serve_one_call`](crate::connection::Session::serve_one_call)
/// loop to actually answer what gets routed here. A station's registration
/// for a procedure does not survive the connection that sent it being
/// replaced, so a long-lived server needs to call this again on its own
/// schedule; see [`keep_advertised_direct`] for that loop.
pub async fn advertise_direct(
    session: &mut Session,
    id: &KeyPair,
    realm: [u8; 32],
    procedure: &str,
    ttl: Duration,
) -> Result<(), AdvertiseDirectError> {
    let advertise_spec = crate::frame::AdvertiseSpec::new(realm, procedure, id.node_id());
    session
        .advertise(&advertise_spec, id)
        .await
        .map_err(AdvertiseDirectError::Advertise)?;

    let uri = dht::discovery_uri(realm, procedure);
    let rec = dht::new_procedure_advertisement(id.node_id(), uri, session.station.node_id, ttl);
    let rec = dht::sign(rec, id);
    dht::put_record(session, id, &rec)
        .await
        .map_err(AdvertiseDirectError::Dht)
}

#[derive(Debug)]
pub enum AdvertiseDirectError {
    /// The ordinary station-side ADVERTISE frame failed to send.
    Advertise(connection::SendFrameError),
    /// The ordinary ADVERTISE succeeded, but publishing the direct-dial
    /// DHT record failed — the procedure IS now reachable via ordinary
    /// advertise-gossip, just not via direct-dial resolution.
    Dht(DhtError),
}

impl std::fmt::Display for AdvertiseDirectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AdvertiseDirectError::Advertise(e) => write!(f, "direct_dial: sending ADVERTISE: {e}"),
            AdvertiseDirectError::Dht(e) => write!(f, "direct_dial: {e}"),
        }
    }
}

impl std::error::Error for AdvertiseDirectError {}

/// Calls [`advertise_direct`] immediately, then again every `interval`,
/// until `stop` resolves. Rust has nothing equivalent to
/// `macula_response`'s `reuse_sup` to worry about here, because
/// [`advertise_direct`] (unlike Erlang's `advertise/5`, which spawns a real
/// per-call OTP supervisor) is already a stateless, side-effect-free-on-
/// repeat async function: nothing is created per tick that could leak —
/// same reasoning `macula-go-sdk`'s `KeepAdvertisedDirect` already applied
/// and verified live.
///
/// `interval` should leave real margin before `ttl` expires — production
/// practice in `hecate-om`'s own capability re-advertise loop (the actual
/// consumer of `advertise_direct`'s `reuse_sup` option on the Erlang side)
/// uses a 4x margin: a 30s republish interval against a 120s record TTL.
///
/// A failed tick (network blip, connection genuinely dead, etc.) is
/// reported via `on_error` but does NOT stop the loop; it tries again at
/// the next interval regardless, matching `hecate-om`'s own log-and-continue
/// practice around every DHT publish. This loop cannot detect or repair a
/// dead `session` on its own — if its underlying connection has actually
/// gone down, every tick will keep failing the same way until `stop`
/// resolves; reconnecting a dead session is a separate, larger concern this
/// does not attempt to solve.
///
/// 8 parameters: a target (`session`/`realm`/`procedure`), a re-advertise
/// schedule (`id`/`ttl`/`interval`), and two independent callbacks
/// (`stop`/`on_error`) with no natural sub-grouping — folding any of them
/// into a synthetic struct would relocate the count, not reduce it.
#[allow(clippy::too_many_arguments)]
pub async fn keep_advertised_direct<F>(
    session: &mut Session,
    id: &KeyPair,
    realm: [u8; 32],
    procedure: &str,
    ttl: Duration,
    interval: Duration,
    stop: F,
    on_error: impl Fn(AdvertiseDirectError),
) where
    F: Future<Output = ()>,
{
    tokio::pin!(stop);
    let mut ticker = tokio::time::interval(interval);
    loop {
        tokio::select! {
            _ = &mut stop => return,
            _ = ticker.tick() => {
                if let Err(e) = advertise_direct(session, id, realm, procedure, ttl).await {
                    on_error(e);
                }
            }
        }
    }
}
