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
//! opt-in here too, matching the reference and `macula-go-sdk`'s own port —
//! see [`resolve_with_cert_chain`]/[`call_with_cert_chain`]/
//! [`advertise_direct_with_cert_chain`]. Plain [`resolve`]/[`call`]/
//! [`advertise_direct`] are completely unaffected.

use std::future::Future;
use std::time::Duration;

use crate::cbor::Value;
use crate::cert_chain::{self, CertChainError};
use crate::connection::{self, Session};
use crate::content;
use crate::dht::{self, DhtError, Record};
use crate::frame::{CallResponse, StreamMode};
use crate::identity::KeyPair;
use crate::manifest::Mcid;
use crate::stream::{self, StreamHandle};
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
    /// [`resolve_with_cert_chain`] only: at least one candidate
    /// advertisement's envelope signature verified (otherwise
    /// [`ResolveError::NoTrustedAdvertisement`] would apply instead), but
    /// none passed cert-chain authorization for the expected org — carries
    /// the specific [`CertChainError`] from the LAST candidate tried
    /// (absent chain, wrong org, untrusted chain, etc.).
    NoAuthorizedAdvertisement(CertChainError),
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
            ResolveError::NoAuthorizedAdvertisement(e) => write!(
                f,
                "direct_dial: no candidate advertisement is cert-chain-authorized for the expected org: {e}"
            ),
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

/// [`resolve`] plus Slice 7c Direction B managed-realm authorization: only
/// an advertisement whose embedded cert chain validates to `realm_ca_pem`
/// and names `expected_org` is trusted. Opt-in — [`resolve`] itself is
/// unaffected and remains the right choice for unmanaged realms.
pub async fn resolve_with_cert_chain(
    session: &mut Session,
    id: &KeyPair,
    realm: [u8; 32],
    procedure: &str,
    realm_ca_pem: &[u8],
    expected_org: &str,
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

    let adv = first_authorized_advertisement(&recs, realm_ca_pem, expected_org)?;
    resolve_station_endpoint(session, id, adv.serving_station).await
}

/// [`first_trusted_advertisement`] plus the cert-chain check. Matches Go's
/// `firstAuthorizedAdvertisement`: if every candidate fails even the plain
/// envelope-signature check, report [`ResolveError::NoTrustedAdvertisement`]
/// (same as the plain path); only report
/// [`ResolveError::NoAuthorizedAdvertisement`] once at least one candidate's
/// signature verified but none passed cert-chain authorization.
fn first_authorized_advertisement(
    recs: &[Record],
    realm_ca_pem: &[u8],
    expected_org: &str,
) -> Result<dht::ProcedureAdvertisement, ResolveError> {
    let mut last_cert_err: Option<CertChainError> = None;
    for rec in recs {
        if dht::verify(rec).is_err() {
            continue;
        }
        match cert_chain::verify_advertisement_cert_chain(realm_ca_pem, rec, expected_org) {
            Ok(()) => {
                if let Ok(adv) = dht::read_procedure_advertisement(rec) {
                    return Ok(adv);
                }
            }
            Err(e) => last_cert_err = Some(e),
        }
    }
    match last_cert_err {
        Some(e) => Err(ResolveError::NoAuthorizedAdvertisement(e)),
        None => Err(ResolveError::NoTrustedAdvertisement),
    }
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

/// [`call`], resolved via [`resolve_with_cert_chain`] instead of
/// [`resolve`] — see both for the full contract. Opt-in managed-realm
/// authorization; [`call`] itself is unaffected.
#[allow(clippy::too_many_arguments)]
pub async fn call_with_cert_chain(
    resolve_via: &mut Session,
    id: &KeyPair,
    realm: [u8; 32],
    procedure: &str,
    realm_ca_pem: &[u8],
    expected_org: &str,
    payload: Value,
    timeout: Duration,
) -> Result<CallResponse, CallError> {
    let resolved = resolve_with_cert_chain(
        resolve_via,
        id,
        realm,
        procedure,
        realm_ca_pem,
        expected_org,
    )
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

/// [`advertise_direct`] plus an embedded X.509 service-cert chain, for
/// Slice 7c Direction B managed-realm authorization — see
/// [`resolve_with_cert_chain`]/[`call_with_cert_chain`] for the
/// corresponding checks. Opt-in: plain [`advertise_direct`] is unaffected.
pub async fn advertise_direct_with_cert_chain(
    session: &mut Session,
    id: &KeyPair,
    realm: [u8; 32],
    procedure: &str,
    ttl: Duration,
    cert_chain_pem: Vec<u8>,
) -> Result<(), AdvertiseDirectError> {
    let advertise_spec = crate::frame::AdvertiseSpec::new(realm, procedure, id.node_id());
    session
        .advertise(&advertise_spec, id)
        .await
        .map_err(AdvertiseDirectError::Advertise)?;

    let uri = dht::discovery_uri(realm, procedure);
    let rec = dht::new_procedure_advertisement_with_cert_chain(
        id.node_id(),
        uri,
        session.station.node_id,
        ttl,
        cert_chain_pem,
    );
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

/// The dial-then-pin sequence every direct-dial call shape needs after
/// resolving: dial `resolved`'s host:port, then check the freshly
/// connected session's own signature-verified HELLO identity against
/// `resolved.station` — factored out here (unlike [`call`]/
/// [`call_with_cert_chain`], which had it inline before this existed)
/// because [`open_stream_direct`]/[`put_direct`]/[`get_direct`] all need
/// the identical sequence against a station identity that isn't
/// necessarily reached via [`resolve`].
#[derive(Debug)]
pub enum DialAndVerifyError {
    Dial(connection::HandshakeError),
    /// The dialed peer's own signature-verified HELLO identity didn't
    /// match the pubkey the signed DHT chain resolved — a trust
    /// violation, not a retryable error.
    TrustViolation {
        resolved: [u8; 32],
        dialed: [u8; 32],
    },
}

impl std::fmt::Display for DialAndVerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DialAndVerifyError::Dial(e) => write!(f, "direct_dial: dialing resolved station: {e}"),
            DialAndVerifyError::TrustViolation { resolved, dialed } => write!(
                f,
                "direct_dial: trust violation -- resolved station {} but the dialed peer proved identity {}",
                hex_of(resolved),
                hex_of(dialed)
            ),
        }
    }
}

impl std::error::Error for DialAndVerifyError {}

async fn dial_and_verify(
    host: &str,
    port: u16,
    station: [u8; 32],
    id: &KeyPair,
    timeout: Duration,
) -> Result<Session, DialAndVerifyError> {
    let target = tokio::time::timeout(
        timeout,
        connection::connect(host, port, Trust::Insecure, id),
    )
    .await
    .unwrap_or(Err(connection::HandshakeError::Timeout))
    .map_err(DialAndVerifyError::Dial)?;

    if target.station.node_id != station {
        let dialed = target.station.node_id;
        target.close("trust_violation", None, id).await;
        return Err(DialAndVerifyError::TrustViolation {
            resolved: station,
            dialed,
        });
    }
    Ok(target)
}

#[derive(Debug)]
pub enum OpenStreamDirectError {
    Resolve(ResolveError),
    Dial(DialAndVerifyError),
    Open(stream::OpenError),
}

impl std::fmt::Display for OpenStreamDirectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenStreamDirectError::Resolve(e) => write!(f, "{e}"),
            OpenStreamDirectError::Dial(e) => write!(f, "{e}"),
            OpenStreamDirectError::Open(e) => write!(f, "direct_dial: open stream: {e}"),
        }
    }
}

impl std::error::Error for OpenStreamDirectError {}

/// Resolves `procedure`'s provider via direct-dial (through `resolve_via`,
/// used only to query the DHT) and opens a stream there, in one hop, in a
/// SEPARATE connection from `resolve_via` — the streaming-RPC counterpart
/// to [`call`]. The provider must have advertised via [`advertise_direct`]:
/// streaming's provider side (`macula_streamer.erl`) shares the identical
/// `procedure_advertisement` mechanism RPC uses (confirmed against
/// `macula_streamer.erl`/`macula_stream_sink.erl`'s own `advertise_direct`/
/// `start_link_direct` — both are `macula_response:advertise_direct`/
/// `macula_direct_dial:call_stream` under the hood, nothing stream-specific
/// added), so no separate stream-shaped advertise function exists or is
/// needed.
///
/// The caller owns the returned [`Session`] (and must close it once the
/// stream and any other work on it is done) alongside the
/// [`StreamHandle`] itself, since — unlike [`call`], which owns its dial
/// for exactly one request/reply — a stream outlives the single function
/// call that opens it.
#[allow(clippy::too_many_arguments)]
pub async fn open_stream_direct(
    resolve_via: &mut Session,
    id: &KeyPair,
    realm: [u8; 32],
    procedure: &str,
    mode: StreamMode,
    args: Value,
    deadline_ms: i128,
    timeout: Duration,
) -> Result<(Session, StreamHandle), OpenStreamDirectError> {
    let resolved = resolve(resolve_via, id, realm, procedure)
        .await
        .map_err(OpenStreamDirectError::Resolve)?;
    let mut target = dial_and_verify(&resolved.host, resolved.port, resolved.station, id, timeout)
        .await
        .map_err(OpenStreamDirectError::Dial)?;
    match StreamHandle::open(&mut target, procedure, realm, mode, args, deadline_ms, id).await {
        Ok(handle) => Ok((target, handle)),
        Err(e) => {
            target.close("normal", None, id).await;
            Err(OpenStreamDirectError::Open(e))
        }
    }
}

/// [`open_stream_direct`], resolved via [`resolve_with_cert_chain`]
/// instead of [`resolve`] — see both for the full contract. Opt-in
/// managed-realm authorization; [`open_stream_direct`] itself is
/// unaffected.
#[allow(clippy::too_many_arguments)]
pub async fn open_stream_direct_with_cert_chain(
    resolve_via: &mut Session,
    id: &KeyPair,
    realm: [u8; 32],
    procedure: &str,
    realm_ca_pem: &[u8],
    expected_org: &str,
    mode: StreamMode,
    args: Value,
    deadline_ms: i128,
    timeout: Duration,
) -> Result<(Session, StreamHandle), OpenStreamDirectError> {
    let resolved = resolve_with_cert_chain(
        resolve_via,
        id,
        realm,
        procedure,
        realm_ca_pem,
        expected_org,
    )
    .await
    .map_err(OpenStreamDirectError::Resolve)?;
    let mut target = dial_and_verify(&resolved.host, resolved.port, resolved.station, id, timeout)
        .await
        .map_err(OpenStreamDirectError::Dial)?;
    match StreamHandle::open(&mut target, procedure, realm, mode, args, deadline_ms, id).await {
        Ok(handle) => Ok((target, handle)),
        Err(e) => {
            target.close("normal", None, id).await;
            Err(OpenStreamDirectError::Open(e))
        }
    }
}

#[derive(Debug)]
pub enum PutDirectError {
    Resolve(ResolveError),
    Dial(DialAndVerifyError),
    Put(content::PutError),
}

impl std::fmt::Display for PutDirectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PutDirectError::Resolve(e) => write!(f, "{e}"),
            PutDirectError::Dial(e) => write!(f, "{e}"),
            PutDirectError::Put(e) => write!(f, "direct_dial: {e}"),
        }
    }
}

impl std::error::Error for PutDirectError {}

/// Stores `data` at a KNOWN `station` directly, in one hop, instead of
/// going through whatever station `resolve_via` happens to be connected
/// to. Mirrors `macula_feeder:start_link_direct/5,6`, which — unlike
/// procedure/stream direct-dial — takes the target station's pubkey
/// directly rather than resolving one via a `procedure_advertisement`:
/// content has no "procedure" to advertise, so there is nothing to
/// resolve here beyond the station's own `station_endpoint`
/// (`resolve_station_endpoint`). `resolve_via` is used only to query the
/// DHT for `station`'s `station_endpoint`; it does not need to already be
/// connected to `station`.
///
/// **Caveat found live in `macula-go-sdk`'s port of this same function**:
/// if `resolve_via` happens to already be connected to `station` (the
/// common case when the caller doesn't have a separate resolver session),
/// this call's own internal dial reuses `id` against the SAME station
/// `resolve_via` is on — this fleet enforces one connection per identity
/// and kicks whichever connects second, so `resolve_via`'s own connection
/// can be closed out from under the caller by this call. Use a different
/// identity for `resolve_via` than for `id` if the caller needs
/// `resolve_via` to keep working afterward against that same station.
pub async fn put_direct(
    resolve_via: &mut Session,
    id: &KeyPair,
    station: [u8; 32],
    data: &[u8],
    name: impl Into<String>,
    timeout: Duration,
) -> Result<Mcid, PutDirectError> {
    let resolved = resolve_station_endpoint(resolve_via, id, station)
        .await
        .map_err(PutDirectError::Resolve)?;
    let mut target = dial_and_verify(&resolved.host, resolved.port, resolved.station, id, timeout)
        .await
        .map_err(PutDirectError::Dial)?;
    let result = content::put(&mut target, data, name, id)
        .await
        .map_err(PutDirectError::Put);
    target.close("normal", None, id).await;
    result
}

/// `mcid` has no live, verifiable `content_announcement` in the DHT —
/// either nobody announced it (common: a single-block content put alone is
/// never announced, matching `macula_content_transfer:put_single_block/3`),
/// or every candidate found failed signature/self-consistency
/// verification.
#[derive(Debug)]
pub struct ContentNotAnnounced;

impl std::fmt::Display for ContentNotAnnounced {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "direct_dial: content has no verifiable announcement in the DHT"
        )
    }
}

impl std::error::Error for ContentNotAnnounced {}

#[derive(Debug)]
pub enum GetDirectError {
    Dht(DhtError),
    NotAnnounced(ContentNotAnnounced),
    /// A `content_announcement`'s `endpoint` field wasn't a dialable
    /// `host:port` or URL.
    EndpointParse(String),
    Dial(DialAndVerifyError),
    Get(content::GetError),
}

impl std::fmt::Display for GetDirectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            GetDirectError::Dht(e) => write!(f, "direct_dial: find content providers: {e}"),
            GetDirectError::NotAnnounced(e) => write!(f, "{e}"),
            GetDirectError::EndpointParse(endpoint) => {
                write!(
                    f,
                    "direct_dial: content provider endpoint {endpoint:?}: not a URL or host:port"
                )
            }
            GetDirectError::Dial(e) => write!(f, "{e}"),
            GetDirectError::Get(e) => write!(f, "direct_dial: {e}"),
        }
    }
}

impl std::error::Error for GetDirectError {}

/// Fetches and verifies the content addressed by `mcid` from whichever
/// station a signed `content_announcement` names as its host, dialing
/// that station in one hop instead of relaying through `resolve_via`'s own
/// station. Mirrors `macula_direct_dial:get_content/3`.
///
/// **Architectural note this module's other direct-dial functions don't
/// need**: a `content_announcement`'s `endpoint` is the FINAL dial target
/// directly (see `macula_record:read_content_announcement/1`'s `endpoint`
/// field and `macula:get_content_station/5`'s use of it as-is) — unlike
/// `procedure_advertisement`, there is no station-relay indirection, so
/// the announcer must genuinely BE independently dialable there. A plain
/// outbound-only leaf (everything this SDK's own identity/session model
/// supports) cannot legitimately publish one of these about itself — only
/// something with its own listening identity (`macula-station`, or a
/// dedicated content-serving relay) can; confirmed directly against
/// `macula.erl`, which states a `content_announcement` is made
/// "automatically by the station on receipt," not by an arbitrary
/// publisher. This crate therefore does not expose a client-facing
/// "announce content direct": [`dht::new_content_announcement`] stays a
/// low-level primitive (mirroring `macula_record.erl`'s own export) for
/// that kind of infrastructure-tier code, not ordinary leaf use.
/// [`get_direct`] itself has no such limitation — resolving and fetching
/// FROM an already-announced provider is a perfectly ordinary leaf
/// operation.
pub async fn get_direct(
    resolve_via: &mut Session,
    id: &KeyPair,
    mcid: Mcid,
    timeout: Duration,
) -> Result<Vec<u8>, GetDirectError> {
    let recs = dht::find_records(resolve_via, id, dht::content_key(mcid))
        .await
        .map_err(GetDirectError::Dht)?;
    let adv = first_trusted_content_provider(&recs)
        .ok_or(GetDirectError::NotAnnounced(ContentNotAnnounced))?;
    let (host, port) = parse_seed_url(&adv.endpoint)
        .ok_or_else(|| GetDirectError::EndpointParse(adv.endpoint.clone()))?;
    let mut target = dial_and_verify(&host, port, adv.announcer_node, id, timeout)
        .await
        .map_err(GetDirectError::Dial)?;
    let result = content::get(&mut target, mcid, id)
        .await
        .map_err(GetDirectError::Get);
    target.close("normal", None, id).await;
    result
}

/// Mirrors `macula.erl`'s `decode_provider/1`: the record's OWN signature
/// must verify, AND the payload's claimed `announcer_node` must equal the
/// record's own envelope key — a record merely stored under the right key
/// but self-signed by a different identity would otherwise still be
/// trusted.
fn first_trusted_content_provider(recs: &[Record]) -> Option<dht::ContentAnnouncement> {
    recs.iter().find_map(|rec| {
        dht::verify(rec).ok()?;
        let adv = dht::read_content_announcement(rec).ok()?;
        (adv.announcer_node == rec.key).then_some(adv)
    })
}

/// Splits a `content_announcement`'s `endpoint` (a dialable seed URL, e.g.
/// `"https://host:4433"` — `macula_client:seed()`'s own format) into the
/// host/port pair [`connection::connect`] wants. Distinct from
/// `station_endpoint`'s already-split `host_advertised`/`quic_port`
/// fields — `content_announcement` embeds a single ready-to-dial URL
/// instead. Tolerates a bare `host:port` with no scheme too, matching this
/// crate's own tolerance elsewhere for a station config given without one.
fn parse_seed_url(seed: &str) -> Option<(String, u16)> {
    if let Some(rest) = seed
        .strip_prefix("https://")
        .or_else(|| seed.strip_prefix("http://"))
    {
        let hostport = rest.split('/').next().unwrap_or(rest);
        let (host, port_str) = hostport.rsplit_once(':')?;
        return Some((host.to_string(), port_str.parse().ok()?));
    }
    let (host, port_str) = seed.rsplit_once(':')?;
    Some((host.to_string(), port_str.parse().ok()?))
}
