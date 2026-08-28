//! Integration tests against real, live macula-station boxes.
//!
//! **Not run by default CI** — every test here is `#[ignore]`d, since it
//! depends on external infrastructure this crate doesn't own or control
//! (network reachability, the fleet's own uptime). Run explicitly with:
//!
//! ```text
//! cargo test --test live_station -- --ignored --nocapture
//! ```
//!
//! **DNS gotcha, confirmed directly against the live box (2026-08-28):**
//! the bare `macula.io` hostname has an A (IPv4) record but genuinely no
//! AAAA record at all, while `macula-station-frankfurt`'s actual QUIC
//! listener (confirmed via `ss -ulnp` on the box itself) is bound to a
//! *specific* IPv6 address that has no relationship to the A record.
//! Dialing `macula.io` therefore resolves to a real, reachable IPv4
//! address with nothing listening on port 4433 — every packet vanishes
//! silently (correct, spec-compliant QUIC behavior for unrecognized
//! traffic, indistinguishable from a firewalled port from the client
//! side alone). `station-de-frankfurt.macula.io` is the name that
//! actually resolves to the listener's real IPv6 address — this matches
//! the DNS-repoint gotcha already on file in project memory
//! (`reference_demo_fleet_boxes`), confirmed still true today.

use macula_rust_sdk::cbor::Value;
use macula_rust_sdk::cert::ed25519_pubkey_from_cert;
use macula_rust_sdk::connection;
use macula_rust_sdk::identity::KeyPair;
use macula_rust_sdk::transport::{connect, Trust};

const STATION_HOST: &str = "station-de-frankfurt.macula.io";
const STATION_PORT: u16 = 4433;

/// Probe: dial with verification skipped, and report exactly what the
/// station presents (cert count, and its Ed25519 pubkey if the leaf is
/// Ed25519) — informational, not asserting a specific pubkey, since
/// that's fleet configuration this crate doesn't control and shouldn't
/// hardcode as a test expectation.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn probe_what_frankfurt_presents() {
    let connection = connect(STATION_HOST, STATION_PORT, Trust::Insecure)
        .await
        .expect("QUIC/TLS handshake with ALPN=macula should succeed against a live station");

    println!(
        "connected: alpn={:?} remote={}",
        connection
            .handshake_data()
            .and_then(|d| d.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
            .and_then(|d| d.protocol)
            .map(|p| String::from_utf8_lossy(&p).into_owned()),
        connection.remote_address(),
    );

    let identity = connection
        .peer_identity()
        .expect("server cert chain should be present after a completed handshake");
    let certs = identity
        .downcast::<Vec<rustls::pki_types::CertificateDer<'static>>>()
        .expect("peer_identity for a rustls-backed QUIC connection is a cert chain");
    println!("station presented {} certificate(s)", certs.len());

    let leaf = certs.first().expect("at least one cert in the chain");
    match ed25519_pubkey_from_cert(leaf.as_ref()) {
        Ok(pubkey) => println!("leaf is Ed25519, pubkey = {}", hex::encode(pubkey)),
        Err(e) => println!("leaf is NOT a bare Ed25519 SPKI cert: {e}"),
    }

    connection.close(0u32.into(), b"probe complete");
}

/// **Empirical finding, 2026-08-28:** `macula-station-frankfurt` presents
/// a 3-certificate RSA chain (SPKI OID `1.2.840.113549.1.1.1`), not a
/// self-signed Ed25519 identity cert — confirmed directly via
/// `probe_what_frankfurt_presents` above. That matches macula's own
/// documented "public-IP path with Let's Encrypt-anchored certs" trust
/// mode exactly (`plans/PLAN_WIRE_PROTOCOL.md` §2's `verify => webpki`),
/// which is what this test exercises. Pubkey-pinned trust
/// (`Trust::Pinned`) is for macula's *other* documented deployment shape
/// — a station without public DNS/CA-issued TLS, identified by its raw
/// Ed25519 key instead — which no box in the current demo fleet happens
/// to be configured as. `PubkeyPinVerifier`'s own matching logic is still
/// fully covered, just as a local unit test against a synthetic cert
/// (`src/cert.rs`'s own tests), not a live one — see that module.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn webpki_trust_succeeds_against_the_real_fleet() {
    let connection = connect(STATION_HOST, STATION_PORT, Trust::WebPki)
        .await
        .expect("CA-chain validation should succeed against a real Let's Encrypt cert");
    connection.close(0u32.into(), b"done");
}

/// The real milestone: not just a QUIC/TLS connection, but a complete
/// macula application-layer handshake — signed CONNECT out, verified
/// HELLO back, `accepted = true` — against a real production station.
/// Uses a **puzzle-hardened** identity deliberately: see
/// `plans/PLAN_WIRE_PROTOCOL.md` §5's callout on why an unhardened one
/// fails this silently (QUIC/TLS looks fine, the station just never
/// accepts).
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn full_handshake_succeeds_against_the_real_fleet() {
    let identity = KeyPair::generate_with_default_puzzle();

    let session = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &identity)
        .await
        .expect("CONNECT/HELLO handshake should succeed against a live station");

    println!(
        "handshake accepted: remote={} station_node_id={} negotiated_capabilities={}",
        session.remote_address(),
        hex::encode(session.station.node_id),
        session.station.negotiated_capabilities,
    );
    assert!(session.station.accepted);

    session
        .close("normal", Some("integration test done"), &identity)
        .await;
}

/// **Empirical finding, 2026-08-28 — contradicts the documented
/// expectation, recorded honestly rather than papered over.** The plan
/// (`plans/PLAN_WIRE_PROTOCOL.md` §5) and the production incident it's
/// based on both describe every station enforcing puzzle admission on
/// every CONNECT. Tested directly against `macula-station-frankfurt`: an
/// **unhardened identity was accepted** (`accepted = true`, same shape
/// as the hardened case). This crate's `puzzle_evidence` computation is
/// independently verified byte-for-byte against real Erlang
/// `crypto:hash/2` output (`src/identity.rs`'s own tests), so this isn't
/// a computation bug here — it means either (a) this specific dev-fleet
/// station has puzzle enforcement disabled or configured leniently (it's
/// documented elsewhere as throwaway dev infra, not production), (b) the
/// deployed image predates that enforcement, or (c) enforcement is
/// scoped to some condition this plain CONNECT doesn't trigger. Which
/// one is true is a `macula-station`-side question, out of scope for
/// this crate to chase — recorded here as a fact about what actually
/// happens against this fleet today, not a guarantee about macula's
/// protocol in general. **Always grind the puzzle regardless** (the cost
/// is negligible and it's clearly the intended, documented behavior) —
/// this test does not license skipping it.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn unhardened_identity_against_the_real_fleet_is_observed_not_assumed() {
    let identity = KeyPair::generate(); // NOT puzzle-hardened, on purpose

    let result = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &identity).await;
    match result {
        Ok(session) => {
            println!(
                "OBSERVED: unhardened identity was ACCEPTED (accepted={}) -- see this \
                 test's doc comment for why that's a fleet-configuration fact, not \
                 evidence this crate's puzzle handling is wrong",
                session.station.accepted
            );
            session.close("normal", None, &identity).await;
        }
        Err(e) => {
            println!("OBSERVED: unhardened identity was rejected, as: {e}");
        }
    }
}

/// A real end-to-end CALL/RESULT-or-ERROR round trip. Calls a procedure
/// name that certainly doesn't exist (`macula_rust_sdk.test_probe`,
/// under the content sentinel realm) — the point isn't to exercise any
/// particular procedure, only to prove the wire round trip itself: a
/// signed CALL sent, and a signed RESULT or ERROR received back,
/// correlated by call_id, with a real BOLT#4 code if it's an error.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn call_round_trip_against_the_real_fleet() {
    let identity = KeyPair::generate_with_default_puzzle();
    let mut session = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &identity)
        .await
        .expect("handshake should succeed");

    let response = session
        .call(
            "macula_rust_sdk.test_probe",
            [0u8; 32], // the content-sentinel realm, reused here as a harmless default
            macula_rust_sdk::cbor::Value::Null,
            (now_ms() + 10_000) as i128,
            &identity,
            std::time::Duration::from_secs(10),
        )
        .await
        .expect("should get SOME response (result or a well-formed error), not a timeout");

    match response {
        macula_rust_sdk::frame::CallResponse::Result {
            payload,
            responded_by,
        } => {
            println!("OBSERVED: got a RESULT (unexpected for a made-up procedure, but valid): payload={payload:?} responded_by={}", hex::encode(responded_by));
        }
        macula_rust_sdk::frame::CallResponse::Error {
            code,
            name,
            reported_by,
            detail,
        } => {
            println!(
                "OBSERVED: got an ERROR (expected for a nonexistent procedure): code={code} name={name} reported_by={} detail={detail:?}",
                hex::encode(reported_by)
            );
        }
    }

    session
        .close("normal", Some("call test done"), &identity)
        .await;
}

fn now_ms() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("system clock after epoch")
        .as_millis() as u64
}

/// A real end-to-end SUBSCRIBE -> PUBLISH -> (maybe) EVENT round trip.
/// Whether a subscriber receives its own publish is genuinely unknown
/// going in — this test observes and reports rather than assuming an
/// answer, same discipline as the unhardened-identity test above.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn pubsub_round_trip_against_the_real_fleet() {
    let identity = KeyPair::generate_with_default_puzzle();
    let mut session = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &identity)
        .await
        .expect("handshake should succeed");

    // A realm+topic scratch value nobody else would collide with.
    let realm: [u8; 32] = rand::random();
    let topic = format!(
        "macula-rust-sdk.test.{}",
        hex::encode(rand::random::<[u8; 8]>())
    );

    session
        .subscribe(
            &macula_rust_sdk::frame::SubscribeSpec::new(topic.clone(), realm, identity.node_id()),
            &identity,
        )
        .await
        .expect("SUBSCRIBE should send without error");

    session
        .publish(
            &macula_rust_sdk::frame::PublishSpec::new(
                topic.clone(),
                realm,
                identity.node_id(),
                1,
                macula_rust_sdk::cbor::Value::text("hello from macula-rust-sdk"),
                now_ms(),
            ),
            &identity,
        )
        .await
        .expect("PUBLISH should send without error");

    match session.recv_event(std::time::Duration::from_secs(5)).await {
        Ok(event) => {
            println!(
                "OBSERVED: received our own EVENT back — topic={} seq={} delivered_via={} payload={:?}",
                event.topic, event.seq, event.delivered_via, event.payload
            );
            assert_eq!(event.topic, topic);
        }
        Err(e) => {
            println!(
                "OBSERVED: no EVENT arrived within 5s ({e}) — a subscriber may not receive its \
                 own publish, or delivery may simply be slower than this test waits. Not \
                 asserted as a failure either way; see this test's doc comment."
            );
        }
    }

    session
        .close("normal", Some("pubsub test done"), &identity)
        .await;
}

/// A real single-block put/get round trip: content small enough
/// (`<= manifest::DEFAULT_CHUNK_SIZE`) to be addressed purely by content
/// hash, no manifest involved. Every byte is randomized per run so
/// there's no risk of colliding with content some other run already
/// stored under the same MCID.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn single_block_put_get_round_trip_against_the_real_fleet() {
    let identity = KeyPair::generate_with_default_puzzle();
    let mut session = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &identity)
        .await
        .expect("handshake should succeed");

    let data: Vec<u8> = (0..4096).map(|_| rand::random::<u8>()).collect();
    let mcid = macula_rust_sdk::content::put(&mut session, &data, "test-block", &identity)
        .await
        .expect("put should succeed");
    assert!(
        !macula_rust_sdk::manifest::mcid_is_chunked(&mcid),
        "4096 bytes is well under the chunking threshold"
    );
    println!(
        "OBSERVED: stored single block under mcid={}",
        hex::encode(mcid)
    );

    let fetched = macula_rust_sdk::content::get(&mut session, mcid, &identity)
        .await
        .expect("get should succeed for content this session just put");
    assert_eq!(
        fetched, data,
        "fetched bytes must match what was put, exactly"
    );

    session
        .close("normal", Some("content single-block test done"), &identity)
        .await;
}

/// A real chunked put/get round trip: content large enough to force
/// `manifest::create`'s multi-chunk path, exercising `_content.put_block`
/// (several times, sequentially — see `src/content.rs`'s module doc on
/// why this crate doesn't parallelize lanes), `_content.put_manifest`,
/// `_content.get_manifest`, and `_content.get_block` (again several
/// times) all against a real station, then verifies the reassembled
/// bytes against the manifest's Merkle root.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn chunked_put_get_round_trip_against_the_real_fleet() {
    let identity = KeyPair::generate_with_default_puzzle();
    let mut session = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &identity)
        .await
        .expect("handshake should succeed");

    let size = macula_rust_sdk::manifest::DEFAULT_CHUNK_SIZE * 2 + 12_345;
    let data: Vec<u8> = (0..size).map(|_| rand::random::<u8>()).collect();
    let mcid = macula_rust_sdk::content::put(&mut session, &data, "test-chunked", &identity)
        .await
        .expect("chunked put should succeed");
    assert!(
        macula_rust_sdk::manifest::mcid_is_chunked(&mcid),
        "{size} bytes is well over the chunking threshold"
    );
    println!(
        "OBSERVED: stored {size} bytes as a manifest under mcid={}",
        hex::encode(mcid)
    );

    let fetched = macula_rust_sdk::content::get(&mut session, mcid, &identity)
        .await
        .expect("chunked get should succeed for content this session just put");
    assert_eq!(
        fetched, data,
        "reassembled bytes must match what was put, exactly"
    );

    session
        .close("normal", Some("content chunked test done"), &identity)
        .await;
}

/// A made-up MCID that (with overwhelming probability) nothing has ever
/// stored — proves the wire-level `not_found` reply is reached and
/// parsed correctly, not just the happy path.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn get_of_an_unknown_block_reports_not_found_against_the_real_fleet() {
    let identity = KeyPair::generate_with_default_puzzle();
    let mut session = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &identity)
        .await
        .expect("handshake should succeed");

    let random_hash: [u8; 32] = rand::random();
    let mcid = macula_rust_sdk::manifest::block_mcid(&random_hash);

    match macula_rust_sdk::content::get(&mut session, mcid, &identity).await {
        Err(macula_rust_sdk::content::GetError::NotFound) => {
            println!("OBSERVED: not_found reported correctly for an unknown mcid");
        }
        other => panic!("expected GetError::NotFound, got {other:?}"),
    }

    session
        .close("normal", Some("content not-found test done"), &identity)
        .await;
}

/// A real STREAM_OPEN round trip against a deliberately nonexistent
/// procedure — same spirit as `call_round_trip_against_the_real_fleet`:
/// there's no known streaming procedure registered anywhere on this
/// fleet to exercise a genuine data exchange against (streaming
/// consumers like hecate-tube are separate app-level services, not part
/// of macula-station itself — see `plans/PLAN_WIRE_PROTOCOL.md` §13.4),
/// so this proves the wire mechanics — opening a dedicated stream,
/// sending a signed STREAM_OPEN, a chunk, a half-close, and awaiting
/// whatever the station does with an unknown procedure — rather than a
/// specific procedure's behavior.
///
/// **Empirical finding, 2026-08-28:** the station DOES actively validate
/// streaming procedures, symmetric to CALL. It replied with a real
/// STREAM_ERROR — `unknown_next_peer` / "procedure not advertised" —
/// which `StreamHandle::await_reply` correctly surfaced as
/// `RecvStreamError::PeerAborted`, round-tripping through
/// `frame::parse_stream_event`'s STREAM_ERROR branch on the very first
/// live run. Still printed as OBSERVED rather than asserted: this test
/// exists to prove the wire mechanics work at all, not to pin the
/// station's procedure-validation behavior as a contract this crate
/// depends on.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn stream_open_round_trip_against_the_real_fleet() {
    let identity = KeyPair::generate_with_default_puzzle();
    let mut session = connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &identity)
        .await
        .expect("handshake should succeed");

    let mut handle = macula_rust_sdk::stream::StreamHandle::open(
        &mut session,
        "macula_rust_sdk.test_stream",
        [0u8; 32],
        macula_rust_sdk::frame::StreamMode::ClientStream,
        macula_rust_sdk::cbor::Value::Null,
        (now_ms() + 10_000) as i128,
        &identity,
    )
    .await
    .expect("opening a dedicated stream and sending STREAM_OPEN should succeed");

    handle
        .send_data(
            macula_rust_sdk::frame::StreamEncoding::Raw,
            macula_rust_sdk::cbor::Value::Bytes(b"hello from macula-rust-sdk".to_vec()),
            &identity,
        )
        .await
        .expect("sending a chunk should succeed");
    handle
        .close_send(&identity)
        .await
        .expect("half-closing should succeed");

    match handle.await_reply(std::time::Duration::from_secs(5)).await {
        Ok((payload, responded_by)) => {
            println!(
                "OBSERVED: got a STREAM_REPLY (unexpected for a made-up procedure, but valid): payload={payload:?} responded_by={}",
                hex::encode(responded_by)
            );
        }
        Err(e) => {
            println!("OBSERVED: no reply within 5s, as: {e}");
        }
    }

    session
        .close("normal", Some("stream test done"), &identity)
        .await;
}

/// The real point of §13.2's whole existence: two independent
/// connections to the SAME live station — one advertises a procedure
/// and accepts inbound streams for it (the provider role), the other
/// dials in and pushes/pulls data against it (the caller role, already
/// live-verified elsewhere). This is the first test in this crate where
/// this process is on the RECEIVING end of a mesh interaction it didn't
/// initiate — everything before this dialed out and waited for a
/// response; here, one session sits idle after `advertise` until the
/// station itself routes a stranger's request back to it.
///
/// Same station on purpose: cross-station routing depends on gossip
/// propagation between stations, which isn't instant and isn't this
/// crate's concern to wait out — same-station is the direct case
/// `plans/PLAN_WIRE_PROTOCOL.md` §6.9 describes ("registers the handler
/// with the pool's advertise-gossip mechanism"), and it's what a real
/// provider dialed into one station actually needs day to day.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn streaming_provider_round_trip_against_the_real_fleet() {
    let provider_identity = KeyPair::generate_with_default_puzzle();
    let caller_identity = KeyPair::generate_with_default_puzzle();

    let mut provider_session = connection::connect(
        STATION_HOST,
        STATION_PORT,
        Trust::WebPki,
        &provider_identity,
    )
    .await
    .expect("provider handshake should succeed");
    let mut caller_session =
        connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &caller_identity)
            .await
            .expect("caller handshake should succeed");

    let realm: [u8; 32] = rand::random();
    let procedure = format!(
        "macula_rust_sdk.test_provider.{}",
        hex::encode(rand::random::<[u8; 8]>())
    );

    let advertise_spec = macula_rust_sdk::frame::AdvertiseSpec::new(
        realm,
        procedure.clone(),
        provider_identity.node_id(),
    );
    provider_session
        .advertise(&advertise_spec, &provider_identity)
        .await
        .expect("advertise should send");

    // Give the station a moment to register the advertisement before
    // the caller dials in against it.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let accept_task = tokio::spawn(async move {
        let result = macula_rust_sdk::stream::StreamHandle::accept(
            &mut provider_session,
            std::time::Duration::from_secs(10),
        )
        .await;
        (result, provider_session)
    });

    let mut caller_handle = macula_rust_sdk::stream::StreamHandle::open(
        &mut caller_session,
        &procedure,
        realm,
        macula_rust_sdk::frame::StreamMode::ServerStream,
        macula_rust_sdk::cbor::Value::Null,
        (now_ms() + 10_000) as i128,
        &caller_identity,
    )
    .await
    .expect("caller should open a stream");

    let (accept_result, provider_session) =
        accept_task.await.expect("accept task should not panic");
    let (mut provider_handle, open_info) =
        accept_result.expect("provider should accept the inbound STREAM_OPEN");

    println!(
        "OBSERVED: provider accepted stream_open for procedure={} mode={:?}",
        open_info.procedure, open_info.mode
    );
    assert_eq!(open_info.procedure, procedure);
    assert_eq!(
        open_info.mode,
        macula_rust_sdk::frame::StreamMode::ServerStream
    );

    provider_handle
        .send_data(
            macula_rust_sdk::frame::StreamEncoding::Raw,
            macula_rust_sdk::cbor::Value::Bytes(b"hello from the provider".to_vec()),
            &provider_identity,
        )
        .await
        .expect("provider should push a chunk");
    provider_handle
        .close_send(&provider_identity)
        .await
        .expect("provider should close its send side");

    match caller_handle
        .recv(std::time::Duration::from_secs(5))
        .await
        .expect("caller should receive the pushed chunk")
    {
        macula_rust_sdk::stream::StreamItem::Data { body, .. } => {
            assert_eq!(
                body,
                macula_rust_sdk::cbor::Value::Bytes(b"hello from the provider".to_vec())
            );
        }
        other => panic!("expected Data, got {other:?}"),
    }
    match caller_handle
        .recv(std::time::Duration::from_secs(5))
        .await
        .expect("caller should see end-of-stream")
    {
        macula_rust_sdk::stream::StreamItem::Eof => {}
        other => panic!("expected Eof, got {other:?}"),
    }

    provider_session
        .close("normal", Some("provider test done"), &provider_identity)
        .await;
    caller_session
        .close("normal", Some("caller test done"), &caller_identity)
        .await;
}

/// The unary-RPC counterpart to `streaming_provider_round_trip_against_the_real_fleet`
/// above, and the gap this crate's own README used to list as "not yet
/// built": two independent connections to the SAME live station, one
/// advertising a procedure and serving inbound CALLs for it via
/// [`connection::Session::serve_one_call`], the other dialing in and
/// calling it — the caller role already covered by
/// `call_round_trip_against_the_real_fleet`. Without this, a service
/// built on this crate could call RPCs and serve streams, but could
/// never serve a request/response procedure at all.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn unary_call_provider_round_trip_against_the_real_fleet() {
    let provider_identity = KeyPair::generate_with_default_puzzle();
    let caller_identity = KeyPair::generate_with_default_puzzle();

    let mut provider_session = connection::connect(
        STATION_HOST,
        STATION_PORT,
        Trust::WebPki,
        &provider_identity,
    )
    .await
    .expect("provider handshake should succeed");
    let mut caller_session =
        connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &caller_identity)
            .await
            .expect("caller handshake should succeed");

    let realm: [u8; 32] = rand::random();
    let procedure = format!(
        "macula_rust_sdk.test_add.{}",
        hex::encode(rand::random::<[u8; 8]>())
    );

    let advertise_spec = macula_rust_sdk::frame::AdvertiseSpec::new(
        realm,
        procedure.clone(),
        provider_identity.node_id(),
    );
    provider_session
        .advertise(&advertise_spec, &provider_identity)
        .await
        .expect("advertise should send");

    // Give the station a moment to register the advertisement before
    // the caller dials in against it.
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let target_procedure = procedure.clone();
    let lookup = move |_realm: &[u8; 32], proc: &str| -> Option<connection::CallHandler> {
        if proc != target_procedure {
            return None;
        }
        let handler: connection::CallHandler = std::sync::Arc::new(|payload: Value| {
            Box::pin(async move {
                let a = match payload.get("a") {
                    Some(Value::Int(n)) => *n,
                    _ => return Err("missing or non-integer field \"a\"".to_string()),
                };
                let b = match payload.get("b") {
                    Some(Value::Int(n)) => *n,
                    _ => return Err("missing or non-integer field \"b\"".to_string()),
                };
                Ok(Value::Int(a + b))
            }) as connection::BoxFuture<'static, Result<Value, String>>
        });
        Some(handler)
    };

    let serve_task = tokio::spawn(async move {
        let result = provider_session
            .serve_one_call(
                lookup,
                &provider_identity,
                std::time::Duration::from_secs(15),
            )
            .await;
        (result, provider_session, provider_identity)
    });

    let payload = Value::Map(vec![
        (Value::text("a"), Value::Int(3)),
        (Value::text("b"), Value::Int(4)),
    ]);
    let response = caller_session
        .call(
            &procedure,
            realm,
            payload,
            (now_ms() + 10_000) as i128,
            &caller_identity,
            std::time::Duration::from_secs(10),
        )
        .await
        .expect("call should succeed");

    let (serve_result, provider_session, provider_identity) =
        serve_task.await.expect("serve task should not panic");
    serve_result.expect("provider should serve the inbound CALL");

    match response {
        macula_rust_sdk::frame::CallResponse::Result { payload, .. } => {
            assert_eq!(payload, Value::Int(7), "3 + 4 should reply with RESULT 7");
        }
        other => panic!("expected a RESULT, got {other:?}"),
    }
    println!(
        "OBSERVED: provider served the inbound CALL for procedure={procedure}, caller got RESULT 7"
    );

    provider_session
        .close(
            "normal",
            Some("unary provider test done"),
            &provider_identity,
        )
        .await;
    caller_session
        .close("normal", Some("unary caller test done"), &caller_identity)
        .await;
}

/// Confirms the BOLT#4 error path: a provider that's advertised but
/// whose lookup (deliberately, here) can't find a handler replies with
/// the exact same `unknown_next_peer` code the reference sends for this
/// race (`macula_station_link.erl`'s `handle_inbound_call/2`, "unknown
/// (realm, procedure)" branch).
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn unary_call_provider_reports_unknown_next_peer_on_lookup_miss_against_the_real_fleet() {
    let provider_identity = KeyPair::generate_with_default_puzzle();
    let caller_identity = KeyPair::generate_with_default_puzzle();

    let mut provider_session = connection::connect(
        STATION_HOST,
        STATION_PORT,
        Trust::WebPki,
        &provider_identity,
    )
    .await
    .expect("provider handshake should succeed");
    let mut caller_session =
        connection::connect(STATION_HOST, STATION_PORT, Trust::WebPki, &caller_identity)
            .await
            .expect("caller handshake should succeed");

    let realm: [u8; 32] = rand::random();
    let procedure = format!(
        "macula_rust_sdk.test_miss.{}",
        hex::encode(rand::random::<[u8; 8]>())
    );

    let advertise_spec = macula_rust_sdk::frame::AdvertiseSpec::new(
        realm,
        procedure.clone(),
        provider_identity.node_id(),
    );
    provider_session
        .advertise(&advertise_spec, &provider_identity)
        .await
        .expect("advertise should send");
    tokio::time::sleep(std::time::Duration::from_millis(500)).await;

    let no_handlers = |_realm: &[u8; 32], _proc: &str| -> Option<connection::CallHandler> { None };
    let serve_task = tokio::spawn(async move {
        let result = provider_session
            .serve_one_call(
                no_handlers,
                &provider_identity,
                std::time::Duration::from_secs(15),
            )
            .await;
        (result, provider_session, provider_identity)
    });

    let response = caller_session
        .call(
            &procedure,
            realm,
            Value::Null,
            (now_ms() + 10_000) as i128,
            &caller_identity,
            std::time::Duration::from_secs(10),
        )
        .await
        .expect("call should succeed");

    let (serve_result, provider_session, provider_identity) =
        serve_task.await.expect("serve task should not panic");
    serve_result.expect("provider should serve the inbound CALL (with an error reply)");

    match response {
        macula_rust_sdk::frame::CallResponse::Error { code, name, .. } => {
            assert_eq!(code, macula_rust_sdk::bolt4::Code::UnknownNextPeer.as_u8());
            println!("OBSERVED: lookup miss correctly reported as ERROR code={code} name={name}");
        }
        other => panic!("expected an ERROR, got {other:?}"),
    }

    provider_session
        .close(
            "normal",
            Some("unary provider miss test done"),
            &provider_identity,
        )
        .await;
    caller_session
        .close(
            "normal",
            Some("unary caller miss test done"),
            &caller_identity,
        )
        .await;
}
