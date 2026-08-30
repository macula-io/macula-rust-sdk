//! Integration tests exercising the actual UniFFI-exported surface
//! (`FfiSession`/`FfiKeyPair`/`FfiValue`/`FfiCallHandler`), not the core
//! crate directly — this is what a generated Kotlin/Swift binding would
//! actually call through. `macula-rust-sdk-ffi` had no test harness at
//! all beyond `FfiValue`'s own pure conversion tests before this file;
//! testing only the core crate (already covered by `../tests/live_station.rs`)
//! would never catch a bug introduced in THIS crate's own wrapping —
//! wrong argument order, a broken error conversion, a type that doesn't
//! actually cross the boundary the way it's assumed to.
//!
//! **Not run by default CI** — every test here is `#[ignore]`d, matching
//! `../tests/live_station.rs`'s own convention:
//!
//! ```text
//! cargo test -p macula-rust-sdk-ffi --test live_ffi -- --ignored --nocapture
//! ```
//!
//! No mobile toolchain (Kotlin/Swift compiler + runtime) is available in
//! this environment, so this cannot exercise the generated bindings
//! themselves end-to-end — only the Rust-side glue every generated binding
//! calls into. `cargo run -p macula-rust-sdk-ffi --bin uniffi-bindgen --
//! generate --library <cdylib> --language kotlin --out-dir <dir>`
//! succeeding without error (checked separately, not in this file) is the
//! remaining piece of confidence that the newly-added types/methods are
//! actually representable in the generated bindings at all.

use macula_rust_sdk_ffi::{
    FfiCallHandler, FfiCallResponse, FfiError, FfiKeyPair, FfiSession, FfiTrust, FfiValue,
};
use std::sync::Arc;

const MILAN_HOST: &str = "station-it-milan.macula.io";
const MILAN_PORT: u16 = 4433;

/// A short, unique-enough procedure-name suffix from an identity's node
/// id, without pulling in a `hex` crate dependency just for test naming.
fn short_hex(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

struct EchoHandler;

#[async_trait::async_trait]
impl FfiCallHandler for EchoHandler {
    async fn handle(
        &self,
        _procedure: String,
        _realm: Vec<u8>,
        payload: FfiValue,
    ) -> Result<FfiValue, FfiError> {
        Ok(payload)
    }
}

/// Proves the newly-exposed `resolve_direct`/`call_direct`/`advertise_direct`
/// work end-to-end THROUGH the FFI types: a provider session advertises
/// direct-dial reachability and serves one call via the exported
/// `FfiCallHandler` trait; a separate session/identity resolves and calls
/// it, and gets back a real RESULT it can inspect via `FfiValue`/
/// `FfiCallResponse` — not just "reached the call stage" (see this
/// session's own `macula-go-sdk`/`macula-rust-sdk` history for why that
/// weaker bar isn't good enough: it already hid a real
/// missing-plain-ADVERTISE bug in `advertise_direct` once).
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn direct_dial_round_trip_through_the_ffi_surface() {
    let provider_id = FfiKeyPair::generate();
    let caller_id = FfiKeyPair::generate();
    let procedure = format!(
        "macula_rust_sdk_ffi.live_test.echo.{}",
        short_hex(&provider_id.node_id())
    );
    let realm = vec![0u8; 32];

    let provider = Arc::new(
        FfiSession::connect(
            MILAN_HOST.to_string(),
            MILAN_PORT,
            FfiTrust::WebPki,
            &provider_id,
        )
        .await
        .expect("provider connect"),
    );

    provider
        .advertise_direct(procedure.clone(), realm.clone(), 60_000, &provider_id)
        .await
        .expect("advertise_direct");

    let serve_provider = Arc::clone(&provider);
    let serve_task = tokio::spawn(async move {
        serve_provider
            .serve_one_call(Arc::new(EchoHandler), 20_000, &provider_id)
            .await
    });

    let caller = FfiSession::connect(
        MILAN_HOST.to_string(),
        MILAN_PORT,
        FfiTrust::WebPki,
        &caller_id,
    )
    .await
    .expect("caller connect");

    let response = caller
        .call_direct(
            procedure,
            realm,
            FfiValue::Text("hello via ffi direct-dial".to_string()),
            15_000,
            &caller_id,
        )
        .await
        .expect("call_direct should succeed through a live provider");

    match response {
        FfiCallResponse::Result { payload, .. } => {
            assert_eq!(
                payload,
                FfiValue::Text("hello via ffi direct-dial".to_string()),
                "echoed payload should round-trip through FfiValue unchanged"
            );
        }
        FfiCallResponse::Error {
            code, name, detail, ..
        } => {
            panic!("expected a real RESULT, got a bolt4 ERROR frame instead: code={code} name={name} detail={detail:?}");
        }
    }

    serve_task
        .await
        .expect("serve task should not panic")
        .expect("serve_one_call should have answered the call cleanly");
}

/// `resolve_direct` alone, without a live call — proves the DHT
/// publish/resolve round trip through the FFI's `FfiResolved` type
/// specifically (the round trip through `FfiCallResponse`/`FfiValue` is
/// already covered above).
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn resolve_direct_through_the_ffi_surface() {
    let id = FfiKeyPair::generate();
    let procedure = format!(
        "macula_rust_sdk_ffi.live_test.resolve_only.{}",
        short_hex(&id.node_id())
    );
    let realm = vec![0u8; 32];

    let session = FfiSession::connect(MILAN_HOST.to_string(), MILAN_PORT, FfiTrust::WebPki, &id)
        .await
        .expect("connect");

    session
        .advertise_direct(procedure.clone(), realm.clone(), 60_000, &id)
        .await
        .expect("advertise_direct");

    let resolved = session
        .resolve_direct(procedure, realm, &id)
        .await
        .expect("resolve_direct should find what was just advertised");

    // `resolved.station` is the STATION's own node id (Milan's, here) --
    // the DHT record's `serving_station` field, per `advertise_direct`'s
    // own design -- NOT this identity's node id. `FfiSession` exposes no
    // accessor for "which station am I connected to" to compare against
    // directly, so a 32-byte sanity check is the honest bound here; the
    // full round trip above already proves resolution correctly finds a
    // station that actually routes the call, which is the real property
    // under test.
    assert_eq!(resolved.station.len(), 32, "station id should be 32 bytes");
    assert!(
        !resolved.host.is_empty(),
        "resolved host should be non-empty"
    );
    assert_eq!(resolved.port, 4433);
}
