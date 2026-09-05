//! Proves `resolve_direct_with_cert_chain`/`call_direct_with_cert_chain`/
//! `advertise_direct_with_cert_chain` work end-to-end THROUGH the FFI
//! surface, mirroring `../../tests/live_cert_chain.rs`'s own self-issued
//! trust anchor (cert-chain authorization is a client-side check on an
//! opaque DHT payload the station itself never inspects, so no fleet
//! provisioning is needed).
//!
//! Not run by default CI — `#[ignore]`d, matching this crate's other live
//! tests. Run explicitly with:
//! `cargo test -p macula-rust-ffi --test live_cert_chain_direct_dial -- --ignored --nocapture`

use macula_rust_ffi::{
    FfiCallHandler, FfiCallResponse, FfiError, FfiKeyPair, FfiSession, FfiTrust, FfiValue,
};
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair as RcgenKeyPair};
use std::sync::Arc;
use std::time::Duration;

const STATION_HOST: &str = "station-de-frankfurt.macula.io";
const STATION_PORT: u16 = 4433;

fn short_hex(bytes: &[u8]) -> String {
    bytes.iter().take(8).map(|b| format!("{b:02x}")).collect()
}

/// Records the procedure of every CALL it answers -- see
/// `live_ffi.rs`'s identical `RecordingEchoHandler` for the full
/// reasoning (a one-shot `serve_one_call` answering SOMETHING is not
/// proof it answered THIS test's own call, on a shared public fleet).
struct RecordingEchoHandler {
    served: Arc<tokio::sync::Mutex<Vec<String>>>,
}

#[async_trait::async_trait]
impl FfiCallHandler for RecordingEchoHandler {
    async fn handle(
        &self,
        procedure: String,
        _realm: Vec<u8>,
        payload: FfiValue,
    ) -> Result<FfiValue, FfiError> {
        self.served.lock().await.push(procedure);
        Ok(payload)
    }
}

/// `serve_one_call` accepts the next inbound CALL unconditionally -- it
/// doesn't filter by procedure. On this shared public fleet a stray
/// unrelated CALL can arrive first; loop past it via a recording handler
/// rather than assuming the first one-shot serve answers this test's own
/// call. A first draft here returned `Ok` on ANY successful serve
/// regardless of which procedure it answered -- real bug, reproduced
/// live (a stray call satisfied the loop while this test's own call went
/// unanswered until it timed out) -- fixed to match `live_ffi.rs`'s
/// already-correct `serve_until_procedure`.
async fn serve_until_procedure(
    session: &FfiSession,
    procedure: &str,
    per_attempt_timeout_ms: u64,
    max_attempts: u32,
    identity: &FfiKeyPair,
) -> Result<(), FfiError> {
    let served = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    for _ in 0..max_attempts {
        let handler = Arc::new(RecordingEchoHandler {
            served: Arc::clone(&served),
        });
        match session
            .serve_one_call(handler, per_attempt_timeout_ms, identity)
            .await
        {
            Ok(()) => {
                if served.lock().await.iter().any(|p| p == procedure) {
                    return Ok(());
                }
            }
            Err(FfiError::Recv { .. }) => {}
            Err(other) => return Err(other),
        }
    }
    Ok(())
}

fn self_issued_realm_ca() -> (Vec<u8>, rcgen::Issuer<'static, RcgenKeyPair>) {
    let key_pair = RcgenKeyPair::generate_for(&rcgen::PKCS_ED25519).expect("ca keygen");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "Live FFI Test Realm CA");
    dn.push(DnType::OrganizationName, "Live FFI Test Realm CA");
    params.distinguished_name = dn;
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let cert = params.self_signed(&key_pair).expect("ca self-sign");
    let pem = cert.pem().into_bytes();
    (pem, rcgen::Issuer::new(params, key_pair))
}

/// RFC 8410 SubjectPublicKeyInfo DER for a raw 32-byte Ed25519 pubkey —
/// duplicated from the core crate's own `tests/live_cert_chain.rs`, which
/// duplicates it from `src/cert_chain.rs`'s own `#[cfg(test)]` helper for
/// the identical reason (not reachable across crate/module boundaries).
fn ed25519_spki_der(pubkey: [u8; 32]) -> Vec<u8> {
    let mut der = vec![
        0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
    ];
    der.extend_from_slice(&pubkey);
    der
}

fn issue_leaf(
    ca_issuer: &rcgen::Issuer<'static, RcgenKeyPair>,
    advertiser_pub: [u8; 32],
    org: &str,
) -> Vec<u8> {
    let subject_spki =
        rcgen::SubjectPublicKeyInfo::from_der(&ed25519_spki_der(advertiser_pub)).expect("spki");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("leaf params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "live-ffi-cert-chain-test-service");
    dn.push(DnType::OrganizationName, org);
    params.distinguished_name = dn;
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::hours(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::hours(1);
    let cert = params
        .signed_by(&subject_spki, ca_issuer)
        .expect("leaf signed_by");
    cert.der().to_vec()
}

fn pem_bundle(ders: &[Vec<u8>]) -> Vec<u8> {
    use base64::Engine;
    let mut out = Vec::new();
    for der in ders {
        let b64 = base64::engine::general_purpose::STANDARD.encode(der);
        out.extend_from_slice(b"-----BEGIN CERTIFICATE-----\n");
        for chunk in b64.as_bytes().chunks(64) {
            out.extend_from_slice(chunk);
            out.push(b'\n');
        }
        out.extend_from_slice(b"-----END CERTIFICATE-----\n");
    }
    out
}

/// Publishes a `cert_chain`-bearing advertisement via
/// `advertise_direct_with_cert_chain`, serves through it, and calls it via
/// `call_direct_with_cert_chain` from a separate session/identity — a real
/// RESULT, not just a reached-the-call-stage outcome (see this session's
/// own history for why that weaker bar already hid a real bug once).
/// Includes the negative control: the SAME chain correctly fails
/// authorization when a caller expects the wrong org.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn cert_chain_direct_dial_round_trip_through_the_ffi_surface() {
    let (ca_pem, ca_issuer) = self_issued_realm_ca();

    let provider_id = FfiKeyPair::generate();
    // Distinct from caller_id -- call_direct_with_cert_chain dials the
    // resolved station in a FRESH connection using this identity while
    // caller_id's own resolver session stays open throughout; reusing one
    // identity for both was a real bug (this fleet kicks whichever
    // connection reuses an identity second), already found and fixed in
    // live_ffi.rs's streaming test after hitting the identical symptom
    // ("timed out waiting for a frame" regardless of how long the
    // timeout was) there first.
    let dial_id = FfiKeyPair::generate();
    let caller_id = FfiKeyPair::generate();
    let procedure = format!(
        "macula_rust_ffi.live_test.cert_chain.{}",
        short_hex(&provider_id.node_id())
    );
    let realm = vec![0u8; 32];
    let org = "live-ffi-test-org";

    let leaf_der = issue_leaf(&ca_issuer, provider_id.node_id().try_into().unwrap(), org);
    let cert_chain_pem = pem_bundle(&[leaf_der]);

    let provider = FfiSession::connect(
        STATION_HOST.to_string(),
        STATION_PORT,
        FfiTrust::WebPki,
        &provider_id,
    )
    .await
    .expect("provider connect");
    provider
        .advertise_direct_with_cert_chain(
            procedure.clone(),
            realm.clone(),
            60_000,
            cert_chain_pem,
            &provider_id,
        )
        .await
        .expect("advertise_direct_with_cert_chain");

    let serve_procedure = procedure.clone();
    let serve_task = tokio::spawn(async move {
        let result =
            serve_until_procedure(&provider, &serve_procedure, 10_000, 10, &provider_id).await;
        // Keep the session alive briefly after the last reply -- Session
        // has no Drop impl, so dropping it immediately on return can
        // close the underlying QUIC connection before the just-sent
        // reply frame actually reaches the peer. Same race already
        // documented on Session::close, same fix already confirmed live
        // for the identical symptom in serve_one_call_gated (see 986b981).
        tokio::time::sleep(Duration::from_millis(300)).await;
        result
    });

    let caller = FfiSession::connect(
        STATION_HOST.to_string(),
        STATION_PORT,
        FfiTrust::WebPki,
        &caller_id,
    )
    .await
    .expect("caller connect");

    // Positive: right org, chain validates, real RESULT comes back.
    let response = match caller
        .call_direct_with_cert_chain(
            procedure.clone(),
            realm.clone(),
            ca_pem.clone(),
            org.to_string(),
            FfiValue::Text("authorized via cert chain".to_string()),
            30_000,
            &dial_id,
        )
        .await
    {
        Ok(r) => r,
        // KNOWN EXTERNAL BLOCKER, not a defect here -- same
        // already-documented gap as live_ffi.rs's streaming/content test
        // and the core crate's own tests/live_direct_dial_extensions.rs:
        // the demo fleet's station_endpoint records expire (5min TTL)
        // faster than they're republished.
        Err(FfiError::Resolve { reason }) if reason.contains("no reachable station_endpoint") => {
            eprintln!(
                "SKIP: resolved station published no reachable station_endpoint -- known \
                 external fleet staleness, not a defect here: {reason}"
            );
            serve_task.abort();
            return;
        }
        // RESOLVED 2026-08-30: the "provider answers correctly, caller
        // never gets the reply" symptom that took 3 rounds of theories to
        // narrow (see git history on this file for the ruled-out ones --
        // not cert-chain-specific, not station-specific, not a
        // timeout-cancellation artifact) turned out to be the exact same
        // premature-Session-drop race confirmed and fixed for
        // serve_one_call_gated in 986b981: `serve_task`'s async block
        // dropped `provider` the instant `serve_until_procedure` returned,
        // and Session has no Drop impl, so the just-sent reply frame could
        // be torn down before it reached the peer. Fixed above by keeping
        // the session alive 300ms after the last reply. Verified with 5
        // consecutive clean passes (was failing reliably before).
        Err(e) => panic!("call_direct_with_cert_chain: {e}"),
    };
    match response {
        FfiCallResponse::Result { payload, .. } => {
            assert_eq!(
                payload,
                FfiValue::Text("authorized via cert chain".to_string())
            );
        }
        FfiCallResponse::Error {
            code, name, detail, ..
        } => {
            panic!("expected a real RESULT, got ERROR code={code} name={name} detail={detail:?}");
        }
    }
    serve_task
        .await
        .expect("serve task should not panic")
        .expect("serve_one_call should have answered the call cleanly");

    // Negative control: same chain, wrong expected org -> resolve itself
    // must fail (nothing to dial), not silently succeed.
    let resolver = FfiSession::connect(
        STATION_HOST.to_string(),
        STATION_PORT,
        FfiTrust::WebPki,
        &caller_id,
    )
    .await
    .expect("resolver connect for negative control");
    let err = resolver
        .resolve_direct_with_cert_chain(
            procedure,
            realm,
            ca_pem,
            "some-other-org".to_string(),
            &caller_id,
        )
        .await
        .expect_err("resolve_direct_with_cert_chain should reject the wrong org");
    match err {
        FfiError::Resolve { reason } => {
            assert!(
                reason.contains("Authorized") || reason.contains("authoriz"),
                "expected an authorization-shaped rejection reason, got: {reason}"
            );
        }
        other => panic!("expected FfiError::Resolve, got {other:?}"),
    }
}
