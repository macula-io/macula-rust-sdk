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

use macula_rust_sdk::cert::ed25519_pubkey_from_cert;
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
