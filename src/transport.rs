//! QUIC transport: dialing a macula-station, ported from
//! `native/macula_quic/src/config.rs` (`macula-io/macula`).
//!
//! Raw QUIC (RFC 9000), not real HTTP/3 despite the "HTTP/3 mesh"
//! branding elsewhere — ALPN is the plain string `"macula"`, and macula's
//! own application framing rides directly on QUIC streams. `quinn` is
//! the exact QUIC engine macula-station's own `native/macula_quic` NIF
//! already runs, so this is wire-compatible by construction, not by
//! coincidence.

use std::net::{SocketAddr, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use quinn::{ClientConfig, Endpoint, IdleTimeout, TransportConfig};

use crate::cert::{PubkeyPinVerifier, SkipServerVerification};

/// The ALPN macula-station listens for. Not `"h3"` — see the module doc.
pub const ALPN: &[u8] = b"macula";

/// Matches macula's own defaults (`macula_quic.erl`'s `idle_timeout_ms` /
/// `keep_alive_interval_ms`): long enough to tolerate a real gap between
/// frames without closing the connection, with keepalive pings sent
/// often enough (~10x within the idle window) that a healthy connection
/// is never mistaken for a dead one.
pub const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);
pub const DEFAULT_KEEP_ALIVE_INTERVAL: Duration = Duration::from_secs(15);

/// How to trust whatever certificate the station presents. Mirrors the
/// three modes `macula_quic`'s own `build_client_config` supports — see
/// `plans/PLAN_WIRE_PROTOCOL.md` §2.
///
/// `Clone, Copy`: every variant is plain data (a bare `[u8; 32]` or
/// nothing at all), and `pool.rs` needs to redial a link — possibly
/// under a DIFFERENT per-link trust than the pool's own configured
/// default, see `pool::PooledLink`'s own doc — more than once over a
/// link's lifetime (initial dial, every respawn).
#[derive(Clone, Copy)]
pub enum Trust {
    /// Pin the station's known Ed25519 pubkey (its macula NodeId). The
    /// right mode once a station's identity is known — DHT-resolved, or
    /// configured directly, which is the normal case for a mobile client
    /// dialing a known station.
    Pinned([u8; 32]),
    /// Standard CA-bundle + hostname validation, for a station whose TLS
    /// is terminated by real PKI (e.g. Let's Encrypt) rather than a
    /// self-signed macula identity cert.
    WebPki,
    /// Skip verification entirely. **Development/diagnostic only** — see
    /// [`crate::cert::SkipServerVerification`]'s own warning.
    Insecure,
}

#[derive(Debug)]
pub enum ConnectError {
    Resolve(std::io::Error),
    NoAddress,
    Endpoint(std::io::Error),
    Config(rustls::Error),
    Connect(quinn::ConnectError),
    Connection(quinn::ConnectionError),
}

impl std::fmt::Display for ConnectError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ConnectError::Resolve(e) => write!(f, "resolving station address: {e}"),
            ConnectError::NoAddress => write!(f, "hostname resolved to no addresses"),
            ConnectError::Endpoint(e) => write!(f, "creating QUIC endpoint: {e}"),
            ConnectError::Config(e) => write!(f, "building TLS config: {e}"),
            ConnectError::Connect(e) => write!(f, "starting QUIC connect: {e}"),
            ConnectError::Connection(e) => write!(f, "QUIC connection failed: {e}"),
        }
    }
}

impl std::error::Error for ConnectError {}

fn client_config(trust: Trust) -> Result<ClientConfig, rustls::Error> {
    let mut crypto = match trust {
        Trust::Pinned(pubkey) => rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(PubkeyPinVerifier::new(pubkey)))
            .with_no_client_auth(),
        Trust::WebPki => {
            let mut roots = rustls::RootCertStore::empty();
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth()
        }
        Trust::Insecure => rustls::ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(SkipServerVerification::new()))
            .with_no_client_auth(),
    };
    crypto.alpn_protocols = vec![ALPN.to_vec()];

    let mut transport = TransportConfig::default();
    transport.max_idle_timeout(Some(
        IdleTimeout::try_from(DEFAULT_IDLE_TIMEOUT).expect("valid idle timeout"),
    ));
    transport.keep_alive_interval(Some(DEFAULT_KEEP_ALIVE_INTERVAL));
    apply_flow_control_defaults(&mut transport);

    let quic_crypto = quinn::crypto::rustls::QuicClientConfig::try_from(crypto)
        .map_err(|e| rustls::Error::General(e.to_string()))?;
    let mut config = ClientConfig::new(Arc::new(quic_crypto));
    config.transport_config(Arc::new(transport));
    Ok(config)
}

/// Matches macula's own `apply_flow_control_defaults` in
/// `native/macula_quic/src/config.rs`: default Quinn flow-control
/// windows are conservative enough to bottleneck a connection carrying
/// many small signed frames, well before either side's application-level
/// backpressure kicks in.
fn apply_flow_control_defaults(transport: &mut TransportConfig) {
    transport.stream_receive_window((16u32 * 1024 * 1024).into());
    transport.receive_window((64u32 * 1024 * 1024).into());
    transport.send_window(64u64 * 1024 * 1024);
}

/// Dial a macula-station at `host:port` over QUIC with the given trust
/// mode, completing the QUIC/TLS handshake (ALPN negotiation included).
/// This is transport-only — it does **not** send or expect any macula
/// application frame (CONNECT/HELLO); see `plans/PLAN_WIRE_PROTOCOL.md`
/// §3 for what happens on top of this connection.
pub async fn connect(
    host: &str,
    port: u16,
    trust: Trust,
) -> Result<quinn::Connection, ConnectError> {
    let addr = resolve(host, port)?;
    let bind_addr: SocketAddr = if addr.is_ipv6() {
        "[::]:0".parse().expect("valid unspecified v6 addr")
    } else {
        "0.0.0.0:0".parse().expect("valid unspecified v4 addr")
    };

    let mut endpoint = Endpoint::client(bind_addr).map_err(ConnectError::Endpoint)?;
    let config = client_config(trust).map_err(ConnectError::Config)?;
    endpoint.set_default_client_config(config);

    let connecting = endpoint
        .connect(addr, host)
        .map_err(ConnectError::Connect)?;
    connecting.await.map_err(ConnectError::Connection)
}

fn resolve(host: &str, port: u16) -> Result<SocketAddr, ConnectError> {
    (host, port)
        .to_socket_addrs()
        .map_err(ConnectError::Resolve)?
        .next()
        .ok_or(ConnectError::NoAddress)
}
