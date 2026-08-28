//! The CONNECT/HELLO handshake, ported from the client-side path of
//! `src/peering/macula_peering_conn.erl`'s `gen_statem`
//! (`macula-io/macula`) — see `plans/PLAN_WIRE_PROTOCOL.md` §3.
//!
//! Only the client role's `connecting -> handshaking -> connected` path
//! is implemented here. Everything after a successful handshake
//! (application frames on the control stream, dedicated streams,
//! draining/close) is future work — see the crate's own README/plan for
//! what's next.

use std::time::Duration;

use crate::frame::{self, Decoded, HelloInfo};
use crate::identity::KeyPair;
use crate::transport::{self, ConnectError, Trust};

/// Matches `HANDSHAKE_TIMEOUT_MS` in `macula_peering_conn.erl`: CONNECT
/// -> HELLO is sub-second on a healthy peer; this is generous. The most
/// common real-world trigger for hitting it is a protocol version
/// mismatch — bytes accumulate but never form a valid frame, so the
/// station-side symptom and this crate's symptom are the same shape.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound on a single read from the QUIC stream while accumulating a
/// frame. Not a protocol limit — just how much to ask the stream for at
/// once; `frame::decode`'s own `MAX_FRAME_BYTES` is the real cap.
const READ_CHUNK: usize = 64 * 1024;

/// A completed, handshaked connection to a macula-station. Holds the
/// open control stream (CONNECT/HELLO already exchanged) and the
/// station's identity as verified by the HELLO frame's own signature.
pub struct Session {
    // Kept alive for future use (application frames on the control
    // stream — CALL/PUBLISH — aren't implemented yet, only the
    // handshake). Unused fields are expected at this stage, not a bug.
    #[allow(dead_code)]
    connection: quinn::Connection,
    #[allow(dead_code)]
    send: quinn::SendStream,
    #[allow(dead_code)]
    recv: quinn::RecvStream,
    /// Bytes read from the stream but not yet consumed by a decoded
    /// frame — carried over from the handshake read loop so a caller
    /// building on this `Session` doesn't lose any already-buffered
    /// bytes belonging to the *next* frame.
    buf: Vec<u8>,
    pub station: HelloInfo,
}

#[derive(Debug)]
pub enum HandshakeError {
    Transport(ConnectError),
    OpenStream(quinn::ConnectionError),
    Write(quinn::WriteError),
    Read(quinn::ReadError),
    /// The peer closed the stream before a complete frame arrived.
    StreamClosed,
    Timeout,
    Encode(frame::EncodeFrameError),
    Decode(frame::DecodeFrameError),
    /// Received a frame, but it wasn't a HELLO — a station is never
    /// expected to send anything else at this point in the handshake.
    UnexpectedFrameType(frame::ParseHelloError),
    /// The HELLO frame's own signature didn't verify against the
    /// node_id it claims — proves nothing about who actually sent it.
    SignatureInvalid(frame::VerifyError),
    /// The station completed the handshake but refused the connection
    /// (`accepted = false`), e.g. a puzzle-invalid or unrecognized
    /// identity.
    Refused {
        refusal_code: Option<i128>,
    },
}

impl std::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            HandshakeError::Transport(e) => write!(f, "transport: {e}"),
            HandshakeError::OpenStream(e) => write!(f, "opening control stream: {e}"),
            HandshakeError::Write(e) => write!(f, "sending CONNECT: {e}"),
            HandshakeError::Read(e) => write!(f, "reading from control stream: {e}"),
            HandshakeError::StreamClosed => {
                write!(f, "station closed the stream before HELLO arrived")
            }
            HandshakeError::Timeout => write!(
                f,
                "no HELLO within {HANDSHAKE_TIMEOUT:?} (likely a protocol mismatch)"
            ),
            HandshakeError::Encode(e) => write!(f, "encoding CONNECT: {e}"),
            HandshakeError::Decode(e) => write!(f, "decoding the station's response: {e}"),
            HandshakeError::UnexpectedFrameType(e) => write!(f, "expected a HELLO frame: {e}"),
            HandshakeError::SignatureInvalid(e) => write!(f, "HELLO signature check failed: {e}"),
            HandshakeError::Refused { refusal_code } => {
                write!(
                    f,
                    "station refused the connection (refusal_code = {refusal_code:?})"
                )
            }
        }
    }
}

impl std::error::Error for HandshakeError {}

/// Dial `host:port` and complete the full CONNECT/HELLO handshake:
/// open a QUIC connection, open the control stream, send a signed
/// CONNECT built from `identity`, and wait for a HELLO whose own
/// signature verifies against the node_id it claims.
///
/// `identity` **must** be puzzle-hardened
/// ([`KeyPair::generate_with_puzzle`](crate::identity::KeyPair::generate_with_puzzle))
/// — see that function's own doc and `plans/PLAN_WIRE_PROTOCOL.md` §5's
/// callout: an unhardened identity fails this handshake silently (the
/// QUIC/TLS layer looks healthy right up until the HELLO never accepts).
pub async fn connect(
    host: &str,
    port: u16,
    trust: Trust,
    identity: &KeyPair,
) -> Result<Session, HandshakeError> {
    tokio::time::timeout(
        HANDSHAKE_TIMEOUT,
        connect_inner(host, port, trust, identity),
    )
    .await
    .unwrap_or(Err(HandshakeError::Timeout))
}

async fn connect_inner(
    host: &str,
    port: u16,
    trust: Trust,
    identity: &KeyPair,
) -> Result<Session, HandshakeError> {
    let connection = transport::connect(host, port, trust)
        .await
        .map_err(HandshakeError::Transport)?;

    let (mut send, mut recv) = connection
        .open_bi()
        .await
        .map_err(HandshakeError::OpenStream)?;

    let connect_spec =
        crate::frame::ConnectSpec::new(identity.node_id(), identity.puzzle_evidence());
    let connect_frame = frame::sign(frame::connect(&connect_spec), identity);
    let encoded = frame::encode(&connect_frame).map_err(HandshakeError::Encode)?;
    send.write_all(&encoded)
        .await
        .map_err(HandshakeError::Write)?;

    let (hello_value, buf) = read_one_frame(&mut recv).await?;

    let station = frame::parse_hello(&hello_value).map_err(HandshakeError::UnexpectedFrameType)?;
    frame::verify(&hello_value, &station.node_id).map_err(HandshakeError::SignatureInvalid)?;

    if !station.accepted {
        return Err(HandshakeError::Refused {
            refusal_code: station.refusal_code,
        });
    }

    Ok(Session {
        connection,
        send,
        recv,
        buf,
        station,
    })
}

/// Read from `recv` until one complete frame has been decoded, returning
/// it along with any leftover bytes already read that belong to the
/// *next* frame (so a caller can carry them forward instead of losing
/// them).
async fn read_one_frame(
    recv: &mut quinn::RecvStream,
) -> Result<(crate::cbor::Value, Vec<u8>), HandshakeError> {
    let mut buf = Vec::new();
    let mut chunk = vec![0u8; READ_CHUNK];
    loop {
        match frame::decode(&buf) {
            Ok(Decoded::Frame(value, consumed)) => {
                buf.drain(..consumed);
                return Ok((value, buf));
            }
            Ok(Decoded::More(_)) => {}
            Err(e) => return Err(HandshakeError::Decode(e)),
        }
        let n = recv
            .read(&mut chunk)
            .await
            .map_err(HandshakeError::Read)?
            .ok_or(HandshakeError::StreamClosed)?;
        buf.extend_from_slice(&chunk[..n]);
    }
}

impl Session {
    /// The remote address this session's connection is with.
    pub fn remote_address(&self) -> std::net::SocketAddr {
        self.connection.remote_address()
    }

    /// Any bytes already read past the HELLO frame during the handshake
    /// (belonging to whatever the station sent next) that a caller
    /// building further protocol handling on top of this `Session`
    /// should treat as already-received.
    pub fn leftover_bytes(&self) -> &[u8] {
        &self.buf
    }

    /// Close the control stream and connection gracefully with a GOODBYE
    /// frame, matching `macula_peering_conn.erl`'s `connected -> draining`
    /// transition (minus the drain-timeout bookkeeping, since this crate
    /// isn't holding a supervisor to clean up).
    pub async fn close(mut self, reason: &str, detail: Option<&str>, identity: &KeyPair) {
        let goodbye = frame::sign(frame::goodbye(reason, detail), identity);
        if let Ok(encoded) = frame::encode(&goodbye) {
            let _ = self.send.write_all(&encoded).await;
        }
        let _ = self.send.finish();
        self.connection.close(0u32.into(), reason.as_bytes());
    }
}
