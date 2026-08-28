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
    connection: quinn::Connection,
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    /// Bytes read from the stream but not yet consumed by a decoded
    /// frame — carried over between reads (starting with whatever was
    /// left over from the handshake) so nothing is ever dropped.
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

/// Default timeout for a single CALL awaiting its RESULT/ERROR. Not from
/// the reference source (macula's own CALL timeout is caller-supplied
/// per-call via `deadline_ms` inside the frame itself, not a transport-
/// level default) — a reasonable local default for this crate's API.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug)]
pub enum SendFrameError {
    Encode(frame::EncodeFrameError),
    Write(quinn::WriteError),
}

impl std::fmt::Display for SendFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendFrameError::Encode(e) => write!(f, "encoding frame: {e}"),
            SendFrameError::Write(e) => write!(f, "writing to control stream: {e}"),
        }
    }
}

impl std::error::Error for SendFrameError {}

#[derive(Debug)]
pub enum RecvFrameError {
    Read(quinn::ReadError),
    StreamClosed,
    Decode(frame::DecodeFrameError),
    Timeout,
}

impl std::fmt::Display for RecvFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecvFrameError::Read(e) => write!(f, "reading from control stream: {e}"),
            RecvFrameError::StreamClosed => write!(f, "station closed the control stream"),
            RecvFrameError::Decode(e) => write!(f, "decoding a frame: {e}"),
            RecvFrameError::Timeout => write!(f, "timed out waiting for a frame"),
        }
    }
}

impl std::error::Error for RecvFrameError {}

#[derive(Debug)]
pub enum CallError {
    Send(SendFrameError),
    Recv(RecvFrameError),
}

impl std::fmt::Display for CallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CallError::Send(e) => write!(f, "sending CALL: {e}"),
            CallError::Recv(e) => write!(f, "awaiting RESULT/ERROR: {e}"),
        }
    }
}

impl std::error::Error for CallError {}

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

    async fn send_frame(&mut self, frame: crate::cbor::Value) -> Result<(), SendFrameError> {
        let encoded = frame::encode(&frame).map_err(SendFrameError::Encode)?;
        self.send
            .write_all(&encoded)
            .await
            .map_err(SendFrameError::Write)
    }

    /// Read the next complete application frame from the control stream,
    /// using (and updating) any bytes already buffered — including
    /// whatever was left over from the handshake itself.
    pub async fn recv_frame(&mut self) -> Result<crate::cbor::Value, RecvFrameError> {
        let mut chunk = vec![0u8; READ_CHUNK];
        loop {
            match frame::decode(&self.buf) {
                Ok(Decoded::Frame(value, consumed)) => {
                    self.buf.drain(..consumed);
                    return Ok(value);
                }
                Ok(Decoded::More(_)) => {}
                Err(e) => return Err(RecvFrameError::Decode(e)),
            }
            let n = self
                .recv
                .read(&mut chunk)
                .await
                .map_err(RecvFrameError::Read)?
                .ok_or(RecvFrameError::StreamClosed)?;
            self.buf.extend_from_slice(&chunk[..n]);
        }
    }

    /// As [`recv_frame`](Self::recv_frame), bounded by `timeout`.
    pub async fn recv_frame_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<crate::cbor::Value, RecvFrameError> {
        tokio::time::timeout(timeout, self.recv_frame())
            .await
            .unwrap_or(Err(RecvFrameError::Timeout))
    }

    /// Send a signed CALL for `procedure` and wait for the matching
    /// RESULT or ERROR, correlated by `call_id`.
    ///
    /// **Known v1 limitation:** any frame that arrives before the match
    /// (e.g. an EVENT from an active SUBSCRIBE) is currently discarded,
    /// not queued or dispatched elsewhere — correct for a client doing
    /// one thing at a time on this control stream, not yet correct for
    /// CALL and PUBLISH/SUBSCRIBE used concurrently. No demultiplexing
    /// layer exists yet; this is exactly the kind of thing a future
    /// `event_tx`/dispatcher would fix, not implemented in this pass.
    pub async fn call(
        &mut self,
        procedure: &str,
        realm: [u8; 32],
        payload: crate::cbor::Value,
        deadline_ms: i128,
        identity: &KeyPair,
        timeout: Duration,
    ) -> Result<frame::CallResponse, CallError> {
        let call_id: [u8; 16] = rand::random();
        let spec = frame::CallSpec::new(
            call_id,
            procedure,
            realm,
            payload,
            deadline_ms,
            identity.node_id(),
        );
        let signed = frame::sign(frame::call(&spec), identity);
        self.send_frame(signed).await.map_err(CallError::Send)?;

        tokio::time::timeout(timeout, self.await_call_response(call_id))
            .await
            .unwrap_or(Err(CallError::Recv(RecvFrameError::Timeout)))
    }

    async fn await_call_response(
        &mut self,
        call_id: [u8; 16],
    ) -> Result<frame::CallResponse, CallError> {
        loop {
            let value = self.recv_frame().await.map_err(CallError::Recv)?;
            if frame::frame_call_id(&value) != Some(call_id) {
                continue; // not ours — see call()'s doc on this limitation
            }
            if let Ok(response) = frame::parse_call_response(&value) {
                return Ok(response);
            }
            // Matching call_id but not a result/error shape: keep
            // waiting rather than erroring, since nothing else in the
            // protocol is expected to carry this call's id.
        }
    }

    /// Send a signed PUBLISH. Fire-and-forget — no reply is expected on
    /// the wire; a subscriber (this session included, if subscribed to
    /// the same topic/realm) receives an EVENT asynchronously, read via
    /// [`recv_frame`](Self::recv_frame) / [`recv_event`](Self::recv_event).
    pub async fn publish(
        &mut self,
        spec: &frame::PublishSpec,
        identity: &KeyPair,
    ) -> Result<(), SendFrameError> {
        let signed = frame::sign(frame::publish(spec), identity);
        self.send_frame(signed).await
    }

    /// Send a signed SUBSCRIBE. Fire-and-forget.
    pub async fn subscribe(
        &mut self,
        spec: &frame::SubscribeSpec,
        identity: &KeyPair,
    ) -> Result<(), SendFrameError> {
        let signed = frame::sign(frame::subscribe(spec), identity);
        self.send_frame(signed).await
    }

    /// Send a signed UNSUBSCRIBE. Fire-and-forget.
    pub async fn unsubscribe(
        &mut self,
        spec: &frame::UnsubscribeSpec,
        identity: &KeyPair,
    ) -> Result<(), SendFrameError> {
        let signed = frame::sign(frame::unsubscribe(spec), identity);
        self.send_frame(signed).await
    }

    /// Read the next frame and parse it as an EVENT, bounded by
    /// `timeout`. Any non-EVENT frame received first is an error, not
    /// silently skipped — unlike [`call`](Self::call)'s response wait,
    /// a caller waiting specifically for a pubsub delivery has no reason
    /// to expect anything else to legitimately arrive first.
    pub async fn recv_event(
        &mut self,
        timeout: Duration,
    ) -> Result<frame::EventInfo, RecvEventError> {
        let value = self
            .recv_frame_timeout(timeout)
            .await
            .map_err(RecvEventError::Recv)?;
        frame::parse_event(&value).map_err(RecvEventError::Parse)
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

#[derive(Debug)]
pub enum RecvEventError {
    Recv(RecvFrameError),
    Parse(frame::ParseEventError),
}

impl std::fmt::Display for RecvEventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecvEventError::Recv(e) => write!(f, "{e}"),
            RecvEventError::Parse(e) => write!(f, "expected an EVENT frame: {e}"),
        }
    }
}

impl std::error::Error for RecvEventError {}
