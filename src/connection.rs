//! The CONNECT/HELLO handshake and the application-frame stream
//! abstraction, ported from `src/peering/macula_peering_conn.erl`
//! (`macula-io/macula`) — see `plans/PLAN_WIRE_PROTOCOL.md` §3.
//!
//! Only the client role's `connecting -> handshaking -> connected` path
//! is implemented. [`FrameStream`] is the reusable "send/receive signed
//! application frames on one QUIC stream" primitive — [`Session`] wraps
//! one for the control stream, and [`Session::open_dedicated_stream`]
//! hands out fresh ones for content transfer (§12) and streaming RPC
//! (§13), which both run on dedicated streams rather than the control
//! stream.

use std::sync::Arc;
use std::time::Duration;

use crate::bolt4;
use crate::cbor::Value;
use crate::frame::{self, Decoded, HelloInfo};
use crate::identity::KeyPair;
use crate::transport::{self, ConnectError, Trust};

/// A boxed, `'static` future — hand-rolled rather than pulling in the
/// `futures` crate for one type alias.
pub type BoxFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Answers one inbound CALL. `Ok(payload)` sends a RESULT; `Err(reason)`
/// sends an ERROR (BOLT#4 `unknown_error`, `detail = reason`); a panic
/// inside the handler (caught via [`tokio::spawn`], the same "one
/// transient task per call" shape `macula_station_link.erl` uses one
/// process per call for) is sent as ERROR `temporary_relay_failure` —
/// matching that module's own `safe_invoke_handler/4` mapping exactly
/// (including sending no `detail` on a crash, since the reference
/// doesn't either — it only logs locally).
pub type CallHandler =
    Arc<dyn Fn(Value) -> BoxFuture<'static, Result<Value, String>> + Send + Sync>;

/// Matches `HANDSHAKE_TIMEOUT_MS` in `macula_peering_conn.erl`: CONNECT
/// -> HELLO is sub-second on a healthy peer; this is generous. The most
/// common real-world trigger for hitting it is a protocol version
/// mismatch — bytes accumulate but never form a valid frame, so the
/// station-side symptom and this crate's symptom are the same shape.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// Default timeout for a single CALL awaiting its RESULT/ERROR. Not from
/// the reference source (macula's own CALL timeout is caller-supplied
/// per-call via `deadline_ms` inside the frame itself, not a transport-
/// level default) — a reasonable local default for this crate's API.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(30);

/// Bound on a single read from a QUIC stream while accumulating a frame.
/// Not a protocol limit — just how much to ask the stream for at once;
/// `frame::decode`'s own `MAX_FRAME_BYTES` is the real cap.
const READ_CHUNK: usize = 64 * 1024;

// ---------------------------------------------------------------------
// FrameStream — send/receive signed application frames on one QUIC
// stream. The control stream (inside Session) and every dedicated
// stream (content transfer, streaming RPC) are each one of these.
// ---------------------------------------------------------------------

pub struct FrameStream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    /// Bytes read but not yet consumed by a decoded frame — carried
    /// over between reads so nothing is ever dropped.
    buf: Vec<u8>,
}

#[derive(Debug)]
pub enum SendFrameError {
    Encode(frame::EncodeFrameError),
    Write(quinn::WriteError),
}

impl std::fmt::Display for SendFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SendFrameError::Encode(e) => write!(f, "encoding frame: {e}"),
            SendFrameError::Write(e) => write!(f, "writing to stream: {e}"),
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
            RecvFrameError::Read(e) => write!(f, "reading from stream: {e}"),
            RecvFrameError::StreamClosed => write!(f, "peer closed the stream"),
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

impl FrameStream {
    fn new(send: quinn::SendStream, recv: quinn::RecvStream) -> Self {
        Self::with_buf(send, recv, Vec::new())
    }

    fn with_buf(send: quinn::SendStream, recv: quinn::RecvStream, buf: Vec<u8>) -> Self {
        Self { send, recv, buf }
    }

    /// Any bytes already read past the last decoded frame — for the
    /// control stream specifically, this starts with whatever was left
    /// over from the handshake itself.
    pub fn leftover_bytes(&self) -> &[u8] {
        &self.buf
    }

    pub async fn send_frame(&mut self, frame: Value) -> Result<(), SendFrameError> {
        let encoded = frame::encode(&frame).map_err(SendFrameError::Encode)?;
        self.send
            .write_all(&encoded)
            .await
            .map_err(SendFrameError::Write)
    }

    /// Read the next complete application frame, using (and updating)
    /// any bytes already buffered.
    pub async fn recv_frame(&mut self) -> Result<Value, RecvFrameError> {
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
    pub async fn recv_frame_timeout(&mut self, timeout: Duration) -> Result<Value, RecvFrameError> {
        tokio::time::timeout(timeout, self.recv_frame())
            .await
            .unwrap_or(Err(RecvFrameError::Timeout))
    }

    /// Send a signed CALL for `procedure` and wait for the matching
    /// RESULT or ERROR, correlated by `call_id`.
    ///
    /// **Known v1 limitation (control stream only):** any frame that
    /// arrives before the match (e.g. an EVENT from an active
    /// SUBSCRIBE) is discarded, not queued or dispatched elsewhere —
    /// correct for a client doing one thing at a time on the control
    /// stream, not yet correct for CALL and PUBLISH/SUBSCRIBE used
    /// concurrently on it. Harmless on a **dedicated** stream (content
    /// transfer, streaming RPC), since nothing else ever arrives there
    /// to discard.
    pub async fn call(
        &mut self,
        procedure: &str,
        realm: [u8; 32],
        payload: Value,
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
}

// ---------------------------------------------------------------------
// Session — the handshaked connection, wrapping the control stream.
// ---------------------------------------------------------------------

/// A completed, handshaked connection to a macula-station. Holds the
/// open control stream (CONNECT/HELLO already exchanged) and the
/// station's identity as verified by the HELLO frame's own signature.
pub struct Session {
    connection: quinn::Connection,
    control: FrameStream,
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
        control: FrameStream::with_buf(send, recv, buf),
        station,
    })
}

/// Read from `recv` until one complete frame has been decoded, returning
/// it along with any leftover bytes already read that belong to the
/// *next* frame (so a caller can carry them forward instead of losing
/// them). Handshake-only — [`FrameStream::recv_frame`] is the
/// post-handshake equivalent.
async fn read_one_frame(recv: &mut quinn::RecvStream) -> Result<(Value, Vec<u8>), HandshakeError> {
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

    /// Open a new dedicated QUIC stream on this same connection, separate
    /// from the control stream — the mechanism content transfer (§12)
    /// and streaming RPC (§13) both use instead of the control stream.
    pub async fn open_dedicated_stream(&mut self) -> Result<FrameStream, quinn::ConnectionError> {
        let (send, recv) = self.connection.open_bi().await?;
        Ok(FrameStream::new(send, recv))
    }

    /// Accept the next dedicated stream the *peer* opens toward us —
    /// e.g. the station routing an inbound STREAM_OPEN for a procedure
    /// this session has [`advertise`](Self::advertise)d (§13.2). Blocks
    /// until one arrives.
    ///
    /// The receiving side has no advance notice of why a new stream
    /// arrived; §7 of `plans/PLAN_WIRE_PROTOCOL.md` says to read the
    /// stream's own first frame to learn its purpose, which is exactly
    /// what a caller of this method does next via the returned
    /// `FrameStream`'s own `recv_frame`. The reference (`quicer`-backed
    /// Erlang) has a documented race here — the peer's first bytes can
    /// arrive before the owning process is notified the stream exists at
    /// all, because its NIF stream resources start passive and only
    /// begin delivering once explicitly armed *after* the notification.
    /// That race doesn't apply here: `quinn`/QUIC buffers inbound stream
    /// data at the transport layer regardless of whether or when the
    /// application starts reading, so nothing analogous to arm before
    /// read is needed on this side.
    pub async fn accept_dedicated_stream(&mut self) -> Result<FrameStream, quinn::ConnectionError> {
        let (send, recv) = self.connection.accept_bi().await?;
        Ok(FrameStream::new(send, recv))
    }

    /// Any bytes already read past the HELLO frame during the handshake
    /// (belonging to whatever the station sent next) that a caller
    /// building further protocol handling on top of this `Session`
    /// should treat as already-received.
    pub fn leftover_bytes(&self) -> &[u8] {
        self.control.leftover_bytes()
    }

    /// Read the next complete application frame from the control stream.
    pub async fn recv_frame(&mut self) -> Result<Value, RecvFrameError> {
        self.control.recv_frame().await
    }

    /// As [`recv_frame`](Self::recv_frame), bounded by `timeout`.
    pub async fn recv_frame_timeout(&mut self, timeout: Duration) -> Result<Value, RecvFrameError> {
        self.control.recv_frame_timeout(timeout).await
    }

    /// Send a signed CALL on the control stream and wait for the
    /// matching RESULT or ERROR — see [`FrameStream::call`].
    pub async fn call(
        &mut self,
        procedure: &str,
        realm: [u8; 32],
        payload: Value,
        deadline_ms: i128,
        identity: &KeyPair,
        timeout: Duration,
    ) -> Result<frame::CallResponse, CallError> {
        self.control
            .call(procedure, realm, payload, deadline_ms, identity, timeout)
            .await
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
        self.control.send_frame(signed).await
    }

    /// Send a signed SUBSCRIBE. Fire-and-forget.
    pub async fn subscribe(
        &mut self,
        spec: &frame::SubscribeSpec,
        identity: &KeyPair,
    ) -> Result<(), SendFrameError> {
        let signed = frame::sign(frame::subscribe(spec), identity);
        self.control.send_frame(signed).await
    }

    /// Send a signed UNSUBSCRIBE. Fire-and-forget.
    pub async fn unsubscribe(
        &mut self,
        spec: &frame::UnsubscribeSpec,
        identity: &KeyPair,
    ) -> Result<(), SendFrameError> {
        let signed = frame::sign(frame::unsubscribe(spec), identity);
        self.control.send_frame(signed).await
    }

    /// Send a signed ADVERTISE (§6.9) — registers this connection as the
    /// handler for `spec`'s `(realm, procedure)`. Fire-and-forget on the
    /// wire; the station then routes inbound CALLs (control stream) and
    /// STREAM_OPENs (a fresh dedicated stream — see
    /// [`accept_dedicated_stream`](Self::accept_dedicated_stream)) for
    /// that procedure back to this connection.
    pub async fn advertise(
        &mut self,
        spec: &frame::AdvertiseSpec,
        identity: &KeyPair,
    ) -> Result<(), SendFrameError> {
        let signed = frame::sign(frame::advertise(spec), identity);
        self.control.send_frame(signed).await
    }

    /// Send a signed UNADVERTISE. Fire-and-forget.
    pub async fn unadvertise(
        &mut self,
        spec: &frame::UnadvertiseSpec,
        identity: &KeyPair,
    ) -> Result<(), SendFrameError> {
        let signed = frame::sign(frame::unadvertise(spec), identity);
        self.control.send_frame(signed).await
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
            .control
            .recv_frame_timeout(timeout)
            .await
            .map_err(RecvEventError::Recv)?;
        frame::parse_event(&value).map_err(RecvEventError::Parse)
    }

    /// The provider role's counterpart to [`call`](Self::call): block
    /// for the next inbound CALL frame on the control stream, bounded
    /// by `timeout`, look it up via `lookup`, invoke the matching
    /// handler, and send the resulting RESULT or ERROR back over this
    /// same connection — see `plans/PLAN_WIRE_PROTOCOL.md` §6.9's
    /// routing description and `macula_station_link.erl`'s
    /// `handle_inbound_call/2`, which this mirrors field for field,
    /// including its BOLT#4 error-code mapping.
    ///
    /// Any non-CALL frame that arrives first (e.g. a stray EVENT from
    /// an active [`subscribe`](Self::subscribe), or a RESULT/ERROR for
    /// some other in-flight [`call`](Self::call)) is discarded, not
    /// queued — the same "control stream, one thing at a time"
    /// limitation [`call`](Self::call)'s own doc already carries. A
    /// session that needs to serve CALLs and also act as a
    /// caller/subscriber concurrently should use a second `Session`,
    /// exactly like this crate's own streaming-provider live test does.
    ///
    /// A caller wanting a long-lived server loops on this:
    ///
    /// ```no_run
    /// # use std::time::Duration;
    /// # async fn example(session: &mut macula_rust_sdk::connection::Session, identity: &macula_rust_sdk::identity::KeyPair, lookup: impl Fn(&[u8; 32], &str) -> Option<macula_rust_sdk::connection::CallHandler>) {
    /// loop {
    ///     if let Err(e) = session.serve_one_call(&lookup, identity, Duration::from_secs(30)).await {
    ///         // ServeCallError::Timeout just means nothing arrived -- keep looping.
    ///         eprintln!("{e}");
    ///     }
    /// }
    /// # }
    /// ```
    pub async fn serve_one_call<L>(
        &mut self,
        lookup: L,
        identity: &KeyPair,
        timeout: Duration,
    ) -> Result<(), ServeCallError>
    where
        L: Fn(&[u8; 32], &str) -> Option<CallHandler>,
    {
        tokio::time::timeout(timeout, self.serve_one_call_inner(lookup, identity))
            .await
            .unwrap_or(Err(ServeCallError::Timeout))
    }

    async fn serve_one_call_inner<L>(
        &mut self,
        lookup: L,
        identity: &KeyPair,
    ) -> Result<(), ServeCallError>
    where
        L: Fn(&[u8; 32], &str) -> Option<CallHandler>,
    {
        loop {
            let value = self
                .control
                .recv_frame()
                .await
                .map_err(ServeCallError::Recv)?;
            let Ok(call_info) = frame::parse_call(&value) else {
                continue; // not ours -- see this method's doc on the limitation
            };
            let reply = build_call_reply(call_info, &lookup, identity.node_id()).await;
            let signed = frame::sign(reply, identity);
            self.control
                .send_frame(signed)
                .await
                .map_err(ServeCallError::Send)?;
            return Ok(());
        }
    }

    /// Close the control stream and connection gracefully with a GOODBYE
    /// frame, matching `macula_peering_conn.erl`'s `connected -> draining`
    /// transition (minus the drain-timeout bookkeeping, since this crate
    /// isn't holding a supervisor to clean up).
    pub async fn close(mut self, reason: &str, detail: Option<&str>, identity: &KeyPair) {
        let goodbye = frame::sign(frame::goodbye(reason, detail), identity);
        if let Ok(encoded) = frame::encode(&goodbye) {
            let _ = self.control.send.write_all(&encoded).await;
        }
        let _ = self.control.send.finish();
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

#[derive(Debug)]
pub enum ServeCallError {
    Recv(RecvFrameError),
    Send(SendFrameError),
    /// No inbound CALL arrived within the requested timeout.
    Timeout,
}

impl std::fmt::Display for ServeCallError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ServeCallError::Recv(e) => write!(f, "{e}"),
            ServeCallError::Send(e) => write!(f, "sending the reply: {e}"),
            ServeCallError::Timeout => write!(f, "timed out waiting for an inbound CALL"),
        }
    }
}

impl std::error::Error for ServeCallError {}

/// Build the RESULT/ERROR reply for one inbound CALL — mirrors
/// `macula_station_link.erl`'s `handle_inbound_call/2` +
/// `safe_invoke_handler/4` exactly: a lookup miss is
/// `unknown_next_peer`; the handler running to completion produces a
/// RESULT (`Ok`) or `unknown_error` with `detail` (`Err`); a handler
/// panic — caught via `tokio::spawn`, the same "one transient task per
/// call" shape the reference's own "one process per call" uses — is
/// `temporary_relay_failure`, with no `detail`, matching the reference
/// not sending one on a crash either.
async fn build_call_reply<L>(call_info: frame::CallInfo, lookup: &L, self_pub: [u8; 32]) -> Value
where
    L: Fn(&[u8; 32], &str) -> Option<CallHandler>,
{
    let Some(handler) = lookup(&call_info.realm, &call_info.procedure) else {
        return frame::call_error(&frame::CallErrorSpec::new(
            call_info.call_id,
            bolt4::Code::UnknownNextPeer,
            self_pub,
        ));
    };

    let payload = call_info.payload;
    let outcome = tokio::spawn(async move { handler(payload).await }).await;
    match outcome {
        Ok(Ok(value)) => frame::result(&frame::ResultSpec::new(call_info.call_id, value, self_pub)),
        Ok(Err(reason)) => {
            let mut spec =
                frame::CallErrorSpec::new(call_info.call_id, bolt4::Code::UnknownError, self_pub);
            spec.detail = Some(reason);
            frame::call_error(&spec)
        }
        Err(_join_error) => frame::call_error(&frame::CallErrorSpec::new(
            call_info.call_id,
            bolt4::Code::TemporaryRelayFailure,
            self_pub,
        )),
    }
}
