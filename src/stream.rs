//! General-purpose streaming RPC, caller/consumer role (§13.1 of
//! `plans/PLAN_WIRE_PROTOCOL.md`), ported from `macula_stream_sink.erl`.
//! Like content transfer (`src/content.rs`), this is not a separate wire
//! mechanism: it runs the frame types built in `src/frame.rs` §13 over a
//! dedicated QUIC stream, opened via
//! [`Session::open_dedicated_stream`](crate::connection::Session::open_dedicated_stream)
//! rather than the control stream.
//!
//! **Provider role (§13.2, exposing a streaming procedure TO the mesh)
//! is not built** — see `src/frame.rs`'s module doc on this same scope
//! decision. Nothing in this crate needs to *serve* RPCs yet.
//!
//! Usage, matching the reference's own pattern:
//! 1. [`StreamHandle::open`] sends STREAM_OPEN and returns a handle once
//!    the frame is on the wire — there's no open-time acknowledgement to
//!    wait for; the provider starts reacting to it directly.
//! 2. Drive a receive loop with [`StreamHandle::recv`] until
//!    [`StreamItem::Eof`] or an error.
//! 3. For `client_stream`/`bidi` modes wanting a result:
//!    [`StreamHandle::send_data`] each chunk in order,
//!    [`StreamHandle::close_send`] when done, then
//!    [`StreamHandle::await_reply`].
//! 4. **Non-normal termination must call [`StreamHandle::abort`], not
//!    just drop the handle** — the peer's only signal to tell a
//!    cancellation/failure apart from a dropped connection
//!    (`plans/PLAN_WIRE_PROTOCOL.md` §13.1, point 4).

use std::time::Duration;

use crate::cbor::Value;
use crate::connection::{FrameStream, RecvFrameError, SendFrameError, Session};
use crate::frame::{self, StreamEncoding, StreamMode, StreamRole};
use crate::identity::KeyPair;

pub struct StreamHandle {
    stream: FrameStream,
    pub stream_id: [u8; 16],
    pub mode: StreamMode,
    seq_out: u64,
}

#[derive(Debug)]
pub enum OpenError {
    OpenStream(quinn::ConnectionError),
    Send(SendFrameError),
}

impl std::fmt::Display for OpenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            OpenError::OpenStream(e) => write!(f, "opening a dedicated stream: {e}"),
            OpenError::Send(e) => write!(f, "sending stream_open: {e}"),
        }
    }
}

impl std::error::Error for OpenError {}

/// One item [`StreamHandle::recv`] hands back: a chunk, or a clean
/// end-of-stream.
#[derive(Debug, Clone)]
pub enum StreamItem {
    Data {
        seq: u64,
        encoding: StreamEncoding,
        body: Value,
    },
    Eof,
}

#[derive(Debug)]
pub enum RecvStreamError {
    Recv(RecvFrameError),
    Parse(frame::ParseStreamEventError),
    /// The peer sent an explicit STREAM_ERROR abort.
    PeerAborted {
        code: String,
        message: String,
    },
    /// A frame for a *different* stream_id arrived on this stream —
    /// never expected on a dedicated stream with a well-behaved peer,
    /// surfaced distinctly rather than silently accepted.
    StreamIdMismatch,
    /// A frame arrived that isn't valid in the context this call is
    /// waiting in — e.g. [`StreamHandle::recv`] got a STREAM_REPLY
    /// (only [`StreamHandle::await_reply`] expects one), or
    /// `await_reply` got a STREAM_DATA/STREAM_END before any reply.
    UnexpectedFrame,
}

impl std::fmt::Display for RecvStreamError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            RecvStreamError::Recv(e) => write!(f, "{e}"),
            RecvStreamError::Parse(e) => write!(f, "{e}"),
            RecvStreamError::PeerAborted { code, message } => {
                write!(f, "peer aborted the stream: {code} ({message})")
            }
            RecvStreamError::StreamIdMismatch => {
                write!(f, "received a frame for a different stream_id")
            }
            RecvStreamError::UnexpectedFrame => {
                write!(f, "received a frame not valid in this context")
            }
        }
    }
}

impl std::error::Error for RecvStreamError {}

impl StreamHandle {
    /// Open a dedicated stream on `session`'s connection and send a
    /// signed STREAM_OPEN. Fire-and-forget at the wire level — no reply
    /// is expected here; drive [`recv`](Self::recv) (for
    /// `server_stream`/`bidi`) or [`send_data`](Self::send_data) (for
    /// `client_stream`/`bidi`) next, depending on `mode`.
    pub async fn open(
        session: &mut Session,
        procedure: &str,
        realm: [u8; 32],
        mode: StreamMode,
        args: Value,
        deadline_ms: i128,
        identity: &KeyPair,
    ) -> Result<Self, OpenError> {
        let mut stream = session
            .open_dedicated_stream()
            .await
            .map_err(OpenError::OpenStream)?;
        let stream_id: [u8; 16] = rand::random();
        let spec = frame::StreamOpenSpec::new(
            stream_id,
            procedure,
            realm,
            mode,
            args,
            deadline_ms,
            identity.node_id(),
        );
        let signed = frame::sign(frame::stream_open(&spec), identity);
        stream.send_frame(signed).await.map_err(OpenError::Send)?;
        Ok(Self {
            stream,
            stream_id,
            mode,
            seq_out: 0,
        })
    }

    /// Send one chunk. `seq` is tracked internally, starting at 0 and
    /// incrementing per call — matches the reference's `seq_out` counter
    /// (a sanity/debugging signal, not used for reordering: frames
    /// arrive in order on a single QUIC stream by construction).
    pub async fn send_data(
        &mut self,
        encoding: StreamEncoding,
        body: Value,
        identity: &KeyPair,
    ) -> Result<(), SendFrameError> {
        let spec = frame::StreamDataSpec::new(self.stream_id, self.seq_out, encoding, body);
        self.seq_out += 1;
        let signed = frame::sign(frame::stream_data(&spec), identity);
        self.stream.send_frame(signed).await
    }

    /// Half-close: signal this side is done sending. For
    /// `client_stream`/`bidi` modes, follow with
    /// [`await_reply`](Self::await_reply).
    pub async fn close_send(&mut self, identity: &KeyPair) -> Result<(), SendFrameError> {
        let spec = frame::StreamEndSpec::new(self.stream_id, StreamRole::Send);
        let signed = frame::sign(frame::stream_end(&spec), identity);
        self.stream.send_frame(signed).await
    }

    /// Receive the next chunk or end-of-stream, bounded by `timeout`.
    pub async fn recv(&mut self, timeout: Duration) -> Result<StreamItem, RecvStreamError> {
        let value = self
            .stream
            .recv_frame_timeout(timeout)
            .await
            .map_err(RecvStreamError::Recv)?;
        match frame::parse_stream_event(&value).map_err(RecvStreamError::Parse)? {
            frame::StreamEvent::Data {
                stream_id,
                seq,
                encoding,
                body,
            } => {
                self.check_stream_id(stream_id)?;
                Ok(StreamItem::Data {
                    seq,
                    encoding,
                    body,
                })
            }
            frame::StreamEvent::End { stream_id, role: _ } => {
                self.check_stream_id(stream_id)?;
                Ok(StreamItem::Eof)
            }
            frame::StreamEvent::Error {
                stream_id,
                code,
                message,
            } => {
                self.check_stream_id(stream_id)?;
                Err(RecvStreamError::PeerAborted { code, message })
            }
            frame::StreamEvent::Reply { .. } => Err(RecvStreamError::UnexpectedFrame),
        }
    }

    /// Block for the provider's terminal STREAM_REPLY (`client_stream`/
    /// `bidi` modes only) — call after [`close_send`](Self::close_send).
    pub async fn await_reply(
        &mut self,
        timeout: Duration,
    ) -> Result<(Value, [u8; 32]), RecvStreamError> {
        let value = self
            .stream
            .recv_frame_timeout(timeout)
            .await
            .map_err(RecvStreamError::Recv)?;
        match frame::parse_stream_event(&value).map_err(RecvStreamError::Parse)? {
            frame::StreamEvent::Reply {
                stream_id,
                payload,
                responded_by,
            } => {
                self.check_stream_id(stream_id)?;
                Ok((payload, responded_by))
            }
            frame::StreamEvent::Error {
                stream_id,
                code,
                message,
            } => {
                self.check_stream_id(stream_id)?;
                Err(RecvStreamError::PeerAborted { code, message })
            }
            frame::StreamEvent::Data { .. } | frame::StreamEvent::End { .. } => {
                Err(RecvStreamError::UnexpectedFrame)
            }
        }
    }

    fn check_stream_id(&self, stream_id: [u8; 16]) -> Result<(), RecvStreamError> {
        if stream_id == self.stream_id {
            Ok(())
        } else {
            Err(RecvStreamError::StreamIdMismatch)
        }
    }

    /// Non-normal termination: explicitly tell the peer this stream is
    /// aborting, per §13.1 point 4 — the only signal the peer gets to
    /// distinguish a cancellation/failure from a dropped connection.
    /// Best-effort, like [`Session::close`](crate::connection::Session::close)'s
    /// GOODBYE — consumes `self` so the handle can't be used again after
    /// aborting.
    pub async fn abort(
        mut self,
        code: impl Into<String>,
        message: impl Into<String>,
        identity: &KeyPair,
    ) {
        let spec = frame::StreamErrorSpec::new(self.stream_id, code, message);
        let signed = frame::sign(frame::stream_error(&spec), identity);
        let _ = self.stream.send_frame(signed).await;
    }
}
