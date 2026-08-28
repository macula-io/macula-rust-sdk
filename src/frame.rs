//! The macula application-frame envelope: construction, Ed25519
//! signing/verification, and the length-prefixed wire codec. Ported from
//! `src/peering/macula_frame.erl` (`macula-io/macula`).
//!
//! A wire frame is `<<Length:32/big, Cbor/binary>>` where `Cbor` is the
//! deterministic encoding of a single map (see [`crate::cbor`]). Every
//! frame carries a common envelope — `version`, `frame_type`, `frame_id`
//! (UUIDv7), `sent_at_ms`, `capabilities`, plus `realm`/`call_id`/
//! `source_route` set to `null` unless the specific frame type populates
//! them — and every frame is Ed25519-signed over its own canonical bytes
//! with `signature`/`publisher_sig` stripped first.
//!
//! This module's correctness is checked against a real reference frame:
//! `tests::connect_frame_matches_the_reference_byte_for_byte` builds
//! the exact same CONNECT frame `macula_frame:connect/1` +
//! `macula_frame:sign/2` produced in a live `rebar3 shell` — same
//! identity, same fixed `frame_id`/`sent_at_ms` (injected explicitly,
//! since the reference randomizes both per call and non-determinism
//! would make an exact byte comparison meaningless) — and asserts the
//! encoded bytes, **including the Ed25519 signature itself**, match
//! exactly. That's the strongest test available short of dialing a real
//! station: it proves the canonical-CBOR encoding, the field set, and
//! the signing domain are all bit-for-bit compatible at once.

use std::time::{SystemTime, UNIX_EPOCH};

use crate::cbor::{self, Value};
use crate::identity::KeyPair;

/// Domain separator for the per-frame Ed25519 signature (every frame's
/// own `signature` field). Distinct from the SWIM-update and
/// publisher-end-to-end domains documented in
/// `plans/PLAN_WIRE_PROTOCOL.md` §4 — neither of those is implemented
/// here yet.
pub const SIG_DOMAIN: &[u8] = b"macula-v2-frame\0";

pub const PROTOCOL_VERSION: i128 = 2;

/// 16 MiB minus one byte — matches `?MAX_FRAME_BYTES` (`16#FFFFFF`)
/// exactly.
pub const MAX_FRAME_BYTES: usize = 0x00FF_FFFF;

fn current_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock is after the Unix epoch")
        .as_millis() as u64
}

fn fresh_frame_id() -> [u8; 16] {
    *uuid::Uuid::now_v7().as_bytes()
}

/// The common envelope every frame carries, matching `base/2`. Field
/// order doesn't matter — canonical CBOR re-sorts by encoded key bytes
/// at encode time regardless (see `crate::cbor`).
fn base(
    frame_type: &str,
    capabilities: u64,
    frame_id: [u8; 16],
    sent_at_ms: u64,
) -> Vec<(Value, Value)> {
    vec![
        (Value::text("version"), Value::Int(PROTOCOL_VERSION)),
        (Value::text("frame_type"), Value::text(frame_type)),
        (Value::text("frame_id"), Value::Bytes(frame_id.to_vec())),
        (Value::text("sent_at_ms"), Value::Int(sent_at_ms as i128)),
        (
            Value::text("capabilities"),
            Value::Int(capabilities as i128),
        ),
        (Value::text("realm"), Value::Null),
        (Value::text("call_id"), Value::Null),
        (Value::text("source_route"), Value::Null),
    ]
}

fn bytes32_list(items: &[[u8; 32]]) -> Value {
    Value::List(items.iter().map(|b| Value::Bytes(b.to_vec())).collect())
}

// ---------------------------------------------------------------------
// CONNECT
// ---------------------------------------------------------------------

/// Fields for a CONNECT frame — see `plans/PLAN_WIRE_PROTOCOL.md` §5.
#[derive(Debug, Clone)]
pub struct ConnectSpec {
    pub node_id: [u8; 32],
    pub station_id: [u8; 32],
    pub realms: Vec<[u8; 32]>,
    pub capabilities: u64,
    pub puzzle_evidence: [u8; 32],
    pub addresses: Vec<Value>,
    pub site: Option<Value>,
    pub endorsements: Vec<Value>,
}

impl ConnectSpec {
    /// A CONNECT with no realm memberships claimed and no advertised
    /// addresses — the shape a dial-out-only leaf client uses (see the
    /// spec's §11 discussion of why edge clients never need reachable
    /// addresses of their own).
    pub fn new(node_id: [u8; 32], puzzle_evidence: [u8; 32]) -> Self {
        Self {
            node_id,
            // `send_connect/2`'s own convention: a plain peer/daemon
            // dial sets station_id equal to node_id.
            station_id: node_id,
            realms: Vec::new(),
            capabilities: 0,
            puzzle_evidence,
            addresses: Vec::new(),
            site: None,
            endorsements: Vec::new(),
        }
    }
}

fn connect_value(spec: &ConnectSpec, frame_id: [u8; 16], sent_at_ms: u64) -> Value {
    let mut fields = base("connect", spec.capabilities, frame_id, sent_at_ms);
    fields.push((Value::text("node_id"), Value::Bytes(spec.node_id.to_vec())));
    fields.push((
        Value::text("station_id"),
        Value::Bytes(spec.station_id.to_vec()),
    ));
    fields.push((Value::text("realms"), bytes32_list(&spec.realms)));
    fields.push((
        Value::text("addresses"),
        Value::List(spec.addresses.clone()),
    ));
    fields.push((
        Value::text("site"),
        spec.site.clone().unwrap_or(Value::Null),
    ));
    fields.push((
        Value::text("puzzle_evidence"),
        Value::Bytes(spec.puzzle_evidence.to_vec()),
    ));
    fields.push((
        Value::text("endorsements"),
        Value::List(spec.endorsements.clone()),
    ));
    Value::Map(fields)
}

/// Build a CONNECT frame with a fresh `frame_id`/`sent_at_ms`. Unsigned —
/// pass the result to [`sign`] before sending.
pub fn connect(spec: &ConnectSpec) -> Value {
    connect_value(spec, fresh_frame_id(), current_millis())
}

// ---------------------------------------------------------------------
// GOODBYE
// ---------------------------------------------------------------------

fn goodbye_value(reason: &str, detail: Option<&str>, frame_id: [u8; 16], sent_at_ms: u64) -> Value {
    let mut fields = base("goodbye", 0, frame_id, sent_at_ms);
    // `reason` is an Erlang atom() -> text (major 3). `detail` is
    // `binary() | undefined` -> a raw byte string (major 2), NOT text —
    // caught by the CALL/PUBLISH/etc. differential vectors failing on
    // this exact mistake for their own binary()-typed fields (procedure,
    // topic). Fixed here too even though no direct GOODBYE vector was
    // captured, since it's the identical type.
    fields.push((Value::text("reason"), Value::text(reason)));
    fields.push((
        Value::text("detail"),
        detail
            .map(|d| Value::Bytes(d.as_bytes().to_vec()))
            .unwrap_or(Value::Null),
    ));
    Value::Map(fields)
}

/// Build a GOODBYE frame. `reason` is a short machine-readable code
/// (e.g. `"normal"`); `detail` is an optional human-readable string.
pub fn goodbye(reason: &str, detail: Option<&str>) -> Value {
    goodbye_value(reason, detail, fresh_frame_id(), current_millis())
}

// ---------------------------------------------------------------------
// CALL / RESULT / ERROR
//
// ⚠ Overriding a base-envelope sentinel field (`realm`, `call_id`,
// `source_route` — all `Null` by default from `base()`) MUST use
// `Value::with_field`, never a raw push onto the field vec. `Value::Map`
// is a plain `Vec<(Value, Value)>`, not a real map — it has none of
// Erlang's automatic key-uniqueness, so appending a second `call_id`
// entry on top of `base()`'s `call_id => Null` would silently produce a
// wire-invalid map with two `call_id` keys instead of overriding it.
// Caught during differential-vector generation against the real
// reference (a hand-built CONNECT test frame subtly differed from
// `macula_frame:call/1`'s own output the same way, before this was
// fixed) — see this crate's own commit history, not hypothetical.
// ---------------------------------------------------------------------

/// Fields for a CALL frame — see `plans/PLAN_WIRE_PROTOCOL.md` §6.4.
#[derive(Debug, Clone)]
pub struct CallSpec {
    pub call_id: [u8; 16],
    pub procedure: String,
    pub realm: [u8; 32],
    pub payload: Value,
    pub deadline_ms: i128,
    pub caller: [u8; 32],
    /// Opaque source-route header bytes (`plans/PLAN_WIRE_PROTOCOL.md`
    /// §8) — empty for a direct call to one known station, which is the
    /// only shape this crate builds so far.
    pub source_route: Vec<u8>,
    pub retry_budget: u64,
    pub ucan_token: Vec<u8>,
}

impl CallSpec {
    pub fn new(
        call_id: [u8; 16],
        procedure: impl Into<String>,
        realm: [u8; 32],
        payload: Value,
        deadline_ms: i128,
        caller: [u8; 32],
    ) -> Self {
        Self {
            call_id,
            procedure: procedure.into(),
            realm,
            payload,
            deadline_ms,
            caller,
            source_route: Vec::new(),
            retry_budget: 0,
            ucan_token: Vec::new(),
        }
    }
}

fn call_value(spec: &CallSpec, frame_id: [u8; 16], sent_at_ms: u64) -> Value {
    Value::Map(base("call", 0, frame_id, sent_at_ms))
        .with_field("realm", Value::Bytes(spec.realm.to_vec()))
        .with_field("call_id", Value::Bytes(spec.call_id.to_vec()))
        // `procedure := binary()` in the Erlang spec — a raw byte
        // string (major 2), not text (major 3). Confirmed the hard way:
        // this was `Value::text(...)` originally and the differential
        // vector test caught the resulting signature mismatch.
        .with_field(
            "procedure",
            Value::Bytes(spec.procedure.as_bytes().to_vec()),
        )
        .with_field("payload", spec.payload.clone())
        .with_field("deadline_ms", Value::Int(spec.deadline_ms))
        .with_field("caller", Value::Bytes(spec.caller.to_vec()))
        .with_field("source_route", Value::Bytes(spec.source_route.clone()))
        .with_field("retry_budget", Value::Int(spec.retry_budget as i128))
        .with_field("ucan_token", Value::Bytes(spec.ucan_token.clone()))
}

/// Build a CALL frame with a fresh `frame_id`/`sent_at_ms`. Unsigned —
/// pass the result to [`sign`] before sending.
pub fn call(spec: &CallSpec) -> Value {
    call_value(spec, fresh_frame_id(), current_millis())
}

/// Fields for a RESULT frame.
#[derive(Debug, Clone)]
pub struct ResultSpec {
    pub call_id: [u8; 16],
    pub payload: Value,
    pub responded_by: [u8; 32],
    pub source_route_reverse: Vec<u8>,
}

impl ResultSpec {
    pub fn new(call_id: [u8; 16], payload: Value, responded_by: [u8; 32]) -> Self {
        Self {
            call_id,
            payload,
            responded_by,
            source_route_reverse: Vec::new(),
        }
    }
}

fn result_value(spec: &ResultSpec, frame_id: [u8; 16], sent_at_ms: u64) -> Value {
    // NOTE: RESULT does not touch the base envelope's `realm` or
    // `source_route` fields at all — they stay `Null`, matching the
    // reference exactly (confirmed by inspecting `macula_frame:result/1`'s
    // own output directly, not assumed from the CALL pattern above).
    // `source_route_reverse` is a distinct field, not a rename.
    Value::Map(base("result", 0, frame_id, sent_at_ms))
        .with_field("call_id", Value::Bytes(spec.call_id.to_vec()))
        .with_field("payload", spec.payload.clone())
        .with_field("responded_by", Value::Bytes(spec.responded_by.to_vec()))
        .with_field(
            "source_route_reverse",
            Value::Bytes(spec.source_route_reverse.clone()),
        )
}

/// Build a RESULT frame with a fresh `frame_id`/`sent_at_ms`.
pub fn result(spec: &ResultSpec) -> Value {
    result_value(spec, fresh_frame_id(), current_millis())
}

/// Fields for an ERROR frame. `name` is derived from `code` automatically
/// (matching `macula_frame:call_error/1`'s own `macula_bolt4:name/1`
/// lookup), not a caller-supplied field.
#[derive(Debug, Clone)]
pub struct CallErrorSpec {
    pub call_id: [u8; 16],
    pub code: crate::bolt4::Code,
    pub reported_by: [u8; 32],
    pub detail: Option<String>,
    pub offending_hop: Option<[u8; 32]>,
    pub source_route_partial: Vec<u8>,
}

impl CallErrorSpec {
    pub fn new(call_id: [u8; 16], code: crate::bolt4::Code, reported_by: [u8; 32]) -> Self {
        Self {
            call_id,
            code,
            reported_by,
            detail: None,
            offending_hop: None,
            source_route_partial: Vec::new(),
        }
    }
}

fn call_error_value(spec: &CallErrorSpec, frame_id: [u8; 16], sent_at_ms: u64) -> Value {
    Value::Map(base("error", 0, frame_id, sent_at_ms))
        .with_field("call_id", Value::Bytes(spec.call_id.to_vec()))
        .with_field("code", Value::Int(spec.code.as_u8() as i128))
        .with_field("name", Value::text(spec.code.name()))
        .with_field("reported_by", Value::Bytes(spec.reported_by.to_vec()))
        .with_field(
            // `detail => binary() | undefined` — bytes, not text. Same
            // fix as CALL's `procedure` and GOODBYE's `detail`.
            "detail",
            spec.detail
                .as_ref()
                .map(|d| Value::Bytes(d.as_bytes().to_vec()))
                .unwrap_or(Value::Null),
        )
        .with_field(
            "offending_hop",
            spec.offending_hop
                .map(|h| Value::Bytes(h.to_vec()))
                .unwrap_or(Value::Null),
        )
        .with_field(
            "source_route_partial",
            Value::Bytes(spec.source_route_partial.clone()),
        )
}

/// Build an ERROR frame with a fresh `frame_id`/`sent_at_ms`.
pub fn call_error(spec: &CallErrorSpec) -> Value {
    call_error_value(spec, fresh_frame_id(), current_millis())
}

/// Parsed fields of a RESULT or ERROR response to a CALL, correlated by
/// `call_id`. Returned by [`crate::connection::Session::call`].
#[derive(Debug, Clone)]
pub enum CallResponse {
    Result {
        payload: Value,
        responded_by: [u8; 32],
    },
    Error {
        code: u8,
        name: String,
        reported_by: [u8; 32],
        detail: Option<String>,
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseCallResponseError {
    NotAResultOrError,
    MissingField(&'static str),
    WrongFieldType(&'static str),
}

impl std::fmt::Display for ParseCallResponseError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseCallResponseError::NotAResultOrError => {
                write!(f, "frame_type is neither \"result\" nor \"error\"")
            }
            ParseCallResponseError::MissingField(name) => {
                write!(f, "missing required field {name:?}")
            }
            ParseCallResponseError::WrongFieldType(name) => {
                write!(f, "field {name:?} has the wrong type")
            }
        }
    }
}

impl std::error::Error for ParseCallResponseError {}

/// Extract this frame's `call_id`, regardless of frame type — used to
/// correlate a RESULT/ERROR back to the CALL that requested it. 16
/// bytes, matching `call_id() :: <<_:128>>` — NOT 32; caught only by
/// re-checking against the spec, since the original test for this
/// function made the identical size mistake and so didn't catch it.
pub fn frame_call_id(frame: &Value) -> Option<[u8; 16]> {
    match frame.get("call_id") {
        Some(Value::Bytes(b)) => b.as_slice().try_into().ok(),
        _ => None,
    }
}

/// Parse a decoded frame as a RESULT or ERROR response to a CALL.
pub fn parse_call_response(frame: &Value) -> Result<CallResponse, ParseCallResponseError> {
    match frame.get("frame_type") {
        Some(Value::Text(t)) if t == "result" => {
            let payload = frame
                .get("payload")
                .cloned()
                .ok_or(ParseCallResponseError::MissingField("payload"))?;
            let responded_by = get_bytes32_generic(frame, "responded_by")?;
            Ok(CallResponse::Result {
                payload,
                responded_by,
            })
        }
        Some(Value::Text(t)) if t == "error" => {
            let code = match frame.get("code") {
                Some(Value::Int(n)) if (0..=255).contains(n) => *n as u8,
                Some(_) => return Err(ParseCallResponseError::WrongFieldType("code")),
                None => return Err(ParseCallResponseError::MissingField("code")),
            };
            let name = match frame.get("name") {
                Some(Value::Text(t)) => t.clone(),
                Some(_) => return Err(ParseCallResponseError::WrongFieldType("name")),
                None => return Err(ParseCallResponseError::MissingField("name")),
            };
            let reported_by = get_bytes32_generic(frame, "reported_by")?;
            // `detail` is `binary() | undefined` on the wire (bytes),
            // not text -- see call_error_value's own comment.
            let detail = match frame.get("detail") {
                None | Some(Value::Null) => None,
                Some(Value::Bytes(b)) => Some(
                    String::from_utf8(b.clone())
                        .map_err(|_| ParseCallResponseError::WrongFieldType("detail"))?,
                ),
                Some(_) => return Err(ParseCallResponseError::WrongFieldType("detail")),
            };
            Ok(CallResponse::Error {
                code,
                name,
                reported_by,
                detail,
            })
        }
        _ => Err(ParseCallResponseError::NotAResultOrError),
    }
}

fn get_bytes32_generic(
    frame: &Value,
    field: &'static str,
) -> Result<[u8; 32], ParseCallResponseError> {
    match frame.get(field) {
        None => Err(ParseCallResponseError::MissingField(field)),
        Some(Value::Bytes(b)) => b
            .as_slice()
            .try_into()
            .map_err(|_| ParseCallResponseError::WrongFieldType(field)),
        Some(_) => Err(ParseCallResponseError::WrongFieldType(field)),
    }
}

// ---------------------------------------------------------------------
// PUBLISH / SUBSCRIBE / UNSUBSCRIBE / EVENT
// ---------------------------------------------------------------------

/// Fields for a PUBLISH frame.
#[derive(Debug, Clone)]
pub struct PublishSpec {
    pub topic: String,
    pub realm: [u8; 32],
    pub publisher: [u8; 32],
    pub seq: u64,
    pub payload: Value,
    pub published_at_ms: u64,
    pub ttl_ms: Option<u64>,
}

impl PublishSpec {
    pub fn new(
        topic: impl Into<String>,
        realm: [u8; 32],
        publisher: [u8; 32],
        seq: u64,
        payload: Value,
        published_at_ms: u64,
    ) -> Self {
        Self {
            topic: topic.into(),
            realm,
            publisher,
            seq,
            payload,
            published_at_ms,
            ttl_ms: None,
        }
    }
}

fn publish_value(spec: &PublishSpec, frame_id: [u8; 16], sent_at_ms: u64) -> Value {
    Value::Map(base("publish", 0, frame_id, sent_at_ms))
        .with_field("realm", Value::Bytes(spec.realm.to_vec()))
        // `topic := binary()` -- bytes, not text. Same fix as CALL's
        // `procedure`.
        .with_field("topic", Value::Bytes(spec.topic.as_bytes().to_vec()))
        .with_field("publisher", Value::Bytes(spec.publisher.to_vec()))
        .with_field("seq", Value::Int(spec.seq as i128))
        .with_field("payload", spec.payload.clone())
        .with_field("published_at_ms", Value::Int(spec.published_at_ms as i128))
        .with_field(
            "ttl_ms",
            spec.ttl_ms
                .map(|t| Value::Int(t as i128))
                .unwrap_or(Value::Null),
        )
}

/// Build a PUBLISH frame with a fresh `frame_id`/`sent_at_ms`. Does not
/// set `publisher_sig` (the separate end-to-end publisher signature,
/// §4/§6.8 of the spec) — not implemented by this crate yet.
pub fn publish(spec: &PublishSpec) -> Value {
    publish_value(spec, fresh_frame_id(), current_millis())
}

/// Fields for a SUBSCRIBE frame.
#[derive(Debug, Clone)]
pub struct SubscribeSpec {
    pub topic: String,
    pub realm: [u8; 32],
    pub subscriber: [u8; 32],
}

impl SubscribeSpec {
    pub fn new(topic: impl Into<String>, realm: [u8; 32], subscriber: [u8; 32]) -> Self {
        Self {
            topic: topic.into(),
            realm,
            subscriber,
        }
    }
}

fn subscribe_value(spec: &SubscribeSpec, frame_id: [u8; 16], sent_at_ms: u64) -> Value {
    Value::Map(base("subscribe", 0, frame_id, sent_at_ms))
        .with_field("realm", Value::Bytes(spec.realm.to_vec()))
        // `topic := binary()` -- bytes, not text. Same fix as CALL's
        // `procedure`.
        .with_field("topic", Value::Bytes(spec.topic.as_bytes().to_vec()))
        .with_field("subscriber", Value::Bytes(spec.subscriber.to_vec()))
        .with_field("filter", Value::Null)
        .with_field("options", Value::Map(vec![]))
}

/// Build a SUBSCRIBE frame with a fresh `frame_id`/`sent_at_ms`. No
/// filter, no options — the plainest possible subscription.
pub fn subscribe(spec: &SubscribeSpec) -> Value {
    subscribe_value(spec, fresh_frame_id(), current_millis())
}

/// Fields for an UNSUBSCRIBE frame.
#[derive(Debug, Clone)]
pub struct UnsubscribeSpec {
    pub topic: String,
    pub realm: [u8; 32],
    pub subscriber: [u8; 32],
}

impl UnsubscribeSpec {
    pub fn new(topic: impl Into<String>, realm: [u8; 32], subscriber: [u8; 32]) -> Self {
        Self {
            topic: topic.into(),
            realm,
            subscriber,
        }
    }
}

fn unsubscribe_value(spec: &UnsubscribeSpec, frame_id: [u8; 16], sent_at_ms: u64) -> Value {
    Value::Map(base("unsubscribe", 0, frame_id, sent_at_ms))
        .with_field("realm", Value::Bytes(spec.realm.to_vec()))
        // `topic := binary()` -- bytes, not text. Same fix as CALL's
        // `procedure`.
        .with_field("topic", Value::Bytes(spec.topic.as_bytes().to_vec()))
        .with_field("subscriber", Value::Bytes(spec.subscriber.to_vec()))
}

/// Build an UNSUBSCRIBE frame with a fresh `frame_id`/`sent_at_ms`.
pub fn unsubscribe(spec: &UnsubscribeSpec) -> Value {
    unsubscribe_value(spec, fresh_frame_id(), current_millis())
}

/// What a subscriber actually receives — parsed fields of an EVENT frame.
#[derive(Debug, Clone)]
pub struct EventInfo {
    pub topic: String,
    pub realm: [u8; 32],
    pub publisher: [u8; 32],
    pub seq: u64,
    pub payload: Value,
    pub delivered_via: String,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseEventError {
    NotAnEventFrame,
    MissingField(&'static str),
    WrongFieldType(&'static str),
}

impl std::fmt::Display for ParseEventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseEventError::NotAnEventFrame => write!(f, "frame_type is not \"event\""),
            ParseEventError::MissingField(name) => write!(f, "missing required field {name:?}"),
            ParseEventError::WrongFieldType(name) => write!(f, "field {name:?} has the wrong type"),
        }
    }
}

impl std::error::Error for ParseEventError {}

/// Parse a decoded frame as an EVENT.
pub fn parse_event(frame: &Value) -> Result<EventInfo, ParseEventError> {
    match frame.get("frame_type") {
        Some(Value::Text(t)) if t == "event" => {}
        _ => return Err(ParseEventError::NotAnEventFrame),
    }
    // `topic := binary()` on the wire -- bytes, not text.
    let topic = match frame.get("topic") {
        Some(Value::Bytes(b)) => {
            String::from_utf8(b.clone()).map_err(|_| ParseEventError::WrongFieldType("topic"))?
        }
        Some(_) => return Err(ParseEventError::WrongFieldType("topic")),
        None => return Err(ParseEventError::MissingField("topic")),
    };
    let realm = match frame.get("realm") {
        Some(Value::Bytes(b)) => b
            .as_slice()
            .try_into()
            .map_err(|_| ParseEventError::WrongFieldType("realm"))?,
        Some(_) => return Err(ParseEventError::WrongFieldType("realm")),
        None => return Err(ParseEventError::MissingField("realm")),
    };
    let publisher = match frame.get("publisher") {
        Some(Value::Bytes(b)) => b
            .as_slice()
            .try_into()
            .map_err(|_| ParseEventError::WrongFieldType("publisher"))?,
        Some(_) => return Err(ParseEventError::WrongFieldType("publisher")),
        None => return Err(ParseEventError::MissingField("publisher")),
    };
    let seq = match frame.get("seq") {
        Some(Value::Int(n)) if *n >= 0 => *n as u64,
        Some(_) => return Err(ParseEventError::WrongFieldType("seq")),
        None => return Err(ParseEventError::MissingField("seq")),
    };
    let payload = frame
        .get("payload")
        .cloned()
        .ok_or(ParseEventError::MissingField("payload"))?;
    let delivered_via = match frame.get("delivered_via") {
        Some(Value::Text(t)) => t.clone(),
        Some(_) => return Err(ParseEventError::WrongFieldType("delivered_via")),
        None => return Err(ParseEventError::MissingField("delivered_via")),
    };
    Ok(EventInfo {
        topic,
        realm,
        publisher,
        seq,
        payload,
        delivered_via,
    })
}

// ---------------------------------------------------------------------
// HELLO (parse only — a client receives these, it doesn't construct them)
// ---------------------------------------------------------------------

/// The fields of a HELLO frame actually needed to drive the handshake
/// state machine (`plans/PLAN_WIRE_PROTOCOL.md` §3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloInfo {
    pub node_id: [u8; 32],
    pub station_id: [u8; 32],
    pub realms: Vec<[u8; 32]>,
    pub capabilities: u64,
    pub accepted: bool,
    pub negotiated_capabilities: u64,
    pub refusal_code: Option<i128>,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseHelloError {
    NotAHelloFrame,
    MissingField(&'static str),
    WrongFieldType(&'static str),
}

impl std::fmt::Display for ParseHelloError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseHelloError::NotAHelloFrame => write!(f, "frame_type is not \"hello\""),
            ParseHelloError::MissingField(name) => write!(f, "missing required field {name:?}"),
            ParseHelloError::WrongFieldType(name) => write!(f, "field {name:?} has the wrong type"),
        }
    }
}

impl std::error::Error for ParseHelloError {}

fn get_bytes32(frame: &Value, field: &'static str) -> Result<[u8; 32], ParseHelloError> {
    match frame.get(field) {
        None => Err(ParseHelloError::MissingField(field)),
        Some(Value::Bytes(b)) => b
            .as_slice()
            .try_into()
            .map_err(|_| ParseHelloError::WrongFieldType(field)),
        Some(_) => Err(ParseHelloError::WrongFieldType(field)),
    }
}

fn get_bytes32_list(frame: &Value, field: &'static str) -> Result<Vec<[u8; 32]>, ParseHelloError> {
    match frame.get(field) {
        None => Err(ParseHelloError::MissingField(field)),
        Some(Value::List(items)) => items
            .iter()
            .map(|v| match v {
                Value::Bytes(b) => b
                    .as_slice()
                    .try_into()
                    .map_err(|_| ParseHelloError::WrongFieldType(field)),
                _ => Err(ParseHelloError::WrongFieldType(field)),
            })
            .collect(),
        Some(_) => Err(ParseHelloError::WrongFieldType(field)),
    }
}

fn get_uint(frame: &Value, field: &'static str) -> Result<u64, ParseHelloError> {
    match frame.get(field) {
        None => Err(ParseHelloError::MissingField(field)),
        Some(Value::Int(n)) if *n >= 0 => Ok(*n as u64),
        Some(_) => Err(ParseHelloError::WrongFieldType(field)),
    }
}

fn get_bool(frame: &Value, field: &'static str) -> Result<bool, ParseHelloError> {
    match frame.get(field) {
        None => Err(ParseHelloError::MissingField(field)),
        Some(Value::Text(t)) if t == "true" => Ok(true),
        Some(Value::Text(t)) if t == "false" => Ok(false),
        Some(_) => Err(ParseHelloError::WrongFieldType(field)),
    }
}

/// Parse a decoded frame as a HELLO, checking `frame_type` first.
pub fn parse_hello(frame: &Value) -> Result<HelloInfo, ParseHelloError> {
    match frame.get("frame_type") {
        Some(Value::Text(t)) if t == "hello" => {}
        _ => return Err(ParseHelloError::NotAHelloFrame),
    }
    let refusal_code = match frame.get("refusal_code") {
        None | Some(Value::Null) => None,
        Some(Value::Int(n)) => Some(*n),
        Some(_) => return Err(ParseHelloError::WrongFieldType("refusal_code")),
    };
    Ok(HelloInfo {
        node_id: get_bytes32(frame, "node_id")?,
        station_id: get_bytes32(frame, "station_id")?,
        realms: get_bytes32_list(frame, "realms")?,
        capabilities: get_uint(frame, "capabilities")?,
        accepted: get_bool(frame, "accepted")?,
        negotiated_capabilities: get_uint(frame, "negotiated_capabilities")?,
        refusal_code,
    })
}

// ---------------------------------------------------------------------
// Sign / verify
// ---------------------------------------------------------------------

/// Sign `frame` with `identity`, over `SIG_DOMAIN || canonical_cbor(frame
/// minus signature/publisher_sig)`, and return the frame with its
/// `signature` field set (64 bytes).
pub fn sign(frame: Value, identity: &KeyPair) -> Value {
    let signable = signable_bytes(&frame);
    let sig = identity.sign(&signable);
    frame.with_field("signature", Value::Bytes(sig.to_vec()))
}

fn signable_bytes(frame: &Value) -> Vec<u8> {
    let unsigned = frame.without(&["signature", "publisher_sig"]);
    let canonical =
        cbor::encode(&unsigned).expect("a frame built by this module is always encodable");
    let mut out = Vec::with_capacity(SIG_DOMAIN.len() + canonical.len());
    out.extend_from_slice(SIG_DOMAIN);
    out.extend_from_slice(&canonical);
    out
}

#[derive(Debug, PartialEq, Eq)]
pub enum VerifyError {
    MissingSignature,
    BadSignature,
    SignatureInvalid,
}

impl std::fmt::Display for VerifyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VerifyError::MissingSignature => write!(f, "frame has no signature field"),
            VerifyError::BadSignature => write!(f, "signature field is not 64 bytes"),
            VerifyError::SignatureInvalid => write!(f, "signature does not verify against pubkey"),
        }
    }
}

impl std::error::Error for VerifyError {}

/// Verify `frame`'s `signature` field against `pubkey`, over the same
/// domain-separated bytes [`sign`] produces.
pub fn verify(frame: &Value, pubkey: &[u8; 32]) -> Result<(), VerifyError> {
    let sig: [u8; 64] = match frame.get("signature") {
        Some(Value::Bytes(b)) => b
            .as_slice()
            .try_into()
            .map_err(|_| VerifyError::BadSignature)?,
        _ => return Err(VerifyError::MissingSignature),
    };
    let signable = signable_bytes(frame);
    if crate::identity::verify(&signable, &sig, pubkey) {
        Ok(())
    } else {
        Err(VerifyError::SignatureInvalid)
    }
}

// ---------------------------------------------------------------------
// Wire codec: length-prefixed CBOR
// ---------------------------------------------------------------------

#[derive(Debug, PartialEq, Eq)]
pub enum EncodeFrameError {
    TooLarge(usize),
    Cbor(cbor::IntOutOfRange),
}

impl std::fmt::Display for EncodeFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EncodeFrameError::TooLarge(n) => {
                write!(
                    f,
                    "frame is {n} bytes, exceeding the {MAX_FRAME_BYTES}-byte cap"
                )
            }
            EncodeFrameError::Cbor(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for EncodeFrameError {}

/// Encode `frame` as `<<Length:32/big, Cbor/binary>>`.
pub fn encode(frame: &Value) -> Result<Vec<u8>, EncodeFrameError> {
    let payload = cbor::encode(frame).map_err(EncodeFrameError::Cbor)?;
    if payload.len() > MAX_FRAME_BYTES {
        return Err(EncodeFrameError::TooLarge(payload.len()));
    }
    let mut out = Vec::with_capacity(4 + payload.len());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(&payload);
    Ok(out)
}

/// Result of attempting to decode one frame from the head of a buffer —
/// mirrors the reference decoder's three-way `{ok,_,_}` / `{more,_}` /
/// `{error,_}` contract, adapted to return a consumed-byte count instead
/// of a remainder slice (equally usable, more idiomatic here).
#[derive(Debug)]
pub enum Decoded {
    /// A complete frame was decoded, consuming this many bytes from the
    /// front of the buffer.
    Frame(Value, usize),
    /// The buffer doesn't yet hold a complete frame; at least this many
    /// more bytes are needed before trying again.
    More(usize),
}

#[derive(Debug)]
pub enum DecodeFrameError {
    TooLarge(usize),
    Cbor(cbor::DecodeError),
}

impl std::fmt::Display for DecodeFrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DecodeFrameError::TooLarge(n) => {
                write!(
                    f,
                    "claimed frame length {n} exceeds the {MAX_FRAME_BYTES}-byte cap"
                )
            }
            DecodeFrameError::Cbor(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for DecodeFrameError {}

/// Decode one length-prefixed frame from the head of `buf`.
pub fn decode(buf: &[u8]) -> Result<Decoded, DecodeFrameError> {
    if buf.len() < 4 {
        return Ok(Decoded::More(4 - buf.len()));
    }
    let len = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;
    if len > MAX_FRAME_BYTES {
        return Err(DecodeFrameError::TooLarge(len));
    }
    if buf.len() < 4 + len {
        return Ok(Decoded::More(4 + len - buf.len()));
    }
    let value = cbor::decode(&buf[4..4 + len]).map_err(DecodeFrameError::Cbor)?;
    Ok(Decoded::Frame(value, 4 + len))
}

// ---------------------------------------------------------------------
// RPC advertise (§6.9 of `plans/PLAN_WIRE_PROTOCOL.md`): ADVERTISE,
// UNADVERTISE. The provider-role building block — registers this
// connection as the handler for `procedure` under `realm`; the station
// then routes inbound CALLs (control stream) and STREAM_OPENs (a fresh
// dedicated stream it opens toward us) for that procedure back to us.
// See `src/provider.rs` for the dispatch side of that, once built.
// ---------------------------------------------------------------------

/// Fields for an ADVERTISE frame.
#[derive(Debug, Clone)]
pub struct AdvertiseSpec {
    pub realm: [u8; 32],
    pub procedure: String,
    pub advertiser: [u8; 32],
}

impl AdvertiseSpec {
    pub fn new(realm: [u8; 32], procedure: impl Into<String>, advertiser: [u8; 32]) -> Self {
        Self {
            realm,
            procedure: procedure.into(),
            advertiser,
        }
    }
}

fn advertise_value(spec: &AdvertiseSpec, frame_id: [u8; 16], sent_at_ms: u64) -> Value {
    // NOTE: `source_route` stays untouched (`Null`) — confirmed directly
    // against the reference, not assumed from CALL/STREAM_OPEN's pattern
    // (which DO override it). `realm` IS overridden here, unlike RESULT/
    // STREAM_DATA/etc.
    Value::Map(base("advertise", 0, frame_id, sent_at_ms))
        .with_field("realm", Value::Bytes(spec.realm.to_vec()))
        // `procedure := binary()` -- bytes, not text. Same fix as CALL's
        // `procedure`.
        .with_field(
            "procedure",
            Value::Bytes(spec.procedure.as_bytes().to_vec()),
        )
        .with_field("advertiser", Value::Bytes(spec.advertiser.to_vec()))
        // `options` has no known use case yet -- always the reference's
        // own default, an empty map.
        .with_field("options", Value::Map(vec![]))
}

/// Build an ADVERTISE frame with a fresh `frame_id`/`sent_at_ms`.
pub fn advertise(spec: &AdvertiseSpec) -> Value {
    advertise_value(spec, fresh_frame_id(), current_millis())
}

/// Fields for an UNADVERTISE frame.
#[derive(Debug, Clone)]
pub struct UnadvertiseSpec {
    pub realm: [u8; 32],
    pub procedure: String,
    pub advertiser: [u8; 32],
}

impl UnadvertiseSpec {
    pub fn new(realm: [u8; 32], procedure: impl Into<String>, advertiser: [u8; 32]) -> Self {
        Self {
            realm,
            procedure: procedure.into(),
            advertiser,
        }
    }
}

fn unadvertise_value(spec: &UnadvertiseSpec, frame_id: [u8; 16], sent_at_ms: u64) -> Value {
    Value::Map(base("unadvertise", 0, frame_id, sent_at_ms))
        .with_field("realm", Value::Bytes(spec.realm.to_vec()))
        .with_field(
            "procedure",
            Value::Bytes(spec.procedure.as_bytes().to_vec()),
        )
        .with_field("advertiser", Value::Bytes(spec.advertiser.to_vec()))
}

/// Build an UNADVERTISE frame with a fresh `frame_id`/`sent_at_ms`.
pub fn unadvertise(spec: &UnadvertiseSpec) -> Value {
    unadvertise_value(spec, fresh_frame_id(), current_millis())
}

// ---------------------------------------------------------------------
// Streaming RPC (§13 of `plans/PLAN_WIRE_PROTOCOL.md`): STREAM_OPEN,
// STREAM_DATA, STREAM_END, STREAM_ERROR, STREAM_REPLY. Ported from
// `macula_frame.erl`'s streaming constructors, verified against real
// `rebar3` output the same way as every other frame type.
//
// **Real finding, empirically verified (2026-08-28), correcting an
// assumption in an earlier draft of the wire-protocol spec:** despite
// `encoding`'s `msgpack` value name, there is no second wire codec.
// `msgpack` was removed from macula's own dependencies in v3.0.0
// (`rebar.config`'s own comment: "wire protocol switched to CBOR"); the
// one remaining `msgpack:pack` call in the whole macula repo is in an
// unrelated legacy DHT test, never on the `stream_data` path. Confirmed
// directly: building a `stream_data` frame with `encoding = msgpack` and
// an arbitrary Erlang map as `body`, then round-tripping it through
// `macula_frame:encode/1` + `decode/1`, hands the map straight back —
// `body` is embedded as an ordinary nested value in the frame's own
// canonical-CBOR envelope, exactly like CALL's `payload` or
// `stream_reply`'s `payload`. So here, `encoding` is purely a semantic
// hint for the receiver ("treat `body` as raw bytes" vs "treat it as a
// structured value") — `StreamDataSpec::body` is just a [`Value`] either
// way, and no `rmp-serde`/msgpack dependency is needed in this crate.
//
// **v1 scope, matching this crate's existing priority (also documented
// in the plan): the caller/consumer role (§13.1) only.** These
// constructors are enough to open a stream, send/receive chunks, close
// or abort — the shape a mobile client actually needs. The provider
// role (§13.2, exposing a streaming procedure *to* the mesh) isn't
// built — nothing in this crate needs to *serve* RPCs yet.
//
// **`signer` (an optional field on STREAM_DATA/STREAM_END/STREAM_ERROR,
// confirmed present in the reference via `maybe_add_signer/2`) is not
// exposed here.** Its stated purpose is multi-hop relay authentication —
// letting a relaying station attribute a frame to the originating daemon
// rather than to itself. A direct-dial client talking to one station
// has no relay hop to authenticate across, matching every other frame
// type this crate already builds (CALL, PUBLISH, etc. — none expose a
// `signer` field either).

/// `mode` on a STREAM_OPEN — who's expected to push data. Matches
/// `macula_stream:mode()`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamMode {
    /// The provider pushes chunks at the caller.
    ServerStream,
    /// The caller pushes chunks at the provider (§12.3's push-upload
    /// path is exactly this mode).
    ClientStream,
    /// Both directions.
    Bidi,
}

impl StreamMode {
    pub fn name(self) -> &'static str {
        match self {
            StreamMode::ServerStream => "server_stream",
            StreamMode::ClientStream => "client_stream",
            StreamMode::Bidi => "bidi",
        }
    }

    // No `from_name`: nothing in this crate parses an *incoming*
    // STREAM_OPEN (that's the provider role, §13.2, not built — see
    // this section's module doc). Add it if/when that role is built.
}

/// `encoding` on a STREAM_DATA — a hint for how to interpret `body`, not
/// a second wire codec. See this section's module-level note.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEncoding {
    /// `body` is opaque bytes.
    Raw,
    /// `body` is a structured [`Value`] (despite the name — no msgpack
    /// byte-level encoding actually happens; see the note above).
    Msgpack,
}

impl StreamEncoding {
    pub fn name(self) -> &'static str {
        match self {
            StreamEncoding::Raw => "raw",
            StreamEncoding::Msgpack => "msgpack",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "raw" => Some(StreamEncoding::Raw),
            "msgpack" => Some(StreamEncoding::Msgpack),
            _ => None,
        }
    }
}

/// `role` on a STREAM_END — which direction(s) are closing.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamRole {
    /// Half-close: this side is done sending, still willing to receive.
    Send,
    /// Full close: this side is done in both directions.
    Both,
}

impl StreamRole {
    pub fn name(self) -> &'static str {
        match self {
            StreamRole::Send => "send",
            StreamRole::Both => "both",
        }
    }

    fn from_name(name: &str) -> Option<Self> {
        match name {
            "send" => Some(StreamRole::Send),
            "both" => Some(StreamRole::Both),
            _ => None,
        }
    }
}

/// Fields for a STREAM_OPEN frame. Mirrors CALL's auth/routing shape —
/// `deadline_ms`/`caller`/`source_route`/`retry_budget` — plus the
/// stream-specific `stream_id`/`mode`/`args`.
#[derive(Debug, Clone)]
pub struct StreamOpenSpec {
    pub stream_id: [u8; 16],
    pub procedure: String,
    pub realm: [u8; 32],
    pub mode: StreamMode,
    pub args: Value,
    pub deadline_ms: i128,
    pub caller: [u8; 32],
    pub source_route: Vec<u8>,
    pub retry_budget: u64,
}

impl StreamOpenSpec {
    pub fn new(
        stream_id: [u8; 16],
        procedure: impl Into<String>,
        realm: [u8; 32],
        mode: StreamMode,
        args: Value,
        deadline_ms: i128,
        caller: [u8; 32],
    ) -> Self {
        Self {
            stream_id,
            procedure: procedure.into(),
            realm,
            mode,
            args,
            deadline_ms,
            caller,
            source_route: Vec::new(),
            retry_budget: 0,
        }
    }
}

fn stream_open_value(spec: &StreamOpenSpec, frame_id: [u8; 16], sent_at_ms: u64) -> Value {
    Value::Map(base("stream_open", 0, frame_id, sent_at_ms))
        .with_field("stream_id", Value::Bytes(spec.stream_id.to_vec()))
        // `procedure := binary()` -- bytes, not text. Same fix as CALL's
        // `procedure`.
        .with_field(
            "procedure",
            Value::Bytes(spec.procedure.as_bytes().to_vec()),
        )
        .with_field("realm", Value::Bytes(spec.realm.to_vec()))
        .with_field("mode", Value::text(spec.mode.name()))
        .with_field("args", spec.args.clone())
        .with_field("deadline_ms", Value::Int(spec.deadline_ms))
        .with_field("caller", Value::Bytes(spec.caller.to_vec()))
        .with_field("source_route", Value::Bytes(spec.source_route.clone()))
        .with_field("retry_budget", Value::Int(spec.retry_budget as i128))
}

/// Build a STREAM_OPEN frame with a fresh `frame_id`/`sent_at_ms`.
/// Unsigned — pass the result to [`sign`] before sending.
pub fn stream_open(spec: &StreamOpenSpec) -> Value {
    stream_open_value(spec, fresh_frame_id(), current_millis())
}

/// Fields for a STREAM_DATA frame — one chunk. `body`'s shape follows
/// `encoding`: [`Value::Bytes`] for [`StreamEncoding::Raw`], any
/// structured [`Value`] for [`StreamEncoding::Msgpack`] (see this
/// section's module-level note on why that's still a plain CBOR value,
/// not a second codec).
#[derive(Debug, Clone)]
pub struct StreamDataSpec {
    pub stream_id: [u8; 16],
    pub seq: u64,
    pub encoding: StreamEncoding,
    pub body: Value,
}

impl StreamDataSpec {
    pub fn new(stream_id: [u8; 16], seq: u64, encoding: StreamEncoding, body: Value) -> Self {
        Self {
            stream_id,
            seq,
            encoding,
            body,
        }
    }
}

fn stream_data_value(spec: &StreamDataSpec, frame_id: [u8; 16], sent_at_ms: u64) -> Value {
    // NOTE: like RESULT, STREAM_DATA does not touch the base envelope's
    // `realm`/`call_id`/`source_route` — they stay `Null`, confirmed
    // directly against the reference's own output, not assumed from
    // STREAM_OPEN's pattern.
    Value::Map(base("stream_data", 0, frame_id, sent_at_ms))
        .with_field("stream_id", Value::Bytes(spec.stream_id.to_vec()))
        .with_field("seq", Value::Int(spec.seq as i128))
        .with_field("encoding", Value::text(spec.encoding.name()))
        .with_field("body", spec.body.clone())
}

/// Build a STREAM_DATA frame with a fresh `frame_id`/`sent_at_ms`.
pub fn stream_data(spec: &StreamDataSpec) -> Value {
    stream_data_value(spec, fresh_frame_id(), current_millis())
}

/// Fields for a STREAM_END frame — a half-close (`role: Send`) or full
/// close (`role: Both`) of one direction.
#[derive(Debug, Clone)]
pub struct StreamEndSpec {
    pub stream_id: [u8; 16],
    pub role: StreamRole,
}

impl StreamEndSpec {
    pub fn new(stream_id: [u8; 16], role: StreamRole) -> Self {
        Self { stream_id, role }
    }
}

fn stream_end_value(spec: &StreamEndSpec, frame_id: [u8; 16], sent_at_ms: u64) -> Value {
    Value::Map(base("stream_end", 0, frame_id, sent_at_ms))
        .with_field("stream_id", Value::Bytes(spec.stream_id.to_vec()))
        .with_field("role", Value::text(spec.role.name()))
}

/// Build a STREAM_END frame with a fresh `frame_id`/`sent_at_ms`.
pub fn stream_end(spec: &StreamEndSpec) -> Value {
    stream_end_value(spec, fresh_frame_id(), current_millis())
}

/// Fields for a STREAM_ERROR frame — the explicit abort a well-behaved
/// peer sends instead of just dropping the stream on any non-normal
/// termination (`plans/PLAN_WIRE_PROTOCOL.md` §13.1, point 4). `code`
/// here is a free-form label (`is_binary(Code)` in the reference), NOT
/// a BOLT#4 numeric code like an ERROR (§6.4) frame's `code` — streaming
/// aborts and unary-call errors use unrelated error vocabularies.
#[derive(Debug, Clone)]
pub struct StreamErrorSpec {
    pub stream_id: [u8; 16],
    pub code: String,
    pub message: String,
}

impl StreamErrorSpec {
    pub fn new(stream_id: [u8; 16], code: impl Into<String>, message: impl Into<String>) -> Self {
        Self {
            stream_id,
            code: code.into(),
            message: message.into(),
        }
    }
}

fn stream_error_value(spec: &StreamErrorSpec, frame_id: [u8; 16], sent_at_ms: u64) -> Value {
    Value::Map(base("stream_error", 0, frame_id, sent_at_ms))
        .with_field("stream_id", Value::Bytes(spec.stream_id.to_vec()))
        .with_field("code", Value::Bytes(spec.code.as_bytes().to_vec()))
        .with_field("message", Value::Bytes(spec.message.as_bytes().to_vec()))
}

/// Build a STREAM_ERROR frame with a fresh `frame_id`/`sent_at_ms`.
pub fn stream_error(spec: &StreamErrorSpec) -> Value {
    stream_error_value(spec, fresh_frame_id(), current_millis())
}

/// Fields for a STREAM_REPLY frame — the terminal result of a
/// `client_stream`/`bidi` exchange, sent once by the provider after it
/// has fully consumed and verified whatever the caller streamed.
#[derive(Debug, Clone)]
pub struct StreamReplySpec {
    pub stream_id: [u8; 16],
    pub payload: Value,
    pub responded_by: [u8; 32],
}

impl StreamReplySpec {
    pub fn new(stream_id: [u8; 16], payload: Value, responded_by: [u8; 32]) -> Self {
        Self {
            stream_id,
            payload,
            responded_by,
        }
    }
}

fn stream_reply_value(spec: &StreamReplySpec, frame_id: [u8; 16], sent_at_ms: u64) -> Value {
    Value::Map(base("stream_reply", 0, frame_id, sent_at_ms))
        .with_field("stream_id", Value::Bytes(spec.stream_id.to_vec()))
        .with_field("payload", spec.payload.clone())
        .with_field("responded_by", Value::Bytes(spec.responded_by.to_vec()))
}

/// Build a STREAM_REPLY frame with a fresh `frame_id`/`sent_at_ms`.
pub fn stream_reply(spec: &StreamReplySpec) -> Value {
    stream_reply_value(spec, fresh_frame_id(), current_millis())
}

/// Extract this frame's `stream_id`, regardless of frame type — used to
/// correlate STREAM_DATA/STREAM_END/STREAM_ERROR/STREAM_REPLY frames
/// back to the STREAM_OPEN that started the exchange. 16 bytes, matching
/// `stream_id() :: <<_:128>>`.
pub fn frame_stream_id(frame: &Value) -> Option<[u8; 16]> {
    match frame.get("stream_id") {
        Some(Value::Bytes(b)) => b.as_slice().try_into().ok(),
        _ => None,
    }
}

/// What a stream consumer actually receives — one parsed
/// STREAM_DATA/STREAM_END/STREAM_ERROR/STREAM_REPLY frame.
#[derive(Debug, Clone)]
pub enum StreamEvent {
    Data {
        stream_id: [u8; 16],
        seq: u64,
        encoding: StreamEncoding,
        body: Value,
    },
    End {
        stream_id: [u8; 16],
        role: StreamRole,
    },
    Error {
        stream_id: [u8; 16],
        code: String,
        message: String,
    },
    Reply {
        stream_id: [u8; 16],
        payload: Value,
        responded_by: [u8; 32],
    },
}

#[derive(Debug, PartialEq, Eq)]
pub enum ParseStreamEventError {
    NotAStreamFrame,
    MissingField(&'static str),
    WrongFieldType(&'static str),
}

impl std::fmt::Display for ParseStreamEventError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ParseStreamEventError::NotAStreamFrame => write!(
                f,
                "frame_type is none of stream_data/stream_end/stream_error/stream_reply"
            ),
            ParseStreamEventError::MissingField(name) => {
                write!(f, "missing required field {name:?}")
            }
            ParseStreamEventError::WrongFieldType(name) => {
                write!(f, "field {name:?} has the wrong type")
            }
        }
    }
}

impl std::error::Error for ParseStreamEventError {}

/// Parse a decoded frame as one of STREAM_DATA/STREAM_END/STREAM_ERROR/
/// STREAM_REPLY.
pub fn parse_stream_event(frame: &Value) -> Result<StreamEvent, ParseStreamEventError> {
    let stream_id = match frame.get("stream_id") {
        Some(Value::Bytes(b)) => b
            .as_slice()
            .try_into()
            .map_err(|_| ParseStreamEventError::WrongFieldType("stream_id"))?,
        Some(_) => return Err(ParseStreamEventError::WrongFieldType("stream_id")),
        None => return Err(ParseStreamEventError::MissingField("stream_id")),
    };
    match frame.get("frame_type") {
        Some(Value::Text(t)) if t == "stream_data" => {
            let seq = match frame.get("seq") {
                Some(Value::Int(n)) if *n >= 0 => *n as u64,
                Some(_) => return Err(ParseStreamEventError::WrongFieldType("seq")),
                None => return Err(ParseStreamEventError::MissingField("seq")),
            };
            let encoding = match frame.get("encoding") {
                Some(Value::Text(t)) => StreamEncoding::from_name(t)
                    .ok_or(ParseStreamEventError::WrongFieldType("encoding"))?,
                Some(_) => return Err(ParseStreamEventError::WrongFieldType("encoding")),
                None => return Err(ParseStreamEventError::MissingField("encoding")),
            };
            let body = frame
                .get("body")
                .cloned()
                .ok_or(ParseStreamEventError::MissingField("body"))?;
            Ok(StreamEvent::Data {
                stream_id,
                seq,
                encoding,
                body,
            })
        }
        Some(Value::Text(t)) if t == "stream_end" => {
            let role = match frame.get("role") {
                Some(Value::Text(t)) => {
                    StreamRole::from_name(t).ok_or(ParseStreamEventError::WrongFieldType("role"))?
                }
                Some(_) => return Err(ParseStreamEventError::WrongFieldType("role")),
                None => return Err(ParseStreamEventError::MissingField("role")),
            };
            Ok(StreamEvent::End { stream_id, role })
        }
        Some(Value::Text(t)) if t == "stream_error" => {
            let code = match frame.get("code") {
                Some(Value::Bytes(b)) => String::from_utf8(b.clone())
                    .map_err(|_| ParseStreamEventError::WrongFieldType("code"))?,
                Some(_) => return Err(ParseStreamEventError::WrongFieldType("code")),
                None => return Err(ParseStreamEventError::MissingField("code")),
            };
            let message = match frame.get("message") {
                Some(Value::Bytes(b)) => String::from_utf8(b.clone())
                    .map_err(|_| ParseStreamEventError::WrongFieldType("message"))?,
                Some(_) => return Err(ParseStreamEventError::WrongFieldType("message")),
                None => return Err(ParseStreamEventError::MissingField("message")),
            };
            Ok(StreamEvent::Error {
                stream_id,
                code,
                message,
            })
        }
        Some(Value::Text(t)) if t == "stream_reply" => {
            let payload = frame
                .get("payload")
                .cloned()
                .ok_or(ParseStreamEventError::MissingField("payload"))?;
            let responded_by = match frame.get("responded_by") {
                Some(Value::Bytes(b)) => b
                    .as_slice()
                    .try_into()
                    .map_err(|_| ParseStreamEventError::WrongFieldType("responded_by"))?,
                Some(_) => return Err(ParseStreamEventError::WrongFieldType("responded_by")),
                None => return Err(ParseStreamEventError::MissingField("responded_by")),
            };
            Ok(StreamEvent::Reply {
                stream_id,
                payload,
                responded_by,
            })
        }
        Some(_) | None => Err(ParseStreamEventError::NotAStreamFrame),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex_bytes(s: &str) -> Vec<u8> {
        ::hex::decode(s).expect("valid hex fixture")
    }

    fn fixed_array(hex_str: &str) -> [u8; 32] {
        hex_bytes(hex_str).try_into().expect("32-byte fixture")
    }

    // Same identity/evidence vectors as src/identity.rs's tests —
    // captured from the same real `rebar3 shell` session.
    const VECTOR_PUB: &str = "B966A9812649C3D5542FF54954FE090C43FDA6574FE48A0DD326626CFAD29A83";
    const VECTOR_PRIV: &str = "457F45FF5A09E172ED15CB20D6CB26B51AD15ED7308C12D478E8631F9CA03D4F";
    const VECTOR_PUZZLE_EVIDENCE: &str =
        "09D48C91CB46513ED2580BDCEA87C40DA508D4E50EC3DF2F701AFC55D1C5C0B2";
    const VECTOR_FRAME_ID: &str = "0192E8B0F1A47000A1B2C3D4E5F60718";
    const VECTOR_SENT_AT_MS: u64 = 1_700_000_000_000;
    const VECTOR_SIGNATURE: &str = "CF6959A61A2F4D2046F0124C1DD56A6541265F36A24CB18CA8C45C95031854D6AECE5FB93E2AE7BA6C444A09C7C5DED195B6EB0D1CC8E487CCF6E4F0D903B409";
    const VECTOR_ENCODED_LEN: usize = 375;

    /// The single strongest test in this crate so far: builds the exact
    /// same CONNECT frame `macula_frame:connect/1` + `sign/2` produced
    /// in a real, live `rebar3 shell` (same identity, fixed
    /// `frame_id`/`sent_at_ms` injected explicitly since the reference
    /// randomizes both per call), and checks the encoded bytes —
    /// including the Ed25519 signature — match exactly. See this
    /// module's doc comment.
    #[test]
    fn connect_frame_matches_the_reference_byte_for_byte() {
        let pub_bytes = fixed_array(VECTOR_PUB);
        let identity = KeyPair::from_seed_bytes(fixed_array(VECTOR_PRIV));
        let puzzle_evidence = fixed_array(VECTOR_PUZZLE_EVIDENCE);
        let frame_id: [u8; 16] = hex_bytes(VECTOR_FRAME_ID).try_into().expect("16 bytes");

        let spec = ConnectSpec::new(pub_bytes, puzzle_evidence);
        let unsigned = connect_value(&spec, frame_id, VECTOR_SENT_AT_MS);
        let signed = sign(unsigned, &identity);

        let sig_field = match signed.get("signature") {
            Some(Value::Bytes(b)) => b.clone(),
            other => panic!("expected a signature field, got {other:?}"),
        };
        assert_eq!(
            hex::encode_upper(&sig_field),
            VECTOR_SIGNATURE,
            "signature diverged from the reference — canonical CBOR encoding \
             or the signing domain/bytes must differ somewhere"
        );

        let encoded = encode(&signed).expect("encodable frame");
        assert_eq!(encoded.len(), VECTOR_ENCODED_LEN);

        // Round-trip: decode what we just built and verify it against
        // the known pubkey, exactly like a receiving station would.
        let decoded = match decode(&encoded).expect("valid frame") {
            Decoded::Frame(value, consumed) => {
                assert_eq!(consumed, encoded.len());
                value
            }
            Decoded::More(n) => panic!("unexpectedly needed {n} more bytes"),
        };
        verify(&decoded, &pub_bytes).expect("our own signature must verify");
    }

    #[test]
    fn verify_rejects_a_tampered_field() {
        let identity = KeyPair::from_seed_bytes(fixed_array(VECTOR_PRIV));
        let pub_bytes = identity.public_bytes();
        let spec = ConnectSpec::new(pub_bytes, fixed_array(VECTOR_PUZZLE_EVIDENCE));
        let signed = sign(connect(&spec), &identity);

        // Flip the capabilities field after signing.
        let tampered = signed.with_field("capabilities", Value::Int(999));
        assert_eq!(
            verify(&tampered, &pub_bytes),
            Err(VerifyError::SignatureInvalid)
        );
    }

    #[test]
    fn verify_rejects_a_missing_signature() {
        let frame = Value::Map(vec![(Value::text("frame_type"), Value::text("connect"))]);
        let pubkey = [0u8; 32];
        assert_eq!(verify(&frame, &pubkey), Err(VerifyError::MissingSignature));
    }

    #[test]
    fn decode_reports_more_for_a_short_buffer() {
        assert!(matches!(decode(&[0, 0]), Ok(Decoded::More(2))));
        // A 4-byte length prefix claiming 10 bytes of payload, but only
        // 2 are present.
        let mut buf = 10u32.to_be_bytes().to_vec();
        buf.extend_from_slice(&[0, 0]);
        assert!(matches!(decode(&buf), Ok(Decoded::More(8))));
    }

    #[test]
    fn decode_rejects_a_length_over_the_cap() {
        let buf = ((MAX_FRAME_BYTES as u32) + 1).to_be_bytes();
        assert!(matches!(
            decode(&buf),
            Err(DecodeFrameError::TooLarge(n)) if n == MAX_FRAME_BYTES + 1
        ));
    }

    #[test]
    fn goodbye_frame_round_trips() {
        let frame = goodbye("normal", Some("bye"));
        assert_eq!(frame.get("frame_type"), Some(&Value::text("goodbye")));
        assert_eq!(frame.get("reason"), Some(&Value::text("normal")));
        assert_eq!(frame.get("detail"), Some(&Value::Bytes(b"bye".to_vec())));
    }

    #[test]
    fn goodbye_without_detail_is_null() {
        let frame = goodbye("timeout", None);
        assert_eq!(frame.get("detail"), Some(&Value::Null));
    }

    #[test]
    fn parse_hello_reads_a_well_formed_frame() {
        let node_id = [7u8; 32];
        let station_id = [8u8; 32];
        let realm = [9u8; 32];
        let hello = Value::Map(vec![
            (Value::text("frame_type"), Value::text("hello")),
            (Value::text("node_id"), Value::Bytes(node_id.to_vec())),
            (Value::text("station_id"), Value::Bytes(station_id.to_vec())),
            (
                Value::text("realms"),
                Value::List(vec![Value::Bytes(realm.to_vec())]),
            ),
            (Value::text("capabilities"), Value::Int(0)),
            (Value::text("accepted"), Value::text("true")),
            (Value::text("negotiated_capabilities"), Value::Int(3)),
        ]);
        let info = parse_hello(&hello).expect("well-formed hello");
        assert_eq!(info.node_id, node_id);
        assert_eq!(info.station_id, station_id);
        assert_eq!(info.realms, vec![realm]);
        assert!(info.accepted);
        assert_eq!(info.negotiated_capabilities, 3);
        assert_eq!(info.refusal_code, None);
    }

    #[test]
    fn parse_hello_rejects_the_wrong_frame_type() {
        let frame = Value::Map(vec![(Value::text("frame_type"), Value::text("connect"))]);
        assert_eq!(parse_hello(&frame), Err(ParseHelloError::NotAHelloFrame));
    }

    #[test]
    fn parse_hello_reports_a_missing_field() {
        let frame = Value::Map(vec![(Value::text("frame_type"), Value::text("hello"))]);
        assert_eq!(
            parse_hello(&frame),
            Err(ParseHelloError::MissingField("node_id"))
        );
    }

    // -------------------------------------------------------------
    // Differential vectors for CALL/RESULT/ERROR/PUBLISH/SUBSCRIBE/
    // UNSUBSCRIBE/EVENT — same method and same identity as the CONNECT
    // vector above: built with fixed frame_id/sent_at_ms in a real
    // `rebar3 shell`, exact encoded bytes (including the Ed25519
    // signature) asserted to match. The CALL vector specifically caught
    // a real discrepancy on the first attempt — a hand-built test frame
    // that assumed `source_route` stayed `null` like other optional
    // fields, when the real constructor always sets it to an empty
    // binary — fixed before this test was written, not after.
    // -------------------------------------------------------------

    const VECTOR_CALL_ID: &str = "AABBCCDDEEFF00112233445566778899";
    const VECTOR_ZERO_REALM: [u8; 32] = [0u8; 32];

    fn vector_identity() -> KeyPair {
        KeyPair::from_seed_bytes(fixed_array(VECTOR_PRIV))
    }

    fn vector_call_id() -> [u8; 16] {
        hex_bytes(VECTOR_CALL_ID).try_into().expect("16 bytes")
    }

    fn vector_frame_id() -> [u8; 16] {
        hex_bytes(VECTOR_FRAME_ID).try_into().expect("16 bytes")
    }

    #[test]
    fn call_frame_matches_the_reference_byte_for_byte() {
        let pub_bytes = fixed_array(VECTOR_PUB);
        let identity = vector_identity();
        let spec = CallSpec::new(
            vector_call_id(),
            "_content.get_manifest",
            VECTOR_ZERO_REALM,
            Value::Map(vec![(Value::text("hello"), Value::text("world"))]),
            1_700_000_030_000,
            pub_bytes,
        );
        let signed = sign(
            call_value(&spec, vector_frame_id(), VECTOR_SENT_AT_MS),
            &identity,
        );
        let sig = match signed.get("signature") {
            Some(Value::Bytes(b)) => b.clone(),
            other => panic!("expected a signature field, got {other:?}"),
        };
        assert_eq!(
            hex::encode_upper(&sig),
            "A6BC174F0241E644F634702C08781C8FC8BD3CDE3CA9650DE8A731A01203D9B9403A2CAD75800F7B8C9AAE16FA146B1195FF03F0E6DC4595A652D7F29BFE350A"
        );
        let encoded = encode(&signed).expect("encodable frame");
        assert_eq!(encoded.len(), 386);
    }

    #[test]
    fn result_frame_matches_the_reference_byte_for_byte() {
        let pub_bytes = fixed_array(VECTOR_PUB);
        let identity = vector_identity();
        let spec = ResultSpec::new(vector_call_id(), Value::text("ok-result"), pub_bytes);
        let signed = sign(
            result_value(&spec, vector_frame_id(), VECTOR_SENT_AT_MS),
            &identity,
        );
        let sig = match signed.get("signature") {
            Some(Value::Bytes(b)) => b.clone(),
            other => panic!("expected a signature field, got {other:?}"),
        };
        assert_eq!(
            hex::encode_upper(&sig),
            "03E8F72D51D958C318B7F1C25D78408408317DEAB23434D6EA32F211CADEA1C62900DA15AFF603E795B19A388D382BDB10E65AEFC6F0CE551270AB172A88E50B"
        );
        assert_eq!(encode(&signed).expect("encodable").len(), 301);
    }

    #[test]
    fn error_frame_matches_the_reference_byte_for_byte() {
        let pub_bytes = fixed_array(VECTOR_PUB);
        let identity = vector_identity();
        let spec = CallErrorSpec::new(
            vector_call_id(),
            crate::bolt4::Code::UnknownNextPeer,
            pub_bytes,
        );
        let signed = sign(
            call_error_value(&spec, vector_frame_id(), VECTOR_SENT_AT_MS),
            &identity,
        );
        let sig = match signed.get("signature") {
            Some(Value::Bytes(b)) => b.clone(),
            other => panic!("expected a signature field, got {other:?}"),
        };
        assert_eq!(
            hex::encode_upper(&sig),
            "182ECD5217CE378F576635B23CC8C9F265555142845D6CBA033A282BAED97966C23FBE91D08507FB8E840375AA17665763804F40F89102F8D3EDAD4DA98FC20D"
        );
        assert_eq!(encode(&signed).expect("encodable").len(), 333);
    }

    #[test]
    fn publish_frame_matches_the_reference_byte_for_byte() {
        let pub_bytes = fixed_array(VECTOR_PUB);
        let identity = vector_identity();
        let spec = PublishSpec::new(
            "test.topic",
            VECTOR_ZERO_REALM,
            pub_bytes,
            42,
            Value::text("published-data"),
            VECTOR_SENT_AT_MS,
        );
        let signed = sign(
            publish_value(&spec, vector_frame_id(), VECTOR_SENT_AT_MS),
            &identity,
        );
        let sig = match signed.get("signature") {
            Some(Value::Bytes(b)) => b.clone(),
            other => panic!("expected a signature field, got {other:?}"),
        };
        assert_eq!(
            hex::encode_upper(&sig),
            "DD49D10EFA9F2EED0A393DC02DC5BBAC25D6731562EA39F5AB2E5337824527AFFBC7D917AF4DE5EFDBE5BC41E58659E05EC6FDE4E91FB1A32CC9C211456DF10C"
        );
        assert_eq!(encode(&signed).expect("encodable").len(), 355);
    }

    #[test]
    fn subscribe_frame_matches_the_reference_byte_for_byte() {
        let pub_bytes = fixed_array(VECTOR_PUB);
        let identity = vector_identity();
        let spec = SubscribeSpec::new("test.topic", VECTOR_ZERO_REALM, pub_bytes);
        let signed = sign(
            subscribe_value(&spec, vector_frame_id(), VECTOR_SENT_AT_MS),
            &identity,
        );
        let sig = match signed.get("signature") {
            Some(Value::Bytes(b)) => b.clone(),
            other => panic!("expected a signature field, got {other:?}"),
        };
        assert_eq!(
            hex::encode_upper(&sig),
            "ABDD7304B887A53B149CE4D4C62F1AFD20AE07D8612B76F22006FA6676B8DDB37C1D5106358D32080246BA4355A9E04BF49F73600E752F5F9037D7A93A47020A"
        );
        assert_eq!(encode(&signed).expect("encodable").len(), 313);
    }

    #[test]
    fn unsubscribe_frame_matches_the_reference_byte_for_byte() {
        let pub_bytes = fixed_array(VECTOR_PUB);
        let identity = vector_identity();
        let spec = UnsubscribeSpec::new("test.topic", VECTOR_ZERO_REALM, pub_bytes);
        let signed = sign(
            unsubscribe_value(&spec, vector_frame_id(), VECTOR_SENT_AT_MS),
            &identity,
        );
        let sig = match signed.get("signature") {
            Some(Value::Bytes(b)) => b.clone(),
            other => panic!("expected a signature field, got {other:?}"),
        };
        assert_eq!(
            hex::encode_upper(&sig),
            "C917068BE4E1C5A3C753F249037DD8F44293D888BB252BF1E828671969547969982160C91A0E3CA1C31DE29ED39E3677E7F20F4BDE61539D4618B3703018E403"
        );
        assert_eq!(encode(&signed).expect("encodable").len(), 298);
    }

    #[test]
    fn event_frame_matches_the_reference_byte_for_byte() {
        let pub_bytes = fixed_array(VECTOR_PUB);
        let identity = vector_identity();
        let fields = base("event", 0, vector_frame_id(), VECTOR_SENT_AT_MS);
        let unsigned = Value::Map(fields)
            .with_field("realm", Value::Bytes(VECTOR_ZERO_REALM.to_vec()))
            .with_field("topic", Value::Bytes(b"test.topic".to_vec()))
            .with_field("publisher", Value::Bytes(pub_bytes.to_vec()))
            .with_field("seq", Value::Int(42))
            .with_field("payload", Value::text("published-data"))
            .with_field("delivered_via", Value::text("direct"));
        let signed = sign(unsigned, &identity);
        let sig = match signed.get("signature") {
            Some(Value::Bytes(b)) => b.clone(),
            other => panic!("expected a signature field, got {other:?}"),
        };
        assert_eq!(
            hex::encode_upper(&sig),
            "9B9EE4EAC375FBD0C9B5A5BC6D82E35739F8ECBF594979891BF35E5BDB53A148B3936AF99217C3D8C12E2EEA0686F68D5FE63284BE6B142F87BFF319DDDB780F"
        );
        assert_eq!(encode(&signed).expect("encodable").len(), 341);

        // Round-trip through parse_event too, since EVENT (unlike the
        // others above) has a real parser a receiving client uses.
        let decoded = decode(&encode(&signed).unwrap()).unwrap();
        let Decoded::Frame(value, _) = decoded else {
            panic!("expected a complete frame")
        };
        let info = parse_event(&value).expect("well-formed event");
        assert_eq!(info.topic, "test.topic");
        assert_eq!(info.seq, 42);
        assert_eq!(info.delivered_via, "direct");
    }

    #[test]
    fn parse_call_response_reads_a_result() {
        let frame = Value::Map(vec![
            (Value::text("frame_type"), Value::text("result")),
            (Value::text("call_id"), Value::Bytes(vec![1; 16])),
            (Value::text("payload"), Value::text("ok")),
            (Value::text("responded_by"), Value::Bytes(vec![2; 32])),
        ]);
        match parse_call_response(&frame).expect("well-formed result") {
            CallResponse::Result {
                payload,
                responded_by,
            } => {
                assert_eq!(payload, Value::text("ok"));
                assert_eq!(responded_by, [2u8; 32]);
            }
            other => panic!("expected Result, got {other:?}"),
        }
    }

    #[test]
    fn parse_call_response_reads_an_error() {
        let frame = Value::Map(vec![
            (Value::text("frame_type"), Value::text("error")),
            (Value::text("call_id"), Value::Bytes(vec![1; 16])),
            (Value::text("code"), Value::Int(1)),
            (Value::text("name"), Value::text("unknown_next_peer")),
            (Value::text("reported_by"), Value::Bytes(vec![2; 32])),
            (Value::text("detail"), Value::Null),
        ]);
        match parse_call_response(&frame).expect("well-formed error") {
            CallResponse::Error {
                code,
                name,
                reported_by,
                detail,
            } => {
                assert_eq!(code, 1);
                assert_eq!(name, "unknown_next_peer");
                assert_eq!(reported_by, [2u8; 32]);
                assert_eq!(detail, None);
            }
            other => panic!("expected Error, got {other:?}"),
        }
    }

    #[test]
    fn frame_call_id_reads_from_any_frame_type() {
        let frame = Value::Map(vec![(Value::text("call_id"), Value::Bytes(vec![9; 16]))]);
        assert_eq!(frame_call_id(&frame), Some([9u8; 16]));
        // A 32-byte value (e.g. a pubkey accidentally in this field) must
        // NOT be accepted as a 16-byte call_id.
        let wrong_size = Value::Map(vec![(Value::text("call_id"), Value::Bytes(vec![9; 32]))]);
        assert_eq!(frame_call_id(&wrong_size), None);
    }

    // -------------------------------------------------------------
    // Streaming RPC (§13) — same differential method as CALL above,
    // vectors captured from a real `macula_frame:stream_open/1` +
    // `stream_data/1` + `stream_end/1` + `stream_error/1` +
    // `stream_reply/1` + `sign/2` in a live `rebar3 shell` session
    // against the same identity/frame_id/sent_at_ms fixtures already
    // defined above.
    // -------------------------------------------------------------

    const VECTOR_STREAM_ID: &str = "0102030405060708090A0B0C0D0E0F10";

    fn vector_stream_id() -> [u8; 16] {
        hex_bytes(VECTOR_STREAM_ID).try_into().expect("16 bytes")
    }

    #[test]
    fn stream_open_frame_matches_the_reference_byte_for_byte() {
        let pub_bytes = fixed_array(VECTOR_PUB);
        let identity = vector_identity();
        let spec = StreamOpenSpec::new(
            vector_stream_id(),
            "macula_rust_sdk.test_stream",
            VECTOR_ZERO_REALM,
            StreamMode::ClientStream,
            Value::Map(vec![(Value::text("hello"), Value::text("world"))]),
            1_700_000_030_000,
            pub_bytes,
        );
        let signed = sign(
            stream_open_value(&spec, vector_frame_id(), VECTOR_SENT_AT_MS),
            &identity,
        );
        let sig = match signed.get("signature") {
            Some(Value::Bytes(b)) => b.clone(),
            other => panic!("expected a signature field, got {other:?}"),
        };
        assert_eq!(hex::encode_upper(&sig), "6070D8AB71F837591AC2C803C04F9E1D3FA01C9310D33C96A90434820C5E50550F9DEA8A764247EB49AF63447C037E192B7892A365C1A4ACB9BC46B98AA5670F");
        let encoded = encode(&signed).expect("encodable frame");
        assert_eq!(encoded.len(), 415);
    }

    #[test]
    fn stream_data_raw_frame_matches_the_reference_byte_for_byte() {
        let identity = vector_identity();
        let spec = StreamDataSpec::new(
            vector_stream_id(),
            0,
            StreamEncoding::Raw,
            Value::Bytes(b"raw chunk bytes".to_vec()),
        );
        let signed = sign(
            stream_data_value(&spec, vector_frame_id(), VECTOR_SENT_AT_MS),
            &identity,
        );
        let sig = match signed.get("signature") {
            Some(Value::Bytes(b)) => b.clone(),
            other => panic!("expected a signature field, got {other:?}"),
        };
        assert_eq!(hex::encode_upper(&sig), "35770744FE5BD01B86DDA01AB4EF855E4E4FE0EDFEDC89FF690728C585C60A5CB035717E3EA9133C4AD833E226F4DB95E9A5AF9AC59E7BACBB8BDF72611F8003");
        let encoded = encode(&signed).expect("encodable frame");
        assert_eq!(encoded.len(), 269);
    }

    /// The real point of this vector: `encoding = msgpack` with a
    /// structured `body` (`{a: 1, greeting: "hi"}`, mirroring the
    /// reference's `#{a => 1, greeting => <<"hi">>}`) still matches the
    /// reference's signature byte-for-byte — proving `body` is encoded
    /// as an ordinary nested CBOR value in the frame's own envelope, not
    /// pre-serialized through a separate msgpack codec this crate would
    /// otherwise need to implement. See this section's module doc.
    #[test]
    fn stream_data_msgpack_frame_matches_the_reference_byte_for_byte() {
        let identity = vector_identity();
        let spec = StreamDataSpec::new(
            vector_stream_id(),
            1,
            StreamEncoding::Msgpack,
            Value::Map(vec![
                (Value::text("a"), Value::Int(1)),
                // `greeting`'s VALUE is a binary (`<<"hi">>`) in the
                // reference, not an atom -- bytes, not text, unlike its
                // (atom) key.
                (Value::text("greeting"), Value::Bytes(b"hi".to_vec())),
            ]),
        );
        let signed = sign(
            stream_data_value(&spec, vector_frame_id(), VECTOR_SENT_AT_MS),
            &identity,
        );
        let sig = match signed.get("signature") {
            Some(Value::Bytes(b)) => b.clone(),
            other => panic!("expected a signature field, got {other:?}"),
        };
        assert_eq!(hex::encode_upper(&sig), "99CA90B0C01FD349DBAF317D03872E5F460426789874D79B6FBE37F4AC92C2AD690A00CDB3734F262D5C58C8F3BFD06F8AE892A8B5655274718A283ABA1D4D08");
        let encoded = encode(&signed).expect("encodable frame");
        assert_eq!(encoded.len(), 273);
    }

    #[test]
    fn stream_end_frame_matches_the_reference_byte_for_byte() {
        let identity = vector_identity();
        let spec = StreamEndSpec::new(vector_stream_id(), StreamRole::Send);
        let signed = sign(
            stream_end_value(&spec, vector_frame_id(), VECTOR_SENT_AT_MS),
            &identity,
        );
        let sig = match signed.get("signature") {
            Some(Value::Bytes(b)) => b.clone(),
            other => panic!("expected a signature field, got {other:?}"),
        };
        assert_eq!(hex::encode_upper(&sig), "78F2B94BD5AC70901EABB31D8B17C89B58A88942300C6232545899AFB933B2C4B7399BB183A5660671981B6346DA27033C8F93A99E7EBA96F0F689B03D4F940A");
        let encoded = encode(&signed).expect("encodable frame");
        assert_eq!(encoded.len(), 239);
    }

    #[test]
    fn stream_error_frame_matches_the_reference_byte_for_byte() {
        let identity = vector_identity();
        let spec = StreamErrorSpec::new(vector_stream_id(), "cancelled", "boom");
        let signed = sign(
            stream_error_value(&spec, vector_frame_id(), VECTOR_SENT_AT_MS),
            &identity,
        );
        let sig = match signed.get("signature") {
            Some(Value::Bytes(b)) => b.clone(),
            other => panic!("expected a signature field, got {other:?}"),
        };
        assert_eq!(hex::encode_upper(&sig), "119F379518EC17C603ED5466A57D7AE53198A8AC4D5CA9849934A78994428CB3DAD40BC0EFECE1A0C8EEB0ACC28973C0F7E55DE6444827091814AF0715D9FF0B");
        let encoded = encode(&signed).expect("encodable frame");
        assert_eq!(encoded.len(), 259);
    }

    #[test]
    fn stream_reply_frame_matches_the_reference_byte_for_byte() {
        let pub_bytes = fixed_array(VECTOR_PUB);
        let identity = vector_identity();
        let spec = StreamReplySpec::new(
            vector_stream_id(),
            Value::Map(vec![(Value::text("ok"), Value::text("true"))]),
            pub_bytes,
        );
        let signed = sign(
            stream_reply_value(&spec, vector_frame_id(), VECTOR_SENT_AT_MS),
            &identity,
        );
        let sig = match signed.get("signature") {
            Some(Value::Bytes(b)) => b.clone(),
            other => panic!("expected a signature field, got {other:?}"),
        };
        assert_eq!(hex::encode_upper(&sig), "ADF57AD58B253F175ADF72E4717E078C62F3E22CBDDBF8DDC0DD8A47CAAA061E8A37C73BAAB91E450D1D8472021B6A0161169D77E9D186C436D3E6580D48C703");
        let encoded = encode(&signed).expect("encodable frame");
        assert_eq!(encoded.len(), 295);
    }

    #[test]
    fn frame_stream_id_reads_from_any_frame_type() {
        let frame = Value::Map(vec![(Value::text("stream_id"), Value::Bytes(vec![9; 16]))]);
        assert_eq!(frame_stream_id(&frame), Some([9u8; 16]));
        let wrong_size = Value::Map(vec![(Value::text("stream_id"), Value::Bytes(vec![9; 32]))]);
        assert_eq!(frame_stream_id(&wrong_size), None);
    }

    #[test]
    fn parse_stream_event_reads_data_end_error_and_reply() {
        let data = Value::Map(vec![
            (Value::text("frame_type"), Value::text("stream_data")),
            (Value::text("stream_id"), Value::Bytes(vec![1; 16])),
            (Value::text("seq"), Value::Int(3)),
            (Value::text("encoding"), Value::text("raw")),
            (Value::text("body"), Value::Bytes(b"hi".to_vec())),
        ]);
        match parse_stream_event(&data).expect("well-formed stream_data") {
            StreamEvent::Data {
                stream_id,
                seq,
                encoding,
                body,
            } => {
                assert_eq!(stream_id, [1u8; 16]);
                assert_eq!(seq, 3);
                assert_eq!(encoding, StreamEncoding::Raw);
                assert_eq!(body, Value::Bytes(b"hi".to_vec()));
            }
            other => panic!("expected Data, got {other:?}"),
        }

        let end = Value::Map(vec![
            (Value::text("frame_type"), Value::text("stream_end")),
            (Value::text("stream_id"), Value::Bytes(vec![1; 16])),
            (Value::text("role"), Value::text("both")),
        ]);
        match parse_stream_event(&end).expect("well-formed stream_end") {
            StreamEvent::End { stream_id, role } => {
                assert_eq!(stream_id, [1u8; 16]);
                assert_eq!(role, StreamRole::Both);
            }
            other => panic!("expected End, got {other:?}"),
        }

        let error = Value::Map(vec![
            (Value::text("frame_type"), Value::text("stream_error")),
            (Value::text("stream_id"), Value::Bytes(vec![1; 16])),
            (Value::text("code"), Value::Bytes(b"cancelled".to_vec())),
            (Value::text("message"), Value::Bytes(b"boom".to_vec())),
        ]);
        match parse_stream_event(&error).expect("well-formed stream_error") {
            StreamEvent::Error {
                stream_id,
                code,
                message,
            } => {
                assert_eq!(stream_id, [1u8; 16]);
                assert_eq!(code, "cancelled");
                assert_eq!(message, "boom");
            }
            other => panic!("expected Error, got {other:?}"),
        }

        let reply = Value::Map(vec![
            (Value::text("frame_type"), Value::text("stream_reply")),
            (Value::text("stream_id"), Value::Bytes(vec![1; 16])),
            (Value::text("payload"), Value::text("done")),
            (Value::text("responded_by"), Value::Bytes(vec![2; 32])),
        ]);
        match parse_stream_event(&reply).expect("well-formed stream_reply") {
            StreamEvent::Reply {
                stream_id,
                payload,
                responded_by,
            } => {
                assert_eq!(stream_id, [1u8; 16]);
                assert_eq!(payload, Value::text("done"));
                assert_eq!(responded_by, [2u8; 32]);
            }
            other => panic!("expected Reply, got {other:?}"),
        }
    }

    #[test]
    fn parse_stream_event_rejects_a_non_stream_frame() {
        let frame = Value::Map(vec![
            (Value::text("frame_type"), Value::text("call")),
            (Value::text("stream_id"), Value::Bytes(vec![1; 16])),
        ]);
        assert_eq!(
            parse_stream_event(&frame).unwrap_err(),
            ParseStreamEventError::NotAStreamFrame
        );
    }

    // -------------------------------------------------------------
    // RPC advertise (§6.9) — same differential method, vectors
    // captured from a real `macula_frame:advertise/1` +
    // `unadvertise/1` + `sign/2` in a live `rebar3 shell`.
    // -------------------------------------------------------------

    #[test]
    fn advertise_frame_matches_the_reference_byte_for_byte() {
        let pub_bytes = fixed_array(VECTOR_PUB);
        let identity = vector_identity();
        let spec = AdvertiseSpec::new(
            VECTOR_ZERO_REALM,
            "macula_rust_sdk.test_procedure",
            pub_bytes,
        );
        let signed = sign(
            advertise_value(&spec, vector_frame_id(), VECTOR_SENT_AT_MS),
            &identity,
        );
        let sig = match signed.get("signature") {
            Some(Value::Bytes(b)) => b.clone(),
            other => panic!("expected a signature field, got {other:?}"),
        };
        assert_eq!(hex::encode_upper(&sig), "22AE051A542289279A56FB9C8587341232EF48208F9A8641C77F37E1B5D3D26A4B7C30CDCA4AE6E851FEB4E2FBF9C5B2469AFCC7317D59F5D775A05C99E99C0A");
        let encoded = encode(&signed).expect("encodable frame");
        assert_eq!(encoded.len(), 330);
    }

    #[test]
    fn unadvertise_frame_matches_the_reference_byte_for_byte() {
        let pub_bytes = fixed_array(VECTOR_PUB);
        let identity = vector_identity();
        let spec = UnadvertiseSpec::new(
            VECTOR_ZERO_REALM,
            "macula_rust_sdk.test_procedure",
            pub_bytes,
        );
        let signed = sign(
            unadvertise_value(&spec, vector_frame_id(), VECTOR_SENT_AT_MS),
            &identity,
        );
        let sig = match signed.get("signature") {
            Some(Value::Bytes(b)) => b.clone(),
            other => panic!("expected a signature field, got {other:?}"),
        };
        assert_eq!(hex::encode_upper(&sig), "C4111E5C2685DCDDB035B9DA29AD2A30D90BC7CAC09620A675D9A3DB480508FDAD7DCDD145B77607395DBF6195643BBA60C2C6D29E2DCFE5F70F20CF15DA2600");
        let encoded = encode(&signed).expect("encodable frame");
        assert_eq!(encoded.len(), 323);
    }
}
