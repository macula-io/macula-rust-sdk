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
    fields.push((Value::text("reason"), Value::text(reason)));
    fields.push((
        Value::text("detail"),
        detail.map(Value::text).unwrap_or(Value::Null),
    ));
    Value::Map(fields)
}

/// Build a GOODBYE frame. `reason` is a short machine-readable code
/// (e.g. `"normal"`); `detail` is an optional human-readable string.
pub fn goodbye(reason: &str, detail: Option<&str>) -> Value {
    goodbye_value(reason, detail, fresh_frame_id(), current_millis())
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
        assert_eq!(frame.get("detail"), Some(&Value::text("bye")));
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
}
