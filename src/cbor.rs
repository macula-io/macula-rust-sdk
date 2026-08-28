//! Deterministic CBOR encode/decode, byte-for-byte compatible with
//! macula's own wire codec.
//!
//! This is NOT generic CBOR (no ciborium involved on either side) — it is
//! a direct Rust transcription of the hand-rolled canonical encoder macula
//! actually ships in `native/macula_cbor_nif/src/deterministic.rs`
//! (`macula-io/macula`), which `macula_frame.erl`'s wire codec calls as
//! `pack_deterministic/1` / `unpack_deterministic/1`. Every frame's
//! Ed25519 signature is computed over these exact bytes, so a divergence
//! here silently breaks signature verification against real stations —
//! this module's tests include fixtures captured directly from the real
//! NIF (`rebar3 shell` against `macula-io/macula` at v10.10.0), not just
//! hand-derived expectations.
//!
//! Encoding rules (all verified against the reference, see `tests` below):
//! - Integers: minimal-length encoding (inline for 0..=23, else the
//!   smallest of 1/2/4/8 extra bytes that fits). Non-negative → major 0.
//!   Negative → major 1, encoded value is `-1 - n`. Range:
//!   `-(2^64)..=u64::MAX` — anything outside that is a hard encode error,
//!   not silent truncation.
//! - Byte strings → major 2, raw bytes.
//! - Text → major 3. Used both for real text payloads and for macula's
//!   fixed field-name/enum-value vocabulary (what the Erlang side encodes
//!   as atoms) — there is no separate "atom" wire type.
//! - Lists → major 4.
//! - Maps → major 5, with keys sorted by the **bytewise order of their
//!   own already-encoded bytes** — encode each key independently, then
//!   sort the resulting `(key_bytes, value_bytes)` pairs by `key_bytes`
//!   using plain `Ord`. This is the single rule most likely to be gotten
//!   wrong: sorting by the *original* value instead of its *encoded*
//!   bytes silently diverges from station output for keys of different
//!   CBOR major types or different lengths.
//! - `Value::Null` → major 7, additional info 22 (`0xF6`).
//! - Floats → **always** binary64 (major 7, AI 27, `0xFB` prefix),
//!   regardless of whether the value would round-trip in fewer bits. This
//!   is a deliberate divergence from RFC 8949's own canonical-form
//!   recommendation (which prefers the shortest float width that
//!   round-trips) — macula's own comment says it's done so the byte
//!   derivation is independent of platform float encoding. A generic
//!   "canonical CBOR" crate that follows the RFC's shortest-float rule
//!   would silently produce non-matching, non-verifying bytes here.
//!
//! Decode is deliberately narrow to match the reference: major type 6
//! (tags) is rejected outright, and major 7 only supports `null` and the
//! three float widths (binary16/32/64, all promoted to `f64`) — no
//! booleans, no "undefined" simple value. Every read is bounds-checked;
//! nothing in this module panics on malformed or truncated input, since
//! decode exists specifically to parse untrusted, network-received bytes.

use std::fmt;

/// A deterministic-CBOR value, restricted to exactly the shapes macula's
/// wire format supports. There is no generic "any CBOR" here on purpose.
#[derive(Debug, Clone, PartialEq)]
pub enum Value {
    /// Signed, but the encodable range is asymmetric: `-(2^64)..=u64::MAX`,
    /// matching the reference codec's own u64/i128 split.
    Int(i128),
    Bytes(Vec<u8>),
    /// Also what an Erlang atom (frame-type names, field names, enum
    /// values) becomes on the wire — see the module doc.
    Text(String),
    List(Vec<Value>),
    /// Insertion order on construction; canonical key sort happens at
    /// encode time, not here. Decode preserves last-write-wins on
    /// duplicate keys, matching the reference decoder exactly.
    Map(Vec<(Value, Value)>),
    Null,
    /// Always round-trips through binary64 — see the module doc's note
    /// on why this diverges from RFC 8949's canonical-form guidance.
    Float(f64),
}

impl Value {
    /// Convenience: build a `Text` value from anything `Into<String>`.
    pub fn text(s: impl Into<String>) -> Self {
        Value::Text(s.into())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IntOutOfRange(pub i128);

impl fmt::Display for IntOutOfRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "integer {} is outside the encodable range -(2^64)..=u64::MAX",
            self.0
        )
    }
}

impl std::error::Error for IntOutOfRange {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DecodeError {
    /// The buffer ended before a complete value could be read.
    Truncated,
    /// Major type 6 (tags) — not part of macula's wire format.
    UnsupportedMajorType(u8),
    /// A major-7 additional-info value with no meaning here (only 22
    /// \[null\] and 25/26/27 \[floats\] are supported).
    UnsupportedAdditionalInfo(u8),
    /// Additional-info 28-31 on any major type — reserved, unused.
    UnsupportedAdditionalInfoEncoding(u8),
    /// A single top-level value didn't consume the whole buffer.
    TrailingBytes,
    /// A major-3 (text) value's bytes were not valid UTF-8. The reference
    /// Erlang/Rust codec does not validate this on decode (it stores
    /// whatever bytes arrived); this port deliberately diverges and
    /// treats it as an error instead of losslessly carrying invalid
    /// UTF-8, since every real macula text value is ASCII/UTF-8 by
    /// construction and failing closed on malformed input from a peer is
    /// the safer default. Documented, not accidental.
    InvalidUtf8,
    /// A half-float (binary16) with exponent 31 — NaN or infinity, which
    /// has no representation as an ordinary `f64` value here (matches
    /// the reference decoder's own behavior: no clause for it).
    UnrepresentableFloat,
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DecodeError::Truncated => write!(f, "truncated input"),
            DecodeError::UnsupportedMajorType(m) => {
                write!(
                    f,
                    "unsupported major type {m} (only 0-5 and 7 are valid here)"
                )
            }
            DecodeError::UnsupportedAdditionalInfo(ai) => {
                write!(f, "unsupported major-7 additional info {ai}")
            }
            DecodeError::UnsupportedAdditionalInfoEncoding(ai) => {
                write!(
                    f,
                    "unsupported additional-info encoding {ai} (28-31 are reserved)"
                )
            }
            DecodeError::TrailingBytes => write!(f, "trailing bytes after the top-level value"),
            DecodeError::InvalidUtf8 => write!(f, "text value was not valid UTF-8"),
            DecodeError::UnrepresentableFloat => {
                write!(f, "half-float NaN/infinity has no f64 representation here")
            }
        }
    }
}

impl std::error::Error for DecodeError {}

/// Encode `value` as deterministic CBOR. See the module doc for the exact
/// rules; every one of them is verified against the real reference in
/// this module's tests.
pub fn encode(value: &Value) -> Result<Vec<u8>, IntOutOfRange> {
    let mut out = Vec::with_capacity(64);
    encode_value(value, &mut out)?;
    Ok(out)
}

fn encode_value(value: &Value, out: &mut Vec<u8>) -> Result<(), IntOutOfRange> {
    match value {
        Value::Int(n) => encode_int(*n, out),
        Value::Bytes(b) => {
            encode_head(2, b.len() as u64, out);
            out.extend_from_slice(b);
            Ok(())
        }
        Value::Text(s) => {
            let bytes = s.as_bytes();
            encode_head(3, bytes.len() as u64, out);
            out.extend_from_slice(bytes);
            Ok(())
        }
        Value::List(items) => {
            encode_head(4, items.len() as u64, out);
            for item in items {
                encode_value(item, out)?;
            }
            Ok(())
        }
        Value::Map(pairs) => encode_map(pairs, out),
        Value::Null => {
            out.push(0xF6); // major 7, additional info 22
            Ok(())
        }
        Value::Float(v) => {
            out.push(0xFB); // major 7, additional info 27 (binary64)
            out.extend_from_slice(&v.to_be_bytes());
            Ok(())
        }
    }
}

fn encode_int(n: i128, out: &mut Vec<u8>) -> Result<(), IntOutOfRange> {
    if n >= 0 {
        if n <= u64::MAX as i128 {
            encode_head(0, n as u64, out);
            Ok(())
        } else {
            Err(IntOutOfRange(n))
        }
    } else {
        // n in -(2^64)..=-1 => count in 0..=2^64-1
        let count = -1i128 - n;
        if (0..=u64::MAX as i128).contains(&count) {
            encode_head(1, count as u64, out);
            Ok(())
        } else {
            Err(IntOutOfRange(n))
        }
    }
}

/// Encode each key/value independently, then sort the resulting pairs by
/// the key's OWN ENCODED BYTES (plain lexicographic `Ord` on `Vec<u8>`,
/// which already implements "shorter is smaller when a prefix" — no
/// special-casing needed). This is the one rule a naive implementation is
/// most likely to get wrong; see the module doc.
fn encode_map(pairs: &[(Value, Value)], out: &mut Vec<u8>) -> Result<(), IntOutOfRange> {
    let mut encoded: Vec<(Vec<u8>, Vec<u8>)> = Vec::with_capacity(pairs.len());
    for (k, v) in pairs {
        let mut kbuf = Vec::with_capacity(16);
        encode_value(k, &mut kbuf)?;
        let mut vbuf = Vec::with_capacity(16);
        encode_value(v, &mut vbuf)?;
        encoded.push((kbuf, vbuf));
    }
    encoded.sort_by(|a, b| a.0.cmp(&b.0));
    encode_head(5, encoded.len() as u64, out);
    for (k, v) in &encoded {
        out.extend_from_slice(k);
        out.extend_from_slice(v);
    }
    Ok(())
}

fn encode_head(major: u8, n: u64, out: &mut Vec<u8>) {
    if n <= 23 {
        out.push((major << 5) | (n as u8));
    } else if n <= 0xFF {
        out.push((major << 5) | 24);
        out.push(n as u8);
    } else if n <= 0xFFFF {
        out.push((major << 5) | 25);
        out.extend_from_slice(&(n as u16).to_be_bytes());
    } else if n <= 0xFFFF_FFFF {
        out.push((major << 5) | 26);
        out.extend_from_slice(&(n as u32).to_be_bytes());
    } else {
        out.push((major << 5) | 27);
        out.extend_from_slice(&n.to_be_bytes());
    }
}

/// Decode a single deterministic-CBOR value from `bytes`. The whole
/// buffer must be consumed by exactly one top-level value — trailing
/// bytes are an error, matching the reference decoder's own contract.
pub fn decode(bytes: &[u8]) -> Result<Value, DecodeError> {
    let (value, pos) = decode_one(bytes, 0)?;
    if pos != bytes.len() {
        return Err(DecodeError::TrailingBytes);
    }
    Ok(value)
}

fn need(buf: &[u8], pos: usize, n: usize) -> Result<(), DecodeError> {
    match pos.checked_add(n) {
        Some(end) if end <= buf.len() => Ok(()),
        _ => Err(DecodeError::Truncated),
    }
}

fn decode_one(buf: &[u8], pos: usize) -> Result<(Value, usize), DecodeError> {
    need(buf, pos, 1)?;
    let byte0 = buf[pos];
    let major = byte0 >> 5;
    let ai = byte0 & 0x1F;

    if major == 7 {
        return decode_major7(buf, pos, ai);
    }

    let (n, next) = decode_count(buf, pos + 1, ai)?;
    match major {
        0 => Ok((Value::Int(n as i128), next)),
        1 => Ok((Value::Int(-1i128 - n as i128), next)),
        2 => {
            let len = n as usize;
            need(buf, next, len)?;
            Ok((Value::Bytes(buf[next..next + len].to_vec()), next + len))
        }
        3 => {
            let len = n as usize;
            need(buf, next, len)?;
            let text = String::from_utf8(buf[next..next + len].to_vec())
                .map_err(|_| DecodeError::InvalidUtf8)?;
            Ok((Value::Text(text), next + len))
        }
        4 => decode_list(buf, next, n),
        5 => decode_map(buf, next, n),
        _ => Err(DecodeError::UnsupportedMajorType(major)),
    }
}

fn decode_count(buf: &[u8], pos: usize, ai: u8) -> Result<(u64, usize), DecodeError> {
    match ai {
        0..=23 => Ok((ai as u64, pos)),
        24 => {
            need(buf, pos, 1)?;
            Ok((buf[pos] as u64, pos + 1))
        }
        25 => {
            need(buf, pos, 2)?;
            Ok((u16::from_be_bytes([buf[pos], buf[pos + 1]]) as u64, pos + 2))
        }
        26 => {
            need(buf, pos, 4)?;
            let b: [u8; 4] = buf[pos..pos + 4].try_into().expect("checked len");
            Ok((u32::from_be_bytes(b) as u64, pos + 4))
        }
        27 => {
            need(buf, pos, 8)?;
            let b: [u8; 8] = buf[pos..pos + 8].try_into().expect("checked len");
            Ok((u64::from_be_bytes(b), pos + 8))
        }
        28..=31 => Err(DecodeError::UnsupportedAdditionalInfoEncoding(ai)),
        _ => unreachable!("additional info is a 5-bit field, 0..=31"),
    }
}

fn decode_major7(buf: &[u8], pos: usize, ai: u8) -> Result<(Value, usize), DecodeError> {
    match ai {
        22 => Ok((Value::Null, pos + 1)),
        25 => {
            need(buf, pos + 1, 2)?;
            let half = u16::from_be_bytes([buf[pos + 1], buf[pos + 2]]);
            Ok((Value::Float(half_to_f64(half)?), pos + 3))
        }
        26 => {
            need(buf, pos + 1, 4)?;
            let b: [u8; 4] = buf[pos + 1..pos + 5].try_into().expect("checked len");
            Ok((Value::Float(f32::from_be_bytes(b) as f64), pos + 5))
        }
        27 => {
            need(buf, pos + 1, 8)?;
            let b: [u8; 8] = buf[pos + 1..pos + 9].try_into().expect("checked len");
            Ok((Value::Float(f64::from_be_bytes(b)), pos + 9))
        }
        _ => Err(DecodeError::UnsupportedAdditionalInfo(ai)),
    }
}

fn decode_list(buf: &[u8], mut pos: usize, count: u64) -> Result<(Value, usize), DecodeError> {
    let mut items = Vec::with_capacity(count.min(1024) as usize);
    for _ in 0..count {
        let (item, next) = decode_one(buf, pos)?;
        items.push(item);
        pos = next;
    }
    Ok((Value::List(items), pos))
}

/// Duplicate keys overwrite (last write wins), matching the reference
/// decoder exactly — not treated as an error.
fn decode_map(buf: &[u8], mut pos: usize, count: u64) -> Result<(Value, usize), DecodeError> {
    let mut pairs: Vec<(Value, Value)> = Vec::with_capacity(count.min(1024) as usize);
    for _ in 0..count {
        let (k, next1) = decode_one(buf, pos)?;
        let (v, next2) = decode_one(buf, next1)?;
        pos = next2;
        match pairs.iter_mut().find(|(ek, _)| *ek == k) {
            Some(entry) => entry.1 = v,
            None => pairs.push((k, v)),
        }
    }
    Ok((Value::Map(pairs), pos))
}

/// IEEE 754 binary16 → f64. Subnormals (exp=0) and normals (1..=30) use
/// the standard formula; exp=31 (NaN/infinity) has no representation here
/// — matches the reference decoder, which has no clause for it either.
fn half_to_f64(half: u16) -> Result<f64, DecodeError> {
    let sign: f64 = if (half >> 15) & 1 == 1 { -1.0 } else { 1.0 };
    let exp = (half >> 10) & 0x1F;
    let frac = (half & 0x3FF) as f64;
    match exp {
        0 => Ok(sign * 2f64.powi(-14) * (frac / 1024.0)),
        1..=30 => Ok(sign * 2f64.powi(exp as i32 - 15) * (1.0 + frac / 1024.0)),
        _ => Err(DecodeError::UnrepresentableFloat),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a hex string into bytes — test-only helper, not exposed
    /// from the crate.
    fn hex(s: &str) -> Vec<u8> {
        ::hex::decode(s).expect("valid hex fixture")
    }

    /// Every fixture below was captured directly from the real
    /// `macula_cbor_nif:pack_deterministic/1` in `macula-io/macula`
    /// (v10.10.0) via `rebar3 shell`, not hand-derived — see this
    /// module's doc comment. If one of these ever fails, the Rust port
    /// has diverged from what a real station actually accepts, not the
    /// test itself.
    fn assert_matches_reference(value: Value, expected_hex: &str) {
        let bytes = encode(&value).expect("encodable fixture");
        assert_eq!(
            bytes,
            hex(expected_hex),
            "encoding of {value:?} did not match the real macula_cbor_nif output"
        );
        // Round-trip: decoding what we just encoded must reproduce an
        // equivalent value (structural equality, not necessarily the
        // exact same Map key order — decode doesn't re-sort).
        let decoded = decode(&bytes).expect("our own output must decode");
        let re_encoded = encode(&decoded).expect("decoded value must re-encode");
        assert_eq!(re_encoded, bytes, "encode(decode(bytes)) != bytes");
    }

    #[test]
    fn empty_map() {
        assert_matches_reference(Value::Map(vec![]), "A0");
    }

    #[test]
    fn integers_non_negative_minimal_length() {
        assert_matches_reference(Value::Int(0), "00");
        assert_matches_reference(Value::Int(23), "17");
        assert_matches_reference(Value::Int(24), "1818");
        assert_matches_reference(Value::Int(255), "18FF");
        assert_matches_reference(Value::Int(256), "190100");
        assert_matches_reference(Value::Int(65535), "19FFFF");
        assert_matches_reference(Value::Int(65536), "1A00010000");
    }

    #[test]
    fn integers_negative_minimal_length() {
        assert_matches_reference(Value::Int(-1), "20");
        assert_matches_reference(Value::Int(-24), "37");
        assert_matches_reference(Value::Int(-25), "3818");
        assert_matches_reference(Value::Int(-256), "38FF");
    }

    #[test]
    fn integer_out_of_range_is_rejected() {
        // One past the documented positive bound.
        assert_eq!(
            encode(&Value::Int(u64::MAX as i128 + 1)),
            Err(IntOutOfRange(u64::MAX as i128 + 1))
        );
        // One past the documented negative bound (-(2^64)).
        let floor = -(1i128 << 64);
        assert!(encode(&Value::Int(floor)).is_ok());
        assert!(encode(&Value::Int(floor - 1)).is_err());
    }

    #[test]
    fn byte_strings() {
        assert_matches_reference(Value::Bytes(vec![]), "40");
        assert_matches_reference(Value::Bytes(b"hello".to_vec()), "4568656C6C6F");
    }

    #[test]
    fn text_and_atom_equivalent_encoding() {
        // "hello" as text, and the Erlang atom `true` (which the
        // reference encodes identically to a text value of the same
        // name) — both are just major-3 text on this wire format.
        assert_matches_reference(Value::text("hello"), "6568656C6C6F");
        assert_matches_reference(Value::text("true"), "6474727565");
    }

    #[test]
    fn lists() {
        assert_matches_reference(Value::List(vec![]), "80");
        assert_matches_reference(
            Value::List(vec![Value::Int(1), Value::Int(2), Value::Int(3)]),
            "83010203",
        );
    }

    #[test]
    fn floats_always_binary64() {
        // Even exactly-representable, "shortenable" values still emit
        // the full 8-byte form — the deliberate divergence from RFC
        // 8949's canonical-form recommendation. This is the fixture most
        // likely to catch a generic "canonical CBOR" crate substituted
        // in by mistake.
        assert_matches_reference(Value::Float(0.0), "FB0000000000000000");
        assert_matches_reference(Value::Float(12345.6789), "FB40C81CD6E631F8A1");
    }

    #[test]
    fn map_keys_sorted_by_encoded_bytes_not_input_order() {
        // Input order is b, a — output must be a, b (bytewise key sort).
        assert_matches_reference(
            Value::Map(vec![
                (Value::text("b"), Value::Int(2)),
                (Value::text("a"), Value::Int(1)),
            ]),
            "A2616101616202",
        );
    }

    #[test]
    fn map_keys_sorted_lexicographically_same_length() {
        assert_matches_reference(
            Value::Map(vec![
                (Value::text("zebra"), Value::Int(1)),
                (Value::text("apple"), Value::Int(2)),
            ]),
            "A2656170706C6502657A6562726101",
        );
    }

    #[test]
    fn map_keys_shorter_sorts_first_when_prefix() {
        // "a" < "aa" < "aaa" — the rule most likely to be implemented
        // wrong if a naive implementation sorts by raw value instead of
        // encoded bytes.
        assert_matches_reference(
            Value::Map(vec![
                (Value::text("aa"), Value::Int(1)),
                (Value::text("a"), Value::Int(2)),
                (Value::text("aaa"), Value::Int(3)),
            ]),
            "A3616102626161016361616103",
        );
    }

    #[test]
    fn null_alone() {
        // The Erlang side special-cases exactly the atom named `null`
        // (0xF6) — a DIFFERENT atom like `undefined` is not recognized at
        // this layer and encodes as ordinary text instead (see
        // `text_and_atom_equivalent_encoding` and this module's doc: the
        // `undefined` -> `null` conversion happens one layer up, in
        // `macula_frame.erl`'s `to_wire/1`, not inside the codec itself).
        assert_matches_reference(Value::Null, "F6");
    }

    #[test]
    fn nested_structure_with_null() {
        assert_matches_reference(
            Value::Map(vec![
                (Value::text("name"), Value::text("macula")),
                (
                    Value::text("nums"),
                    Value::List(vec![Value::Int(1), Value::Int(2), Value::Int(3)]),
                ),
                (Value::text("nil"), Value::Null),
            ]),
            "A3636E696CF6646E616D65666D6163756C61646E756D7383010203",
        );
    }

    #[test]
    fn frame_shaped_map() {
        let node_id: Vec<u8> = (1u8..=32).collect();
        assert_matches_reference(
            Value::Map(vec![
                (Value::text("node_id"), Value::Bytes(node_id)),
                (Value::text("version"), Value::Int(2)),
                (Value::text("frame_type"), Value::text("connect")),
                (Value::text("capabilities"), Value::Int(0)),
            ]),
            "A4676E6F64655F696458200102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F206776657273696F6E026A6672616D655F7479706567636F6E6E6563746C6361706162696C697469657300",
        );
    }

    #[test]
    fn decode_rejects_tags() {
        // Major type 6, additional info 0 — a tag, not part of this wire
        // format.
        assert_eq!(decode(&[0xC0]), Err(DecodeError::UnsupportedMajorType(6)));
    }

    #[test]
    fn decode_rejects_trailing_bytes() {
        // A valid `0` (0x00) followed by a stray byte.
        assert_eq!(decode(&[0x00, 0xFF]), Err(DecodeError::TrailingBytes));
    }

    #[test]
    fn decode_rejects_truncated_input() {
        // Major 0, AI 24 (one more byte expected) but the buffer ends.
        assert_eq!(decode(&[0x18]), Err(DecodeError::Truncated));
    }

    #[test]
    fn decode_duplicate_map_keys_last_write_wins() {
        // Two entries both keyed "a" (0x61 0x61), values 1 then 2.
        let bytes = hex("A2616101616102");
        let decoded = decode(&bytes).expect("valid map");
        match decoded {
            Value::Map(pairs) => {
                assert_eq!(pairs.len(), 1);
                assert_eq!(pairs[0], (Value::text("a"), Value::Int(2)));
            }
            other => panic!("expected a map, got {other:?}"),
        }
    }
}
