//! Rust port of macula's SDK (client/leaf) protocol — see
//! `plans/PLAN_WIRE_PROTOCOL.md` for the full wire-format spec this crate
//! is built against, traced directly to `macula-io/macula` source.
//!
//! Mobile (iOS/Android via UniFFI) is the flagship consumer driving this
//! work, not the ceiling on it — nothing below the eventual FFI binding
//! layer is mobile-specific.

pub mod cbor;
pub mod identity;
