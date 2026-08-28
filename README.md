# macula-rust-sdk

[![CI](https://img.shields.io/github/actions/workflow/status/macula-io/macula-rust-sdk/ci.yml?branch=master&label=CI)](https://github.com/macula-io/macula-rust-sdk/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0%20OR%20MIT-blue.svg)](#license)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange?logo=rust)](https://www.rust-lang.org)
[![unsafe forbidden](https://img.shields.io/badge/unsafe-forbidden-success.svg)](https://github.com/rust-secure-code/safety-dance/)
[![Buy Me A Coffee](https://img.shields.io/badge/Buy%20Me%20A%20Coffee-support-yellow.svg)](https://buymeacoffee.com/rlefever)

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/macula-rust-full-dark.svg">
    <img src="assets/macula-rust-full-light.svg" alt="Macula" width="320">
  </picture>
</p>

<p align="center">
  <strong>Rust port of the Macula SDK wire protocol — mobile first, not mobile-only</strong>
</p>

---

> **Status, 2026-08-28:** the client/leaf side of the wire protocol is
> built and **live-verified against the production station fleet**
> (`station-de-frankfurt.macula.io`) — handshake, unary RPC, PubSub,
> content transfer, and streaming RPC, every primitive in both caller
> and provider roles. Mobile bindings (Kotlin + Swift, via UniFFI) wrap
> the entire surface, generated and CI-checked on every push. See
> [Status](#status) for what's not there yet.

## What is this?

A ground-up Rust implementation of the client half of Macula's wire
protocol — the same protocol [`macula-io/macula`](https://github.com/macula-io/macula)
(the Erlang/OTP SDK) speaks, extracted directly from that source and
tracked in [`plans/PLAN_WIRE_PROTOCOL.md`](plans/PLAN_WIRE_PROTOCOL.md).
Macula is a federated mesh for sovereign, end-to-end-encrypted
application networks; a **station** is the relay/DHT node, and this crate
is what a **leaf** — a phone, a desktop app, a CLI, anything that isn't
itself a station — uses to join it.

Mobile is the flagship consumer driving the work (hence the UniFFI
crate), not a ceiling on it: the core crate has zero UniFFI dependency
and zero FFI-shaped types, so it's exactly as usable from plain Rust, a
CLI, or WASM as any other Rust SDK.

## Features

| Primitive | Caller | Provider | Notes |
|---|---|---|---|
| Handshake (CONNECT/HELLO) | ✅ | — | Ed25519 identity, S/Kademlia puzzle-hardened |
| Unary RPC (CALL/RESULT/ERROR) | ✅ | ✅ | `Session::serve_one_call`, BOLT#4 error mapping live-verified |
| PubSub (PUBLISH/SUBSCRIBE/EVENT) | ✅ | ✅ | A subscriber gets its own publish, verified live |
| Content transfer (single-block + chunked) | ✅ | ✅ | Content-addressed, BLAKE3/SHA-256 |
| Streaming RPC (STREAM_OPEN/DATA/END/REPLY) | ✅ | ✅ | Both roles live-verified against the real fleet |
| RPC advertise/unadvertise | ✅ | — | |
| Mobile bindings (Kotlin, Swift) | ✅ | ✅ | Via [UniFFI](#mobile-bindings-uniffi) — provider role serves via `FfiCallHandler`, a foreign-implemented async trait (`suspend fun`/`async throws`), not a closure |
| Pubkey-pinned trust | 🏗️ | — | `Trust::Pinned` exists in the core crate, not yet surfaced through FFI |

`unsafe_code = "forbid"` at the crate level — the only unsafe in this
workspace lives inside its pinned dependencies (`quinn`, `ring`), not
here.

## Quick start

Also lives as a runnable example — `cargo run --example quickstart`:

```rust
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use macula_rust_sdk::{cbor::Value, connection, identity::KeyPair, transport::Trust};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Puzzle-hardened identity — required. An unhardened identity fails
    // the handshake silently (QUIC/TLS looks healthy, HELLO never accepts).
    let identity = KeyPair::generate_with_default_puzzle();

    let mut session = connection::connect(
        "station-de-frankfurt.macula.io",
        4433,
        Trust::WebPki,
        &identity,
    )
    .await?;

    let now_ms = SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis() as i128;
    let response = session
        .call(
            "io.macula.echo",
            [0u8; 32], // realm id
            Value::Text("hello".into()),
            now_ms + 5_000, // deadline_ms
            &identity,
            Duration::from_secs(5),
        )
        .await?;

    println!("{response:?}");
    Ok(())
}
```

## Mobile bindings (UniFFI)

`macula-rust-sdk-ffi` is a separate crate — not code bolted onto the
core one — wrapping every application primitive (`FfiSession::connect`/
`call`/`serve_one_call`/`publish`/`subscribe`/`content_put`/
`content_get`/`stream_open`/`advertise`/`accept_stream`) for Kotlin and
Swift, in the modern proc-macro UniFFI style (`#[uniffi::export]`,
native `async`/`await` and Kotlin coroutines, no `.udl` file). CI
rebuilds the `cdylib` and regenerates both language bindings on every
push as a codegen smoke test.

Serving an RPC from Kotlin or Swift means implementing `FfiCallHandler`
— a **foreign trait** (`#[uniffi::export(foreign)]`), not a callback
closure (UniFFI foreign traits can't carry a plain closure, so
`handle` receives the full inbound call and does its own procedure
routing if a session serves more than one):

```kotlin
class Doubler : FfiCallHandler {
    override suspend fun handle(procedure: String, realm: ByteArray, payload: FfiValue): FfiValue {
        val n = (payload as FfiValue.Int).v1
        return FfiValue.Int(n * 2)
    }
}

session.advertise("math.double", realm, identity)
session.serveOneCall(Doubler(), timeoutMs = 30_000u, identity)
```

(`FfiValue` currently covers `Null`/`Int`/`Bytes`/`Text`/`Float` — see
this crate's own module doc for why `List`/`Map` aren't there yet; a
handler needing a structured payload should encode it as `Bytes`
today.)

```bash
cargo build -p macula-rust-sdk-ffi --release
cargo run -p macula-rust-sdk-ffi --release --bin uniffi-bindgen -- generate \
    --library target/release/libmacula_rust_sdk_ffi.so \
    --language kotlin --out-dir bindings-kotlin
```

## Testing

```bash
cargo test --workspace --all-features
```

100+ tests across the workspace, plus a separate live-verification suite
(`tests/live_station.rs`) that dials the real production fleet —
`#[ignore]`d by default since it depends on infrastructure this crate
doesn't control:

```bash
cargo test --test live_station -- --ignored --nocapture
```

## Status

**Live-verified, 2026-08-28 — full parity, both directions:** handshake,
CALL/RESULT/ERROR as both caller (`Session::call`) and provider
(`Session::serve_one_call`, BOLT#4 error mapping — `unknown_next_peer`
on a lookup miss, `temporary_relay_failure` on a handler panic (caught
via `tokio::spawn`, one task per call, the same shape
`macula_station_link.erl`'s one-process-per-call already uses),
`unknown_error` with detail on a handler-returned error, all ported
field-for-field from that module's `handle_inbound_call/2`), PUBLISH/
SUBSCRIBE/EVENT (a subscriber does receive its own publish), content
transfer, and streaming RPC in both the caller and provider roles — all
against `station-de-frankfurt.macula.io`, the real fleet, not a local
mock. Two independent connections to the same station (one advertising
and serving, the other calling in) is the pattern behind every
provider-role test — see `tests/live_station.rs`'s
`unary_call_provider_round_trip_against_the_real_fleet` for the unary
case. Three real protocol bugs were caught by differential-vector tests
before ever touching production.

Unary-RPC provider dispatch was the one gap left after the streaming
and content-transfer provider roles landed — a service built on this
crate could call RPCs and serve streams, but couldn't serve a
request/response procedure at all. It's now built here and in
[`macula-go-sdk`](https://github.com/macula-io/macula-go-sdk) in the
same pass, so both SDKs serve RPCs, not just call them, and wrapped in
the FFI layer the same day: [`FfiCallHandler`](#mobile-bindings-uniffi)
is a **foreign trait** (`#[uniffi::export(foreign)]`), not a callback
closure — UniFFI doesn't support passing a bare closure across the
boundary, so `handle` receives the full inbound call and a Kotlin/Swift
implementation does its own procedure routing if a session serves more
than one. Verified past "it compiles": rebuilt the release `cdylib`,
regenerated both Kotlin and Swift, and inspected the actual generated
code — `FfiCallHandler.handle` renders as `suspend fun ... : FfiValue`
in Kotlin and `func handle(...) async throws -> FfiValue` in Swift,
`FfiSession.serveOneCall`/`serveOneCall` takes it as a parameter in
both, not just as an exit-code smoke test.

**Not yet built:**
- Pubkey-pinned trust surfaced through the FFI layer (`Trust::Pinned`
  exists in the core crate)

See [`plans/PLAN_WIRE_PROTOCOL.md`](plans/PLAN_WIRE_PROTOCOL.md) for the
full wire-format spec this crate is built against, section by section,
traced directly to the Erlang SDK's source.

## Related projects

| Project | Description |
|---|---|
| [macula](https://github.com/macula-io/macula) | The reference SDK (Erlang/OTP) — the protocol this crate ports |
| [macula-station](https://github.com/macula-io/macula-station) | The station: DHT, SWIM, routing, peering |
| [macula-realm](https://github.com/macula-io/macula-realm) | Managed-realm identity + certificate authority |

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or <http://www.apache.org/licenses/LICENSE-2.0>)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or <http://opensource.org/licenses/MIT>)

at your option.

Unless you explicitly state otherwise, any contribution intentionally
submitted for inclusion in this crate by you, as defined in the
Apache-2.0 license, shall be dual licensed as above, without any
additional terms or conditions.

---

<p align="center">
  <sub>Built with the BEAM's protocol, ported to Rust — <a href="https://buymeacoffee.com/rlefever">buy me a coffee</a> if this saved you some time</sub>
</p>
