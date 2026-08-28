//! Minimal end-to-end example: connect to a station, issue one RPC call.
//! Dials the real fleet, so this isn't run by CI — see README.md's
//! "Quick start" section, which this file backs (kept compiling by
//! `cargo build --examples` in CI, run manually with
//! `cargo run --example quickstart`).
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
