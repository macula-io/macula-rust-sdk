//! Integration tests for `pool::Pool` against real, live macula-station
//! boxes.
//!
//! **Not run by default CI** — every test here is `#[ignore]`d, matching
//! `tests/live_station.rs`'s own convention. Run explicitly with:
//!
//! ```text
//! cargo test --test live_pool -- --ignored --nocapture
//! ```

use std::time::Duration;

use macula_rust::cbor::Value;
use macula_rust::frame::CallResponse;
use macula_rust::identity::KeyPair;
use macula_rust::pool::{
    LinkSelection, Pool, PoolOptions, PoolStatus, Seed, StationDiscoveryOptions,
};
use macula_rust::transport::Trust;

const STATION_HOST: &str = "station-de-frankfurt.macula.io";
const STATION_PORT: u16 = 4433;

/// Polls `pool.status()` until `until` returns true or `timeout` elapses.
/// Returns the last observed [`PoolStatus`] either way, so a caller can
/// build a rich panic message from it on failure.
async fn wait_for_status(
    pool: &Pool,
    until: impl Fn(&PoolStatus) -> bool,
    timeout: Duration,
) -> PoolStatus {
    let deadline = std::time::Instant::now() + timeout;
    loop {
        let status = pool.status().await;
        if until(&status) || std::time::Instant::now() >= deadline {
            return status;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
}

fn now_ms() -> i128 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("system clock before 1970")
        .as_millis() as i128
}

/// The primitive: a pool with ONE bootstrap seed, no discovery, connects
/// and can `call` a real procedure against the real fleet.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn single_seed_pool_connects_and_calls_against_the_real_fleet() {
    let identity = KeyPair::generate_with_default_puzzle();
    let pool = Pool::connect(
        vec![Seed::new(STATION_HOST, STATION_PORT)],
        Trust::WebPki,
        identity,
        PoolOptions::default(),
    );

    let status = wait_for_status(&pool, PoolStatus::is_healthy, Duration::from_secs(15)).await;
    assert!(
        status.is_healthy(),
        "pool never completed its bootstrap handshake: {status:?}"
    );

    let deadline = now_ms() + 5_000;
    let result = pool
        .call(
            "_dht.find_records_by_type",
            [0u8; 32],
            Value::Map(vec![(Value::text("type"), Value::Int(0x06))]),
            deadline,
        )
        .await;
    assert!(
        result.is_ok(),
        "expected a real RESULT/ERROR, got {result:?}"
    );

    pool.close("normal", Some("test done")).await;
}

/// Station discovery: a pool bootstrapped against ONE seed, with discovery
/// enabled, should find and connect to additional real fleet stations via
/// `hecate_stations.list_stations` — mirroring the identical live test in
/// macula-go's (`pool_discovery_live_test.go`) and macula-dotnet's
/// (`StationDiscoveryLiveTests.cs`) own ports of this feature.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn station_discovery_finds_and_connects_to_real_fleet_stations() {
    let identity = KeyPair::generate_with_default_puzzle();
    let pool = Pool::connect(
        vec![Seed::new(STATION_HOST, STATION_PORT)],
        Trust::WebPki,
        identity,
        PoolOptions {
            link_selection: LinkSelection::Auto,
            station_discovery: StationDiscoveryOptions {
                enabled: true,
                refresh_interval: Duration::from_secs(3600), // one attempt is enough
                max_links: 5,
            },
            ..PoolOptions::default()
        },
    );

    let bootstrap_status =
        wait_for_status(&pool, PoolStatus::is_healthy, Duration::from_secs(15)).await;
    assert!(
        bootstrap_status.is_healthy(),
        "pool never completed its initial bootstrap handshake: {bootstrap_status:?}"
    );

    // Give the background discovery task time to run its first attempt
    // (DHT lookup + list_stations call, both real network round trips)
    // and for at least one discovered link to complete its own handshake.
    let discovered_status =
        wait_for_status(&pool, |s| s.healthy_links >= 2, Duration::from_secs(30)).await;
    let links = pool.links().await;
    assert!(
        discovered_status.healthy_links >= 2,
        "station discovery found no additional healthy stations against the real fleet \
         (status={discovered_status:?}, links={links:?}) -- either hecate_stations.list_stations \
         isn't currently advertised/visible from {STATION_HOST}, or discovery has a real bug"
    );

    pool.close("normal", Some("test done")).await;
}

/// [`LinkSelection::Random`] actually rotates which link `call` tries
/// first, against two real, independently-dialed stations — not just the
/// pure-logic unit coverage in `pool.rs`'s own `#[cfg(test)]` module.
#[tokio::test]
#[ignore = "requires network access to a live macula-station"]
async fn random_link_selection_uses_more_than_one_link_against_the_real_fleet() {
    let identity = KeyPair::generate_with_default_puzzle();
    let pool = Pool::connect(
        vec![
            Seed::new(STATION_HOST, STATION_PORT),
            Seed::new("station-it-milan.macula.io", 4433),
        ],
        Trust::WebPki,
        identity,
        PoolOptions {
            link_selection: LinkSelection::Random,
            ..PoolOptions::default()
        },
    );

    let status = wait_for_status(&pool, |s| s.healthy_links >= 2, Duration::from_secs(15)).await;
    assert!(
        status.healthy_links >= 2,
        "expected both bootstrap seeds to come up healthy: {status:?}"
    );

    let mut responders = std::collections::HashSet::new();
    for _ in 0..20 {
        let deadline = now_ms() + 5_000;
        if let Ok(CallResponse::Result { responded_by, .. }) = pool
            .call(
                "_dht.find_records_by_type",
                [0u8; 32],
                Value::Map(vec![(Value::text("type"), Value::Int(0x06))]),
                deadline,
            )
            .await
        {
            responders.insert(responded_by);
        }
    }
    assert!(
        responders.len() >= 2,
        "expected calls to be answered by at least 2 different stations under Random \
         selection across 20 calls, saw {}: {responders:?}",
        responders.len()
    );

    pool.close("normal", Some("test done")).await;
}
