# Changelog

All notable changes to `macula-rust` are documented here. Format loosely
follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this crate
does not yet promise strict [SemVer](https://semver.org/) stability
(pre-1.0), so a minor version bump may include a small breaking change where
one was the right call.

## [0.2.3] - 2026-09-05

A full adversarial security/correctness sweep of the whole crate, requested
independent of the dependency refresh above — every fix here closes a way a
malicious or malformed peer could crash or hang a node, not a feature change.

### Fixed

- **CBOR decoder: unbounded recursion.** `cbor::decode` had no nesting-depth
  limit; a single crafted frame well under the 16 MiB wire-frame cap could
  crash the whole process via stack overflow, before any signature
  verification on the frame. Now capped at 128 levels
  (`cbor::MAX_NESTING_DEPTH`), returning `DecodeError::NestingTooDeep`
  instead.
- **CBOR decoder: O(n²) map decoding.** `decode_map`'s duplicate-key
  handling was a linear scan over every entry already seen — a crafted map
  with many distinct keys, still well under the frame cap, could peg a CPU
  core for tens of seconds per frame, and in the FFI bindings this also
  blocked every other call on that session (the decode ran under the
  session's own lock). Fixed by building each decoded value's canonical
  wire bytes bottom-up during decode and using them as an O(1) dedup key,
  computed only where a map key actually needs one.
- **`content::get`: eager allocation from an unverified size.** Fetching
  chunked content pre-allocated a buffer sized to the remote manifest's own
  `size` field, before a single chunk was fetched or hash-verified. A
  manifest lying about its size could trigger a large allocation attempt
  from a small message. Now grows only as genuinely-received, hash-verified
  chunks arrive.
- **`manifest::from_wire`: two ways a malformed manifest could panic.** A
  manifest claiming `chunk_size: 0` reached `[T]::chunks(0)` in `verify`,
  which panics unconditionally. A manifest whose `chunk_count` didn't match
  its actual `chunks` list let `content::get`'s fetch loop index past the
  end and panic. Both are now rejected as parse errors
  (`FromWireError::ZeroChunkSize` /
  `FromWireError::InconsistentChunkCount`).

### Added

- `cbor::DecodeError::NestingTooDeep`, `cbor::MAX_NESTING_DEPTH` (`pub`).
- `manifest::FromWireError::ZeroChunkSize`,
  `manifest::FromWireError::InconsistentChunkCount`.

## [0.2.2] - 2026-09-05

### Added

- `direct_dial::call_with_ucan` — direct-dial calls can now carry a UCAN,
  matching the gated-serving support `serve_one_call_gated` already had.

### Changed

- Full dependency refresh: every dependency bumped to its latest release,
  including 7 across a semver-major line (`ed25519-dalek` 2→3, `rand`
  0.8→0.10, `sha2` 0.10→0.11, `webpki-roots` 0.26→1.0, `x509-parser`
  0.16→0.18, `base64` 0.22→0.23, dev-only `rcgen` 0.13→0.14). Identity
  generation's RNG source changed accordingly
  (`rand::rand_core::UnwrapErr(rand::rngs::SysRng)`, restoring the same
  fail-fast-on-OS-entropy-failure semantics `rand` 0.8's `OsRng` had) — no
  behavioral change for callers.
- Dropped the MIT license option; `macula-rust` is Apache-2.0 only.
- `Cargo.lock` is no longer tracked in this repository (library crate
  convention — a consuming project's own lock governs what actually
  builds).

### Fixed

- `direct_dial::discovery_uri` now uses uppercase hex to match the live
  fleet's own DHT record encoding.

## [0.2.0] - 2026-08-30

Renamed from `macula-rust-sdk`/`macula-rust-sdk-ffi` to `macula-rust`/
`macula-rust-ffi`. Major feature push: direct-dial as a first-class path
alongside the advertise-gossip one, UCAN authorization, and org/realm
cert-chain verification.

### Added

- Direct-dial: `direct_dial::{resolve,call,advertise_direct}` — reach a
  service without depending on advertise-gossip propagation, plus
  cert-chain-authorized variants (`*_with_cert_chain`) and streaming/content
  direct-dial (`open_stream_direct`, `put_direct`, `get_direct`).
- Periodic re-advertise: `Session::keep_advertised` /
  `direct_dial::keep_advertised_direct`, a cancellable loop (a station's
  registration doesn't survive its connection being replaced).
- UCAN support: `ucan::{create,verify,decode,get_*}`, plus
  `Session::call_with_ucan`/`serve_one_call_gated` for policy-gated serving.
- Cert-chain (org/realm authorization): `cert_chain::verify_advertisement_cert_chain`.
- Supervised pubsub pair: `Session::run_publisher`/`run_subscriber`,
  auto-publishing `pubsub.publish_*_v1` facts.
- RPC telemetry auto-facts: `rpc.sent_v1`/`rpc.completed_v1` (caller),
  `rpc.received_v1`/`rpc.replied_v1` (provider) — always-on, fire-and-forget.
- Overridable `KeyStore` trait (`keystore::KeyStore`,
  `KeyringStore`/`LinuxKeyutilsStore`) for platform-native identity
  persistence; `KeyPair::save_to_keystore`/`load_from_keystore`.
- `FfiValue` gained `List`/`Map` variants (as `Items`/`Fields`), closing a
  deferred recursive-enum gap in the mobile bindings.
- FFI coverage extended to match: direct-dial, UCAN, cert-chain,
  streaming/content direct-dial, `KeyStore`.

### Fixed

- `publisher_sig` now implemented correctly; a `Session::close` data-loss
  race fixed.
- A stream-relay bug where cross-station `STREAM_DATA` frames weren't
  correctly signer-stamped.
- `call_direct_with_cert_chain` / `serve_one_call_gated` timeouts, both
  traced to the same premature-`Session`-drop race in the test harness (not
  an SDK defect).

## [0.1.0] - 2026-08-28

Initial implementation, built and live-verified against a real production
macula-station in a single day. Every wire primitive listed here was
confirmed against the real fleet, not just unit-tested — see each module's
own differential test fixtures (captured directly from the Erlang reference
via `rebar3 shell`).

### Added

- Deterministic CBOR codec (`cbor`) — a from-scratch transcription of
  macula's own canonical wire codec, verified byte-for-byte against the
  Erlang/Rust NIF reference.
- Ed25519 identity + S/Kademlia puzzle hardening (`identity`).
- QUIC transport (`transport`) with both pubkey-pinned and WebPKI trust
  modes.
- Frame envelope construction, signing, and the length-prefixed wire codec
  (`frame`).
- CONNECT/HELLO handshake state machine (`connection`).
- Unary RPC: `Session::call` / `Session::serve_one_call` (CALL/RESULT/ERROR,
  full BOLT#4 error-code mapping), both caller and provider roles.
- PubSub: `Session::publish`/`subscribe` (PUBLISH/SUBSCRIBE/EVENT).
- Content transfer (`content`, `manifest`): content-addressed single-block
  and chunked storage, BLAKE3/SHA-256.
- Streaming RPC (`stream`): STREAM_OPEN/DATA/END/ERROR/REPLY, both caller
  and provider roles.
- RPC advertise/unadvertise.
- Mobile bindings crate `macula-rust-ffi` (UniFFI, Kotlin + Swift): covers
  every primitive above, including the streaming provider role via
  `FfiCallHandler` (a foreign-implemented async trait, not a closure).
- `unsafe_code = "forbid"` at the crate level.

[0.2.3]: https://github.com/macula-io/macula-rust/compare/v0.2.2...v0.2.3
[0.2.2]: https://github.com/macula-io/macula-rust/compare/v0.2.1...v0.2.2
[0.2.0]: https://github.com/macula-io/macula-rust/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/macula-io/macula-rust/releases/tag/v0.1.0
