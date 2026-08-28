# Macula Wire Protocol — Spec Extracted for a Rust SDK Port

**Status:** Reference spec, extracted from source. Not a build plan yet.
**Created:** 2026-08-28
**Repo renamed 2026-08-28:** `macula-mobile` → `macula-rust-sdk`. This is a
Rust port of macula's *SDK* half (the client/leaf side — see
`macula/CLAUDE.md`'s own SDK-vs-Relay split), not the relay/station. Mobile
(iOS/Android via UniFFI) is the flagship, driving consumer and the reason
this work started, not the ceiling on it — the same core is equally usable
from a future WASM build, CLI tool, or any other non-BEAM Rust consumer,
with no code shaped specifically around "mobile" below the UniFFI binding
layer itself.
**Scope constraint:** macula-station cannot change. Everything below describes
the wire contract as it exists today so a client can be built against it
unmodified.

**Why this exists:** so a non-BEAM Rust consumer — a phone first — can hold
a QUIC session with an unmodified macula-station and speak its real
application primitives (pubsub, RPC, capability advertise), without
macula's own Erlang code changing at all.

This is a BUILD artifact (a wire-format spec extracted from existing,
shipped, tested source), not a CLAIM about the world — nothing here needs
an adversarial gate. It needs to be *correct against the source*, which is
why every section below is traced to specific files and line ranges in
`macula-io/macula` at v10.10.0 rather than reconstructed from memory.

Source files read in full for this spec: `native/macula_quic/{Cargo.toml,
src/cert.rs, src/config.rs}`, `native/macula_cbor_nif/src/deterministic.rs`,
`src/identity/macula_identity.erl`, `src/peering/{macula_protocol_types.erl,
macula_frame.erl, macula_peering_conn.erl, macula_bolt4.erl,
macula_source_route.erl}`, `src/content/macula_manifest.erl`,
`src/macula_content_transfer.erl`, `src/macula_upload.erl`,
`src/macula_pusher.erl`, `src/macula_download.erl`, `src/macula_stream.erl`,
`src/macula_streamer.erl`, `src/macula_stream_sink.erl`, plus lines 890-964
of `src/client/macula_client.erl` (identity-resolution/puzzle-lifecycle
context). Skimmed for scope only (not needed for a client, station/config-side):
`macula_tls.erl`, `macula_peering.erl`, `macula_quic.erl`. Not read, role
inferred from siblings (§12.3): `macula_feeder.erl`,
`macula_content_transfer_registry.erl`, `macula_stream_local.erl`,
`macula_streamer_sup.erl`, `macula_feeder_sup.erl`, `macula_download_sup.erl`.
Not yet read: the rest of `macula_client.erl` (1376 lines total — only the
identity-resolution section was needed so far), `macula_record_cbor.erl`
(corroborating source for the CBOR codec, not primary), `macula_crypto_nif`'s
`grind_puzzle` implementation (not needed — algorithm fully specified from
the Erlang side). Confirmed dead:
`macula_protocol_types.erl`, `macula_protocol_encoder.erl`,
`macula_protocol_decoder.erl` — an unreferenced legacy (V1, msgpack/byte-tag)
scheme, superseded entirely by `macula_frame.erl` ("Macula V2"). Ignore all
three; nothing in the live peering connection state machine calls them.

---

## 1. Transport layer

- **Engine:** `quinn` 0.11 + `rustls` 0.23 (`ring` backend), driven from
  Erlang via a `rustler` NIF (`native/macula_quic`). Despite the "HTTP/3
  mesh" branding elsewhere in the docs, this is **raw QUIC**, not real
  HTTP/3 — there is no `h3` crate dependency anywhere in `macula_quic`'s
  `Cargo.toml`.
- **ALPN:** `"macula"` (single string, `native/macula_quic/src/config.rs:13`
  default). A client MUST negotiate this ALPN, not `h3` or anything else.
- **Framing on top of QUIC:** one long-lived bidirectional "control stream"
  per connection carries the handshake and all application frames after
  it. Separate QUIC streams ("dedicated streams") are opened per streaming
  RPC session or per content-transfer session — see §7.

A Rust client depending on the same `quinn`/`rustls` combination macula
already trusts should be wire-compatible at the transport level with zero
station-side changes. Dial directly on `quinn` — see §11.4 for why `iroh`
was considered and dropped: macula's edges are dial-out only, and macula
already owns discovery/gossip/pubsub/identity, so Iroh's actual
distinguishing features (NAT traversal, its own discovery, its own
gossip/doc-sync) would compete with macula's stack rather than fill a
gap in it.

## 2. Identity and trust model

Every peer's identity **is** an Ed25519 keypair. There is no separate
account system at the transport layer.

- **Certs:** self-signed Ed25519 leaf certs generated per node
  (`native/macula_quic/src/cert.rs`, using `rcgen`). No CA chain, no
  DNS-anchored trust, by design — the doc comment says so explicitly.
- **TLS-layer verification**, chosen per dial (`macula_peering_conn.erl`
  `dial_trust_opts/1`, lines 785-812):
  - `verify_pubkey => NodeId` (32-byte Ed25519 pubkey): pins the server
    cert's SubjectPublicKeyInfo to that exact key via a custom
    `rustls::client::danger::ServerCertVerifier`
    (`cert.rs::PubkeyPinVerifier`, ~line 140). Used when the dialer already
    knows the peer's identity (DHT records, pre-shared relay identities).
  - `verify => webpki` (default since macula 5.0.0): standard CA-bundle +
    hostname validation (`webpki-roots` crate). Used for bootstrap-style
    dials by hostname where the peer's Ed25519 identity isn't known yet.
  - `verify => none`: skips TLS verification entirely — dev/lab only, logs
    a warning.
- **Application-layer verification, independent of the above:** the
  CONNECT/HELLO handshake frame itself carries the peer's self-claimed
  `node_id` and is Ed25519-signed. `macula_frame:verify/2` checks the
  signature proves the sender holds the private key for that `node_id` —
  this is checked **regardless of which TLS trust mode was used**. If the
  dialer additionally set `expected_node_id`, `bind_peer_identity/2`
  (`macula_peering_conn.erl:481`) rejects the handshake unless the
  verified frame identity matches, closing the gap where TLS-layer trust
  and application-layer identity could otherwise diverge (e.g. under
  `pin_tls_cert => false`, where a peer's TLS is terminated by an
  unrelated PKI).

**For a mobile client dialing a known macula-station:** use
`verify_pubkey` with the station's known Ed25519 identity, matching what
DHT-resolved or pre-configured station records already give you, rather
than `webpki`.

**Empirical finding, 2026-08-28 — confirmed against a live production
station, not assumed:** `macula-station-frankfurt` (`macula.io`, part of
the 7-box demo fleet) presents a **3-certificate RSA chain** (SPKI OID
`1.2.840.113549.1.1.1`), not a self-signed Ed25519 identity cert. That's
macula's *other* documented trust mode (`verify => webpki`, "public-IP
path with Let's Encrypt-anchored certs"), confirmed working end-to-end
from `macula-rust-sdk` (`tests/live_station.rs`): full QUIC/TLS handshake
completes, ALPN negotiates as `"macula"` exactly per spec, CA-chain
validation against `webpki-roots` succeeds. Pubkey-pinned trust is fully
implemented and unit-tested (`src/cert.rs`, against a synthetic cert —
see its test module), but **no box in the currently-reachable demo fleet
happens to be configured that way**, so it hasn't been exercised live.
Whoever configures the *target* station for a real deployment decides
which trust mode applies — this crate needs to support both regardless,
which it does.

**Operational note for reaching this fleet specifically:** the bare
`macula.io` hostname has an A record but genuinely no AAAA record, while
the station's actual QUIC listener is bound to a specific IPv6 address
with no relationship to that A record — dialing `macula.io:4433` directly
resolves to a real, reachable IPv4 address with nothing listening, and
every packet vanishes silently (indistinguishable from a firewalled port
from the client side alone; confirmed via `ss -ulnp` on the box itself,
not guessed). `station-de-frankfurt.macula.io` is the name that actually
resolves to the listener. Matches the DNS-repoint gotcha already on file
in project memory (`reference_demo_fleet_boxes`) — confirmed still true.

## 3. Connection lifecycle (state machine)

From `macula_peering_conn.erl` (`gen_statem`), module doc lines 1-11:

```
client: connecting → handshaking → connected → draining → (terminate)
server: awaiting_start → handshaking → connected → draining → (terminate)
```

Client-side flow a Rust implementation needs to reproduce:

1. Dial QUIC to `(host, port)` with ALPN `["macula"]` and the trust mode
   from §2. (`do_connect/1`, line 785.)
2. Open one bidirectional stream on the connection (the control stream).
3. Send a **signed CONNECT frame** (§5) on that stream.
4. Start a 30-second handshake timeout (`HANDSHAKE_TIMEOUT_MS`, line 181).
   Its most common real-world trigger, per the code comment, is a protocol
   version mismatch (bytes accumulate but never form a valid frame) — a
   Rust client that gets this wrong will just silently time out, not get
   an explicit error frame.
5. Receive and verify the peer's **signed HELLO frame**. If
   `accepted := true`, absorb peer info (`node_id`, `station_id`,
   `realms`, `capabilities`) and transition to `connected`. If
   `accepted := false`, the connection is refused (`refusal_code` present)
   — terminate.
6. In `connected`, every frame arriving on the control stream is
   length-prefixed CBOR (§4) parsed via `parse_stream/1` and dispatched by
   `frame_type`. Every outbound application frame is auto-signed if not
   already signed (`ensure_signed/2`, line 771) and written to the same
   control stream. Frames may be batched into one write (up to 64 queued
   sends coalesced, line 757) — purely a sender-side optimization, no
   wire implication.
7. `GOODBYE` (§5) + close, or the peer's own stream/connection closure,
   moves to `draining` (5-second grace timeout) then terminates.

Note for implementers: the actual QUIC "closed" event the Rust NIF *could*
send is never wired up on the Erlang side (dead code, confirmed by
comment at `macula_peering_conn.erl:329`) — what a real disconnect looks
like on the wire is a `stream_closed` or `peer_send_shutdown` condition at
the QUIC-stream level, not a distinct "connection closed" frame. A Rust
client should treat stream-level close/reset the same way.

## 4. Wire frame codec

From `macula_frame.erl`, module doc lines 1-28.

```
<<Length:32/big, Cbor/binary>>
```

`Cbor` is the **RFC 8949 §4.2.1 deterministic encoding** of a single CBOR
map. `Length` is the byte length of `Cbor` alone (not including itself).
`MAX_FRAME_BYTES = 0xFFFFFF` (16 MiB) — a frame at or under 4 bytes header
is either read whole or the caller is told how many more bytes are needed
(`decode/1`, lines 1546-1557; three-way return: `{ok, Frame, Rest}`,
`{more, N}`, `{error, Reason}`).

**⚠ Deterministic/canonical CBOR is load-bearing for correctness, not
just a style choice.** Every frame's Ed25519 signature is computed over
the canonical CBOR bytes of the unsigned frame (§5). If a Rust CBOR
encoder produces different bytes for the same logical map (different key
ordering, non-minimal integer encoding, etc.), signatures will not
verify against station-produced frames and vice versa.

**RESOLVED — `ciborium` is not involved at all, and that's good news, not
a gap.** `macula_cbor_nif` has two separate code paths
(`native/macula_cbor_nif/src/`): `nif_pack`/`nif_unpack` go through
`ciborium::value::Value` and are genuinely non-deterministic (not what
the wire uses). `pack_deterministic`/`unpack_deterministic` — what
`macula_frame.erl` actually calls — live in a **separate, hand-rolled
encoder** (`deterministic.rs`, 410 lines) that bypasses `ciborium`
entirely and operates directly on `rustler::Term`. Its own doc comment
says it "mirrors `macula_record_cbor.erl` byte-for-byte" and the two are
kept in sync by a differential test
(`test/macula_cbor_deterministic_diff_tests.erl`). This means the exact
canonical algorithm is fully known, small, and directly portable —
nothing to "verify against the RFC," just a mechanical Rust-to-Rust
transcription of an already-correct 200-line core:

- **Integers:** non-negative → major 0; negative → major 1, encoded value
  `-1 - N`. Both use **minimal-length encoding**: inline if ≤23, else the
  smallest of 1/2/4/8 extra bytes that fits (AI 24/25/26/27). Range:
  positive up to `u64::MAX`; negative down to `-(2^64)` (via `i128`
  internally, since plain `i64::MIN` is one bit short). Anything outside
  that range is a hard encode error, not silent bignum handling.
- **Binary** → major 2 (byte string), raw bytes, unchanged.
- **`{text, Binary}`** → major 3 (text string), bytes used **as-is, no
  UTF-8 validation** (matches the Erlang encoder's own leniency — don't
  add validation a Rust port that isn't there in the source).
- **Atom (not `null`)** → major 3, via the atom's own UTF-8 name. This
  NIF encodes atoms directly to text on the way out, but **on decode
  every major-3 value always comes back as `{text, Binary}`, never a bare
  atom** — atom reconstitution (`binary_to_existing_atom`) happens one
  layer up, in `macula_frame.erl`'s own `from_wire_envelope/1` (§ above).
  A Rust port has no atom-table-exhaustion risk to defend against, so
  this two-layer split collapses to nothing: just decode major-3 as a
  `String`/`&str` and match it against the fixed vocabulary in §6
  directly.
- **List** → major 4 (array).
- **Tuple**: the **only** encodable tuple shape is `{text, Binary}` —
  anything else is a hard encode error. There is no general tuple
  encoding.
- **Map** → major 5. Keys are sorted by the **bytewise lexicographic
  order of their own already-encoded bytes** (encode each key
  independently first, then sort the `(key_bytes, value_bytes)` pairs by
  `key_bytes` using plain byte-vector `Ord`, then concatenate). This is
  the one rule a naive implementation is most likely to get wrong —
  sorting by the *original* key representation instead of its *encoded*
  bytes will diverge from station output for keys of different CBOR
  major types.
- **`null` (Erlang `undefined`)** → major 7, AI 22 (`0xF6`).
- **Float → ALWAYS binary64** (major 7, AI 27, `0xFB` prefix) on encode,
  regardless of whether the value would round-trip in fewer bits. This is
  a **deliberate divergence from RFC 8949's own canonical-form
  recommendation** (which prefers the shortest float width that
  round-trips) — done so the byte derivation is independent of platform
  float encoding. A generic "canonical CBOR" crate that follows the RFC's
  shortest-float rule instead of this will silently produce
  non-matching, non-verifying bytes. Decode accepts binary16/32/64 for
  interop, converting all to `f64`.
- **Decode rejects major type 6 (tags) outright** — not supported at all.
  Major 7 only supports `null` and the three float widths; no booleans,
  no "undefined" simple value, nothing else. Duplicate map keys on decode
  are last-write-wins, not an error.
- Every decode path is panic-free by construction (explicit bounds checks
  throughout, no `unwrap`/`expect`/panicking slice index) — worth
  matching in a Rust port that will also be parsing untrusted
  network input.

Net effect: this open item is closed. Define a small Rust `Value` enum
mirroring these variants (`UInt`, `NegInt`, `Bytes`, `Text`, `List`,
`Map`, `Null`, `Float`) and transcribe `encode_value`/`decode_one` from
`deterministic.rs` directly — no external crate needed for this part at
all.

**Atom ↔ wire-string mapping** (`to_wire/1` / `from_wire_envelope/1`,
lines 1855-1909): every Erlang atom (frame type names, field names like
`frame_type`, `capabilities`, enum values like `alive`/`suspect`) encodes
as a CBOR text string (major type 3) on the wire — there is no compact
integer tag scheme in the *live* protocol (that was the legacy
`macula_protocol_types.erl` design; dead, see header). A Rust
implementation needs a fixed table mapping each known atom name to/from
its literal string spelling — every such name is enumerated in §6 below.
Erlang's `undefined` maps to CBOR `null` and back. Plain binaries
(signatures, node IDs, payloads, nonces) stay as CBOR byte strings (major
type 2), never text.

**Signing domains** (Ed25519, `macula_identity:sign/2`):
| Domain separator | Covers |
|---|---|
| `"macula-v2-frame\0"` | Every frame's own `signature` field, over the canonical CBOR of the frame with `signature` and `publisher_sig` stripped (`canonical_unsigned/1`, line 1633). |
| `"macula-v2-swim-update\0"` | Each individual SWIM piggyback update's own `signature`, over the update map minus `signature` (`canonical_swim_update/1`, line 807). |
| `"macula-v2-event-pub\0"` | `publisher_sig` on PUBLISH/EVENT frames — a **separate**, end-to-end signature over just `(topic, realm, publisher, seq, payload)`, independent of frame type, so it survives PUBLISH→EVENT conversion across relay hops (§6.6). |

Domain separation is deliberate and enforced by construction: a signature
valid under one domain must never be replayable as a signature under
another.

## 5. Handshake frames (CONNECT / HELLO / GOODBYE)

`connect_spec()` (`macula_frame.erl:180`):

| Field | Type | Notes |
|---|---|---|
| `node_id` | 32 bytes | Ed25519 pubkey, the connecting identity |
| `station_id` | 32 bytes | for a plain peer/daemon dial, `send_connect/2` sets this equal to `node_id` |
| `realms` | list of 32-byte pubkeys | realms this identity claims membership in |
| `capabilities` | non-neg integer | bitmask, negotiated in HELLO |
| `puzzle_evidence` | 32 bytes | `SHA-256(node_id)` — see the dedicated callout below. Applies to **every** CONNECT, edge clients included, not just station-to-station peering. |
| `addresses` | optional list of maps | |
| `site` | optional map | |
| `endorsements` | optional list | realm-membership endorsement records (ties into HyParView admission, §6.3) |

**⚠ The puzzle is an identity property, not a per-connection cost — and
skipping it fails silently.** From `macula_identity.erl` (177 lines) and
`macula_client.erl` (lines 928-952):

- `puzzle_evidence(Pub)` is just `crypto:hash(sha256, Pub)` — a plain,
  deterministic hash of the node's own 32-byte pubkey. No nonce, no
  per-connection computation.
- The actual proof-of-work happens **once, at identity creation**:
  `macula_identity:generate(#{puzzle => true})` grinds fresh Ed25519
  keypairs (via the `macula_crypto_nif:grind_puzzle/1` NIF) until one's
  pubkey hash has at least `N` leading zero bits (S/Kademlia Sybil
  defense — mints an identity expensively, not a connection). Default
  `N = 8` (`?DEFAULT_PUZZLE_DIFFICULTY`), configurable via
  `application:get_env(macula_identity, puzzle_difficulty, 8)`. The code
  comment states grinding at the default is sub-millisecond.
- `puzzle_valid(Pub, N)` — the check any station runs — is just
  "hash + leading-zero-bit check," equally trivial.
- **Every station checks this on every CONNECT/HELLO, for every kind of
  dialer, not only station-to-station peering.** Confirmed directly:
  `macula_client.erl` — the ordinary leaf SDK any daemon uses — defaults
  to a puzzle-hardened identity specifically because, quoting the source
  comment, "this identity is exactly what every station's
  `puzzle_enforcement_mode/0` checks on CONNECT/HELLO."
- **Real incident, cited in the source (2026-08-21):** a client connected
  with an *unhardened* identity. The QUIC/TLS connection reported
  healthy, `subscribe/5` returned `{ok, _}` — and the station silently
  rejected the HELLO at the application layer. Result: a link that looked
  fully healthy delivered zero events for over an hour before the missing
  puzzle was identified as the cause. **A mobile client that skips this
  will exhibit exactly that failure mode**, and will be far harder to
  diagnose without Erlang-side introspection. Do not skip it, and don't
  bury the identity-generation step where a future implementer might
  reach for the cheap `generate()` instead of `generate(#{puzzle=>true})`.
- **Empirical caveat, 2026-08-28 — tested directly, not assumed.** Against
  the live `macula-station-frankfurt` (`macula-rust-sdk`'s
  `tests/live_station.rs`), an **unhardened** identity was accepted
  (`accepted = true`), not rejected — contradicting the incident above.
  `macula-rust-sdk`'s own puzzle-evidence computation is independently
  verified byte-for-byte against real Erlang `crypto:hash/2` output, so
  this isn't a client-side computation bug; it means either this
  particular dev-fleet station has enforcement disabled/lenient (it's
  documented elsewhere as throwaway dev infra, not production), the
  deployed image predates the enforcement described above, or
  enforcement is scoped to a condition a plain CONNECT doesn't trigger.
  Which one is true is a `macula-station`-side question, not chased here.
  **Grind the puzzle regardless** — the cost is negligible and it's
  unambiguously the documented, intended behavior; this caveat is a fact
  about one dev station's current configuration, not license to skip it.

**Lifecycle for the mobile port:** grind once — at first run/onboarding,
not per connection — persist the resulting keypair in secure device
storage (Keychain on iOS, Keystore on Android; the Erlang side's analog
is an atomic, 0600-permission local file write via `macula_identity:save/2`),
and reuse that same identity for every subsequent CONNECT. Never re-grind
per connection; `resolve_identity/1` in `macula_client.erl` is written
specifically to avoid that (`maps:get/3`'s default argument evaluates
unconditionally, so a naive lookup-with-default would grind on every
call even when an identity already exists — the source works around this
with an explicit `maps:find/2` check first).

`hello_spec()` mirrors `connect_spec()` plus `accepted` (bool),
`negotiated_capabilities`, optional `refusal_code`.

`goodbye(Reason, Detail)`: `reason` (atom, e.g. `normal`/`error`/`timeout`)
+ optional `detail` (binary).

Every frame carries a common envelope from `base/2` (line 1621):
`version` (currently `2`), `frame_type` (atom), `frame_id` (UUIDv7),
`sent_at_ms`, `capabilities`, plus `realm`/`call_id`/`source_route` set to
`null` unless the specific frame type populates them.

## 6. Full frame-type catalogue (the "application primitives")

All from `macula_frame.erl`'s `frame_type()` union (lines 155-174) —
this is authoritative; ignore the differently-named, differently-scoped
message list in the dead `macula_protocol_types.erl`.

### 6.1 Control
`connect`, `hello`, `goodbye` — §5.

### 6.2 SWIM membership (`swim_ping`, `swim_ack`, `swim_suspect`,
`swim_confirm`)
Ping/Ack carry `round`, `incarnation`, optional `piggyback` (list of
signed `swim_update` maps: `target`, `state` ∈
`alive|suspect|confirmed_failed`, `incarnation`, `observed_at`, `by`,
`signature`). Ack additionally carries `responder`. Suspect/Confirm carry
`target`, `target_incarnation`, `suspected_by`, `ttl` (decremented per
rebroadcast). No `swim_ping_req` in the live protocol (present in the
dead legacy catalogue only).

### 6.3 Kademlia DHT (`ping`, `pong`, `find_node`, `nodes`, `find_value`,
`value`, `store`, `store_ack`, `replicate`, `replicate_ack`)
`ping`/`pong` carry a 16-byte `nonce`. `find_node` carries `key` (32
bytes), `origin` (32-byte pubkey), `depth`. `nodes` returns a list of
`station_ref()`: `node_id`, `station_id`, `addresses`, `tier` (0-4),
`asn` (optional), `country` (2-byte ISO code), `last_seen_at`. `store`/
`replicate` carry an opaque `macula_record:m_record()` (encoded
separately by `macula_record:encode/1`, not covered in this pass — needed
before DHT put/get can be ported).

### 6.4 RPC (`call`, `result`, `error`)
This is the primitive a mobile client most needs early. `call_spec()`
(line 322): `call_id` (16 bytes), `procedure` (binary, e.g.
`"my.app.get_user"`), `realm` (32 bytes), `payload` (arbitrary CBOR-able
term), `deadline_ms`, `caller` (32-byte pubkey), optional
`source_route` (opaque binary, §8), optional `retry_budget`, optional
`ucan_token` (capability token for gated procedures). `result_spec()`:
`call_id`, `payload`, `responded_by`, optional
`source_route_reverse`. `call_error` uses the BOLT#4 taxonomy (§9):
`call_id`, `code` (0-255), `reported_by`, optional `detail`,
`offending_hop`, `source_route_partial`.

**⚠ `procedure` (and `topic` in §6.8, and `detail` on ERROR/GOODBYE) are
`binary()` on the wire — a raw byte string (CBOR major 2), NOT text
(major 3).** Easy to get backwards, since most other string-ish fields
(`frame_type`, `reason`, `delivered_via`) really are atoms and do encode
as text. Caught by `macula-rust-sdk`'s own differential-vector tests: a
hand-built CALL frame using text encoding for `procedure` produced a
completely different (still validly-formed, silently wrong) signature
from the reference — see that crate's `src/frame.rs` for the fix and the
byte-level trace that found it.

**Live-verified, 2026-08-28** (`macula-rust-sdk`'s
`tests/live_station.rs`): a full CALL/RESULT-or-ERROR round trip against
`macula-station-frankfurt` — signed CALL out, signed ERROR back
(`unknown_next_peer`, correctly correlated by `call_id`) for a
deliberately-nonexistent procedure name.

### 6.5 HyParView membership overlay (`hyparview_join`,
`hyparview_forward_join`, `hyparview_neighbor`, `hyparview_disconnect`,
`hyparview_shuffle`, `hyparview_shuffle_reply`)
JOIN/FORWARD_JOIN/NEIGHBOR each optionally carry a signed
`macula_record:m_record()` admission endorsement — a realm requiring
admission-gated JOIN must reject a JOIN missing it. Likely not needed for
a leaf mobile client connecting to one known station; relevant mainly for
station-to-station overlay membership.

### 6.6 Plumtree gossip (`plumtree_gossip`, `plumtree_ihave`,
`plumtree_graft`, `plumtree_prune`)
Epidemic broadcast tree primitives, keyed by `realm` + 16-byte `msg_id` +
`round`. Also station-to-station territory, not a leaf client concern for
v1.

### 6.7 Overlay relay (`overlay_relay`)
Envelope wrapping an already-encoded HyParView/Plumtree frame with an
explicit target `peer`, so a station forwards it to whichever other
connection authenticates as that peer. Opaque `payload`; the relaying
station never decodes it. Not a leaf client concern.

### 6.8 PubSub (`publish`, `subscribe`, `unsubscribe`, `event`)
The other primitive a mobile client needs early. `publish_spec()`:
`topic`, `realm` (32 bytes), `publisher` (32-byte pubkey), `seq`,
`payload`, `published_at_ms`, optional `ttl_ms`, optional
`publisher_sig` (the separate end-to-end signature, §4). `subscribe`:
`topic`, `realm`, `subscriber`, optional `filter`, optional `options`.
`event` is what a subscriber actually receives: same shape as `publish`
plus `delivered_via` ∈ `plumtree|dht|direct`. A relay station copies
`publisher_sig` verbatim from PUBLISH onto the EVENT(s) it fans out, so a
receiving mobile client can verify authenticity against the *original
publisher*, independent of which station relayed it.

**Live-verified, 2026-08-28** (`macula-rust-sdk`'s
`tests/live_station.rs`): SUBSCRIBE → PUBLISH → EVENT against
`macula-station-frankfurt`, answering a question the spec had left open
— **yes, a subscriber receives its own publish** (`delivered_via =
"direct"`), essentially instantly on this fleet. Not guaranteed to
generalize to every delivery path (`plumtree`/`dht` weren't exercised),
but confirms the direct case works end-to-end, wire format included.

### 6.9 RPC advertise (`advertise`, `unadvertise`) — frame types BUILT 2026-08-28
A peer registers itself as the handler for `procedure` under `realm` on
its own connection; the station routes inbound CALLs for that procedure
back over that connection. Tombstoned on UNADVERTISE or disconnect.
Needed if a mobile client wants to *expose* an RPC procedure, not just
call one. Frame construction (`src/frame.rs`'s `AdvertiseSpec`/
`UnadvertiseSpec`) is built and byte-verified; `Session::advertise`/
`unadvertise` (`src/connection.rs`) send them. Consumed today by the
streaming provider role (§13.2, live-verified) — unary CALL routing to
an advertised procedure (accepting an inbound CALL on the control stream
and replying with RESULT/ERROR, mirroring
`macula_station_link.erl`'s `handle_inbound_call`) is not built yet;
nothing in this crate has needed to serve unary RPC so far, only
streams.

### 6.10 Streaming RPC (`stream_open`, `stream_data`, `stream_end`,
`stream_error`, `stream_reply`)
`stream_open` mirrors `call`'s auth/routing shape (`deadline_ms`,
`caller`, `source_route`) plus `stream_id` (16 bytes) and `mode` ∈
`server_stream|client_stream|bidi`. Runs on its own dedicated QUIC
stream, not the control stream — see §7. `stream_data` carries `seq` +
`body` with `encoding` ∈ `raw|msgpack`. `stream_end`'s `role` ∈
`send|both` (half-close vs full close). Non-OPEN stream frames may carry
an optional `signer` pubkey so a relaying station (not just the
originating daemon) can be authenticated per-hop. See §13 for the full
client-side usage pattern (caller and provider roles) on top of these
frames.

**Correction, 2026-08-28 — the `msgpack` encoding is not a second wire
codec.** An earlier draft of this section (quoted above in the original
form for the record) read `encoding`'s `msgpack` value as meaning
`stream_data`'s `body` is pre-serialized through a real MessagePack
codec, distinct from the frame envelope's own CBOR — implying a Rust
port would need an `rmp-serde` dependency. Verified directly against
`macula-io/macula` v10.10.0 and it's wrong: `msgpack` was **removed from
macula's own dependencies in v3.0.0** (`rebar.config`'s own comment:
"wire protocol switched to CBOR"); the one remaining `msgpack:pack` call
in the entire repo is in an unrelated legacy DHT test, never on the
`stream_data` path. Built a real `stream_data` frame with
`encoding = msgpack` and a structured Erlang map as `body` in a live
`rebar3 shell`, round-tripped it through `macula_frame:encode/1` +
`decode/1`, and got the map straight back — `body` is embedded as an
ordinary nested value in the frame's own canonical-CBOR envelope, same
as CALL's `payload`. `encoding` is purely a semantic hint for the
receiver; **no second codec, no `rmp-serde` dependency needed.**
Confirmed at the crate level too:
`stream_data_msgpack_frame_matches_the_reference_byte_for_byte` (Rust
crate `macula-rust-sdk`, `src/frame.rs`) matches the reference's
signature byte-for-byte with exactly this shape.

### 6.11 Content transfer (`want`, `have`, `block`, `manifest_req`,
`manifest_res`, `cancel`)
Bitswap-style block exchange keyed by 34-byte MCID
(`<<Version:8, Codec:8, Hash:32/binary>>`).

**Correction, 2026-08-28: these frame types are very likely
station-to-station only, not something a mobile client needs at all.**
A full read of the client-side content-sharing stack
(`macula_content_transfer.erl`, `macula_upload.erl`, `macula_download.erl`,
`macula_pusher.erl`, `macula_manifest.erl`) found **zero references** to
`want`/`have`/`block`/`manifest_req`/`manifest_res`/`cancel` anywhere in
the client SDK. The client-facing content API uses ordinary `call`/
`result` (§6.4) against well-known `_content.*` procedure names instead
— see §12. These frame types are plausible station-to-station DHT
replication/gossip primitives (matching `macula/CLAUDE.md`'s listing of
"content" as a Relay, not SDK, concern), not part of what a client speaks.
Not fully confirmed (would need to read macula-station's own source to
be certain), but strong enough evidence to deprioritize this section
entirely for a mobile client — see §12 for the actual mechanism to build.

## 7. Stream model

- **Control stream:** one bidirectional QUIC stream, opened by the client
  right after the handshake starts, carries CONNECT/HELLO/GOODBYE and
  every non-streaming application frame in both directions for the life
  of the connection.
- **Dedicated streams:** opened per streaming-RPC session
  (`stream_open`/…) or per content-transfer session. Either side can open
  one; the receiving side has no advance notice of *why* — it reads the
  new stream's own first frame to learn its purpose
  (`macula_peering_conn.erl:565`, comment block explains a real
  production race here: the peer must be notified of the new stream
  *before* the NIF is told to start delivering data on it, or fast/local
  peers can lose the opening bytes — worth replicating this ordering
  exactly in a Rust client that also accepts inbound dedicated streams).

## 8. Source-route header (binary, not CBOR)

Used inside the opaque `source_route`/`source_route_reverse`/
`source_route_partial` fields of `call`/`stream_open`/`result`/`error`.
Fully specified, fixed binary layout
(`macula_source_route.erl`, doc lines 1-37):

```
offset  size  field
0       1     version (currently 1)
1       1     total_hops (1..8)
2       1     current_hop
3       8     deadline (unsigned, big-endian, absolute Unix ms)
11      16    path_hash — first 16 bytes of SHA-256(concat(hops))
27      16×N  hops[0..N-1] — each the first 16 bytes of the hop's NodeId
```

Fixed overhead 27 bytes; max size (8 hops) 155 bytes. `path_hash` is
verified on every decode — a mismatch is a hard reject
(`path_hash_mismatch`), not a warning. For a mobile client making a
*direct* call to one known station (no multi-hop routing requested),
this field is simply empty/absent; it only needs implementing when the
client wants to request or interpret explicit multi-hop routing.

## 9. BOLT#4 error taxonomy

`macula_bolt4.erl`, 17 entries (0x00-0x10), adapted from Lightning
Network's onion-failure codes. Each `call_error` frame carries one of
these as `code`, plus the reporting station's own frame signature so a
downstream hop can't forge "not my fault." Full table (code, name, advisory
retry policy):

| Code | Name | Retry policy |
|---|---|---|
| 0x00 | `ok` | none |
| 0x01 | `unknown_next_peer` | different_path |
| 0x02 | `temporary_relay_failure` | same_path_after_backoff |
| 0x03 | `relay_disabled` | different_path |
| 0x04 | `node_not_found_at_target_relay` | caller_recompute_with_lookup |
| 0x05 | `target_realm_refused` | application |
| 0x06 | `loop_detected` | caller_recompute |
| 0x07 | `expiry_too_soon` | caller_extends_deadline |
| 0x08 | `upstream_congestion` | exponential_backoff |
| 0x09 | `invalid_path_header` | caller_recompute |
| 0x0A | `crypto_puzzle_invalid` | crypto_drop |
| 0x0B | `realm_not_authoritative_here` | caller_recompute_with_lookup |
| 0x0C | `tombstoned` | application |
| 0x0D | `payload_too_large` | application |
| 0x0E | `signature_invalid` | crypto_drop |
| 0x0F | `unknown_error` | log_and_caution |
| 0x10 | `unauthorized` | application (missing/invalid UCAN on a gated procedure) |

`none`, `application`, and `crypto_drop` are the three non-retryable
policies; everything else means "retry, differently."

## 10. Rust crate reuse — what's already there vs. what needs writing

Confirmed from the NIF `Cargo.toml`s in `native/*`:

| Concern | Existing Rust crate (already a macula dependency) | Reuse directly? |
|---|---|---|
| QUIC engine | `quinn` 0.11 | Yes |
| TLS | `rustls` 0.23 (`ring` backend) | Yes |
| Self-signed cert generation | `rcgen` 0.13 | Yes |
| Pubkey-pin verifier | (hand-written, ~150 lines in `cert.rs`) | Port near-verbatim |
| Ed25519 sign/verify | `ed25519-dalek` 2.1 | Yes |
| Puzzle grind/verify | (hand-written, `macula_crypto_nif::grind_puzzle`) | Trivial to reimplement: generate Ed25519 keypairs, SHA-256 the pubkey, check leading zero bits, repeat. No need to read the NIF source — the algorithm is fully specified from the Erlang side (§5). |
| Hashing | `blake3` 1.5 (where BLAKE3 is used; source-route hop-hash uses SHA-256 via Erlang's `crypto:hash/2`, a separate primitive — confirm which Rust crate covers that path, likely `sha2`) | Yes for BLAKE3 uses |
| CBOR (deterministic wire codec) | none — hand-rolled in `native/macula_cbor_nif/src/deterministic.rs` (410 lines) | Transcribe directly, algorithm fully known (§4). `ciborium` is a *different*, non-deterministic code path in the same NIF crate and is irrelevant to the wire format. |
| MRI parsing | (custom, `macula_mri_nif`) | Study before porting |
| DID/UCAN | `ed25519-dalek`-based (`macula_did_nif`/`macula_ucan_nif`) | Study before porting |

What still needs writing in Rust, with no existing crate to lean on: the
frame envelope + atom-vocabulary table (§4, §6), the connection state
machine (§3), the source-route codec (§8, trivial — ~60 lines given the
fixed layout above), and the puzzle-evidence handshake field (unresolved,
§5).

## 11. Open items before any Rust code gets written

1. ~~Canonical CBOR verification.~~ **RESOLVED, 2026-08-28** — see §4.
   `ciborium` was never the actual wire codec; the real algorithm is
   hand-rolled, fully traced, and directly portable.
2. ~~`puzzle_evidence`.~~ **RESOLVED, 2026-08-28** — see §5's callout.
   One-time keypair grinding at identity creation (sub-millisecond at
   default difficulty), a trivial deterministic hash on every CONNECT
   after that, and confirmed to apply to every dialer, edge clients
   included — not a station-to-station-only concern.
3. **`macula_record:encode/1`.** Needed for DHT `store`/`replicate`/
   `value` frames (record payloads are encoded by a separate codec, not
   `macula_frame`'s own `to_wire/1`). Not needed for CALL/PUBLISH-only v1.
4. ~~Iroh raw-dial capability.~~ **DECIDED, 2026-08-28 — not pursuing
   Iroh.** Reassessed against what's now confirmed about macula's actual
   architecture: edges are dial-out only (no NAT-traversal/relay gap for
   Iroh to fill), and macula already owns its own discovery (Kademlia
   DHT), gossip (Plumtree/HyParView), pubsub, and pubkey-pinned identity
   — all things Iroh would otherwise bring, and all things that would
   *compete* with macula's own stack rather than complement it if
   adopted. The one real remaining candidate, QUIC connection migration
   for WiFi↔cellular handover, is a baseline feature of QUIC itself
   (RFC 9000 Connection IDs) that `quinn` — already a macula dependency —
   should already support; any extra mobile-specific network-change
   detection glue can be hand-written directly against `quinn` later if
   real-world testing shows it's needed, without adopting Iroh's whole
   addressing/discovery/gossip stack to get it. The one genuinely useful
   thing Iroh demonstrated — shipping a Rust core to iOS/Android via
   UniFFI — doesn't require Iroh either: UniFFI is a separate,
   general-purpose Mozilla tool this crate can depend on directly.
5. **v1 scope decision — superseded, 2026-08-28.** The original cut
   deferred streaming RPC and content transfer wholesale. Both have now
   been fully traced (§12-§13) and turn out to be cheap additions, not
   separate protocols: content sharing's core path reuses `call`/`result`
   (§6.4) verbatim, and push-upload reuses streaming RPC (§6.10)
   verbatim. Revised v1 cut: transport + handshake (§2-§5) +
   `call`/`result`/`error` (§6.4) + `publish`/`subscribe`/`event` (§6.8)
   + `advertise`/`unadvertise` (§6.9) + streaming RPC caller role (§13.1)
   + content get/put, single-block and chunked (§12), still deferring
   DHT, HyParView, Plumtree, and the streaming/content *provider* roles
   (§13.2) as v2. See §12-§13 for what's now specced and what's still
   open within them.

## 12. Content sharing (upload/download) — client-side mechanism

Traced in full from `macula_content_transfer.erl` (799 lines — the core),
`macula_manifest.erl` (268 — chunking/hashing, §4's "Rust crate reuse"
table already covers reuse), `macula_upload.erl` (299), `macula_pusher.erl`
(308), `macula_download.erl` (270). `macula_feeder.erl` (278,
`macula_content_transfer_registry.erl`, 81, and the trivial `*_sup.erl`
files) were not read in full — their role is inferable from what their
callers/siblings already show (see §12.3), and none of it is wire-level.

**Headline finding: this is not a separate wire protocol.** Content
put/get is ordinary `call`/`result` (§6.4) against four well-known
procedure names, sent over a *dedicated* QUIC stream (§7) instead of the
control stream. Push-upload (§12.3) is ordinary streaming RPC (§6.10),
full stop. Nothing here needs new frame types — §6.11's `want`/`have`/
`block` frames appear to be unused by the client entirely (see the
correction there).

### 12.1 The four procedures

All calls use realm `<<0:256>>` (32 zero bytes — a reserved sentinel for
content operations, distinct from any real realm), and run over a
dedicated stream opened via the same "dedicated stream" mechanism as
streaming RPC (§7), not the control stream.

| Procedure | Payload (call) | Reply (result) |
|---|---|---|
| `_content.put_block` | `#{mcid, payload}` — `payload` is the raw chunk bytes | `ok` \| `hash_mismatch` |
| `_content.get_block` | `#{mcid}` | raw binary (the block) \| `not_found` |
| `_content.put_manifest` | `#{manifest}` — the full manifest map (§4's crate-reuse table, chunking algorithm) | `ok` |
| `_content.get_manifest` | `#{mcid}` | the manifest map \| `not_found` |

**Implemented + live-verified 2026-08-28** (`src/manifest.rs`, `src/content.rs`,
Rust crate `macula-rust-sdk`). Two things worth recording that weren't obvious
from reading the Erlang alone:

- **`name`'s wire representation depends on which computation you're in.**
  `macula_manifest`'s canonical MCID hash input wraps `name` as CBOR *text*
  (`compute_mcid`'s own narrow special case), but the manifest map as actually
  sent in a `_content.put_manifest` call payload (`to_wire`) encodes `name` as
  a raw *byte string* — its real `binary()` type. Confirmed by encoding a real
  manifest through the general deterministic-CBOR codec and inspecting the
  bytes, not inferred from the type spec (the CALL `procedure`/PUBLISH `topic`
  lesson elsewhere in this doc was exactly this kind of inference trap).
- **v1 client implementation is deliberately sequential, not multi-lane.** The
  Rust crate opens exactly one dedicated stream per `put`/`get` call and runs
  every `_content.*` call on it in order — no round-robin lanes. This is a
  documented simplification, not a wire deviation: every call, the MCID
  scheme, and the manifest format are identical either way, so a sequential
  client interoperates fully with a station built to serve a parallel-lane
  peer. Multi-lane parallelism is purely a throughput optimization, addable
  later with zero wire change. Confirmed live: both a 4096-byte single-block
  round trip and a ~536KB (3-chunk) round trip succeeded first try against
  `station-de-frankfurt.macula.io`, including a `not_found` probe against a
  made-up MCID.

**MCID for a single block** is computed client-side before the call:
`<<1, 0x55, blake3(bytes)>>` (`macula_content_transfer.erl:put_single_block/3`).
**Always re-verify a fetched block's hash client-side against its MCID**,
even though the station verified it at put time — you may be fetching
from a station that only relayed it, not the one that stored it, so its
answer isn't inherently trustworthy. `verify_block_hash/2` is the
reference: recompute `blake3(bytes)`, compare to the MCID's embedded
hash.

### 12.2 Single-block vs. chunked

Determined without any network round trip:
- **Put:** chunked iff `byte_size(Bytes) > 262144` (256 KiB, `macula_manifest:default_chunk_size/0`).
- **Get:** chunked iff the MCID's codec byte is `0x56` (`CODEC_MANIFEST`); single-block iff `0x55` (`CODEC_RAW`).

**Single-block** is one dedicated stream, one CALL/RESULT round trip.
Nothing more to it.

**Chunked** runs a "multi-stream lanes" algorithm
(`macula_content_transfer.erl` lines 539-765):
- **Put:** the manifest is computed entirely locally
  (`macula_manifest:create/1`, pure, no network) — chunks and their MCIDs
  are all known upfront. Chunks are distributed round-robin
  (`index rem stream_count`) across up to `stream_count` dedicated
  streams (default 4, capped at the actual chunk count — a 2-chunk
  transfer never opens more than 2). Each stream ("lane") runs its own
  independent sequential queue: one `_content.put_block` in flight at a
  time per lane, next chunk starts only once the current one's
  CALL/RESULT completes. Once every lane's queue is empty, fire one
  final `_content.put_manifest` on the primal stream (the first stream
  opened) to register it.
- **Get:** the manifest is unknown upfront, so it's fetched first — one
  `_content.get_manifest` call on the single stream the initial connect
  opened. Once it's back (with `chunk_count`), lanes are set up the same
  way, this time distributing chunk *indices* rather than bytes. Each
  lane sequentially `_content.get_block`s its assigned indices,
  accumulating results into a map keyed by index (lanes finish in
  whatever order their own network calls complete, not necessarily
  index order). Once every lane is done, reassemble bytes in index order
  and verify against the manifest's root hash via `macula_manifest:verify/2`
  — this final step is pure, no network.
- **Extra streams are cheap to open** (a local QUIC operation on an
  already-live connection — allocate a stream id, no peer round trip)
  and opening one is allowed to fail without failing the transfer: it
  just degrades to fewer lanes.
- **Retry:** each `_content.*` call is retried up to 3 times (200 ms
  backoff) if the BOLT#4 error code it failed with is itself flagged
  retryable (§9's table) — directly reuses the taxonomy already specced,
  no separate retry policy to invent.
- **Cancel is QUIC-level, not application-level:** resets every
  currently-open lane stream via QUIC `RESET_STREAM`
  (`macula_station_link:abort_content_stream/4`), **not** a
  `stream_error` application frame — a genuinely different abort
  mechanism from general streaming RPC (§13), because a content-transfer
  stream is a raw dedicated QUIC stream, not a `macula_stream`-managed
  one. Don't conflate the two when porting.
- **Pause/resume** (chunked only): gates whether a lane starts its *next*
  queued item; whatever's already in flight always finishes; resume
  continues each lane from wherever it left off. A reasonable thing to
  skip for a first mobile port — v1 can always run to completion or
  cancel outright.

### 12.3 Two ways content moves: pull vs. push

**Pull (`macula_download`/`macula_feeder`):** fetch by an already-known
MCID, or announce content into the mesh for others to discover and pull
later (`macula_feeder`, not read in full — inferred role from
`macula_download`'s module doc: a provider's station auto-publishes a
signed `content_announcement` DHT record on receipt, so there's nothing
to explicitly advertise on the feeder side, unlike RPC procedures).
Trust model is deliberately lighter than RPC's direct-dial path — content
is self-verifying by hash, so `macula_download`'s direct-dial fetch can
use `pin_tls_cert => false, verify => none` for the QUIC dial itself and
still be safe, because §12.1's client-side hash re-verification is what
actually protects the caller, not the station's identity.

**Push (`macula_pusher`/`macula_upload`):** actively sends bytes AT a
specific, already-known recipient advertising an upload procedure —
**and this path uses zero content-transfer machinery at all.** It's
`client_stream`-mode streaming RPC (§6.10/§13), full stop: the manifest
(`macula_manifest:create/2`) rides as `stream_open`'s `args`, each chunk
is one `stream_data` frame sent in order over the ONE stream (no
multi-lane parallelism — that's explicitly a content-transfer-only
mechanism, per `macula_pusher.erl`'s own doc comment correcting an
earlier draft of the plan that claimed otherwise), `close_send` half-closes,
and the terminal `stream_reply` (§6.10) carries the receiver's verified
`{ok, Mcid}` or `{error, Reason}` — the receiver (`macula_upload`)
reassembles and verifies against the manifest before ever setting that
reply, so a caller blocking on it knows the bytes actually arrived
intact, not merely that local `send/2,3` calls returned `ok`.

**For a mobile client:** push is the better fit for "upload a photo to a
known destination" (simpler, reuses §13's already-specced streaming
primitive, no new mechanism). Pull is the better fit for "fetch a piece
of content by its content-address" (§12.1-§12.2). Both are worth having;
neither requires touching §6.11's frames.

## 13. General-purpose streaming RPC — client-side mechanism

Traced in full from `macula_stream.erl` (581 lines — the per-stream wire
state machine), `macula_streamer.erl` (452 — provider/server role),
`macula_stream_sink.erl` (253 — caller/consumer role). Not read:
`macula_stream_local.erl` (195, an in-process test-only carrier, not
wire-relevant) and `macula_streamer_sup.erl` (33, trivial supervisor
boilerplate).

### 13.1 Caller (consumer) role — the one a mobile client mostly wants

Pattern, from `macula_stream_sink.erl`:

1. `call_stream(Pool, Realm, Procedure, Args, Opts)` sends `stream_open`
   (§6.10) and returns a stream handle once opened. `Opts` selects
   `mode` (`server_stream` for "the provider pushes chunks at me,"
   `client_stream` for "I push chunks at the provider" — see §12.3's push
   path for that mode in practice, `bidi` for both directions).
2. Drive a receive loop: `recv/2` blocks for the next `stream_data`
   frame, decoded per its own `encoding` field (`raw` → bytes, `msgpack`
   → a structured value — **not** a second wire codec, see §6.10/§13.3's
   correction: `body` is an ordinary nested value in the frame's own
   CBOR envelope either way). Loop until `eof` (peer sent `stream_end`)
   or `{error, Reason}` (peer sent `stream_error`, or the underlying
   connection died).
3. For `client_stream`/`bidi` modes wanting a result: `send/2,3` each
   chunk in order (`stream_data`), `close_send/1` when done
   (`stream_end` with `role => send`), then `await_reply/1,2` blocks for
   the provider's terminal `stream_reply`.
4. **Non-normal termination must send an explicit abort, not just drop
   the connection.** `macula_stream_sink.erl`'s own rule: a clean stop
   (eof reached, or the consumer's own callback choosing to stop
   cleanly) closes both sides normally; anything else (a `recv` error, a
   crash, a non-normal stop) sends the peer an explicit `stream_error`
   abort — so the other side learns this was a cancellation/failure
   rather than mistaking a dropped connection for a clean end-of-stream.
   Worth replicating exactly: the distinction is the only signal the
   peer gets.

### 13.2 Provider (server) role — BUILT + LIVE-VERIFIED 2026-08-28

Pattern, from `macula_streamer.erl` and `macula_station_link.erl`
(`handle_inbound_stream_open`, `dispatch_dedicated_frame`,
`macula_peering_conn.erl`'s inbound-`new_dedicated_stream` handoff):
`advertise_stream/5` registers a handler invoked per inbound
`stream_open`; the module drives `recv/2` on the provider's own stream
for `client_stream`-mode procedures (mirroring §13.1's loop, just on the
other end) and exposes `send/2,3`/`close/1` for `server_stream`-mode
ones to push with. Same non-normal-termination → explicit abort rule as
§13.1, symmetric. **Wire mechanics, confirmed from source before any
Rust was written:** an inbound `stream_open` for an advertised procedure
arrives as the first frame on a *fresh dedicated QUIC stream the station
opens toward the advertiser* — the advertiser has no other notice it's
coming; ADVERTISE itself (§6.9) flows on the shared control stream and
is the SAME wire frame whether registering for unary CALL routing or
streaming.

**Rust port (`src/frame.rs`'s `parse_stream_open`, `src/connection.rs`'s
`Session::advertise`/`accept_dedicated_stream`, `src/stream.rs`'s
`StreamHandle::accept`/`send_reply`) built and live-verified same day**
against `station-de-frankfurt.macula.io`: two independent connections,
one advertises and accepts an inbound stream, the other dials in and
pushes/pulls data — the station really does open a fresh dedicated
stream toward the advertiser and route the caller's `stream_open` onto
it, exactly as the Erlang source says. First time this crate has been on
the *receiving* end of a mesh interaction it didn't initiate.

The Erlang reference's own inbound-stream handoff has a documented race
(`macula_peering_conn.erl`'s "notify before enabling active mode" — a
fast/local peer's first bytes can arrive before the owning Erlang process
even knows the stream exists, because the `quicer` NIF's stream
resources start passive). **Confirmed this doesn't apply to the Rust
port:** `quinn`/QUIC buffers inbound stream data at the transport layer
regardless of when the application calls `accept_bi()`/starts reading,
so there's no analogous "arm before read" step needed here — the race is
specific to macula-station's own NIF architecture, not a general QUIC
property.

### 13.3 Wire-level notes that apply to both roles

- One dedicated QUIC stream per streaming-RPC session (§7), never the
  control stream.
- `stream_data`'s `encoding` field: `raw` (bytes as-is) or `msgpack`
  (a structured value). **Corrected 2026-08-28, see §6.10 above: this is
  NOT a second serialization format.** msgpack was removed from macula's
  own dependencies in v3.0.0; `body` for `encoding = msgpack` is embedded
  directly as an ordinary nested value in the frame's own deterministic
  CBOR envelope (§4), verified by round-tripping a real frame through
  `macula_frame:encode/1`/`decode/1`. No msgpack codec (`rmp-serde` or
  otherwise) is needed in a Rust port — a plain `Value` covers both
  `encoding` variants.
- Sequencing: `seq_out`/`seq_in` counters per direction, tracked
  independently — not used for reordering (frames arrive in order on a
  single QUIC stream by construction) but as a sanity/debugging signal.
- `handle_down`/owner-death semantics (`macula_stream.erl`) matter less
  for a Rust port — that's Erlang-process-monitor plumbing with no wire
  equivalent; the wire-relevant rule is just "stream owner gone ⇒ close
  or abort the stream," which any reasonable async-Rust structured-
  concurrency approach gets for free.

### 13.4 Forward-compatibility note: live/unbounded streaming (2026-08-28)

**Confirmed gap, out of scope here, but worth designing around.** A
concrete real-world case (`hecate-tube` / macula-realm's "Macula TV") was
checked directly: its ingest path is plain HTTP upload to a conventional
web server (mesh not involved at all — confirmed in
`maybe_upload_video_clip.erl`), and its *playback* path is `server_stream`
streaming RPC reading an **already-complete file** off local disk
(`stream_video_clip_by_id.erl`, whose own comment states "the mesh
Content primitive is never the video-bytes path"). Neither is "capture
device pushes a live, unbounded feed into the mesh as it happens." Nothing
in the ecosystem does that today, on either the client or the receiving
side.

The wire primitive is not the gap: `client_stream`-mode `stream_open` with
no manifest, followed by `stream_data` frames pushed continuously with no
predetermined end, is already valid against everything in §13.1 — a
producer just never knows total length upfront and that's fine, nothing
in the frame format requires it. The gap is entirely a missing *receiving
service* (something implementing §13.2's provider role in `client_stream`
mode, doing something useful with each chunk as it arrives — re-publish
live, buffer into a rolling window, hand off to a segmenter) — that's SDK/
station-side application design, explicitly out of scope for this repo and
not something to build now.

**What this means for this crate's design, without building the receiving
side:** don't route a live/unbounded producer through the same API shape
as §12.3's bounded push-upload (which computes a manifest from the full
byte count upfront — structurally wrong for "still recording, unknown
duration"). Expose live `client_stream` publishing as its own API surface
— open, push chunks as captured, close when done — separate from the
manifest-based upload path, so the day a receiving procedure exists on the
SDK/station side, this crate points at a new procedure name with no
protocol-level rework. A seam, not a feature.

## 14. UniFFI mobile bindings — crate architecture, started 2026-08-28

**Every application primitive wrapped, same day.** A separate crate, `macula-rust-sdk-ffi`,
depending on the core `macula-rust-sdk` crate via a path dependency —
structurally identical to `iroh-ffi`'s relationship to `iroh`, confirmed
by reading the live `n0-computer/iroh-ffi` repo directly rather than
assuming: same crate separation, same modern UniFFI proc-macro style
(`uniffi::setup_scaffolding!()`, `#[uniffi::export]`, `#[derive(uniffi::
Object/Enum/Error)]`) instead of the older `.udl`-file approach, same
`tokio` async-runtime feature (native async support, no callback/blocking
rewrite needed since this crate is already tokio-based throughout), same
`crate-type = ["staticlib", "cdylib"]` plus a `uniffi-bindgen` binary
target for codegen.

**Why a separate crate, not code inside the core one:** this is what
keeps `macula-rust-sdk` itself exactly as usable from plain Rust, a CLI,
or WASM as it was before — zero UniFFI dependency, zero FFI-shaped types,
in the core crate. The doc comment at the top of `src/lib.rs`
("Mobile... is the flagship consumer driving this work, not the ceiling
on it") is enforced structurally by this separation, not just stated.

**What's exposed — every application primitive the core crate has:**
- `FfiKeyPair` — identity generation, `node_id()`.
- `FfiSession` — `connect` (CONNECT/HELLO), `call` (CALL/RESULT/ERROR),
  `publish`/`subscribe`/`unsubscribe`/`recv_event` (§6.8), `content_put`/
  `content_get` (§12), `stream_open` (§13.1, returns an `FfiStream`),
  `advertise`/`unadvertise` (§6.9), `accept_stream` (§13.2, blocks for
  the next inbound STREAM_OPEN, returns an `FfiAcceptedStream`), `close`.
- `FfiStream` — `send_data`/`close_send`/`recv`/`await_reply`/`abort`
  (caller role, §13.1) plus `send_reply` (provider role, §13.2) — the
  same object serves either role, since a stream's wire vocabulary is
  symmetric regardless of which side opened it (mirrors `StreamHandle`
  exactly).
- `FfiValue` — a **restricted** mirror of `cbor::Value`: `Null`/`Int`/
  `Bytes`/`Text`/`Float`. Missing `List`/`Map` (need recursive UniFFI
  enums — deferred, not a wire limitation) and `Int` is narrowed from
  `i128` to `i64` (UniFFI has no 128-bit integer type; an out-of-range
  value returns an explicit `FfiError::UnrepresentableValue` rather than
  silently truncating).
- `FfiCallResponse`, `FfiEvent`, `FfiStreamItem`, `FfiStreamReply`,
  `FfiStreamOpenInfo`, `FfiAcceptedStream` — mirror
  `frame::CallResponse`/`frame::EventInfo`/`stream::StreamItem`/the
  `(payload, responded_by)` pair `StreamHandle::await_reply` returns/
  `frame::StreamOpenInfo`/the `(StreamHandle, StreamOpenInfo)` pair
  `StreamHandle::accept` returns. `FfiAcceptedStream` embeds an
  `Arc<FfiStream>` directly as a record field — confirmed UniFFI 0.32
  supports an Object handle inside a Record, generating correctly in
  both languages (Kotlin's version even picks up `Disposable`
  automatically). `publish`'s `seq`/`published_at_ms` stay
  caller-supplied rather than tracked internally by `FfiSession` (unlike
  streaming RPC's per-stream `seq_out` counter): PUBLISH's `seq` is a
  per-publisher, per-topic gap-detection sequence, and a client
  publishing to several topics has to own that bookkeeping itself.

**`accept_stream` holds the session's lock for as long as it waits** —
no other `FfiSession` method can run concurrently during that wait. Not
an FFI-layer restriction: the core crate's own `Session` has the same
property, since its control stream is single-owner by construction.

**Not wrapped, and won't be until the core crate has it:** unary-RPC
provider dispatch (accepting an inbound CALL on the control stream and
replying — the core crate doesn't implement that role either, only
streaming's provider side needed it so far) and pubkey-pinned trust
(`connect` always uses WebPki — the core crate's `Trust::Pinned` exists
but isn't surfaced here yet).

**Verified past "it compiles":** built the release `cdylib` and actually
ran `uniffi-bindgen generate` for both Kotlin and Swift, then inspected
the *generated source* — not just the build exit code — for the expected
async surface: Kotlin's `suspend fun connect(...)`/`suspend fun call(...)`
(proper coroutine integration, `AutoCloseable` object handles), Swift's
`static func connect(...) async throws -> FfiSession`/`func call(...)
async throws -> FfiCallResponse` (`Sendable` conformance, `Data` for byte
arrays). CI gained a `ffi-bindings` job that rebuilds the `cdylib` and
regenerates both languages on every push, as a codegen smoke test — it
doesn't (and, without a macOS/Android runner, can't) compile the
generated Kotlin/Swift against the real platform SDKs; that's the next
gap once actual mobile app integration starts.

**Also fixed while wiring this up:** the existing CI workflow's
`clippy`/`test`/`doc` jobs were missing `--workspace` — Cargo's default
behavior for a workspace root that is *also* a package member is to
operate on just that root package unless `--workspace` is passed
explicitly, so before this fix those three jobs were silently never
touching the new crate at all (only `fmt --all` already covered it,
since `--all` is fmt's own workspace flag, spelled differently from the
others for historical reasons). Caught by directly comparing `cargo test`
vs `cargo test --workspace`'s own `Running` output, not assumed.
