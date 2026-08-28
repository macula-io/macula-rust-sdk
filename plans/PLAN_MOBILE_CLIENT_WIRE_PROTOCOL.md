# Macula Wire Protocol — Spec Extracted for a Mobile (Rust) Client Port

**Status:** Reference spec, extracted from source. Not a build plan yet.
**Created:** 2026-08-28
**Scope constraint:** macula-station cannot change. Everything below describes
the wire contract as it exists today so a client can be built against it
unmodified.

**Why this exists:** so a phone can hold a QUIC session with an unmodified
macula-station and speak its real application primitives (pubsub, RPC,
capability advertise), without macula's own Erlang code changing at all.

This is a BUILD artifact (a wire-format spec extracted from existing,
shipped, tested source), not a CLAIM about the world — nothing here needs
an adversarial gate. It needs to be *correct against the source*, which is
why every section below is traced to specific files and line ranges in
`macula-io/macula` at v10.10.0 rather than reconstructed from memory.

Source files read in full for this spec: `native/macula_quic/{Cargo.toml,
src/cert.rs, src/config.rs}`, `native/macula_cbor_nif/src/deterministic.rs`,
`src/identity/macula_identity.erl`, `src/peering/{macula_protocol_types.erl,
macula_frame.erl, macula_peering_conn.erl, macula_bolt4.erl,
macula_source_route.erl}`, plus lines 890-964 of `src/client/macula_client.erl`
(identity-resolution/puzzle-lifecycle context). Skimmed for scope only
(not needed for a client, station/config-side): `macula_tls.erl`,
`macula_peering.erl`, `macula_quic.erl`. Not yet read: the rest of
`macula_client.erl` (1376 lines total — only the identity-resolution
section was needed so far), `macula_record_cbor.erl` (the Erlang
reference `deterministic.rs` is differentially tested against —
corroborating source, not primary, since a Rust port transcribes the
Rust file directly), `macula_crypto_nif`'s `grind_puzzle` implementation
(not needed — the algorithm is fully specified from the Erlang side).
Confirmed dead:
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

### 6.9 RPC advertise (`advertise`, `unadvertise`)
A peer registers itself as the handler for `procedure` under `realm` on
its own connection; the station routes inbound CALLs for that procedure
back over that connection. Tombstoned on UNADVERTISE or disconnect.
Needed if a mobile client wants to *expose* an RPC procedure, not just
call one.

### 6.10 Streaming RPC (`stream_open`, `stream_data`, `stream_end`,
`stream_error`, `stream_reply`)
`stream_open` mirrors `call`'s auth/routing shape (`deadline_ms`,
`caller`, `source_route`) plus `stream_id` (16 bytes) and `mode` ∈
`server_stream|client_stream|bidi`. Runs on its own dedicated QUIC
stream, not the control stream — see §7. `stream_data` carries `seq` +
`body` with `encoding` ∈ `raw|msgpack` (note: **msgpack**, not CBOR, for
chunk bodies specifically — distinct from the frame envelope's own CBOR
encoding). `stream_end`'s `role` ∈ `send|both` (half-close vs full
close). Non-OPEN stream frames may carry an optional `signer` pubkey so a
relaying station (not just the originating daemon) can be authenticated
per-hop.

### 6.11 Content transfer (`want`, `have`, `block`, `manifest_req`,
`manifest_res`, `cancel`)
Bitswap-style block exchange keyed by 34-byte MCID
(`<<Version:8, Codec:8, Hash:32/binary>>`). Lower priority for a v1
mobile client.

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
   general-purpose Mozilla tool that `macula-mobile` can depend on
   directly.
5. **v1 scope decision.** Given the above, a defensible first cut is:
   transport + handshake (§2-§5) + `call`/`result`/`error` (§6.4) +
   `publish`/`subscribe`/`event` (§6.8) + `advertise`/`unadvertise`
   (§6.9), deferring DHT, HyParView, Plumtree, streaming RPC, and content
   transfer. That covers "connect to a station and use pubsub + RPC,"
   which is what was asked for.
