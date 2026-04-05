# http2_core — v0.2 scope

What this implementation covers and, more importantly, what it
deliberately does not. Authoritative for review and audit; the spec
files in this directory are written **with these simplifications
assumed**.

Source decision: `project_v02_pivot.md` memory entry, dated
2026-05-02. Headline rule:

> Single bidi stream, static HPACK (or tiny bounded dynamic),
> bounded messages, no heap, no multiplexing, no priorities.
> Wire-compatible with standard gRPC peers. Server-streaming /
> client-streaming / bidi-streaming all on one stream.

## Wire layer (RFC 9113 §4)

Full RFC 9113 frame shapes are modeled — **wire bytes have no
"simple version".** A spec that under-models the wire is one a
real peer will reject. Frame_Type, Length, Stream_Identifier
ranges all match the registry verbatim.

| §  | Frame           | Shape  | Status |
|----|-----------------|--------|--------|
|6.1 | DATA            | Opaque | spec'd implicitly via Frame::Payload |
|6.2 | HEADERS         | HPACK-encoded fragment | TODO; static-table-only HPACK below |
|6.3 | PRIORITY        | 5-byte | NOT IMPLEMENTED — deprecated in RFC 9113, peer SHOULD ignore |
|6.4 | RST_STREAM      | 4-byte | spec'd (`rst_stream.rflx`) |
|6.5 | SETTINGS        | seq of (id:16, value:32) | TODO; multi-value sequence pattern |
|6.6 | PUSH_PROMISE    | server push | OUT OF SCOPE — clients ignore via SETTINGS_ENABLE_PUSH=0 |
|6.7 | PING            | 8-byte opaque | spec'd (`ping.rflx`) |
|6.8 | GOAWAY          | 8-byte + opaque | spec'd (`goaway.rflx`) |
|6.9 | WINDOW_UPDATE   | 4-byte | spec'd (`window_update.rflx`) |
|6.10| CONTINUATION    | HPACK fragment | NOT IMPLEMENTED — bound HEADERS to one frame, reject CONTINUATION as PROTOCOL_ERROR |

### Padding (§5.1.2)

Not supported. PADDED flag bit on DATA / HEADERS is treated as
PROTOCOL_ERROR by our parser. Same posture as `mqtt_core` takes
toward MQTT 3.1.1 RETAIN: model what we support, reject what we
don't, document the gap rather than silently mis-handle.

## Streams (RFC 9113 §5.1)

**Single stream at a time.** The connection holds at most one open
stream; the next RPC waits for the current one to close (`closed`
state). Implementation:

- Stream FSM is a *single named instance*, not a collection. Same
  shape as `mqtt_core/specs/session.rflx` machines. One
  `Stream_Identifier` variable, one FSM context.
- Stream IDs are issued sequentially by the client (1, 3, 5, ...)
  per §5.1.1; we do not reuse, and old IDs simply become invalid
  after their stream closes.
- We advertise `SETTINGS_MAX_CONCURRENT_STREAMS=1` to the peer
  (§6.5.2). A compliant peer (server or client) accepts this.
- Server push disabled via `SETTINGS_ENABLE_PUSH=0`.
- No multiplexing means no head-of-line blocking concerns, no
  priority arbitration, no cross-stream flow-control accounting
  beyond the connection-level window.

Server-streaming / client-streaming / bidi-streaming are still
supported because gRPC frames them as one bidirectional stream
each — sequencing the streams (one RPC at a time) is the
restriction.

## HPACK (RFC 7541)

**Static-table-only encoding.** All header fields use the 61-entry
static table (RFC 7541 Appendix A) plus literal-with-incremental-
indexing-NEVER (i.e. literals that the peer is told never to add
to its dynamic table). This means:

- We never index a custom name/value into our dynamic table.
- The peer's dynamic-table state, if it has one, is irrelevant to
  us — we never reference indices `>= 62` in encode.
- On decode, we tolerate dynamic-table-indexed entries from the
  peer **only if** they were entered earlier in the same header
  block under our limited-size dynamic table. v0.2: dynamic table
  size advertised as 0 (`SETTINGS_HEADER_TABLE_SIZE=0`), so peers
  MUST NOT use dynamic-table indices, and any index `>= 62`
  decoded is a PROTOCOL_ERROR.
- Huffman encoding (§5.2) is hand-written SPARK with the canonical
  table (RFC 7541 Appendix B). Static; no dynamic state.

This sidesteps the bulk of HPACK's stateful complexity while
remaining wire-compatible: every gRPC peer must accept literal
headers without dynamic-table use.

If a real-world peer turns out to require dynamic-table use, the
fallback (per `project_v02_pivot.md`) is a tiny bounded dynamic
table; not in v0.2.

## Connection lifecycle

- **Connection preface** (§3.4): client sends the 24-byte
  `PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n` then SETTINGS.
- **Initial SETTINGS exchange**: each side sends SETTINGS, both
  ack the other's. We advertise:
  - `SETTINGS_HEADER_TABLE_SIZE=0` (no dynamic HPACK)
  - `SETTINGS_ENABLE_PUSH=0`
  - `SETTINGS_MAX_CONCURRENT_STREAMS=1`
  - `SETTINGS_INITIAL_WINDOW_SIZE=65535` (default)
  - `SETTINGS_MAX_FRAME_SIZE=16384` (default)
- **GOAWAY** is implemented; sent and received as part of clean
  shutdown.
- **No TLS at this layer.** TLS is `mbedTLS` (or wolfSSL) as a
  black-box transport adapter; trust boundary documented in
  `tools/tls/SCOPE.md` (TBD).

## Flow control (§5.2)

Implemented but simplified by single-stream:

- Connection window: tracked, `WINDOW_UPDATE` issued as we consume
  inbound DATA.
- Stream window: same value (since exactly one stream at a time).
- Outbound: stop sending DATA when the window goes to zero; resume
  on receiving WINDOW_UPDATE.

No multiplexing means we never have to arbitrate which stream gets
to send when the connection window has space.

## Memory & runtime

Same constraints as `mqtt_core`:

- **Zero per-RPC heap.** One fixed buffer per `Connection`,
  re-used across operations via Initialize → Take_Buffer cycles
  (the established RecordFlux idiom).
- **Bounded everything.** Max method/path lengths, max headers
  per request, max payload size — compile-time constants chosen
  to fit the gRPC use case (kilobytes, not megabytes).
- **Targets:** hosted Linux/macOS via GNAT.Sockets first; STM32 +
  Zynq via swappable `Transport.Channel` adapter.

## Out of scope (explicit)

- Connection coalescing / re-use across origins
- Server push (`PUSH_PROMISE`)
- HTTP/3 (QUIC)
- gRPC-Web (browser variant; uses different framing)
- Compression negotiation other than `compression-flag = 0`
- TLS certificate verification (the transport black box does it
  or doesn't, but it's not this crate's concern)
- Connect-RPC bridge

## V&V tiers (community tools only)

Per `project_v02_pivot.md`:

1. SPARK Silver everywhere — no runtime errors. Achievable with
   community gnatprove `--level=2`.
2. SPARK Gold on load-bearing invariants — flow-control window
   non-negative, stream FSM transitions exhaustive, parser bounds.
   Where community tools don't reach Gold, document as a known
   gap rather than reach for SPARK Pro.
3. **NOT** chasing full functional correctness vs RFC 9113. The
   spec faithfully models the wire shapes we exchange; semantic
   correctness on edge cases ("what happens if the peer sends a
   malformed CONTINUATION frame interleaved with a different
   stream's HEADERS") is a runtime concern, not a proof goal.
