# HTTP/2 — RecordFlux specifications

`.rflx` files describing HTTP/2 frame layouts and the connection +
single-stream state machine. Compiled to SPARK Ada under
`../generated/` by `rflx generate`.

## Source documents

- **RFC 9113** — HTTP/2, IETF Standard, June 2022. Obsoletes RFC 7540.
  URL: <https://www.rfc-editor.org/rfc/rfc9113>.
  Retrieved: 2026-04-02.
- **RFC 7541** — HPACK: Header Compression for HTTP/2, May 2015.
  URL: <https://www.rfc-editor.org/rfc/rfc7541>.
- **IANA HTTP/2 Parameters** — registry of frame types, settings,
  error codes. URL:
  <https://www.iana.org/assignments/http2-parameters/http2-parameters.xml>.
  Retrieved: 2026-04-02.

In scope (v0.2): RFC 9113 §4 frame layer (DATA, HEADERS, SETTINGS,
PING, GOAWAY, WINDOW_UPDATE, RST_STREAM, CONTINUATION); §5 streams
(state machine); a stripped HPACK enough to encode/decode the gRPC
header set.

Out of scope (deferred): server push (§5.3), priority signalling
(§5.3 PRIORITY_UPDATE / RFC 9218), ALTSVC (RFC 7838), full HPACK
dynamic table reuse across requests beyond what gRPC needs.

## IANA-derived enums (generated)

`http2_parameters.rflx` is **machine-generated** from
`iana-http2-parameters.xml` by:

```sh
scripts/rflx convert --reproducible iana -a \
  -d crates/http2_core/specs/ \
  crates/http2_core/specs/iana-http2-parameters.xml
```

The XML is checked in alongside so regenerating is reproducible
(IANA may add entries; re-pull and re-run when adopting them).

Pre-process step: the converter rejects "Unassigned" registry rows
that use hex-range values (e.g. `0x0d-0x0f`). Strip them with the
one-liner the generation commit uses; they contribute nothing to
the spec because by definition they have no name to bind.

### Converter quirks to know

- **Enum `Size` reflects the smallest bit-width that can hold all
  *known* values, not the wire-field width.** `HTTP_2_Frame_Type`
  (max value 0x10) → 8 bits, matches the wire (RFC 9113 §4.1).
  `HTTP_2_Settings` (max 0x4D44) → 16 bits, matches §6.5.1.
  `HTTP_2_Error_Code` (max 0x0D) → 4 bits, **does NOT match** the
  32-bit wire field used in RST_STREAM (§6.4) and GOAWAY (§6.8).
- **Resolution:** structural specs that use Error_Code on the wire
  declare a 32-bit unsigned field and refer to the IANA enum only
  for the named-value semantics. Don't edit the generated file —
  keep it as a faithful registry mirror.
- **`Always_Valid` aspect** is added (`-a` flag) so the enum type
  accepts any in-range value, not just the named ones. Required
  because IANA leaves room for IETF Review additions.

## File header convention

Every hand-written `.rflx` file in this directory opens with:

```rflx
--  <Package>: <one-line description>.
--
--  Source: RFC 9113 (HTTP/2), IETF Standard, June 2022.
--  Section coverage: §<X.Y> — <topic>.

package <Name> is
   ...
```

Per-construct comments cite §X.Y where the field/message is defined,
following the same convention as `crates/mqtt_core/specs/`. See
`tools/recordflux/conventions.md` for full authoring conventions.
