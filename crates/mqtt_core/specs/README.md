# MQTT 3.1.1 — RecordFlux specs

This directory holds RecordFlux DSL specifications for the MQTT 3.1.1
wire protocol and client session state machine. Specs are compiled
to SPARK Ada via `rflx generate` into the sibling `generated/`
directory.

## Source of truth

**MQTT Version 3.1.1 Plus Errata 01**
OASIS Standard
29 October 2014

URL:
[docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html](https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html)

Retrieved: 2026-02-02.

All `.rflx` files here are traceable to this document. Section
references in spec headers and inline comments use the OASIS
document's numbering. `coverage.md` is the section-by-section
implementation status table.

## Scope (v0.2)

### In scope

| § | Topic |
|---|---|
| 1.5 | Data representations (bits, integer values, UTF-8 strings) |
| 2 | MQTT Control Packet format (fixed/variable header, remaining-length varint, payload) |
| 3.1 | CONNECT (without Will — see *Deferred*) |
| 3.2 | CONNACK |
| 3.3 | PUBLISH (without RETAIN — see *Deferred*) |
| 3.4 – 3.7 | PUBACK / PUBREC / PUBREL / PUBCOMP (QoS 1 + 2 protocol flows) |
| 3.8 – 3.11 | SUBSCRIBE / SUBACK / UNSUBSCRIBE / UNSUBACK |
| 3.12 – 3.13 | PINGREQ / PINGRESP |
| 3.14 | DISCONNECT |
| 4.1 – 4.4 | Storing state, network connections, QoS levels, message delivery retry |
| 4.6 – 4.8 | Message ordering, topic names, error handling |

### Deferred (post-v0.2)

| § | Topic | Why |
|---|---|---|
| 3.1.2.3 – 3.1.2.5 | Will Flag / QoS / Retain | Not required for the headline "first verified MQTT client" publish/subscribe demo. |
| 3.1.3 (Will Topic / Will Message) | CONNECT payload Will fields | Same. |
| 3.3.1.3 | RETAIN flag in PUBLISH | Same. |
| 4.5 | Message receipt (server-side) | Server only; we ship a client. |

### Out of scope

| § | Topic | Why |
|---|---|---|
| 5 | Security | TLS sits below RecordFlux's scope. Handled by mbedTLS as a verified black box on bare metal, or a TLS-terminating gateway in front of the broker on hosted deployments. Trust-boundary doc forthcoming. |
| 6 | Conformance | Server conformance is N/A (client-only). Client conformance *is* the verification effort itself — once SPARK proofs close, the proof obligations are the conformance evidence. |

## Files

Layout per `tools/recordflux/conventions.md`: flat directory, lowercase,
section numbers in file headers (not filenames). RecordFlux's `with`
resolver works cleanly across files in one directory.

| File | § | Status |
|---|---|---|
| `control_packet.rflx` | 2 | TODO |
| `connect.rflx` | 3.1 | TODO |
| `connack.rflx` | 3.2 | TODO |
| `publish.rflx` | 3.3 | TODO |
| `puback.rflx` | 3.4 | TODO |
| `pubrec.rflx` | 3.5 | TODO |
| `pubrel.rflx` | 3.6 | TODO |
| `pubcomp.rflx` | 3.7 | TODO |
| `subscribe.rflx` | 3.8 | TODO |
| `suback.rflx` | 3.9 | TODO |
| `unsubscribe.rflx` | 3.10 | TODO |
| `unsuback.rflx` | 3.11 | TODO |
| `pingreq.rflx` | 3.12 | TODO |
| `pingresp.rflx` | 3.13 | TODO |
| `disconnect.rflx` | 3.14 | TODO |
| `session.rflx` | 4 | TODO |

## Convention summary

Every `.rflx` file opens with:

```rflx
--  <Package>: <one-line description>.
--
--  Source: MQTT Version 3.1.1 + Errata 01, OASIS Standard, 29 Oct 2014.
--  Section coverage: §<X.Y> — <topic>.

package <Name> is
   ...
```

Per-construct comments cite §X.Y. Magic values (e.g. the `"MQTT"`
protocol-name string), conditional fields (present iff a flag bit
set), and bit-field positions get inline notes referencing the
relevant subsection.

## Status

Status legend (used here and in `coverage.md`):

- **TODO** — section in scope, not yet implemented.
- **WIP** — partial implementation; some sub-sections done.
- **DONE** — implemented; SPARK generates cleanly; spec audit passed.
- **DEFERRED** — planned post-v0.2; rationale recorded.
- **OUT-OF-SCOPE** — intentional non-coverage with rationale.
- **INFO** — informational section in the source; nothing to implement.

## Audit

`coverage.md` is the audit baseline. End-of-track procedure:

1. Open the OASIS PDF and `coverage.md` side by side.
2. Walk every section. For each:
   - Confirm `coverage.md` matches reality (status + scope).
   - DONE rows: open the cited `.rflx`, verify the §X.Y trace, confirm the construct matches the source.
   - DEFERRED / OUT-OF-SCOPE rows: confirm the rationale still holds.
3. Spot-check 10 random MUST clauses from the OASIS doc; locate enforcement in spec.
4. Run `scripts/rflx check crates/mqtt_core/specs/*.rflx`.
5. Record audit date + reviewer in `coverage.md` footer.
