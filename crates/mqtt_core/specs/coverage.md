# MQTT 3.1.1 — coverage matrix

Audit baseline for the RecordFlux specs in this directory.
Source: MQTT Version 3.1.1 Plus Errata 01, OASIS Standard, 29 Oct 2014.

Status legend:

- `TODO` — in scope, not yet implemented.
- `WIP` — partial.
- `DONE` — implemented and verified.
- `DEFERRED` — planned post-v0.2; rationale below.
- `OUT-OF-SCOPE` — intentional; rationale below.
- `INFO` — informational only; nothing to implement.

| § | Topic | Status | Trace / notes |
|---|---|---|---|
| 1.1 | Organization of MQTT | INFO | non-normative |
| 1.2 | Terminology | INFO | non-normative |
| 1.3 | Normative references | INFO | |
| 1.4 | Non-normative references | INFO | |
| 1.5 | Data representations | TODO | |
| 1.5.1 | Bits | TODO | |
| 1.5.2 | Integer data values | TODO | |
| 1.5.3 | UTF-8 encoded strings | TODO | |
| 2.1 | Structure of an MQTT Control Packet | TODO | `control_packet.rflx` |
| 2.2 | Fixed header | TODO | `control_packet.rflx` |
| 2.2.1 | MQTT Control Packet type | TODO | Table 2.1 |
| 2.2.2 | Flags | TODO | per-packet override in 3.x |
| 2.2.3 | Remaining Length | TODO | varint, 1–4 bytes |
| 2.3 | Variable header | TODO | per-packet |
| 2.3.1 | Packet Identifier | TODO | |
| 2.4 | Payload | TODO | per-packet |
| 3.1 | CONNECT | TODO | `connect.rflx` |
| 3.1.1 | Fixed header | TODO | |
| 3.1.2 | Variable header | TODO | |
| 3.1.2.1 | Reserved bit | TODO | |
| 3.1.2.2 | Clean Session | TODO | |
| 3.1.2.3 | Will Flag | DEFERRED | post-v0.2 |
| 3.1.2.4 | Will QoS | DEFERRED | post-v0.2 |
| 3.1.2.5 | Will Retain | DEFERRED | post-v0.2 |
| 3.1.2.6 | User Name Flag | TODO | |
| 3.1.2.7 | Password Flag | TODO | |
| 3.1.2.8 | Keep Alive | TODO | |
| 3.1.3 | Payload (Client ID, Will Topic/Msg, User Name, Password) | TODO | Will fields deferred — see 3.1.2.3-5 |
| 3.1.4 | Response | TODO | refers to CONNACK |
| 3.2 | CONNACK | TODO | `connack.rflx` |
| 3.2.1 | Fixed header | TODO | |
| 3.2.2 | Variable header | TODO | |
| 3.2.2.1 | Connect Acknowledge Flags | TODO | |
| 3.2.2.2 | Session Present | TODO | |
| 3.2.2.3 | Connect Return code | TODO | Table 3.1 |
| 3.2.3 | Payload | INFO | none |
| 3.3 | PUBLISH | TODO | `publish.rflx` |
| 3.3.1 | Fixed header | TODO | |
| 3.3.1.1 | DUP | TODO | |
| 3.3.1.2 | QoS | TODO | values 0, 1, 2 |
| 3.3.1.3 | RETAIN | DEFERRED | post-v0.2 |
| 3.3.2 | Variable header | TODO | Topic Name + optional Packet Identifier |
| 3.3.3 | Payload | TODO | opaque, sized by remaining length |
| 3.3.4 | Response | TODO | depends on QoS |
| 3.4 | PUBACK | TODO | `puback.rflx` |
| 3.4.1 | Fixed header | TODO | |
| 3.4.2 | Variable header | TODO | Packet Identifier |
| 3.4.3 | Payload | INFO | none |
| 3.4.4 | Action | TODO | client-side state transition |
| 3.5 | PUBREC | TODO | `pubrec.rflx` |
| 3.5.1 | Fixed header | TODO | |
| 3.5.2 | Variable header | TODO | |
| 3.5.3 | Payload | INFO | none |
| 3.5.4 | Action | TODO | |
| 3.6 | PUBREL | TODO | `pubrel.rflx` |
| 3.6.1 | Fixed header | TODO | reserved bits 0010 |
| 3.6.2 | Variable header | TODO | |
| 3.6.3 | Payload | INFO | none |
| 3.6.4 | Action | TODO | |
| 3.7 | PUBCOMP | TODO | `pubcomp.rflx` |
| 3.7.1 | Fixed header | TODO | |
| 3.7.2 | Variable header | TODO | |
| 3.7.3 | Payload | INFO | none |
| 3.7.4 | Action | TODO | |
| 3.8 | SUBSCRIBE | TODO | `subscribe.rflx` |
| 3.8.1 | Fixed header | TODO | reserved bits 0010 |
| 3.8.2 | Variable header | TODO | Packet Identifier |
| 3.8.3 | Payload | TODO | list of (Topic Filter, requested QoS) |
| 3.8.4 | Response | TODO | refers to SUBACK |
| 3.9 | SUBACK | TODO | `suback.rflx` |
| 3.9.1 | Fixed header | TODO | |
| 3.9.2 | Variable header | TODO | Packet Identifier |
| 3.9.3 | Payload | TODO | list of return codes |
| 3.10 | UNSUBSCRIBE | TODO | `unsubscribe.rflx` |
| 3.10.1 | Fixed header | TODO | reserved bits 0010 |
| 3.10.2 | Variable header | TODO | |
| 3.10.3 | Payload | TODO | list of Topic Filters |
| 3.10.4 | Response | TODO | refers to UNSUBACK |
| 3.11 | UNSUBACK | TODO | `unsuback.rflx` |
| 3.11.1 | Fixed header | TODO | |
| 3.11.2 | Variable header | TODO | |
| 3.11.3 | Payload | INFO | none |
| 3.12 | PINGREQ | TODO | `pingreq.rflx` |
| 3.12.1 | Fixed header | TODO | |
| 3.12.2 | Variable header | INFO | none |
| 3.12.3 | Payload | INFO | none |
| 3.13 | PINGRESP | TODO | `pingresp.rflx` |
| 3.13.1 | Fixed header | TODO | |
| 3.13.2 | Variable header | INFO | none |
| 3.13.3 | Payload | INFO | none |
| 3.14 | DISCONNECT | TODO | `disconnect.rflx` |
| 3.14.1 | Fixed header | TODO | |
| 3.14.2 | Variable header | INFO | none |
| 3.14.3 | Payload | INFO | none |
| 4.1 | Storing state | TODO | `session.rflx` |
| 4.2 | Network Connections | TODO | `session.rflx` |
| 4.3 | Quality of Service levels and protocol flows | TODO | `session.rflx` |
| 4.3.1 | QoS 0 — At most once | TODO | |
| 4.3.2 | QoS 1 — At least once | TODO | |
| 4.3.3 | QoS 2 — Exactly once | TODO | |
| 4.4 | Message delivery retry | TODO | `session.rflx` |
| 4.5 | Message receipt | DEFERRED | server-side; client-only here |
| 4.6 | Message ordering | TODO | |
| 4.7 | Topic Names and Topic Filters | TODO | |
| 4.7.1 | Topic wildcards | TODO | |
| 4.7.2 | Topics beginning with $ | TODO | |
| 4.8 | Handling errors | TODO | |
| 5 | Security | OUT-OF-SCOPE | TLS handled outside RecordFlux; see README |
| 5.1 | Introduction | OUT-OF-SCOPE | |
| 5.2 | Authentication of Clients by the Server | OUT-OF-SCOPE | |
| 5.3 | Authorization of Clients by the Server | OUT-OF-SCOPE | |
| 5.4 | Authentication of the Server by the Client | OUT-OF-SCOPE | |
| 5.5 | Integrity of Application Messages and Control Packets | OUT-OF-SCOPE | |
| 5.6 | Privacy of Application Messages and Control Packets | OUT-OF-SCOPE | |
| 5.7 | Non-repudiation of message transmission | OUT-OF-SCOPE | |
| 5.8 | Detecting compromise of Clients and Servers | OUT-OF-SCOPE | |
| 5.9 | Detecting abnormal behaviors | OUT-OF-SCOPE | |
| 5.10 | Other security considerations | OUT-OF-SCOPE | |
| 5.11 | Use of SOCKS | OUT-OF-SCOPE | |
| 5.12 | Implementation notes | OUT-OF-SCOPE | |
| 6 | Conformance | OUT-OF-SCOPE | client-only; see README |

## Audit log

| Date | Reviewer | Status | Notes |
|---|---|---|---|
| — | — | — | (no audit performed yet) |
