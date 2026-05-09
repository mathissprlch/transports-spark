# RecordFlux specs — authoring & audit conventions

Working notes for everyone writing `.rflx` specs in this repo. Not
committed (matched by `CLAUDE.md` in `.git/info/exclude`).

## North star

Every `.rflx` file is **traceable to a public, versioned, dated source
document** — an RFC, OASIS standard, IEEE spec. The traceability is
how someone (you, me, an auditor) confirms the spec actually
implements what it claims to implement, without re-deriving the
protocol from scratch.

This matters because:

- Verification claims ("first SPARK-verified MQTT") only mean
  something if the spec being verified is the standard one.
- The DACH-aerospace audience (Airbus, Rheinmetall, Thales, TTTech)
  works with DO-178C / IEC 61508 traceability requirements daily —
  a spec without source provenance is unauditable.
- We will eventually need to walk the source doc section-by-section
  and confirm each normative requirement (MUST / SHOULD / MAY) is
  either implemented or documented as out-of-scope. That audit
  must be possible to do quickly.

## Convention

### Source of truth per spec package

Each `crates/<core>/specs/` directory has a `README.md` that:

- Names the source document with **full citation**: title, version,
  organisation, publication date, retrieval URL.
- Lists which sections are in scope, which are deferred, which are
  intentionally out of scope (and why).
- Lists the source doc's normative-language counts (MUST / SHOULD /
  MAY) when feasible — this is the audit baseline.

Example header for `crates/mqtt_core/specs/README.md`:

```markdown
# MQTT 3.1.1 RecordFlux specs

Source: **MQTT Version 3.1.1**, OASIS Standard, 29 October 2014.
URL: https://docs.oasis-open.org/mqtt/mqtt/v3.1.1/os/mqtt-v3.1.1-os.html
Retrieved: 2026-02-01.

In scope: §2 (control packet format), §3 (all 14 control packets),
§4 (session state, QoS 0/1/2 client side).

Out of scope: §5 (security — TLS handled separately), §6 (server
conformance — we ship a client only), retained messages and Will
messages from §3.1 (deferred).
```

### File header in every `.rflx`

Every `.rflx` opens with a header comment block:

```rflx
--  <Package>: <one-line description>.
--
--  Source: <Document title>, <Version>, <Organisation>, <Date>.
--  Section coverage: §<X.Y> — <topic>.
--
--  All section references in this file refer to the document above
--  unless otherwise noted.

package <Name> is
   ...
```

### Per-construct references

For every type, message, sequence, or session: a one-line comment
naming the §X.Y where it's defined, and figure/table reference if
applicable. Keep short — link, don't restate.

```rflx
   --  §2.2.1 — MQTT Control Packet type. Table 2.1.
   type Control_Packet_Type is
      (CONNECT     =>  1,
       CONNACK     =>  2,
       ...
```

### Inline notes for non-obvious encoding

When a field's encoding has a quirk that's not obvious from the type
declaration, comment it. Examples:

- Bit positions that don't match natural byte boundaries.
- Magic values (e.g. MQTT protocol-name string `"MQTT"`).
- Conditional fields (present iff some flag bit is set).
- Cross-field invariants (e.g. `Remaining_Length` covers everything
  after the fixed header).

Inline comments cite §X.Y where the rule lives.

### Out-of-scope markers

If a §X.Y is intentionally not implemented, leave a comment in the
nearest related construct rather than silent omission:

```rflx
   --  Note: §3.1.2.4 (Will Flag) and §3.1.2.5 (Will QoS) are deferred.
   --  CONNECT_Flags below treats them as RFU bits.
```

This is what makes the audit step feasible.

## File / folder organisation

Per `crates/<core>/specs/`:

```
specs/
├── README.md           # source citation + scope + audit baseline
├── coverage.md         # section-by-section status table
├── <package>.rflx      # one .rflx per logical chunk
└── <package>.rflx
```

For MQTT 3.1.1, the proposed layout (flat — RecordFlux's `with`
imports work cleanly across files in one dir):

```
crates/mqtt_core/specs/
├── README.md
├── coverage.md
├── control_packet.rflx   # §2 — fixed header, packet types
├── connect.rflx          # §3.1
├── connack.rflx          # §3.2
├── publish.rflx          # §3.3
├── puback.rflx           # §3.4
├── pubrec.rflx           # §3.5
├── pubrel.rflx           # §3.6
├── pubcomp.rflx          # §3.7
├── subscribe.rflx        # §3.8
├── suback.rflx           # §3.9
├── unsubscribe.rflx      # §3.10
├── unsuback.rflx         # §3.11
├── pingreq.rflx          # §3.12
├── pingresp.rflx         # §3.13
├── disconnect.rflx       # §3.14
└── session.rflx          # §4 — RecordFlux session FSM
```

Filenames are flat lowercase (RecordFlux maps `with "Foo";` to
`foo.rflx`); the §X.Y trace lives in the header comment, not the
filename.

## Coverage tracking

`crates/<core>/specs/coverage.md` is a flat checklist mirroring the
source doc's table of contents, with status per section:

```markdown
| § | Topic | Status | Notes |
|---|---|---|---|
| 2.1 | Fixed header structure | ✅ implemented | control_packet.rflx |
| 2.2.1 | Control Packet type | ✅ implemented | Table 2.1 |
| 2.2.2 | Flags | ✅ implemented | per-packet in connect.rflx etc. |
| 2.2.3 | Remaining Length | ✅ implemented | varint encoder |
| 3.1 | CONNECT | 🔶 partial | Will fields deferred |
| 3.1.2.4 | Will Flag | ❌ deferred | tracked: GH issue #N |
| 3.1.2.5 | Will QoS | ❌ deferred | tracked: GH issue #N |
| ... | ... | ... | ... |
| 4.4 | Message delivery retry | ✅ implemented | session.rflx |
| 5 | Security | ⛔ out of scope | TLS handled outside RecordFlux |
| 6 | Conformance | ⛔ out of scope | client-only |
```

Status legend: ✅ implemented · 🔶 partial · ❌ deferred · ⛔ out of scope.

Update this file when a section's status changes. The audit walk is
this file vs. the actual `.rflx` content.

## Audit process (end of MQTT track)

1. Open the OASIS doc PDF and `coverage.md` side by side.
2. Walk every section of the source doc. For each:
   - Confirm `coverage.md` matches reality (status + scope).
   - For ✅ rows: open the cited `.rflx`, find the §X.Y comment, read
     the construct, confirm it matches the source doc's statement.
   - For 🔶 rows: confirm the partial scope is what was actually
     intended, not silent skipping.
   - For ❌ / ⛔ rows: confirm the rationale (deferred-with-issue or
     out-of-scope-with-reason) holds.
3. Spot-check normative language: pick 10 random MUST clauses from
   the source doc, find them in the spec, confirm they're enforced.
4. Run `rflx check` — RecordFlux's structural validator.
5. Record audit date + reviewer in `coverage.md`'s footer.

## Generation pipeline

Source flow:

```
source RFC/OASIS  →  .rflx specs (this convention)  →  rflx generate  →  generated SPARK
                                                                          ↓
                                                                          gnatprove  →  proof obligations
```

`scripts/rflx generate -d crates/<core>/generated crates/<core>/specs/*.rflx`
emits SPARK Ada from the specs. Generated code is checked in so the
host build doesn't depend on RecordFlux.

## Session machines — runtime adoption

Beyond byte-format specs, RecordFlux session machines (`machine X is
... begin ... end X;`) generate driver-loop FSMs that the Ada client
can adopt as the runtime, replacing hand-written request-response
loops. Doing so is what gives the verification dividend its teeth:
the dispatch logic is exhaustively checked at `rflx check`, not at
runtime.

### When session machines are worth it

- Any state that does `Channel'Read` + dispatches on packet type.
  RecordFlux forces every transition to be declared; "forgot a
  packet type" is a spec error, not a runtime bug.
- Multi-step request-response protocols where intermediate states
  matter (handshakes, ACKed publishes, subscribe→suback).

Skip the FSM for fire-and-forget operations (no reply, no dispatch)
— it adds spec/build cost with zero verification dividend.

### The Loading → Sending → Awaiting → Forwarding template

For request-response protocols, this is the consistent shape:

```
machine X is
   Outgoing : <RequestType>;
   Inbound  : Control_Packet::Incoming_Packet;  -- meta-shape, dispatch
begin
   state Loading is               -- caller hands in pre-encoded bytes
      App_Outbox'Read (Outgoing);
   transition
      goto Sending if Outgoing'Valid
      goto null
   exception goto null
   end Loading;

   state Sending is               -- forward to broker
      Network'Write (Outgoing);
   transition goto Awaiting_Reply
   end Sending;

   state Awaiting_Reply is        -- read inbound, dispatch by type
      Network'Read (Inbound);
   transition
      goto Forwarding_Reply        if Inbound'Valid and Inbound.Packet_Type = <ExpectedReply>
      goto Forwarding_Inbound      if Inbound'Valid and Inbound.Packet_Type = <UnrelatedPublish>
      goto Awaiting_Reply          if Inbound'Valid and (other_legal_inband_traffic)
      goto null                                  -- protocol violation
   exception goto null
   end Awaiting_Reply;

   state Forwarding_Inbound is    -- queue unrelated PUBLISH for caller
      App_Pending'Write (Inbound);
   transition goto Awaiting_Reply
   end Forwarding_Inbound;

   state Forwarding_Reply is      -- emit the expected reply for caller
      App_Pending'Write (Inbound);
   transition goto null
   end Forwarding_Reply;
end X;
```

For receive-only flows (no outbox), drop Loading + Sending and start
at the Awaiting state.

### Channel use convention

- `Network` (Readable+Writable) — TCP socket, bidirectional with peer
- `App_Outbox` (Readable from FSM) — caller hands in pre-encoded
  outgoing bytes; the FSM reads them as the typed request message
- `App_Pending` (Writable from FSM) — FSM emits inbound bytes the
  caller needs to drain (queued PUBLISHes + the expected reply)

### Generated FSM API

Per machine, the `RFLX.<Pkg>.<Machine>.FSM` package exposes:

- `type Channel is (...)` — enum of declared channels
- `type State is (...)` — enum of state names + `S_Final`
- `type Context is private`
- `Initialize`, `Finalize` — lifecycle
- `Run`, `Tick`, `Active`, `Next_State`, `In_IO_State` — stepping
- `Has_Data (Ctx, Chan)`, `Read (Ctx, Chan, Buffer, Offset)` — drain
- `Needs_Data (Ctx, Chan)`, `Write (Ctx, Chan, Buffer, Offset)` — feed
- `Read_Buffer_Size`, `Write_Buffer_Size` — sizing

### Driver loop pattern in Ada

```ada
FSM.Initialize (Ctx);
--  Pre-feed App_Outbox so first Run has data to consume.
if FSM.Needs_Data (Ctx, FSM.C_App_Outbox) then
   FSM.Write (Ctx, FSM.C_App_Outbox, Encoded_Bytes);
end if;

loop
   FSM.Run (Ctx);                    -- advance until next IO state
   exit when not FSM.Active (Ctx);

   if FSM.Has_Data (Ctx, FSM.C_Network) then
      FSM.Read (Ctx, FSM.C_Network, View);
      Transport.Send (Sock, View);
   end if;

   if FSM.Has_Data (Ctx, FSM.C_App_Pending) then
      FSM.Read (Ctx, FSM.C_App_Pending, View);
      classify_and_route (View);     -- expected reply OR queued PUBLISH
   end if;

   if FSM.Needs_Data (Ctx, FSM.C_Network) then
      Read_Full_Packet (Sock, Buf, Last);
      FSM.Write (Ctx, FSM.C_Network, Buf.all (1 .. Last));
   end if;
end loop;
FSM.Finalize (Ctx);
```

For receive-only FSMs (no Loading state), pre-feed Network data
**before** the first Run — Reading state's `Verify_Message` fails on
empty buffer and the FSM transitions straight to S_Final.

### Walls hit and worked around (recorded once so it doesn't bite again)

1. **Function return types must be definite.** `with function
   Build_Outgoing return Publish::Packet;` is rejected because
   `Publish::Packet` has variable-length fields. Fix: caller pre-
   encodes via the per-packet wire encoder, then writes bytes to
   `App_Outbox`; FSM reads them as the typed message.
2. **Channel'IO can't mix with other actions in one state.** Split
   into two states: one assigns/transforms, the next does the
   read or write.
3. **`Network'Read` consumes bytes — can't re-read.** Don't model
   "re-decode the inbound bytes as a more specific type" by
   re-reading the channel. Forward the bytes via `App_Pending` and
   let the Ada caller decode.
4. **No success/error distinction in `Next_State`.** Both terminal
   paths reach `S_Final`. Track success in the Ada driver via
   "did App_Pending emit the expected reply?" or via what was
   queued.
5. **Naming overlap between machine and package.** `Session::Subscribe`
   and `Subscribe::Packet` collide in generated code. Rename the
   machine (`Subscribing`, `Unsubscribing`). `Connect_Handshake`,
   `Publish_Qos1`, `Receive` are safe.
6. **Partial-update error on regenerate after spec rename.** Stale
   files for the old machine name have to be removed manually:
   `rm crates/<core>/generated/rflx-<pkg>-<old_name>*`.

### RFC traceability for FSM specs

Per-state comments cite §X.Y just like wire specs. The dispatch
table in `Awaiting_*` enumerates "legal Server→Client packet types
per §2.2.1 Table 2.1 (Direction column)" — that enumeration is the
spec-grounded part. The sequential single-thread model of the FSM
is an *implementation choice*, not RFC-mandated; protocols are
fundamentally async and a multi-threaded client could be shaped
differently.

### Anti-patterns to avoid (FSM-specific)

- **Drop-on-PUBLISH while waiting for a non-PUBLISH reply.** §3.3.4
  obligates Clients to deliver subscribed PUBLISHes. Forward via
  `App_Pending` so the application's Receive_Publish path drains
  them.
- **Re-reading the same channel in two states.** Channels are FIFO
  byte streams; once consumed, the bytes are gone. Restructure to
  emit on `App_Pending` instead.
- **Mixing protocol-level logic into the FSM that the RFC doesn't
  mandate.** Application timeouts, retry policies, keep-alive
  scheduling — those go in Ada code above the FSM.

## Future protocols

When `crates/http2_core/specs/` and `crates/hpack_core/specs/` come
online: same convention, same `README.md` + `coverage.md` structure,
sources will be RFC 7540 (HTTP/2) and RFC 7541 (HPACK).

Re-use this CLAUDE.md unchanged — it's protocol-agnostic.

## Anti-patterns to avoid

- **Spec written from memory or "reverse-engineered from a working
  client".** No traceability, no audit possible.
- **Silent omission.** A field that exists in the source doc but not
  in the `.rflx` with no comment explaining why.
- **Stale `coverage.md`.** Either keep it updated or delete it.
- **Inline comments restating the §X.Y text.** Cite, don't paraphrase
  — paraphrases drift from source.
- **Filename §-prefix tricks.** Section numbers belong in the
  header comment, not the filename (and RecordFlux's `with` resolver
  doesn't handle special characters).


## Buffer ownership: heap vs. caller-supplied

**Default RecordFlux generation uses `Bytes_Ptr` (access-to-
unconstrained-array) with move semantics.** `Initialize` takes the
buffer in via `Buffer : in out Bytes_Ptr` with `Pre Buffer /= null`
and `Post Buffer = null`; `Take_Buffer` returns ownership the same
way. The standard caller pattern is `new Bytes'(...)` once, then
move-pass around. AdaCore's own RSP tutorial uses `new` explicitly.

For mission-critical / DO-178C / bare-metal targets where heap is
forbidden, this is unacceptable.

### State machines: use `External_IO_Buffers` (officially supported)

For every `machine X is ... end X` declaration, write a `.rfi`
integration file at `crates/<core>/specs/<basename>.rfi`:

```yaml
Machine:
  X:
    External_IO_Buffers: True
    Buffer_Size:
      Default: 4096
      <Per-channel overrides if needed>:
```

When the generator sees this, it emits `Add_Buffer` /
`Remove_Buffer` / `Buffer_Accessible` / `Has_Data` /
`Needs_Data` instead of taking ownership of `Bytes_Ptr` at
`Initialize`. The buffer is the caller's responsibility from
declaration to teardown — it can live in `.bss` (a library-level
`aliased Bytes` array), on the stack, or come from a custom pool.
The state machine never calls `new`.

Generator invocation: pass `--integration-files-dir
crates/<core>/specs/` to `rflx generate` so the `.rfi` files are
picked up alongside the `.rflx` specs.

Caller-side discipline (NOT enforced by SPARK contracts):

- Only modify a buffer when `Needs_Data (Ctx, B_X)` is True
- Only call `Add_Buffer` when `Buffer_Accessible (Next_State (Ctx),
  B_X)` is True
- Pass `Written_Last (Ctx, B_X)` as the `Written_Last` parameter
  when re-attaching unchanged data; pass the actual written index
  when you wrote new data

### Message-context API: no equivalent flag exists

`RFLX.<Pkg>.<Msg>.Packet.Initialize` for individual message types
(used outside any state machine, e.g. by the standalone
`Mqtt_Core.Wire.Encode_Connect` style of API) has NO
`External_IO_Buffers` equivalent in current RecordFlux. Confirmed
via upstream research:

- The `.rfi` schema only declares keys under `Machine:`. There is
  no `Message:` section.
- `rflx generate --help` shows no allocation-related CLI flag.
- AdaCore's published examples (RSP tutorial, DCCP walkthrough)
  all use `new RFLX_Types.Bytes'(...)` for the message-context
  buffer.
- Componolit/RecordFlux issue #911 addresses bare-metal compat
  but at the function-return / secondary-stack level, not buffer
  ownership.
- No public discussion (GitHub issues, RFCs, conference talks)
  of an external-IO-buffer mode for messages.

**Workaround: wrap standalone messages in a trivial state machine.**

If a message needs to be parsed or serialised in a no-heap context,
declare a one-state machine in `.rflx` that does the IO over
channels, enable `External_IO_Buffers: True` in its `.rfi`, and
treat the resulting `Add_Buffer`/`Remove_Buffer`/`Run` cycle as the
"encode" or "decode" call. Adds plumbing but uses an officially-
supported pattern.

For mqtt_core / http2_core specifically, the protocols ARE
session machines; standalone-message use is an artifact of how
`Mqtt_Core.Wire.Encode_X` is currently written (it calls
`Packet.Initialize` directly with a `Bytes_Ptr`). Refactoring those
encoders to drive trivial state machines is the path; tracked
in CLAUDE.md (not this file) under the bare-metal track.

### What this means for new specs

When you add a new session machine:

1. Write the `.rflx` spec under `crates/<core>/specs/`
2. Immediately write a matching `<basename>.rfi` at the same path
   with `External_IO_Buffers: True` for every machine
3. Make sure `scripts/rflx` (or whichever wrapper invokes
   `rflx generate`) passes `--integration-files-dir`

Do NOT add a session machine without the `.rfi` and assume
"we'll add it later" — the API of generated code differs between
the two modes, and refactoring callers later is more work than
getting the `.rfi` right at the start.

### Generate flags to always use

When generating code that will live alongside a shared
`rflx_runtime` crate (i.e. when multiple `*_core` crates use
RecordFlux), **always** pass `--no-library` (`-n`):

```sh
scripts/rflx generate -n -d crates/<core>/generated \
  crates/<core>/specs/*.rflx
```

Without `-n`, each `rflx generate` emits its own copy of the RFLX
runtime files (`rflx-rflx_types.ads`, `rflx-rflx_arithmetic.*`,
`rflx-rflx_builtin_types.*`, etc.). If two crates both include
these in their Source_Dirs, gprbuild rejects the binary with
"unit X cannot belong to several projects." The shared
`rflx_runtime` crate (`crates/rflx_runtime/`) holds the canonical
copy; `--no-library` tells the generator to emit only the
message-specific files.

For single-crate use (no shared runtime), omit `-n` — the
generator will include everything needed.
