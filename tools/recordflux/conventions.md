# RecordFlux — spec authoring, Ada integration, and operational rules

Working notes for everyone writing `.rflx` specs and integrating
generated SPARK into this repo.

**Read this entire file before writing or modifying any RFLX spec or
Ada integration code.** Every section contains at least one rule that
was learned from a real debugging session. Skipping ahead and building
first has cost hours multiple times.

---

## 1. Hard operational rules (from real mistakes)

These override everything else. If a rule here conflicts with "faster"
or "simpler," the rule wins.

### 1a — Read all rules first, then build

Before writing any RFLX spec, session machine, or Ada integration
code: read this entire file. The walls, anti-patterns, and Opaque
semantics documented below were each discovered through multi-hour
debugging sessions. Reading takes 5 minutes; re-discovering takes
hours.

### 1b — No heap allocations per operation

The project targets bare-metal and DO-178C contexts. **Zero per-
operation heap traffic** is a hard requirement.

For **session machines**: use `External_IO_Buffers: True` in a `.rfi`
integration file. This generates `Add_Buffer` / `Remove_Buffer` /
`Buffer_Accessible` instead of `Bytes_Ptr` ownership transfer at
`Initialize`. The buffer lives in `.bss`, on the stack, or in a
custom pool — never `new` per call.

For **message contexts** (standalone `Verify_Message` validation):
allocate the `Bytes_Ptr` **once** at connection setup (e.g.
`Connect` / `Accept_One` / `Open`), store it in the owning record,
reuse it across all operations via `Initialize → Take_Buffer` cycles,
and free it in `Close`. This is the MQTT `Mqtt_Core.Client.Buf`
pattern and the TLS `Tls_Transport.Channel.Rflx_Buf` pattern.

**Never** call `new RFLX_Types.Bytes'(...)` inside a per-record,
per-packet, or per-message procedure. The only `new` calls are at
connection-lifecycle boundaries.

### 1c — Generated code is NOT committed

Generated SPARK files in `crates/<core>/generated/` are build
artifacts. **Do not commit them.** They should be in `.gitignore`
(or `.git/info/exclude`). Regenerate from the `.rflx` specs as
part of the build.

Why: committing generated code creates the illusion of hand-written
code, hides spec drift (the `.rflx` says one thing, the committed
`.ads` says another), and causes merge conflicts on regeneration.

Regenerate frequently — after every spec change and before every
build. This catches spec drift immediately:

```sh
scripts/rflx generate -n -d crates/<core>/generated \
  crates/<core>/specs/*.rflx
```

If regeneration changes files you didn't expect, your spec drifted.

### 1d — Always pass `--no-library` (`-n`) when generating

When multiple `*_core` crates share a `rflx_runtime` crate, each
`rflx generate` emits its own RFLX runtime files. Without `-n`,
gprbuild rejects the binary: "unit X cannot belong to several
projects." The shared `rflx_runtime` crate holds the canonical
runtime; `-n` tells the generator to skip runtime files.

If runtime files slip through (you forgot `-n`), delete them:

```sh
cd crates/<core>/generated
rm -f rflx.ads rflx-rflx_arithmetic.* rflx-rflx_builtin_types* \
      rflx-rflx_generic_types* rflx-rflx_message_sequence.* \
      rflx-rflx_scalar_sequence.* rflx-rflx_types*
```

### 1e — Opaque fields use `Well_Formed_Message`, not `Valid_Message`

**This is a recurring wall.** RFLX sets Opaque (variable-length
byte-array) fields to `S_Well_Formed` state, not `S_Valid`.
`Valid_Message` requires ALL fields to be `S_Valid`. Therefore
`Valid_Message` always returns False for any message containing an
Opaque field, even when the message is structurally correct.

**Use `Well_Formed_Message` instead.** This checks that all fields
are at least `S_Well_Formed`, which is the correct semantic for
messages with Opaque payloads (TLS record Fragment, MQTT payload,
HTTP/2 frame body, etc.).

This was discovered three times independently. The symptom is always
the same: `Verify_Message` completes without exception, individual
fields show `Valid = TRUE` for all typed fields, but `Valid_Message`
returns False. The fix is always `Well_Formed_Message`.

### 1f — `rflx check` before `rflx generate`

Always validate specs before generating:

```sh
scripts/rflx check crates/<core>/specs/<package>.rflx
```

`rflx check` is fast (sub-second) and catches structural errors,
missing transitions, unnecessary exception clauses, and type
mismatches before you wait for code generation + compilation.

### 1g — Regenerate all specs in a directory together

RecordFlux rejects partial regeneration:

```
error: partial update of generated files
```

Always regenerate all `.rflx` files in a crate together:

```sh
scripts/rflx generate -n -d crates/<core>/generated \
  crates/<core>/specs/*.rflx
```

After removing or renaming a machine in a `.rflx` spec, manually
delete stale generated files:

```sh
rm crates/<core>/generated/rflx-<pkg>-<old_name>*
```

---

## 2. Spec authoring conventions

### 2a — Traceability: every spec traces to a source document

Every `.rflx` file is traceable to a public, versioned, dated source
document (RFC, OASIS standard, IEEE spec). This is how an auditor
confirms correctness without re-deriving the protocol.

**File header** (required on every `.rflx`):

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

**Per-construct references** — one-line comment citing §X.Y for
every type, message, sequence, or session state:

```rflx
   --  §5.1 — TLSPlaintext record envelope.
   type Plaintext is
      message
         ...
```

**Out-of-scope markers** — if a §X.Y is intentionally not
implemented, comment it rather than silently omitting:

```rflx
   --  Note: §3.1.2.4 (Will Flag) deferred.
```

### 2b — File / folder organisation

```
crates/<core>/specs/
├── README.md           # full source citation + scope + audit baseline
├── coverage.md         # section-by-section status table
├── <package>.rflx      # one .rflx per logical chunk
├── <package>.rfi       # External_IO_Buffers config per session machine
└── ...
```

Filenames are flat lowercase. §X.Y references live in the header
comment, not the filename.

### 2c — Coverage tracking

`coverage.md` mirrors the source doc's table of contents with per-
section status: ✅ implemented · 🔶 partial · ❌ deferred · ⛔ out of
scope. Update when status changes. The audit walk is this file vs.
actual `.rflx` content.

---

## 3. Session machines

### 3a — When session machines are worth it

- Any state that reads from a channel and dispatches on type/field.
  RFLX forces every transition to be declared; "forgot a case" is a
  spec error, not a runtime bug.
- Multi-step request-response protocols where intermediate states
  matter (handshakes, ACKed publishes, subscribe→suback).
- Skip the FSM for fire-and-forget (no reply, no dispatch) — it adds
  cost with zero verification dividend.

### 3b — The Loading → Sending → Awaiting → Forwarding template

```rflx
machine X is
   Outgoing : <RequestType>;
   Inbound  : <ResponseType>;
begin
   state Loading is
      App_Outbox'Read (Outgoing);
   transition
      goto Sending if Outgoing'Valid
      goto null
   exception goto null
   end Loading;

   state Sending is
      Network'Write (Outgoing);
   transition goto Awaiting_Reply
   end Sending;

   state Awaiting_Reply is
      Network'Read (Inbound);
   transition
      goto Forwarding_Reply if Inbound'Valid and <expected>
      goto Forwarding_Inbound if Inbound'Valid and <side-traffic>
      goto null
   exception goto null
   end Awaiting_Reply;

   state Forwarding_Inbound is
      App_Pending'Write (Inbound);
   transition goto Awaiting_Reply
   end Forwarding_Inbound;

   state Forwarding_Reply is
      App_Pending'Write (Inbound);
   transition goto null
   end Forwarding_Reply;
end X;
```

For receive-only flows, drop Loading + Sending and start at
Awaiting. Pre-feed Network data before the first Run — empty
buffers cause immediate S_Final.

### 3c — Channel convention

- `Network` (Readable+Writable) — TCP socket, bidirectional
- `App_Outbox` (Readable from FSM) — caller feeds pre-encoded bytes
- `App_Pending` (Writable from FSM) — FSM emits bytes for caller

### 3d — Generated FSM API

Per machine, `RFLX.<Pkg>.<Machine>.FSM` exposes:

- `type Channel is (C_Network, C_App_Outbox, ...)` — channel enum
- `type State is (S_Loading, ..., S_Final)` — state enum
- `Initialize`, `Finalize` — lifecycle
- `Run`, `Tick`, `Active`, `Next_State`, `In_IO_State` — stepping
- `Has_Data`, `Read`, `Read_Buffer_Size` — drain output channels
- `Needs_Data`, `Write`, `Write_Buffer_Size` — feed input channels

### 3e — Driver loop pattern in Ada

```ada
FSM.Initialize (Ctx);
if FSM.Needs_Data (Ctx, FSM.C_App_Outbox) then
   FSM.Write (Ctx, FSM.C_App_Outbox, Encoded_Bytes);
end if;

loop
   FSM.Run (Ctx);
   exit when not FSM.Active (Ctx);

   if FSM.Has_Data (Ctx, FSM.C_Network) then
      FSM.Read (Ctx, FSM.C_Network, View);
      Transport.Send (Sock, View);
   end if;

   if FSM.Has_Data (Ctx, FSM.C_App_Pending) then
      FSM.Read (Ctx, FSM.C_App_Pending, View);
      classify_and_route (View);
   end if;

   if FSM.Needs_Data (Ctx, FSM.C_Network) then
      Read_Full_Packet (Sock, Buf, Last);
      FSM.Write (Ctx, FSM.C_Network, Buf.all (1 .. Last));
   end if;
end loop;
FSM.Finalize (Ctx);
```

### 3f — `.rfi` for External_IO_Buffers (REQUIRED for every machine)

```yaml
Machine:
  X:
    External_IO_Buffers: True
    Buffer_Size:
      Default: 4096
```

Place at `crates/<core>/specs/<basename>.rfi`. Pass
`--integration-files-dir crates/<core>/specs/` to `rflx generate`.

**Do NOT add a session machine without the `.rfi`.** The generated
API differs between Bytes_Ptr-ownership and External_IO_Buffers
modes; retrofitting callers later is more work.

---

## 4. Message-context validation (standalone, no session machine)

When you only need structural validation of a single message (e.g.
validating a TLS record header), use the message context directly:

```ada
declare
   Ctx : RFLX.<Pkg>.<Msg>.Context;
begin
   RFLX.<Pkg>.<Msg>.Initialize
     (Ctx, Buf_Ptr, Written_Last => W_Last);
   RFLX.<Pkg>.<Msg>.Verify_Message (Ctx);
   if RFLX.<Pkg>.<Msg>.Well_Formed_Message (Ctx) then  -- NOT Valid_Message!
      --  record is structurally valid
   end if;
   RFLX.<Pkg>.<Msg>.Take_Buffer (Ctx, Buf_Ptr);
end;
```

Key points:

- **`Well_Formed_Message`** not `Valid_Message` (see §1e)
- **`Written_Last`** must be set to the actual data boundary —
  `To_Last_Bit_Index (Length (byte_count))` — not left at 0
- **`Initialize` sets `Buf_Ptr := null`**; `Take_Buffer` restores it.
  The buffer is borrowed, not consumed.
- **No per-message `new`** — reuse a persistent `Bytes_Ptr` (see §1b)
- There is no `External_IO_Buffers` equivalent for message contexts.
  If you need no-heap message parsing, wrap in a trivial session
  machine.

---

## 5. Walls hit and worked around

These were each discovered in real debugging sessions. Recorded so
they don't bite again.

1. **Opaque = Well_Formed, not Valid** (§1e). Causes `Valid_Message`
   to return False on structurally correct messages. Symptom: all
   typed fields show Valid=TRUE but the overall message is INVALID.
   Fix: `Well_Formed_Message`.

2. **Function return types must be definite.** RFLX rejects
   `with function Build return Publish::Packet` because Packet has
   variable-length fields. Fix: caller pre-encodes, writes bytes to
   channel; FSM reads as typed message.

3. **Channel IO can't mix with other actions in one state.** Split
   into two states: one computes/assigns, the next does the read
   or write.

4. **`Network'Read` consumes bytes — can't re-read.** Forward via
   `App_Pending` and let the Ada caller decode the specific type.

5. **No success/error distinction in `Next_State`.** Both terminal
   paths reach `S_Final`. Track success in Ada via what was emitted
   on `App_Pending`.

6. **Naming overlap between machine and package.** `Session::Subscribe`
   and `Subscribe::Packet` collide. Rename the machine:
   `Subscribing`, `Unsubscribing`.

7. **Partial-update error on regenerate after spec rename.** Stale
   files for old machine names must be removed manually.

8. **`Written_Last` must match actual data, not buffer capacity.**
   If `Written_Last = 0`, the buffer is treated as empty and
   `Verify_Message` produces no valid fields. Set it to
   `To_Last_Bit_Index(Length(actual_byte_count))`.

9. **Unnecessary exception transitions.** `rflx check` rejects
   exception clauses on states that can't throw (e.g. `Write`-only
   states). Only add `exception goto null` on states with
   `Channel'Read`.

10. **Generated runtime files conflict with shared rflx_runtime.**
    Always use `-n` flag (§1d). If files slip through, delete them.

11. **`RFLX_Types.Byte` is `mod 2**8`; `Tls_Core.Octet` is
    `Interfaces.Unsigned_8`.** Both are 8-bit modular but distinct
    types. Explicit conversion required at the boundary:
    `RFLX_Types.Byte(Octet_Value)` and vice versa.

---

## 6. RFLX + ghost-spec platinum pattern

**This is the path to platinum for wire parsers.** RFLX validates
structure (Silver-level: content-type enums, length bounds, fragment
size consistency). Direct byte reads with ghost specs prove functional
correctness (Platinum-level: "the decoded value matches the spec
function over the raw bytes").

The pattern:

1. **RFLX spec** defines the message structure per RFC §X.Y.
2. **RFLX `Verify_Message` / `Well_Formed_Message`** at the transport
   boundary validates every inbound record/packet structurally. This
   is the Silver proof — no malformed message passes.
3. **Hand-written SPARK wrapper** with ghost spec reads fields from
   the validated buffer using direct byte indexing. The Post
   references a `Spec_Decode` ghost function that computes the
   expected output from the raw bytes. This is the Platinum proof —
   functional correctness tied to the RFC.

Example (TLS record layer):

```
-- RFLX: Record_Layer.Plaintext validates content_type ∈ {0,20..23},
--   length ∈ 0..16640, fragment_size = length * 8.
-- Ghost spec: Spec_Record_Content_Type(Buf) = Buf(1)
--             Spec_Record_Length(Buf) = Buf(4)*256 + Buf(5)
-- Post: Content_Type = Spec_Record_Content_Type(Buf)
--   and Length = Spec_Record_Length(Buf)
```

**Why both layers:** RFLX alone gives structural Silver (no AoRTE
violations, valid field boundaries). Ghost specs alone give
functional correctness but don't guarantee the parser handles all
wire-format edge cases. Together: the RFLX-validated buffer is the
input to the ghost-spec-proven decoder. The structural proof from
RFLX removes the "what if the buffer is malformed?" question that
would otherwise require defensive checks in every ghost lemma.

### Current RFLX usage inventory

| Crate | RFLX specs | What RFLX validates | Platinum layer |
|---|---|---|---|
| mqtt_core | 16 message specs + 5 session FSMs | All 14 MQTT control packets, session state transitions | FSM-driven client dispatch |
| http2_core | frame.rflx, settings.rflx, etc. | HTTP/2 frame headers, SETTINGS params | Hand-written HPACK (proven at level=4) |
| tls_core | record_layer, client_hello, server_hello, handshake_layer, key_share, pre_shared_key, tls_extensions, certificate, certificate_verify, new_session_ticket, hkdf | TLS record envelope, handshake envelope, extension structure, key share entries, PSK fields | Hand-written crypto + driver (platinum on all primitives) |
| tls_transport | Uses tls_core Record_Layer.Plaintext | Every TLS record read validated via message context | Structural validation at transport boundary |

**RFLX is the default wire parser.** For any new binary wire-format
code (parsing or emitting bytes with length-prefixed / enum-typed /
variable-length structure), start with an RFLX spec. Hand-written
parsers are the fallback for formats RFLX doesn't handle well (DER/
ASN.1 walkers, ABNF/text protocols, protobuf varints).

---

## 7. Audit process (per-crate, end of track)

1. Open the source doc (RFC, OASIS) and `coverage.md` side by side.
2. Walk every section. For each:
   - ✅: open the cited `.rflx`, confirm the construct matches.
   - 🔶: confirm partial scope is intentional.
   - ❌ / ⛔: confirm rationale holds.
3. Spot-check: pick 10 random MUST clauses, find them in the spec.
4. Run `rflx check` on all specs.
5. Record audit date + reviewer in `coverage.md`'s footer.

---

## 7. Anti-patterns to avoid

- **Spec from memory.** No traceability, no audit.
- **Silent omission.** A field in the source doc but not in the
  `.rflx` with no comment.
- **`Valid_Message` on messages with Opaque fields.** Always wrong.
- **`new Bytes'(...)` inside per-record procedures.** Heap per call.
- **Committing generated code.** Hides spec drift.
- **`rflx generate` without `-n`.** Runtime file conflicts.
- **Adding a session machine without `.rfi`.** API mismatch later.
- **Paraphrasing the source doc.** Cite §X.Y, don't restate.
- **Skipping `rflx check` before `rflx generate`.** Catches errors
  faster than a full compilation cycle.
- **Building before reading this file.** See §1a.

---

## 9. RFLX refactor backlog

Hand-written wire code to lift to RFLX when touched next:

| Location | What | RFLX target |
|---|---|---|
| `tls_transport.adb` Handshake_Loop CCS skip | Content-type dispatch + CCS discard loop | `tls_record_reader.rflx` session machine: add `Skip_CCS` state that loops back to `Await_Record` when `Record_Msg.Type_Field = Change_Cipher_Spec` |
| `tls_transport.adb` Read_One_Record + Read_Flight | Hand-written 5-byte header parse + body read + flight polling | Replace with RFLX session machine driver loop (full channel I/O) |
| `tls_core` Hello.Encode_*/Decode_* | Hand-written CH/SH extension walks | Lift to RFLX Extension_List sequence parser (partially done via ext_walk_rflx) |
| `tls_core` Cert_Verify.Encode_Body_* / Decode_Body_* | Hand-written DER-like body parser | Candidate if RFLX can model the structure; DER walks don't fit RFLX cleanly |
