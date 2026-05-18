# The wrapper pattern

A walkthrough of the verification technique that drives every
proof in `transports-spark` from "binary wire format" or
"protocol state machine" to a SPARK Post citing the relevant
RFC clause or HACL\* / miTLS lemma.

If you remember three things from this doc:

1. **RFLX writes the parser; we write the meaning.** The
   RecordFlux toolchain generates a SPARK parser/serialiser that
   proves runtime-error freedom for free. The hand-written Ada
   on top carries the *functional* Post — what the procedure
   actually computes, cited against a real upstream spec.
2. **Session machines lift "correctness over time" into the
   type system.** Protocol state machines (TLS handshake, MQTT
   QoS handshake, HTTP/2 flow control) are RFLX session
   machines, not hand-rolled `case`-statements. The unreachable
   transitions are structurally impossible — gnatprove proves
   exhaustiveness; the Ada driver can only invoke states that
   the FSM enumerates.
3. **Specs are ported, not invented.** Every Post references
   either an RFC clause (e.g. `RFC 8446 §4.4.3`) or a HACL\*
   `Hacl.Spec.*.fst` file:line. We don't write FIPS specs from
   scratch.

## A concrete example: HTTP/2 outbound flow control

v0.5.2 added a session machine that enforces the HTTP/2 §6.9
outbound flow-control invariant: *don't emit a DATA frame
whose payload exceeds either the per-stream or connection
window.* It's a clean example because it's small (~260 lines
of `.rflx` + 360 lines of Ada wrapper) and the invariant is
load-bearing for interop correctness.

### Step 1 — write the RFLX spec

`crates/http2_core/specs/flow_gate.rflx`:

```rflx
package Flow_Gate is

   --  §6.9.1 — Window. 31-bit unsigned non-negative integer;
   --  values above 2^31-1 are FLOW_CONTROL_ERROR per the RFC.
   type Window_Bytes is range 0 .. 2 ** 31 - 1 with Size => 32;

   --  Driver-to-gate operation kinds.
   type Op_Kind is
      (Op_Send_Request => 1,
       Op_Wu_Conn      => 2,
       Op_Wu_Stream    => 3,
       Op_Init_Stream  => 4)
   with Size => 8;

   type Op_Packet is
      message
         Kind  : Op_Kind;
         Bytes : Window_Bytes;
      end message;

   type Decision_Kind is
      (Dec_Allow      => 1,
       Dec_Deny       => 2,
       Dec_Flow_Error => 3)
   with Size => 8;

   type Decision_Packet is
      message
         Kind  : Decision_Kind;
         Bytes : Window_Bytes;
      end message;

   generic
      App_Outbox   : Channel with Readable;
      App_Decision : Channel with Writable;
   machine Send_Gate is
      Conn_Window   : Window_Bytes := 65535;     --  §6.9.2 default
      Stream_Window : Window_Bytes := 65535;     --  reseeded by driver
      Pending       : Op_Packet;
      Reply         : Decision_Packet;
   begin

      state Idle is
      begin
         App_Outbox'Read (Pending);
      transition
         goto Dispatch
            if Pending'Valid
         goto null
      exception
         goto null
      end Idle;

      state Dispatch is
      begin
      transition
         goto Check_Send         if Pending.Kind = Op_Send_Request
         goto Apply_Conn         if Pending.Kind = Op_Wu_Conn
         goto Apply_Stream       if Pending.Kind = Op_Wu_Stream
         goto Init_Stream_Window if Pending.Kind = Op_Init_Stream
         goto null
      exception
         goto null
      end Dispatch;

      --  The structural invariant lives here:
      --  Approve_Send is reachable ONLY when both windows hold
      --  enough credit. There is no other path from Check_Send
      --  to Approve_Send.
      state Check_Send is
      begin
      transition
         goto Approve_Send
            if Pending.Bytes <= Conn_Window
               and Pending.Bytes <= Stream_Window
         goto Deny_Send
      exception
         goto null
      end Check_Send;

      state Approve_Send is
      begin
         Conn_Window   := Conn_Window - Pending.Bytes;
         Stream_Window := Stream_Window - Pending.Bytes;
         Reply := Decision_Packet'(Kind  => Dec_Allow,
                                   Bytes => Pending.Bytes);
      transition
         goto Emit_Decision
      exception
         goto null
      end Approve_Send;

      --  …  Apply_Conn / Apply_Stream / Bump_*_OK / Init_Stream_Window
      --  /  Flow_Error / Emit_Decision …

   end Send_Gate;

end Flow_Gate;
```

What RFLX gives us for free:

- **Bit-level wire format** for `Op_Packet` and
  `Decision_Packet`, with `Verify_Message` provably exhaustive.
- **Reachability proofs**: the SMT solver verifies that every
  transition can be reached and the only path to `Approve_Send`
  decrements both windows.
- **Arithmetic safety**: the `Conn_Window - Pending.Bytes`
  subtraction is guarded by the `Check_Send` transition; RFLX
  generates a precondition on `Approve_Send` enforcing it.
- **Overflow on the bump path**: the `Apply_Conn` /
  `Apply_Stream` transitions explicitly guard
  `Conn_Window + Pending.Bytes <= 2 ** 31 - 1` — anything else
  routes to a `Flow_Error` state.

The whole file passes `scripts/rflx check` clean.

### Step 2 — generate the SPARK code

```sh
scripts/rflx generate -d crates/http2_core/generated \
   crates/http2_core/specs/flow_gate.rflx
```

That writes:

```
crates/http2_core/generated/
├── rflx-flow_gate.ads
├── rflx-flow_gate-op_packet.{ads,adb}
├── rflx-flow_gate-decision_packet.{ads,adb}
├── rflx-flow_gate-send_gate.ads
├── rflx-flow_gate-send_gate-fsm.{ads,adb}
└── rflx-flow_gate-send_gate-fsm_allocator.{ads,adb}
```

All of it is SPARK; gnatprove discharges every generated VC.
The FSM exposes a `Run` / `Tick` API plus `Write` / `Read`
methods for the typed channels.

### Step 3 — write the Ada wrapper

The generated FSM is pure machine. Application code needs:

- a friendly Ada-shaped API
- defensive marshaling between Ada types and RFLX wire bytes
- structured logging from `crates/logger/` per
  `docs/conventions.md` §14

`crates/http2_core/src/http2_core-flow_gate.ads`:

```ada
package Http2_Core.Flow_Gate
with SPARK_Mode
is

   subtype Window_Bytes is
     RFLX.RFLX_Builtin_Types.Bit_Length range 0 .. 2 ** 31 - 1;

   type Decision is (Decision_Allow,
                     Decision_Deny,
                     Decision_Flow_Error);

   type Gate is limited private;

   procedure Initialize (G : in out Gate)
   with Pre  => not Is_Active (G),
        Post => Is_Active (G);

   procedure Finalize (G : in out Gate)
   with Pre  => Is_Active (G),
        Post => not Is_Active (G);

   --  Driver asks: may I emit `Bytes` bytes of DATA right now?
   --
   --  On Decision_Allow: both windows decremented; caller MUST
   --  emit those bytes.
   --
   --  On Decision_Deny: neither window changed; caller MUST NOT
   --  emit; should read peer frames (feeding back into
   --  Apply_Wu_*) until enough credit returns, then retry.
   --
   --  On Decision_Flow_Error: structurally unreachable on this
   --  call — only Apply_Wu_* can drive the error — kept for
   --  exhaustive case handling.
   procedure Request_Send
     (G        : in out Gate;
      Bytes    : Window_Bytes;
      Outcome  : out Decision)
   with Pre  => Is_Active (G),
        Post => Is_Active (G);

   --  Peer sent WINDOW_UPDATE on stream 0 — grow the connection
   --  window. Sets OK to False if §6.9.1 overflow would occur.
   procedure Apply_Wu_Conn
     (G     : in out Gate;
      Bytes : Window_Bytes;
      OK    : out Boolean)
   with Pre  => Is_Active (G) and then Bytes > 0,
        Post => Is_Active (G);

   --  …
end Http2_Core.Flow_Gate;
```

Three things to notice:

1. **`Bytes : Window_Bytes` is a refined subtype**
   (`0 .. 2^31 - 1`). That tightening flows through the entire
   API; callers can't even *express* an out-of-spec value.
2. **`Is_Active (G)` is a ghost function** — it's used in
   Pre/Post but vanishes at runtime. It lets us state the state-
   transition invariant without paying for it.
3. **`Outcome : out Decision` is the gate's verdict** — the
   wrapper's API contract says the gate's three-way decision is
   the *only* possible answer; the caller can't bypass it by
   reaching past the wrapper to the FSM.

The body (`http2_core-flow_gate.adb`) drives the generated FSM:
encodes the `Op_Packet` request, writes it to the FSM's
`C_App_Outbox` channel, runs the FSM to a decision, reads the
`Decision_Packet` back from `C_App_Decision`. All structured
logging via `Logger.Log (Logger.Debug, ...)` per §14, so the
release build optimises the calls away entirely.

### Step 4 — wire into the production driver

`crates/http2_core/src/http2_core-server.adb`'s `Send_Data_Frame`
calls `Flow_Gate.Request_Send` before every DATA chunk:

```ada
   Flow_Gate.Request_Send
     (L.Gate, Flow_Gate.Window_Bytes (Chunk), Outcome);
   if Outcome = Flow_Gate.Decision_Deny then
      Wait_For_Window (L, Chan, Flow_Gate.Window_Bytes (Chunk), Gate_OK);
      if not Gate_OK then return; end if;
   end if;
   --  Either gate Allow on the first try, or Wait_For_Window
   --  succeeded (which itself called Request_Send and got
   --  Allow). Either way, credit is debited — emit.
   Wire.Encode_Data (…);
   Transport.Send (…);
```

The SETTINGS / WINDOW_UPDATE inbound dispatch feeds back into
`Flow_Gate.Apply_Wu_Conn` / `Apply_Wu_Stream` /
`Process_Peer_Settings_Body` so peer-sent credit updates the
gate's internal windows.

The structural property:

> The server's outbound `Wire.Encode_Data` call is
> control-flow-dominated by a `Decision_Allow` from
> `Flow_Gate.Request_Send`. Reaching the encode without an
> Allow is **structurally impossible** — gnatprove discharges
> this from the FSM's reachability constraints.

### Step 5 — prove

```sh
make tls-prove   # or `alr -C crates/http2_core build` for AoRTE-only
```

The generated FSM proves all its own VCs (loop invariants,
arithmetic safety, transition exhaustiveness). The Ada wrapper
proves AoRTE plus the contract Posts that mention `Is_Active`.
The `Send_Data_Frame` integration in `Http2_Core.Server` proves
that the encode is reachable only via the Allow path.

## When this pattern applies

| Surface | Apply RFLX wrapper? |
|---|---|
| Binary wire formats with length prefixes, vectors, choice fields | ✅ Yes — perfect fit |
| Protocol state machines (handshake, QoS, flow control) | ✅ Yes — session machines |
| IANA-derived enumeration tables | ✅ Yes — `rflx convert iana` |
| ABNF / textual protocols (HTTP/1.1, header field values) | ❌ Better: miTLS-style parser combinators or hand-written SPARK with full functional Posts |
| Ad-hoc DER walks (X.509, ECDSA-Sig-Value) | ❌ Better: EverParse-style combinators or hand-written SPARK |
| Pure crypto primitives (block ciphers, hash functions) | ❌ Not RFLX — port HACL\* `Hacl.Spec.*.fst` directly as SPARK ghost functions and reference them in the Post |

## What you DO NOT do

`docs/conventions.md` §0d enumerates the bans:

- No `SPARK_Mode (Off)` to make VCs disappear.
- No `pragma Assume` bridging an imperative impl to a stub
  ghost specification (§1).
- No `pragma Annotate (GNATprove, ...)` to justify a VC.
- No stub `Spec_*` ghost function whose body is `return False`
  or `others => 0` — every ghost must be a real, computable
  body.
- No `[VERIFIED — PLATINUM]` tag on a procedure that hasn't
  cleared the §0d audit checklist.

If you find yourself reaching for any of those, the answer is:
- *Add a stronger Post on the called procedure.* The fact you
  need IS the callee's contract, not an SMT deduction.
- *Use a defensive runtime guard.* Let the code prove the
  property, not the solver.
- *Restructure to keep the fact in scope.* The
  "output-before-mutation" pattern from miTLS.

## Cross-references

- `docs/conventions.md` §4 — `[VERIFIED — …]` tag vocabulary
- `docs/conventions.md` §4a — proof-engineering patterns from
  miTLS / HACL\*
- `docs/conventions.md` §5 — mirror miTLS / HACL\* before
  opening any TLS proof
- `docs/conventions.md` §10c — formalise wire-format code in
  RFLX where it applies
- `crates/http2_core/specs/flow_gate.rflx` — the spec used in
  this walkthrough
- `crates/http2_core/src/http2_core-flow_gate.{ads,adb}` —
  the wrapper
- `crates/mqtt_core/specs/session.rflx` — five MQTT session
  machines (CONNECT, PUBLISH-QoS1, PUBLISH-QoS2, SUBSCRIBE,
  UNSUBSCRIBE)
- `crates/tls_core/src/crypto/tls_core-x25519.adb` — port of
  HACL\* `Hacl.Spec.Curve25519.fst`, full functional Post

## Past wins

- **HPACK** (v0.4) — `Int_Codec`, `Huffman`, `String_Literal`
  all platinum at gnatprove level=4. Full functional Post for
  every primitive, RFC 7541 Appendix A/B literal mirror in
  ghost form.
- **MQTT session machines** (v0.2) — the PUBACK / echo-PUBLISH
  interleave bug class is structurally unwriteable. 99.76 % of
  10 147 obligations discharged automatically.
- **TLS 1.3 crypto primitives** (v0.5) — every SHA, HMAC,
  HKDF, ChaCha20, Poly1305, AES, GCM, X25519, Ed25519, P-256,
  ECDSA, RSA-PSS-verify carries a real `Spec_X (...)` ghost
  ported from HACL\*. The Post says `Output = Spec_X (Input)`.

## Where v0.5 fell short and what v0.5.x fixes

`Tls_Core.Hello.Decode_*`, `Tls_Core.Ext_Walk_Rflx`, and
`Tls_Core.Psk_Binder` were written hand-rolled because the
RFLX-via-Cert-mode path wasn't ready in time for v0.5.0.
Result: these files (plus `Mqtt_Core.Wire`, `Tls_Core.X509`,
and the HPACK encoder subtree) account for roughly 80 % of the
unproved VCs in the workspace gnatprove sweep
(see `docs/proof-results.txt`). The v0.5.x track lifts them to
the wrapper pattern — RFLX `.rflx` spec for the wire format,
SPARK wrapper with a miTLS-mirrored Post. Same trick that took
HPACK to platinum.
