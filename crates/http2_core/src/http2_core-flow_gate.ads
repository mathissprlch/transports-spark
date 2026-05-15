--  Http2_Core.Flow_Gate — outbound HTTP/2 flow-control gate (RFC
--  9113 §6.9), Ada-level façade around the generated RFLX
--  session machine `Flow_Gate.Send_Gate.FSM`.
--
--  Why this exists: outbound flow control is fundamentally a
--  cross-cutting invariant ("never emit a DATA frame whose payload
--  exceeds the remaining per-stream OR connection window"). The
--  invariant lives in `crates/http2_core/specs/flow_gate.rflx` —
--  the FSM's topology makes it structurally impossible to reach
--  Approve_Send without the credit check passing. This package is
--  the Ada-side adapter the connection driver calls; all the
--  flow-control state-machine logic is the generated SPARK code.
--
--  Lifecycle:
--    1. Initialize — once per TCP connection, allocates FSM slots.
--    2. Init_Stream — once per new HTTP/2 stream, sets the per-
--       stream window to peer's SETTINGS_INITIAL_WINDOW_SIZE.
--    3. Request_Send — before every DATA frame emit; returns
--       Decision_Allow / Decision_Deny / Decision_Flow_Error.
--    4. Apply_Wu_Conn / Apply_Wu_Stream — whenever the peer's
--       WINDOW_UPDATE handler decodes an increment.
--    5. Finalize — once at TCP-connection teardown.

with RFLX.RFLX_Builtin_Types;
with RFLX.Flow_Gate.Send_Gate.FSM;

package Http2_Core.Flow_Gate
with SPARK_Mode
is

   use type RFLX.RFLX_Builtin_Types.Bit_Length;

   subtype Window_Bytes is RFLX.RFLX_Builtin_Types.Bit_Length range
     0 .. 2 ** 31 - 1;

   --  §6.9 — possible gate decisions.
   type Decision is (Decision_Allow,
                     Decision_Deny,
                     Decision_Flow_Error);

   type Gate is limited private;

   procedure Initialize (G : in out Gate)
   with
     Pre  => not Is_Active (G),
     Post => Is_Active (G);

   procedure Finalize (G : in out Gate)
   with
     Pre  => Is_Active (G),
     Post => not Is_Active (G);

   --  Driver asks: may I emit Bytes bytes of DATA right now?
   --  On Decision_Allow: both connection and stream windows are
   --  decremented by Bytes; driver MUST emit those bytes.
   --  On Decision_Deny: neither window changed; driver MUST NOT
   --  emit; driver should read peer frames (which feed back into
   --  Apply_Wu_*) until enough credit returns, then retry.
   --  On Decision_Flow_Error: structurally unreachable on this
   --  call (only Apply_Wu_* can drive the error) — kept for
   --  exhaustive case handling.
   procedure Request_Send
     (G        : in out Gate;
      Bytes    : Window_Bytes;
      Outcome  : out Decision)
   with
     Pre  => Is_Active (G),
     Post => Is_Active (G);

   --  Peer sent WINDOW_UPDATE on stream 0 — grow the connection
   --  window. Sets OK to False if §6.9.1 overflow would occur.
   procedure Apply_Wu_Conn
     (G     : in out Gate;
      Bytes : Window_Bytes;
      OK    : out Boolean)
   with
     Pre  => Is_Active (G) and then Bytes > 0,
     Post => Is_Active (G);

   --  Peer sent WINDOW_UPDATE on a stream != 0 — grow per-stream.
   procedure Apply_Wu_Stream
     (G     : in out Gate;
      Bytes : Window_Bytes;
      OK    : out Boolean)
   with
     Pre  => Is_Active (G) and then Bytes > 0,
     Post => Is_Active (G);

   --  Reset per-stream window to peer's SETTINGS_INITIAL_WINDOW_SIZE.
   --  Driver calls this exactly once per new HTTP/2 stream before
   --  any Request_Send for that stream.
   procedure Init_Stream
     (G     : in out Gate;
      Bytes : Window_Bytes)
   with
     Pre  => Is_Active (G),
     Post => Is_Active (G);

   function Is_Active (G : Gate) return Boolean
   with
     Ghost;

private

   type Gate is limited record
      Ctx : RFLX.Flow_Gate.Send_Gate.FSM.Context;
   end record;

   function Is_Active (G : Gate) return Boolean is
     (RFLX.Flow_Gate.Send_Gate.FSM.Initialized (G.Ctx));

end Http2_Core.Flow_Gate;
