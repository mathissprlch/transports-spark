--  Mqtt_Core.Client — synchronous, single-connection MQTT 3.1.1
--  client API.
--
--  Every request-response operation (Open, Subscribe, Unsubscribe,
--  Publish_Qos1, Receive_Publish) is driven by a generated session.rflx
--  state machine. The dispatch logic — what to do with each kind of
--  Server→Client packet that may arrive while we wait for a specific
--  reply — is verified at spec-compile time by RecordFlux's
--  exhaustiveness check; "forgot a packet type" is a spec error, not
--  a runtime bug. Wire compatibility against any compliant 3.1.1
--  broker follows from the spec, not from per-broker testing.
--
--  Inbound PUBLISHes that arrive while another operation is in
--  flight are queued in the Client record and drained by
--  Receive_Publish in arrival order. Per §3.3.4 the Server obligates
--  the Client to deliver subscribed PUBLISHes; we never drop one.
--
--  Buffer model: a single fixed-size Bytes_Ptr is allocated in Open
--  and freed in Close. No per-op heap traffic.
--
--  Out of scope (current version): QoS 1/2 retry on reconnect,
--  keep-alive PINGREQ scheduling in a background task, Will fields,
--  TLS. The wire / spec layers leave room for these without API
--  breakage.

with RFLX.RFLX_Types;
with RFLX.Control_Packet;

with Mqtt_Core.Transport;
with Mqtt_Core.Wire;

package Mqtt_Core.Client is

   type Client is limited private;

   --  Re-exports of the multi-topic filter types from Mqtt_Core.Wire,
   --  so callers don't need a second `with` clause for the simple case
   --  of building up SUBSCRIBE / UNSUBSCRIBE payloads.
   subtype Subscription_Filter  is Wire.Subscription_Filter;
   subtype Subscription_Filters is Wire.Subscription_Filters;
   subtype Topic_Filter         is Wire.Topic_Filter;
   subtype Topic_Filters        is Wire.Topic_Filters;

   --  Caller-supplied buffers. The Client takes ownership of all
   --  three on Attach (move semantics: caller's Bytes_Ptr variables
   --  are nilled). Detach returns them. The library NEVER calls
   --  `new`; the application decides where the bytes live (heap on
   --  hosted, .bss on bare-metal via custom storage pool).
   --
   --  Sizing: Buf is the Wire-encoder scratch; Inbound_Buf and
   --  Outgoing_Buf back the FSM's internal message contexts (per
   --  External_IO_Buffers in session.rfi). All three should be at
   --  least Buffer_Capacity bytes (256 in the current build).
   procedure Attach_Buffers
     (C            : in out Client;
      Buf          : in out RFLX.RFLX_Types.Bytes_Ptr;
      Inbound_Buf  : in out RFLX.RFLX_Types.Bytes_Ptr;
      Outgoing_Buf : in out RFLX.RFLX_Types.Bytes_Ptr);

   --  Reverse of Attach_Buffers. Call after Close (or instead of
   --  Close) to recover the buffers for re-use or deallocation by
   --  the application.
   procedure Detach_Buffers
     (C            : in out Client;
      Buf          : out RFLX.RFLX_Types.Bytes_Ptr;
      Inbound_Buf  : out RFLX.RFLX_Types.Bytes_Ptr;
      Outgoing_Buf : out RFLX.RFLX_Types.Bytes_Ptr);

   procedure Open
     (C             : in out Client;
      Host          : String;
      Port          : Natural := 1883;
      Client_Id     : String;
      Keep_Alive_S  : Natural := 60;
      Clean_Session : Boolean := True;
      Will_Topic    : String := "";
      Will_Message  : RFLX.RFLX_Types.Bytes := Wire.Empty_Bytes;
      Will_QoS      : RFLX.Control_Packet.QoS_Level :=
                        RFLX.Control_Packet.QOS_0;
      Will_Retain   : Boolean := False);

   --  Publish QoS 0 — fire-and-forget. No FSM (no reply, no dispatch).
   --  Retain=True asks the broker to store the message and replay
   --  it (with RETAIN=1) to subsequent SUBSCRIBEs that match the
   --  topic — see §3.3.1.3.
   procedure Publish
     (C       : in out Client;
      Topic   : String;
      Payload : RFLX.RFLX_Types.Bytes;
      Retain  : Boolean := False);

   --  Publish QoS 1 — sends PUBLISH, awaits PUBACK with matching id.
   --  Inbound PUBLISHes interleaved while waiting for PUBACK are
   --  enqueued for Receive_Publish to drain. No data is dropped.
   procedure Publish_Qos1
     (C       : in out Client;
      Topic   : String;
      Payload : RFLX.RFLX_Types.Bytes;
      Retain  : Boolean := False);

   --  Publish QoS 2 — four-step handshake (§4.3.3): client sends
   --  PUBLISH, awaits PUBREC, sends PUBREL, awaits PUBCOMP. Inbound
   --  PUBLISHes interleaved at either await stage are enqueued for
   --  Receive_Publish to drain. No data is dropped.
   procedure Publish_Qos2
     (C       : in out Client;
      Topic   : String;
      Payload : RFLX.RFLX_Types.Bytes;
      Retain  : Boolean := False);

   procedure Subscribe
     (C     : in out Client;
      Topic : String;
      QoS   : RFLX.Control_Packet.QoS_Level :=
        RFLX.Control_Packet.QOS_0);

   --  Subscribe to several Topic Filters in a single SUBSCRIBE packet
   --  (§3.8.3). Raises Subscribe_Failure if the broker returns Failure
   --  for *any* filter — caller can rebuild Filters with the bad ones
   --  removed and retry.
   procedure Subscribe_Many
     (C       : in out Client;
      Filters : Subscription_Filters);

   procedure Unsubscribe
     (C     : in out Client;
      Topic : String);

   --  Unsubscribe from several Topic Filters in one packet (§3.10.3).
   procedure Unsubscribe_Many
     (C       : in out Client;
      Filters : Topic_Filters);

   --  Block until the next inbound PUBLISH is available — first
   --  draining any PUBLISHes that were queued by a concurrent
   --  Subscribe / Unsubscribe / Publish_Qos1 / Open call, then
   --  reading from the network if the queue is empty.
   procedure Receive_Publish
     (C            : in out Client;
      Topic        : in out String;
      Topic_Last   :    out Natural;
      Payload      : in out RFLX.RFLX_Types.Bytes;
      Payload_Last :    out RFLX.RFLX_Types.Length);

   procedure Close (C : in out Client);

   --  Slam the socket shut without sending DISCONNECT. Useful for
   --  exercising the broker's Will/Testament path (§3.1.2.5) — the
   --  broker MUST then publish the Will message for clients that
   --  set Will_Topic on Open.
   procedure Drop (C : in out Client);

   Connect_Failure     : exception;
   Subscribe_Failure   : exception;
   Unsubscribe_Failure : exception;
   Publish_Failure     : exception;
   Receive_Failure     : exception;

private

   Buffer_Capacity      : constant := 256;
   Max_Queued_Publishes : constant := 4;

   --  One slot for a queued inbound PUBLISH packet. Stored as raw
   --  Incoming_Packet bytes; Receive_Publish decodes when draining.
   type Pending_Slot is record
      Buf    : RFLX.RFLX_Types.Bytes (1 .. Buffer_Capacity) :=
        (others => 0);
      Last   : RFLX.RFLX_Types.Index := 1;
      In_Use : Boolean := False;
   end record;

   type Pending_Array is
     array (1 .. Max_Queued_Publishes) of Pending_Slot;

   type Client is limited record
      Trans          : Transport.Channel;
      Buf            : RFLX.RFLX_Types.Bytes_Ptr := null;
      --  Inbound + Outgoing buffers required by the External_IO_
      --  Buffers state-machine API (.rfi files set this on every
      --  session machine). The FSM takes ownership of these at
      --  Initialize, returns at Finalize. Allocated once at Open,
      --  freed at Close. NOTE: between Initialize and Finalize
      --  these fields are null (FSM has them); the field is
      --  re-populated at Finalize.
      Inbound_Buf    : RFLX.RFLX_Types.Bytes_Ptr := null;
      Outgoing_Buf   : RFLX.RFLX_Types.Bytes_Ptr := null;
      Next_Packet_Id :
        RFLX.Control_Packet.Packet_Identifier := 1;
      Pending        : Pending_Array;
   end record;

end Mqtt_Core.Client;
