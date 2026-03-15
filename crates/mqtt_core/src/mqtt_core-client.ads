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

   procedure Open
     (C             : in out Client;
      Host          : String;
      Port          : Natural := 1883;
      Client_Id     : String;
      Keep_Alive_S  : Natural := 60;
      Clean_Session : Boolean := True);

   --  Publish QoS 0 — fire-and-forget. No FSM (no reply, no dispatch).
   procedure Publish
     (C       : in out Client;
      Topic   : String;
      Payload : RFLX.RFLX_Types.Bytes);

   --  Publish QoS 1 — sends PUBLISH, awaits PUBACK with matching id.
   --  Inbound PUBLISHes interleaved while waiting for PUBACK are
   --  enqueued for Receive_Publish to drain. No data is dropped.
   procedure Publish_Qos1
     (C       : in out Client;
      Topic   : String;
      Payload : RFLX.RFLX_Types.Bytes);

   --  Publish QoS 2 — four-step handshake (§4.3.3): client sends
   --  PUBLISH, awaits PUBREC, sends PUBREL, awaits PUBCOMP. Inbound
   --  PUBLISHes interleaved at either await stage are enqueued for
   --  Receive_Publish to drain. No data is dropped.
   procedure Publish_Qos2
     (C       : in out Client;
      Topic   : String;
      Payload : RFLX.RFLX_Types.Bytes);

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
      Next_Packet_Id :
        RFLX.Control_Packet.Packet_Identifier := 1;
      Pending        : Pending_Array;
   end record;

end Mqtt_Core.Client;
