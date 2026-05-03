--  Mqtt_Core.Broker — minimal MQTT 3.1.1 broker (single-client v0.2).
--
--  Accepts one TCP connection, drives the Session::Broker_Reading FSM
--  through CONNECT/CONNACK + the post-CONNECT dispatch loop, and
--  surfaces each inbound application packet to the caller via a
--  generic handler subprogram.
--
--  v0.2 limits:
--    * One client at a time (no accept-and-spawn).
--    * No topic routing — handler decides what to do with each
--      PUBLISH; a real broker would route to subscribed sessions.
--    * Single-filter SUBSCRIBE only (multi-filter is v0.3 work).
--    * QoS 0 + QoS 1 only on inbound PUBLISH; QoS 2 inbound stub.
--    * No persistent session, no will message, no retained.
--
--  Verification dividend lives in the Session::Broker_Reading FSM
--  (RFLX-generated): the post-CONNECT dispatch table enumerates
--  every legal client→server packet type from MQTT 3.1.1 §2.2.1
--  Table 2.1, exhaustiveness-checked at spec time.

with RFLX.RFLX_Types;
with RFLX.RFLX_Builtin_Types;
with RFLX.Control_Packet;

with Mqtt_Core.Transport;

package Mqtt_Core.Broker is

   type Listener is limited private;

   procedure Listen
     (L    : in out Listener;
      Host : String;
      Port : Natural := 1883);

   procedure Attach_Buffers
     (L            : in out Listener;
      Buf          : in out RFLX.RFLX_Types.Bytes_Ptr;
      Inbound_Buf  : in out RFLX.RFLX_Types.Bytes_Ptr;
      Outgoing_Buf : in out RFLX.RFLX_Types.Bytes_Ptr);

   procedure Detach_Buffers
     (L            : in out Listener;
      Buf          : out RFLX.RFLX_Types.Bytes_Ptr;
      Inbound_Buf  : out RFLX.RFLX_Types.Bytes_Ptr;
      Outgoing_Buf : out RFLX.RFLX_Types.Bytes_Ptr);

   procedure Stop (L : in out Listener);

   --  Handler invoked once per inbound application packet (PUBLISH /
   --  SUBSCRIBE / etc.). The Ada driver has already done the wire-
   --  level decode and any required ACK emission (PUBACK, SUBACK,
   --  PINGRESP) before calling the handler — handler is purely the
   --  application-level callback.
   type Event_Kind is
     (Client_Connected,    --  CONNECT received, CONNACK sent
      Client_Subscribed,   --  SUBSCRIBE received, SUBACK sent
      Publish_Received,    --  PUBLISH received, PUBACK sent if q1
      Pingreq_Received,    --  PINGREQ received, PINGRESP sent
      Client_Disconnected); --  DISCONNECT received

   generic
      with procedure On_Event
        (Kind         : Event_Kind;
         Client_Id    : String;
         Client_Id_Last : Natural;
         Topic        : String;
         Topic_Last   : Natural;
         Payload      : RFLX.RFLX_Types.Bytes;
         Payload_Last : RFLX.RFLX_Types.Length;
         QoS          : RFLX.Control_Packet.QoS_Level;
         Packet_Id    : RFLX.RFLX_Builtin_Types.Bit_Length);
   procedure Accept_And_Serve (L : in out Listener);

   Server_Error : exception;

private

   type Listener is limited record
      Trans         : Transport.Listener;
      Buf           : RFLX.RFLX_Types.Bytes_Ptr := null;
      Inbound_Buf   : RFLX.RFLX_Types.Bytes_Ptr := null;
      Outgoing_Buf  : RFLX.RFLX_Types.Bytes_Ptr := null;
   end record;

end Mqtt_Core.Broker;
