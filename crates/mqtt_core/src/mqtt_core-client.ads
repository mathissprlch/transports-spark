--  Mqtt_Core.Client — synchronous, single-connection MQTT 3.1.1
--  client API.
--
--  Wires Mqtt_Core.Transport (TCP) and Mqtt_Core.Wire (RecordFlux
--  encoders / decoders) into a request-response API:
--
--    Open        sends CONNECT, awaits CONNACK
--    Subscribe   sends SUBSCRIBE, awaits SUBACK
--    Publish     fire-and-forget QoS 0
--    Receive_*   blocks for next inbound packet
--    Close       sends DISCONNECT, closes the socket
--
--  Buffer model: Open allocates a single fixed-size byte buffer in the
--  Client record; every operation reuses it. Close frees it. There are
--  no per-operation heap allocations on the steady-state path.
--
--  Out of scope (current implementation): QoS 1/2 retry, keep-alive
--  PINGREQ scheduling in a background task, last-will, server-initiated
--  reconnection. The API shape leaves room to add these without
--  breaking callers.

with RFLX.RFLX_Types;
with RFLX.Control_Packet;

with Mqtt_Core.Transport;

package Mqtt_Core.Client is

   type Client is limited private;

   ---------------------------------------------------------------------
   --  Open: TCP connect + MQTT handshake.
   ---------------------------------------------------------------------

   procedure Open
     (C             : in out Client;
      Host          : String;
      Port          : Natural := 1883;
      Client_Id     : String;
      Keep_Alive_S  : Natural := 60;
      Clean_Session : Boolean := True);

   ---------------------------------------------------------------------
   --  Publish QoS 0 (fire-and-forget). Topic + payload together must
   --  fit within the spec's single-byte Remaining-Length cap.
   ---------------------------------------------------------------------

   procedure Publish
     (C       : in out Client;
      Topic   : String;
      Payload : RFLX.RFLX_Types.Bytes);

   ---------------------------------------------------------------------
   --  Publish QoS 1: send PUBLISH with a Packet Identifier, then block
   --  until the broker's PUBACK with a matching id arrives.
   ---------------------------------------------------------------------

   procedure Publish_Qos1
     (C       : in out Client;
      Topic   : String;
      Payload : RFLX.RFLX_Types.Bytes);

   ---------------------------------------------------------------------
   --  Publish QoS 1, FSM-driven variant.
   --
   --  Uses the generated session.rflx Publish_Qos1 state machine to
   --  drive the protocol exchange, including correct handling of any
   --  inbound PUBLISH that arrives in the Awaiting_Puback window
   --  (forwarded via the FSM's App_Pending channel; this initial
   --  version drains that channel into a discard buffer, but the
   --  shape is in place for the next iteration to re-queue it for
   --  Receive_Publish).
   --
   --  The state-machine dispatch is exhaustively verified by RecordFlux
   --  at spec-compile time: any Server→Client packet type MQTT 3.1.1
   --  permits is handled (or routed to error) explicitly.
   ---------------------------------------------------------------------

   procedure Publish_Qos1_FSM
     (C       : in out Client;
      Topic   : String;
      Payload : RFLX.RFLX_Types.Bytes);

   ---------------------------------------------------------------------
   --  Subscribe to a single topic, await SUBACK.
   ---------------------------------------------------------------------

   procedure Subscribe
     (C     : in out Client;
      Topic : String;
      QoS   : RFLX.Control_Packet.QoS_Level :=
        RFLX.Control_Packet.QOS_0);

   ---------------------------------------------------------------------
   --  Unsubscribe from a single topic, await UNSUBACK.
   ---------------------------------------------------------------------

   procedure Unsubscribe
     (C     : in out Client;
      Topic : String);

   ---------------------------------------------------------------------
   --  Block until the next inbound PUBLISH arrives. PINGRESP and other
   --  in-band server traffic are silently skipped.
   --
   --  Topic / Payload buffers are caller-allocated; the procedure
   --  writes into them and reports the actual lengths.
   ---------------------------------------------------------------------

   procedure Receive_Publish
     (C            : in out Client;
      Topic        : in out String;
      Topic_Last   :    out Natural;
      Payload      : in out RFLX.RFLX_Types.Bytes;
      Payload_Last :    out RFLX.RFLX_Types.Length);

   ---------------------------------------------------------------------
   --  Close: send DISCONNECT, close the socket, release buffer.
   ---------------------------------------------------------------------

   procedure Close (C : in out Client);

   ---------------------------------------------------------------------
   --  Errors. Exceptions chosen for ergonomics; a SPARK-compatible
   --  status-return variant can be added later.
   ---------------------------------------------------------------------

   Connect_Failure     : exception;
   Subscribe_Failure   : exception;
   Unsubscribe_Failure : exception;
   Publish_Failure     : exception;
   Receive_Failure     : exception;

private

   --  Re-usable I/O buffer size. The current Remaining-Length spec is
   --  the single-byte varint form (max 127), so the largest packet on
   --  the wire is 129 bytes (1 fixed-header byte + 1 RL byte + 127).
   --  256 leaves headroom for when the spec's RL is widened.
   Buffer_Capacity : constant := 256;

   type Client is limited record
      Trans          : Transport.Channel;
      Buf            : RFLX.RFLX_Types.Bytes_Ptr := null;
      Next_Packet_Id :
        RFLX.Control_Packet.Packet_Identifier := 1;
   end record;

end Mqtt_Core.Client;
