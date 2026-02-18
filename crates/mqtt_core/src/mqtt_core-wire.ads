--  Mqtt_Core.Wire — ergonomic encode/decode wrappers around the
--  RecordFlux-generated packet contexts. Hides the buffer/cursor
--  bookkeeping of `RFLX.<Packet>.Packet.{Initialize, Set_*, Get_*,
--  Verify_Message, Take_Buffer}` behind flat procedures that take
--  Ada-native types and a single byte buffer.
--
--  The wire layer is only responsible for *one packet at a time*. The
--  caller decides how packets are framed and dispatched on the
--  network — that is the job of `Mqtt_Core.Client`.
--
--  Buffer ownership: encode procedures take the byte buffer in/out
--  and return a `Last` index; the buffer is the caller's to free or
--  re-use. Decode procedures do the same in reverse.

with RFLX.RFLX_Types;
with RFLX.RFLX_Builtin_Types;
with RFLX.Connect;
with RFLX.Connack;
with RFLX.Control_Packet;

package Mqtt_Core.Wire
with SPARK_Mode
is

   subtype Bytes_Ptr is RFLX.RFLX_Types.Bytes_Ptr;
   subtype Index     is RFLX.RFLX_Types.Index;

   use type RFLX.RFLX_Builtin_Types.Bytes_Ptr;

   subtype Keep_Alive is RFLX.Connect.Keep_Alive;

   ---------------------------------------------------------------------
   --  PINGREQ — §3.12. 2-byte fixed packet (0xC0 0x00).
   ---------------------------------------------------------------------

   procedure Encode_Pingreq
     (Buffer : in out Bytes_Ptr;
      Last   :    out Index)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 2,
     Post => Buffer = null;

   ---------------------------------------------------------------------
   --  DISCONNECT — §3.14. 2-byte fixed packet (0xE0 0x00).
   ---------------------------------------------------------------------

   procedure Encode_Disconnect
     (Buffer : in out Bytes_Ptr;
      Last   :    out Index)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 2,
     Post => Buffer = null;

   ---------------------------------------------------------------------
   --  CONNECT — §3.1. v0.2 minimal: no Username/Password (Mosquitto
   --  local-test usage). Will fields are deferred per coverage.md.
   --
   --  The v0.2 RecordFlux spec restricts the Remaining Length field to
   --  a single varint byte (max 127). The buffer must therefore hold
   --  at most 129 bytes (1 fixed-header byte + 1 RL byte + 127).
   ---------------------------------------------------------------------

   procedure Encode_Connect
     (Buffer        : in out Bytes_Ptr;
      Last          :    out Index;
      Client_Id     : String;
      Keep_Alive_S  : Keep_Alive;
      Clean_Session : Boolean := True)
   with
     Pre  => Buffer /= null
             and then Buffer'Length >= 14 + Client_Id'Length
             and then Client_Id'Length in 1 .. 115,
     Post => Buffer = null;

   ---------------------------------------------------------------------
   --  CONNACK — §3.2. Decode a 4-byte server response.
   ---------------------------------------------------------------------

   subtype Return_Code is RFLX.Connack.Connect_Return_Code;

   procedure Decode_Connack
     (Buffer          : in out Bytes_Ptr;
      Valid           :    out Boolean;
      Session_Present :    out Boolean;
      Code            :    out Return_Code)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 4,
     Post => Buffer = null;

   ---------------------------------------------------------------------
   --  PUBLISH (QoS 0) — §3.3. Application bytes published on a topic.
   --
   --  v0.2 minimal: DUP=0, QoS=0, RETAIN=0 (deferred). RL is single
   --  varint byte so the sum (2 + Topic'Length + Payload'Length)
   --  must fit in 0..127.
   ---------------------------------------------------------------------

   procedure Encode_Publish_Qos0
     (Buffer  : in out Bytes_Ptr;
      Last    :    out Index;
      Topic   : String;
      Payload : RFLX.RFLX_Types.Bytes)
   with
     Pre  => Buffer /= null
             and then Topic'Length in 1 .. 124
             and then Payload'Length <= 125 - Topic'Length
             and then Buffer'Length >= 4 + Topic'Length + Payload'Length,
     Post => Buffer = null;

   ---------------------------------------------------------------------
   --  PINGRESP — §3.13. Verify a 2-byte ping response from the broker.
   ---------------------------------------------------------------------

   procedure Decode_Pingresp
     (Buffer : in out Bytes_Ptr;
      Valid  :    out Boolean)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 2,
     Post => Buffer = null;

   ---------------------------------------------------------------------
   --  SUBSCRIBE (single topic) — §3.8. v0.2 demo path.
   ---------------------------------------------------------------------

   subtype Packet_Identifier is RFLX.Control_Packet.Packet_Identifier;
   subtype QoS_Level         is RFLX.Control_Packet.QoS_Level;

   procedure Encode_Subscribe_Single
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier;
      Topic     : String;
      QoS       : QoS_Level := RFLX.Control_Packet.QOS_0)
   with
     Pre  => Buffer /= null
             and then Topic'Length in 1 .. 120
             and then Buffer'Length >= 7 + Topic'Length,
     Post => Buffer = null;

   ---------------------------------------------------------------------
   --  SUBACK (single return code) — §3.9. v0.2 demo path.
   ---------------------------------------------------------------------

   type Suback_Return_Code is
     (Granted_QoS_0,
      Granted_QoS_1,
      Granted_QoS_2,
      Failure);

   procedure Decode_Suback_Single
     (Buffer    : in out Bytes_Ptr;
      Valid     :    out Boolean;
      Packet_Id :    out Packet_Identifier;
      Code      :    out Suback_Return_Code)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 5,
     Post => Buffer = null;

   ---------------------------------------------------------------------
   --  PUBLISH (decode) — extract Topic + Payload from an incoming
   --  PUBLISH. v0.2: QoS 0 only (no Packet Identifier consumption).
   --
   --  Caller supplies max-sized String/Bytes; the procedure writes the
   --  actual length into Topic_Last/Payload_Last (one-past-the-end of
   --  written data, or 'First - 1 if empty).
   ---------------------------------------------------------------------

   procedure Decode_Publish_Qos0
     (Buffer        : in out Bytes_Ptr;
      Valid         :    out Boolean;
      Topic         : in out String;
      Topic_Last    :    out Natural;
      Payload       : in out RFLX.RFLX_Types.Bytes;
      Payload_Last  :    out RFLX.RFLX_Types.Length)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 4,
     Post => Buffer = null;

   ---------------------------------------------------------------------
   --  Peek at the high 4 bits of a buffer's first byte to dispatch on
   --  incoming packet type without parsing the whole message yet.
   ---------------------------------------------------------------------

   function Peek_Packet_Type
     (Buffer : RFLX.RFLX_Types.Bytes)
      return RFLX.Control_Packet.Packet_Type
   with
     Pre => Buffer'Length >= 1;

end Mqtt_Core.Wire;
