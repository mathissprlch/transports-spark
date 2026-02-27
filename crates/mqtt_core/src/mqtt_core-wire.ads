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
     Post => Buffer /= null;  --  ownership returned to caller after encode/decode

   ---------------------------------------------------------------------
   --  DISCONNECT — §3.14. 2-byte fixed packet (0xE0 0x00).
   ---------------------------------------------------------------------

   procedure Encode_Disconnect
     (Buffer : in out Bytes_Ptr;
      Last   :    out Index)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 2,
     Post => Buffer /= null;  --  ownership returned to caller after encode/decode

   ---------------------------------------------------------------------
   --  CONNECT — §3.1. Encodes a CONNECT without Username/Password and
   --  without Will fields (the latter are deferred per coverage.md and
   --  forced to 0 in connect.rflx).
   --
   --  The Remaining Length field uses the single-byte varint form
   --  (spec restriction): packet size on the wire is at most 129 bytes
   --  (1 fixed-header byte + 1 RL byte + 127 payload).
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
     Post => Buffer /= null;  --  ownership returned to caller after encode/decode

   ---------------------------------------------------------------------
   --  CONNACK — §3.2. Decode a 4-byte server response.
   ---------------------------------------------------------------------

   subtype Return_Code is RFLX.Connack.Connect_Return_Code;

   procedure Decode_Connack
     (Buffer          : in out Bytes_Ptr;
      Last            : Index;
      Valid           :    out Boolean;
      Session_Present :    out Boolean;
      Code            :    out Return_Code)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 4,
     Post => Buffer /= null;  --  ownership returned to caller after encode/decode

   ---------------------------------------------------------------------
   --  PUBLISH (QoS 0) — §3.3. Application bytes published on a topic.
   --
   --  Forces DUP=0 and RETAIN=0 (RETAIN is deferred per coverage.md,
   --  see publish.rflx). Total wire size is bounded by the single-byte
   --  Remaining-Length cap: 2 + Topic'Length + Payload'Length <= 127.
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
     Post => Buffer /= null;  --  ownership returned to caller after encode/decode

   ---------------------------------------------------------------------
   --  PINGRESP — §3.13. Verify a 2-byte ping response from the broker.
   ---------------------------------------------------------------------

   procedure Decode_Pingresp
     (Buffer : in out Bytes_Ptr;
      Last   : Index;
      Valid  :    out Boolean)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 2,
     Post => Buffer /= null;  --  ownership returned to caller after encode/decode

   ---------------------------------------------------------------------
   --  SUBSCRIBE (single topic) — §3.8. Subscribes to one Topic Filter
   --  with one Requested QoS. A future multi-topic variant will take a
   --  caller-supplied subscription list.
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
     Post => Buffer /= null;  --  ownership returned to caller after encode/decode

   ---------------------------------------------------------------------
   --  SUBACK (single return code) — §3.9. Decodes the head Return Code
   --  from the SUBACK payload. A future multi-topic variant will yield
   --  the full sequence.
   ---------------------------------------------------------------------

   type Suback_Return_Code is
     (Granted_QoS_0,
      Granted_QoS_1,
      Granted_QoS_2,
      Failure);

   procedure Decode_Suback_Single
     (Buffer    : in out Bytes_Ptr;
      Last      : Index;
      Valid     :    out Boolean;
      Packet_Id :    out Packet_Identifier;
      Code      :    out Suback_Return_Code)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 5,
     Post => Buffer /= null;  --  ownership returned to caller after encode/decode

   ---------------------------------------------------------------------
   --  UNSUBSCRIBE (single topic) — §3.10. Sibling of
   --  Encode_Subscribe_Single without the Requested-QoS byte.
   ---------------------------------------------------------------------

   procedure Encode_Unsubscribe_Single
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier;
      Topic     : String)
   with
     Pre  => Buffer /= null
             and then Topic'Length in 1 .. 121
             and then Buffer'Length >= 6 + Topic'Length,
     Post => Buffer /= null;  --  ownership returned to caller after encode/decode

   ---------------------------------------------------------------------
   --  UNSUBACK — §3.11. Decode the 4-byte server response (fixed
   --  shape: Packet Identifier only, no payload).
   ---------------------------------------------------------------------

   procedure Decode_Unsuback
     (Buffer    : in out Bytes_Ptr;
      Last      : Index;
      Valid     :    out Boolean;
      Packet_Id :    out Packet_Identifier)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 4,
     Post => Buffer /= null;  --  ownership returned to caller after encode/decode

   ---------------------------------------------------------------------
   --  PUBLISH (decode) — extract Topic + Payload from an incoming
   --  PUBLISH. QoS 0 only (no Packet Identifier in the variable
   --  header); QoS 1/2 incoming will need a sibling procedure that
   --  also returns the Packet_Identifier.
   --
   --  Caller supplies max-sized String/Bytes; the procedure writes the
   --  actual length into Topic_Last/Payload_Last.
   ---------------------------------------------------------------------

   procedure Decode_Publish_Qos0
     (Buffer        : in out Bytes_Ptr;
      Last          : Index;
      Valid         :    out Boolean;
      Topic         : in out String;
      Topic_Last    :    out Natural;
      Payload       : in out RFLX.RFLX_Types.Bytes;
      Payload_Last  :    out RFLX.RFLX_Types.Length)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 4,
     Post => Buffer /= null;  --  ownership returned to caller after encode/decode

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
