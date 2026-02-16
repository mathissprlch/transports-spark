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

end Mqtt_Core.Wire;
