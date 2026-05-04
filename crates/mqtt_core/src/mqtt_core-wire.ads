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
with RFLX.Suback;

package Mqtt_Core.Wire
with SPARK_Mode
is

   subtype Bytes_Ptr is RFLX.RFLX_Types.Bytes_Ptr;
   subtype Index     is RFLX.RFLX_Types.Index;

   use type RFLX.RFLX_Builtin_Types.Bytes_Ptr;

   subtype Keep_Alive        is RFLX.Connect.Keep_Alive;
   subtype Packet_Identifier is RFLX.Control_Packet.Packet_Identifier;
   subtype QoS_Level         is RFLX.Control_Packet.QoS_Level;

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

   --  §3.1 — broker side: decode an inbound CONNECT. v0.2 surfaces
   --  client_id only; clean_session, keep-alive and other fields are
   --  parsed by the underlying RFLX message but we only echo the
   --  client id back. Returns Valid=False if the packet doesn't
   --  parse as a Connect::Packet.
   procedure Decode_Connect
     (Buffer    : in out Bytes_Ptr;
      Last      : Index;
      Valid     :    out Boolean;
      Client_Id : out String;
      Cid_Last  : out Natural)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 12
             and then Client_Id'Length > 0,
     Post => Buffer /= null;

   --  §3.2 — broker side: encode a CONNACK with given session-present
   --  bit + return code. v0.2 broker always emits Session_Present=0
   --  + ACCEPTED; the helper preserves the full surface for refused-
   --  CONNECT use.
   procedure Encode_Connack
     (Buffer          : in out Bytes_Ptr;
      Last            :    out Index;
      Session_Present : Boolean := False;
      Return_Code     : RFLX.Connack.Connect_Return_Code :=
                          RFLX.Connack.ACCEPTED)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 4,
     Post => Buffer /= null;

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
   --  PUBLISH (QoS 1) — §3.3 with QoS=1 + Packet Identifier.
   --
   --  Forces DUP=0 (no retransmission yet) and RETAIN=0 (deferred).
   --  Wire size bound: 4 + Topic'Length + Payload'Length <= 127
   --  (extra 2 bytes vs QoS 0 for the Packet Identifier).
   ---------------------------------------------------------------------

   procedure Encode_Publish_Qos1
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier;
      Topic     : String;
      Payload   : RFLX.RFLX_Types.Bytes)
   with
     Pre  => Buffer /= null
             and then Topic'Length in 1 .. 122
             and then Payload'Length <= 123 - Topic'Length
             and then Buffer'Length >= 6 + Topic'Length + Payload'Length,
     Post => Buffer /= null;  --  ownership returned to caller after encode/decode

   ---------------------------------------------------------------------
   --  PUBACK — §3.4. Decode the 4-byte ack from the broker for a
   --  QoS 1 PUBLISH we sent.
   ---------------------------------------------------------------------

   procedure Decode_Puback
     (Buffer    : in out Bytes_Ptr;
      Last      : Index;
      Valid     :    out Boolean;
      Packet_Id :    out Packet_Identifier)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 4,
     Post => Buffer /= null;  --  ownership returned to caller after encode/decode

   ---------------------------------------------------------------------
   --  PUBACK (encode) — §3.4. Emit the 4-byte ack the Client owes the
   --  broker after receiving an inbound QoS 1 PUBLISH (§4.3.2).
   --  Wire form: 0x40 0x02 PI_high PI_low.
   ---------------------------------------------------------------------

   procedure Encode_Puback
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 4,
     Post => Buffer /= null;  --  ownership returned to caller after encode/decode

   ---------------------------------------------------------------------
   --  PUBLISH (QoS 2) — §3.3 with QoS=2 + Packet Identifier. Same
   --  wire shape as QoS 1; only the QoS sub-field differs (10b).
   ---------------------------------------------------------------------

   procedure Encode_Publish_Qos2
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier;
      Topic     : String;
      Payload   : RFLX.RFLX_Types.Bytes)
   with
     Pre  => Buffer /= null
             and then Topic'Length in 1 .. 122
             and then Payload'Length <= 123 - Topic'Length
             and then Buffer'Length >= 6 + Topic'Length + Payload'Length,
     Post => Buffer /= null;  --  ownership returned to caller after encode/decode

   ---------------------------------------------------------------------
   --  PUBREC — §3.5. Decode the broker's response to our QoS 2 PUBLISH.
   ---------------------------------------------------------------------

   procedure Decode_Pubrec
     (Buffer    : in out Bytes_Ptr;
      Last      : Index;
      Valid     :    out Boolean;
      Packet_Id :    out Packet_Identifier)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 4,
     Post => Buffer /= null;  --  ownership returned to caller after encode/decode

   --  §3.5 — encode our PUBREC reply to the broker for an inbound q2
   --  PUBLISH. Echoes the Packet Identifier from the PUBLISH.
   procedure Encode_Pubrec
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 4,
     Post => Buffer /= null;

   ---------------------------------------------------------------------
   --  PUBREL — §3.6. Encode the third leg of QoS 2 (sender releases
   --  the Packet Identifier after PUBREC). 4 bytes (0x62 0x02 + Pid).
   ---------------------------------------------------------------------

   procedure Encode_Pubrel
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 4,
     Post => Buffer /= null;  --  ownership returned to caller after encode/decode

   --  §3.6 — decode an inbound PUBREL (broker→us, third leg of inbound q2).
   procedure Decode_Pubrel
     (Buffer    : in out Bytes_Ptr;
      Last      : Index;
      Valid     :    out Boolean;
      Packet_Id :    out Packet_Identifier)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 4,
     Post => Buffer /= null;

   ---------------------------------------------------------------------
   --  PUBCOMP — §3.7. Decode the final QoS 2 ack from the broker.
   ---------------------------------------------------------------------

   --  §3.7 — encode our PUBCOMP, the final leg of inbound q2.
   procedure Encode_Pubcomp
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 4,
     Post => Buffer /= null;

   procedure Decode_Pubcomp
     (Buffer    : in out Bytes_Ptr;
      Last      : Index;
      Valid     :    out Boolean;
      Packet_Id :    out Packet_Identifier)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 4,
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
   --  Multi-topic SUBSCRIBE / UNSUBSCRIBE bounds.
   --
   --  The 1-byte-varint Remaining-Length cap forces the full packet
   --  body to fit in 127 bytes; with N filters that's 5 + 3*N +
   --  sum(topic_len) <= 127 for SUBSCRIBE (per-filter overhead = 3
   --  bytes: 2-byte length prefix + 1-byte Requested QoS) and
   --  4 + 2*N + sum(topic_len) <= 127 for UNSUBSCRIBE.
   ---------------------------------------------------------------------

   Max_Topic_Length    : constant := 120;
   Max_Filters_Per_Pkt : constant := 8;

   type Subscription_Filter is record
      Topic      : String (1 .. Max_Topic_Length) := (others => ' ');
      Topic_Last : Natural := 0;
      QoS        : QoS_Level := RFLX.Control_Packet.QOS_0;
   end record;

   type Subscription_Filters is
     array (Positive range <>) of Subscription_Filter;

   function Make_Subscription
     (Topic : String;
      QoS   : QoS_Level := RFLX.Control_Packet.QOS_0)
      return Subscription_Filter
   with Pre => Topic'Length in 1 .. Max_Topic_Length;

   type Topic_Filter is record
      Topic      : String (1 .. Max_Topic_Length) := (others => ' ');
      Topic_Last : Natural := 0;
   end record;

   type Topic_Filters is array (Positive range <>) of Topic_Filter;

   function Make_Topic_Filter (Topic : String) return Topic_Filter
   with Pre => Topic'Length in 1 .. Max_Topic_Length;

   ---------------------------------------------------------------------
   --  SUBSCRIBE (single topic) — §3.8. Convenience wrapper around the
   --  multi-topic encoder for the common one-filter case.
   ---------------------------------------------------------------------

   procedure Encode_Subscribe_Single
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier;
      Topic     : String;
      QoS       : QoS_Level := RFLX.Control_Packet.QOS_0)
   with
     Pre  => Buffer /= null
             and then Topic'Length in 1 .. Max_Topic_Length
             and then Buffer'Length >= 7 + Topic'Length,
     Post => Buffer /= null;  --  ownership returned to caller after encode/decode

   ---------------------------------------------------------------------
   --  SUBSCRIBE (multi-topic) — §3.8. Encodes a list of Topic Filter +
   --  Requested QoS pairs in a single SUBSCRIBE packet (§3.8.3).
   ---------------------------------------------------------------------

   procedure Encode_Subscribe
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier;
      Filters   : Subscription_Filters)
   with
     Pre  => Buffer /= null
             and then Buffer'Length >= 130
             and then Filters'Length in 1 .. Max_Filters_Per_Pkt,
     Post => Buffer /= null;  --  ownership returned to caller after encode/decode

   ---------------------------------------------------------------------
   --  SUBACK return code — §3.9.3. Per-filter outcome the broker
   --  reports back; one entry per Topic Filter sent in the SUBSCRIBE.
   ---------------------------------------------------------------------

   type Suback_Return_Code is
     (Granted_QoS_0,
      Granted_QoS_1,
      Granted_QoS_2,
      Failure);

   type Suback_Code_Array is array (Positive range <>) of Suback_Return_Code;

   ---------------------------------------------------------------------
   --  SUBACK (single return code) — §3.9. Convenience wrapper for the
   --  one-filter case; pulls the head of the return-code list.
   ---------------------------------------------------------------------

   --  §3.8 — broker side: decode an inbound SUBSCRIBE, surface the
   --  packet identifier + first topic filter. v0.2 supports only
   --  single-filter subscribe in the broker's decode path; multi-
   --  filter SUBSCRIBE handling is a v0.3 feature.
   procedure Decode_Subscribe
     (Buffer       : in out Bytes_Ptr;
      Last         : Index;
      Valid        :    out Boolean;
      Packet_Id    :    out Packet_Identifier;
      Topic_Filter : out String;
      Filter_Last  : out Natural;
      Requested_QoS : out RFLX.Control_Packet.QoS_Level)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 8
             and then Topic_Filter'Length > 0,
     Post => Buffer /= null;

   --  §3.9 — broker side: encode a SUBACK with one return code
   --  echoing the granted QoS. v0.2 broker grants whatever the
   --  client requested.
   procedure Encode_Suback_Single
     (Buffer      : in out Bytes_Ptr;
      Last        :    out Index;
      Packet_Id   : Packet_Identifier;
      Granted_QoS : RFLX.Suback.Return_Code := RFLX.Suback.SUCCESS_QOS_0)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 5,
     Post => Buffer /= null;

   --  §3.8 — broker-side multi-filter SUBSCRIBE decode. Surfaces up
   --  to Filter_Topics'Last filters; each Filter_Lasts(I) gives the
   --  meaningful slice of Filter_Topics(I). Sets Filter_Count to the
   --  number of filters parsed (may be < input N if the array is
   --  smaller than the SUBSCRIBE).
   type Filter_Topic_Array is
     array (Positive range <>) of String (1 .. 256);
   type Filter_Last_Array is array (Positive range <>) of Natural;
   type Filter_QoS_Array is
     array (Positive range <>)
       of RFLX.Control_Packet.QoS_Level;

   procedure Decode_Subscribe_Filters
     (Buffer       : in out Bytes_Ptr;
      Last         : Index;
      Valid        :    out Boolean;
      Packet_Id    :    out Packet_Identifier;
      Filter_Topics : out Filter_Topic_Array;
      Filter_Lasts  : out Filter_Last_Array;
      Filter_QoS    : out Filter_QoS_Array;
      Filter_Count  : out Natural)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 8
             and then Filter_Topics'Length = Filter_Lasts'Length
             and then Filter_Topics'Length = Filter_QoS'Length
             and then Filter_Topics'Length > 0,
     Post => Buffer /= null;

   --  §3.9 — broker-side multi-return-code SUBACK encode. Emits one
   --  return code per granted filter in order.
   type Suback_Wire_Codes is
     array (Positive range <>) of RFLX.Suback.Return_Code;

   procedure Encode_Suback
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier;
      Codes     : Suback_Wire_Codes)
   with
     Pre  => Buffer /= null and then Codes'Length > 0
             and then Buffer'Length >= 4 + Codes'Length,
     Post => Buffer /= null;

   --  §3.13 — broker side: respond to PINGREQ. Fixed 2-byte response.
   procedure Encode_Pingresp
     (Buffer : in out Bytes_Ptr;
      Last   :    out Index)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 2,
     Post => Buffer /= null;

   --  §3.10 — broker side: decode an inbound UNSUBSCRIBE. Just
   --  surfaces the packet identifier; the broker uses Client_Id +
   --  topic-filter scan to drop matching subscriptions (caller
   --  loops over Decode_Unsubscribe_Filter).
   procedure Decode_Unsubscribe_Pid
     (Buffer    : in out Bytes_Ptr;
      Last      : Index;
      Valid     :    out Boolean;
      Packet_Id : out Packet_Identifier)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 5,
     Post => Buffer /= null;

   --  §3.11 — broker side: encode UNSUBACK echoing packet_id.
   procedure Encode_Unsuback
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 4,
     Post => Buffer /= null;

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
   --  SUBACK (multi return code) — §3.9. Fills `Codes` with the list
   --  of per-filter outcomes; sets `Codes_Last` to the index of the
   --  last filled slot. Caller's array must accommodate at least the
   --  expected number of codes (matching Filters'Length on the
   --  preceding SUBSCRIBE).
   ---------------------------------------------------------------------

   procedure Decode_Suback
     (Buffer     : in out Bytes_Ptr;
      Last       : Index;
      Valid      :    out Boolean;
      Packet_Id  :    out Packet_Identifier;
      Codes      : in out Suback_Code_Array;
      Codes_Last :    out Natural)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 5
             and then Codes'Length in 1 .. Max_Filters_Per_Pkt,
     Post => Buffer /= null;  --  ownership returned to caller after encode/decode

   ---------------------------------------------------------------------
   --  UNSUBSCRIBE (single topic) — §3.10. Convenience wrapper around
   --  the multi-topic encoder.
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
   --  UNSUBSCRIBE (multi-topic) — §3.10. Encodes a list of Topic
   --  Filters in one packet.
   ---------------------------------------------------------------------

   procedure Encode_Unsubscribe
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Packet_Id : Packet_Identifier;
      Filters   : Topic_Filters)
   with
     Pre  => Buffer /= null
             and then Buffer'Length >= 130
             and then Filters'Length in 1 .. Max_Filters_Per_Pkt,
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
   --  PUBLISH (decode) — extract QoS, Packet Identifier (only when
   --  QoS > 0), Topic, and Payload from an incoming PUBLISH.
   --
   --  For QoS 0 the spec omits the Packet Identifier from the variable
   --  header, so Packet_Id is set to 1 (the lowest legal value) and
   --  must be ignored by the caller.
   --
   --  Caller supplies max-sized String/Bytes; the procedure writes the
   --  actual length into Topic_Last/Payload_Last.
   ---------------------------------------------------------------------

   procedure Decode_Publish
     (Buffer       : in out Bytes_Ptr;
      Last         : Index;
      Valid        :    out Boolean;
      QoS          :    out QoS_Level;
      Packet_Id    :    out Packet_Identifier;
      Topic        : in out String;
      Topic_Last   :    out Natural;
      Payload      : in out RFLX.RFLX_Types.Bytes;
      Payload_Last :    out RFLX.RFLX_Types.Length)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 4,
     Post => Buffer /= null;  --  ownership returned to caller after encode/decode

   ---------------------------------------------------------------------
   --  PUBLISH (decode header only) — extract QoS + Packet Identifier
   --  without touching Topic / Payload. Used by the client to PUBACK
   --  inbound QoS 1 PUBLISHes the moment they arrive (§4.3.2), before
   --  the application has drained the body out of the pending queue.
   ---------------------------------------------------------------------

   procedure Decode_Publish_Header
     (Buffer    : in out Bytes_Ptr;
      Last      : Index;
      Valid     :    out Boolean;
      QoS       :    out QoS_Level;
      Packet_Id :    out Packet_Identifier)
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
