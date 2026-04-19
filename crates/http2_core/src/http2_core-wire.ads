--  Http2_Core.Wire — ergonomic encode/decode wrappers around the
--  HTTP/2 frame layer (RFC 9113 §4.1 + §6).
--
--  Mirrors the layout of Mqtt_Core.Wire: one Encode_X / Decode_X per
--  frame type we exchange. Each encoder produces the complete frame
--  on the wire (9-byte fixed header + payload); each decoder takes
--  a buffer slice that has already been read off the network and
--  extracts the body.
--
--  Output ownership: encoders take the byte buffer in/out and
--  return a Last index; the buffer remains the caller's. Decoders
--  do the same in reverse — they don't allocate.

with RFLX.RFLX_Types;
with RFLX.RFLX_Builtin_Types;
with RFLX.Http2_Parameters;

package Http2_Core.Wire
with SPARK_Mode
is

   subtype Bytes_Ptr is RFLX.RFLX_Types.Bytes_Ptr;
   subtype Index     is RFLX.RFLX_Types.Index;
   subtype Byte      is RFLX.RFLX_Builtin_Types.Byte;
   subtype Bit_Len   is RFLX.RFLX_Builtin_Types.Bit_Length;

   --  IANA-derived enums are Always_Valid, which generates a record
   --  wrapper around the Enum literal type (Known + Enum / Raw).
   --  For the wire layer we only ever deal with KNOWN values on
   --  encode and dispatch on the raw 8/16-bit byte value on decode,
   --  so the bare enum form is what callers want.
   subtype Frame_Type  is RFLX.Http2_Parameters.HTTP_2_Frame_Type_Enum;
   subtype Settings_Id is RFLX.Http2_Parameters.HTTP_2_Settings_Enum;

   use type RFLX.RFLX_Builtin_Types.Bytes_Ptr;
   use type RFLX.RFLX_Builtin_Types.Bit_Length;

   --  Connection preface (RFC 9113 §3.4) — 24 bytes the client MUST
   --  emit first thing on a fresh connection. Constant; never
   --  varies. Sent verbatim by the connection driver before any
   --  frame.
   Preface : constant String := "PRI * HTTP/2.0" & ASCII.CR & ASCII.LF
                                 & ASCII.CR & ASCII.LF
                                 & "SM" & ASCII.CR & ASCII.LF
                                 & ASCII.CR & ASCII.LF;

   ---------------------------------------------------------------------
   --  Frame flags (RFC 9113 §6) — bit positions for the flags byte.
   ---------------------------------------------------------------------

   Flag_END_STREAM   : constant Byte := 16#01#;  --  DATA, HEADERS
   Flag_ACK          : constant Byte := 16#01#;  --  SETTINGS, PING
   Flag_END_HEADERS  : constant Byte := 16#04#;  --  HEADERS, CONTINUATION
   Flag_PADDED       : constant Byte := 16#08#;  --  DATA, HEADERS
   Flag_PRIORITY     : constant Byte := 16#20#;  --  HEADERS

   ---------------------------------------------------------------------
   --  SETTINGS (RFC 9113 §6.5). Body is a sequence of 6-byte
   --  (Identifier:16, Value:32) parameters.
   ---------------------------------------------------------------------

   type Settings_Parameter is record
      Identifier : Settings_Id := RFLX.Http2_Parameters.HEADER_TABLE_SIZE;
      Value      : Bit_Len     := 0;
   end record;

   type Settings_List is array (Positive range <>) of Settings_Parameter;

   procedure Encode_Settings
     (Buffer : in out Bytes_Ptr;
      Last   :    out Index;
      Params : Settings_List)
   with
     Pre  => Buffer /= null
             and then Params'Length in 0 .. 16
             and then Buffer'Length >= 9 + 6 * Params'Length,
     Post => Buffer /= null;

   --  SETTINGS-ACK frame: empty body, ACK flag set, stream 0. RFC
   --  9113 §6.5.3 obligates the receiver of a SETTINGS frame to
   --  acknowledge.
   procedure Encode_Settings_Ack
     (Buffer : in out Bytes_Ptr;
      Last   :    out Index)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 9,
     Post => Buffer /= null;

   --  Decode a SETTINGS payload (assumed already separated from the
   --  9-byte fixed header by the caller — Buffer'First..Last is
   --  body bytes only). Fills Params up to its capacity; sets
   --  Params_Last to the count actually decoded; Valid=False if
   --  the body length isn't a multiple of 6.
   procedure Decode_Settings_Payload
     (Buffer       : RFLX.RFLX_Types.Bytes;
      Valid        :    out Boolean;
      Params       : in out Settings_List;
      Params_Last  :    out Natural)
   with
     Pre  => Params'Length in 1 .. 16;

   ---------------------------------------------------------------------
   --  PING (RFC 9113 §6.7). Fixed 8-byte opaque echo.
   ---------------------------------------------------------------------

   procedure Encode_Ping
     (Buffer       : in out Bytes_Ptr;
      Last         :    out Index;
      Opaque_Data  : RFLX.RFLX_Types.Bytes;
      Ack          : Boolean := False)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 17
             and then Opaque_Data'Length = 8,
     Post => Buffer /= null;

   ---------------------------------------------------------------------
   --  RST_STREAM (RFC 9113 §6.4). 4-byte error code body.
   ---------------------------------------------------------------------

   procedure Encode_Rst_Stream
     (Buffer     : in out Bytes_Ptr;
      Last       :    out Index;
      Stream_Id  : Bit_Len;
      Error_Code : Bit_Len)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 13
             and then Stream_Id in 1 .. 2 ** 31 - 1,
     Post => Buffer /= null;

   ---------------------------------------------------------------------
   --  WINDOW_UPDATE (RFC 9113 §6.9). 4-byte 31-bit increment.
   ---------------------------------------------------------------------

   procedure Encode_Window_Update
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Stream_Id : Bit_Len;
      Increment : Bit_Len)
   with
     Pre  => Buffer /= null and then Buffer'Length >= 13
             and then Stream_Id <= 2 ** 31 - 1
             and then Increment in 1 .. 2 ** 31 - 1,
     Post => Buffer /= null;

   ---------------------------------------------------------------------
   --  GOAWAY (RFC 9113 §6.8). 8-byte fixed prefix + opaque debug.
   ---------------------------------------------------------------------

   procedure Encode_Goaway
     (Buffer         : in out Bytes_Ptr;
      Last           :    out Index;
      Last_Stream_Id : Bit_Len;
      Error_Code     : Bit_Len;
      Debug_Data     : RFLX.RFLX_Types.Bytes)
   with
     Pre  => Buffer /= null
             and then Buffer'Length >= 17 + Debug_Data'Length
             and then Last_Stream_Id <= 2 ** 31 - 1,
     Post => Buffer /= null;

   ---------------------------------------------------------------------
   --  HEADERS (RFC 9113 §6.2). Caller pre-encodes the HPACK fragment
   --  via Http2_Core.Hpack.Encode and passes the resulting bytes here.
   --  END_STREAM is signalled via the eponymous flag.
   ---------------------------------------------------------------------

   procedure Encode_Headers
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Stream_Id : Bit_Len;
      Fragment  : RFLX.RFLX_Types.Bytes;
      End_Stream : Boolean)
   with
     Pre  => Buffer /= null
             and then Buffer'Length >= 9 + Fragment'Length
             and then Stream_Id in 1 .. 2 ** 31 - 1
             and then Fragment'Length <= 2 ** 14,
     Post => Buffer /= null;

   ---------------------------------------------------------------------
   --  DATA (RFC 9113 §6.1). Application bytes. END_STREAM flag for
   --  the final chunk.
   ---------------------------------------------------------------------

   procedure Encode_Data
     (Buffer     : in out Bytes_Ptr;
      Last       :    out Index;
      Stream_Id  : Bit_Len;
      Payload    : RFLX.RFLX_Types.Bytes;
      End_Stream : Boolean)
   with
     Pre  => Buffer /= null
             and then Buffer'Length >= 9 + Payload'Length
             and then Stream_Id in 1 .. 2 ** 31 - 1
             and then Payload'Length <= 2 ** 14,
     Post => Buffer /= null;

   ---------------------------------------------------------------------
   --  Decode a 9-byte frame fixed header at the start of `Buffer`.
   --  Used by the connection driver to dispatch incoming bytes
   --  before routing the Payload tail to a per-type decoder.
   ---------------------------------------------------------------------

   type Frame_Header is record
      Length            : Bit_Len    := 0;
      Frame_Type_Value  : Frame_Type := RFLX.Http2_Parameters.DATA;
      Flags             : Byte       := 0;
      Stream_Identifier : Bit_Len    := 0;
   end record;

   procedure Decode_Frame_Header
     (Buffer : RFLX.RFLX_Types.Bytes;
      Header : out Frame_Header;
      Valid  : out Boolean)
   with
     Pre => Buffer'Length >= 9;

end Http2_Core.Wire;
