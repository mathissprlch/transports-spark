--  Protobuf_Core.Wire — minimal SPARK Protocol Buffers wire codec.
--
--  Source: https://protobuf.dev/programming-guides/encoding/
--
--  v0.2 scope: just enough to encode and decode the request /
--  reply types of the helloworld.Greeter service (a single
--  string field per message). The full set of wire types is
--  declared so the decoder can skip unknown fields per the
--  proto3 forward-compatibility rule, but only the codecs we
--  exercise are implemented.
--
--  Operates on RFLX.RFLX_Types.Bytes slices so the same buffer
--  travels through Protobuf_Core.Wire → Grpc_Core.Framing →
--  Http2_Core.Connection without intermediate copies. No `new`,
--  no exceptions, all errors surface as Output_OK = False.

with Interfaces;

with RFLX.RFLX_Types;

package Protobuf_Core.Wire
  with SPARK_Mode, Always_Terminates
is

   use type RFLX.RFLX_Types.Index;

   subtype Index is RFLX.RFLX_Types.Index;
   subtype Bytes is RFLX.RFLX_Types.Bytes;

   --  Wire types per "Structure" section of the encoding spec.
   --  v0.2 surface only encodes/decodes Length_Delim; the others
   --  are kept for tag introspection.
   Wire_Varint       : constant := 0;
   Wire_Fixed_64     : constant := 1;
   Wire_Length_Delim : constant := 2;
   Wire_Fixed_32     : constant := 5;

   --  Worst-case bytes for a 64-bit varint per §"Base 128 Varints".
   Max_Varint_Bytes : constant := 10;

   ----------------------------------------------------------------
   --  Varint (§"Base 128 Varints")
   --
   --  Little-endian, 7 data bits per byte; MSB=1 means continue.
   --  Up to 10 bytes for a 64-bit value (the high byte holds at
   --  most 1 bit).
   ----------------------------------------------------------------

   procedure Encode_Varint
     (Buffer : in out Bytes;
      First  : Index;
      Value  : Interfaces.Unsigned_64;
      Last   : out Index;
      OK     : out Boolean)
   with
     Pre  => First in Buffer'Range,
     Post =>
       (if OK
        then
          Last in First .. Buffer'Last and then Last - First < Max_Varint_Bytes
        else Last = First);

   procedure Decode_Varint
     (Input : Bytes;
      First : Index;
      Value : out Interfaces.Unsigned_64;
      Last  : out Index;
      OK    : out Boolean)
   with
     Pre  => First in Input'Range,
     Post =>
       (if OK
        then
          Last in First .. Input'Last and then Last - First < Max_Varint_Bytes
        else Last = First);

   ----------------------------------------------------------------
   --  Tag = (Field_Number << 3) | Wire_Type  (varint-encoded)
   ----------------------------------------------------------------

   procedure Encode_Tag
     (Buffer    : in out Bytes;
      First     : Index;
      Field_Num : Positive;
      Wire      : Natural;
      Last      : out Index;
      OK        : out Boolean)
   with
     Pre  => First in Buffer'Range and then Wire <= 7,
     Post =>
       (if OK
        then
          Last in First .. Buffer'Last and then Last - First < Max_Varint_Bytes
        else Last = First);

   procedure Decode_Tag
     (Input     : Bytes;
      First     : Index;
      Field_Num : out Natural;
      Wire      : out Natural;
      Last      : out Index;
      OK        : out Boolean)
   with
     Pre  => First in Input'Range,
     Post =>
       (if OK
        then
          Last in First .. Input'Last and then Last - First < Max_Varint_Bytes
        else Last = First);

   ----------------------------------------------------------------
   --  String / bytes field (wire type Length_Delim).
   --
   --  Encode writes tag + varint length + raw bytes.
   --  Decode_String_Value consumes the varint length + that many
   --  bytes (caller has already read the tag with Decode_Tag).
   ----------------------------------------------------------------

   procedure Encode_String_Field
     (Buffer    : in out Bytes;
      First     : Index;
      Field_Num : Positive;
      Value     : String;
      Last      : out Index;
      OK        : out Boolean)
   with
     Pre  => First in Buffer'Range,
     Post => (if OK then Last in First .. Buffer'Last else Last = First);

   procedure Decode_String_Value
     (Input      : Bytes;
      First      : Index;
      Value      : out String;
      Value_Last : out Natural;
      Last       : out Index;
      OK         : out Boolean)
   with
     Pre  => First in Input'Range and then Value'Length > 0,
     Post =>
       (if OK
        then
          Last in First .. Input'Last
          and then Value_Last in 0 | Value'First .. Value'Last
        else Last = First and then Value_Last = 0);

end Protobuf_Core.Wire;
