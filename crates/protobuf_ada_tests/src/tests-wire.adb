with Ada.Streams;
with Interfaces;        use Interfaces;
with Protobuf.IO;
with Protobuf.Wire;
with Test_Support;

package body Tests.Wire is

   use type Ada.Streams.Stream_Element;
   use type Ada.Streams.Stream_Element_Offset;
   use type Protobuf.Wire.Wire_Type;

   type Int32_Array is array (Positive range <>) of Integer_32;
   type Int64_Array is array (Positive range <>) of Integer_64;

   procedure Roundtrip_Varint_32_Small is
      Buffer : Protobuf.IO.Octet_Array (1 .. 16) := [others => 0];
      W      : Protobuf.IO.Write_Cursor;
      R      : Protobuf.IO.Read_Cursor;
      V      : Unsigned_32;
   begin
      Protobuf.Wire.Encode_Varint_32 (W, Buffer, 0);
      Protobuf.Wire.Encode_Varint_32 (W, Buffer, 1);
      Protobuf.Wire.Encode_Varint_32 (W, Buffer, 127);
      Protobuf.Wire.Encode_Varint_32 (W, Buffer, 128);
      Protobuf.Wire.Encode_Varint_32 (W, Buffer, 16383);
      Protobuf.Wire.Encode_Varint_32 (W, Buffer, 16384);
      Test_Support.Assert (W.Position = 1 + 1 + 1 + 2 + 2 + 3,
                           "Varint widths for boundary values");
      Protobuf.Wire.Decode_Varint_32 (R, Buffer, V);
      Test_Support.Assert (V = 0, "decode 0");
      Protobuf.Wire.Decode_Varint_32 (R, Buffer, V);
      Test_Support.Assert (V = 1, "decode 1");
      Protobuf.Wire.Decode_Varint_32 (R, Buffer, V);
      Test_Support.Assert (V = 127, "decode 127");
      Protobuf.Wire.Decode_Varint_32 (R, Buffer, V);
      Test_Support.Assert (V = 128, "decode 128");
      Protobuf.Wire.Decode_Varint_32 (R, Buffer, V);
      Test_Support.Assert (V = 16383, "decode 16383");
      Protobuf.Wire.Decode_Varint_32 (R, Buffer, V);
      Test_Support.Assert (V = 16384, "decode 16384");
   end Roundtrip_Varint_32_Small;

   procedure Roundtrip_Varint_32_Max is
      Buffer : Protobuf.IO.Octet_Array (1 .. 16) := [others => 0];
      W      : Protobuf.IO.Write_Cursor;
      R      : Protobuf.IO.Read_Cursor;
      V      : Unsigned_32;
   begin
      Protobuf.Wire.Encode_Varint_32 (W, Buffer, Unsigned_32'Last);
      Test_Support.Assert (W.Position = 5, "Unsigned_32'Last takes 5 bytes");
      Protobuf.Wire.Decode_Varint_32 (R, Buffer, V);
      Test_Support.Assert (V = Unsigned_32'Last, "roundtrip Unsigned_32'Last");
   end Roundtrip_Varint_32_Max;

   procedure Roundtrip_Varint_64 is
      Buffer : Protobuf.IO.Octet_Array (1 .. 32) := [others => 0];
      W      : Protobuf.IO.Write_Cursor;
      R      : Protobuf.IO.Read_Cursor;
      V      : Unsigned_64;
   begin
      Protobuf.Wire.Encode_Varint_64 (W, Buffer, 0);
      Protobuf.Wire.Encode_Varint_64 (W, Buffer, 16#1_0000_0000#);
      Protobuf.Wire.Encode_Varint_64 (W, Buffer, Unsigned_64'Last);
      Test_Support.Assert (W.Position = 1 + 5 + 10,
                           "Unsigned_64'Last takes 10 bytes");
      Protobuf.Wire.Decode_Varint_64 (R, Buffer, V);
      Test_Support.Assert (V = 0, "decode 0");
      Protobuf.Wire.Decode_Varint_64 (R, Buffer, V);
      Test_Support.Assert (V = 16#1_0000_0000#, "decode 2^32");
      Protobuf.Wire.Decode_Varint_64 (R, Buffer, V);
      Test_Support.Assert (V = Unsigned_64'Last, "decode Unsigned_64'Last");
   end Roundtrip_Varint_64;

   procedure Roundtrip_ZigZag is
   begin
      Test_Support.Assert (Protobuf.Wire.ZigZag_Encode_32 (0)  = 0,  "zz(0) = 0");
      Test_Support.Assert (Protobuf.Wire.ZigZag_Encode_32 (-1) = 1,  "zz(-1) = 1");
      Test_Support.Assert (Protobuf.Wire.ZigZag_Encode_32 (1)  = 2,  "zz(1) = 2");
      Test_Support.Assert (Protobuf.Wire.ZigZag_Encode_32 (-2) = 3,  "zz(-2) = 3");
      Test_Support.Assert (Protobuf.Wire.ZigZag_Encode_32 (Integer_32'Last)
                           = 16#FFFF_FFFE#, "zz(I32 max)");
      Test_Support.Assert (Protobuf.Wire.ZigZag_Encode_32 (Integer_32'First)
                           = 16#FFFF_FFFF#, "zz(I32 min)");

      declare
         Samples_32 : constant Int32_Array :=
           [0, 1, -1, 1234, -1234, Integer_32'Last, Integer_32'First];
         Samples_64 : constant Int64_Array :=
           [0, 1, -1, Integer_64'Last, Integer_64'First];
      begin
         for Sample of Samples_32 loop
            Test_Support.Assert
              (Protobuf.Wire.ZigZag_Decode_32
                 (Protobuf.Wire.ZigZag_Encode_32 (Sample)) = Sample,
               "zz roundtrip 32");
         end loop;
         for Sample of Samples_64 loop
            Test_Support.Assert
              (Protobuf.Wire.ZigZag_Decode_64
                 (Protobuf.Wire.ZigZag_Encode_64 (Sample)) = Sample,
               "zz roundtrip 64");
         end loop;
      end;
   end Roundtrip_ZigZag;

   procedure Roundtrip_Fixed is
      Buffer : Protobuf.IO.Octet_Array (1 .. 16) := [others => 0];
      W      : Protobuf.IO.Write_Cursor;
      R      : Protobuf.IO.Read_Cursor;
      U32    : Unsigned_32;
      U64    : Unsigned_64;
   begin
      Protobuf.Wire.Encode_Fixed_32 (W, Buffer, 16#DEAD_BEEF#);
      Protobuf.Wire.Encode_Fixed_64 (W, Buffer, 16#0123_4567_89AB_CDEF#);
      Test_Support.Assert (Buffer (1) = 16#EF#, "fixed32 LE byte 0");
      Test_Support.Assert (Buffer (4) = 16#DE#, "fixed32 LE byte 3");
      Protobuf.Wire.Decode_Fixed_32 (R, Buffer, U32);
      Test_Support.Assert (U32 = 16#DEAD_BEEF#, "fixed32 roundtrip");
      Protobuf.Wire.Decode_Fixed_64 (R, Buffer, U64);
      Test_Support.Assert (U64 = 16#0123_4567_89AB_CDEF#, "fixed64 roundtrip");
   end Roundtrip_Fixed;

   procedure Roundtrip_Tag is
      Buffer : Protobuf.IO.Octet_Array (1 .. 16) := [others => 0];
      W      : Protobuf.IO.Write_Cursor;
      R      : Protobuf.IO.Read_Cursor;
      Num    : Protobuf.Wire.Field_Number;
      Wire   : Protobuf.Wire.Wire_Type;
   begin
      Protobuf.Wire.Encode_Tag (W, Buffer, 1, Protobuf.Wire.Varint);
      Protobuf.Wire.Encode_Tag (W, Buffer, 16, Protobuf.Wire.Length_Delim);
      Protobuf.Wire.Encode_Tag (W, Buffer, 2049, Protobuf.Wire.Fixed_32);

      Protobuf.Wire.Decode_Tag (R, Buffer, Num, Wire);
      Test_Support.Assert (Num = 1 and Wire = Protobuf.Wire.Varint,
                           "tag (1, Varint)");
      Protobuf.Wire.Decode_Tag (R, Buffer, Num, Wire);
      Test_Support.Assert (Num = 16 and Wire = Protobuf.Wire.Length_Delim,
                           "tag (16, Length_Delim)");
      Protobuf.Wire.Decode_Tag (R, Buffer, Num, Wire);
      Test_Support.Assert (Num = 2049 and Wire = Protobuf.Wire.Fixed_32,
                           "tag (2049, Fixed_32)");
   end Roundtrip_Tag;

   procedure Run is
   begin
      Test_Support.Run_Test ("Roundtrip_Varint_32_Small",
                             Roundtrip_Varint_32_Small'Access);
      Test_Support.Run_Test ("Roundtrip_Varint_32_Max",
                             Roundtrip_Varint_32_Max'Access);
      Test_Support.Run_Test ("Roundtrip_Varint_64",
                             Roundtrip_Varint_64'Access);
      Test_Support.Run_Test ("Roundtrip_ZigZag",
                             Roundtrip_ZigZag'Access);
      Test_Support.Run_Test ("Roundtrip_Fixed",
                             Roundtrip_Fixed'Access);
      Test_Support.Run_Test ("Roundtrip_Tag",
                             Roundtrip_Tag'Access);
   end Run;

end Tests.Wire;
