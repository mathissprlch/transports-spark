with Interfaces; use Interfaces;

package body GRPC.Framing is

   procedure Encode_Header
     (Buffer : in out Protobuf.IO.Octet_Array;
      Cursor : in out Protobuf.IO.Write_Cursor;
      Length : Unsigned_32;
      Flag   : Compression_Flag := 0)
   is
   begin
      Protobuf.IO.Write_Octet (Cursor, Buffer, Protobuf.IO.Octet (Flag));
      --  4 bytes big-endian.
      for Shift in reverse 0 .. 3 loop
         Protobuf.IO.Write_Octet
           (Cursor, Buffer,
            Protobuf.IO.Octet (Shift_Right (Length, Shift * 8) and 16#FF#));
      end loop;
   end Encode_Header;

   procedure Decode_Header
     (Buffer : Protobuf.IO.Octet_Array;
      Cursor : in out Protobuf.IO.Read_Cursor;
      Length : out Unsigned_32;
      Flag   : out Compression_Flag)
   is
      Octet : Protobuf.IO.Octet;
      Acc   : Unsigned_32 := 0;
   begin
      Protobuf.IO.Read_Octet (Cursor, Buffer, Octet);
      if Unsigned_8 (Octet) > 1 then
         raise Frame_Format_Error
           with "compression flag must be 0 or 1, got"
                & Unsigned_8 (Octet)'Image;
      end if;
      Flag := Compression_Flag (Octet);
      for I in 1 .. 4 loop
         Protobuf.IO.Read_Octet (Cursor, Buffer, Octet);
         Acc := Shift_Left (Acc, 8) or Unsigned_32 (Octet);
      end loop;
      Length := Acc;
   end Decode_Header;

end GRPC.Framing;
