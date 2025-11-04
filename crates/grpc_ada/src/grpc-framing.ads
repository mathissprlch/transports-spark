--  GRPC.Framing
--
--  The length-prefix used inside HTTP/2 DATA frames carrying gRPC
--  messages. Per https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md
--
--    Length-Prefixed-Message = Compressed-Flag Message-Length Message
--    Compressed-Flag         = 0 / 1                  ; 1 byte
--    Message-Length          = {length of Message}    ; 4 bytes, big-endian
--    Message                 = *{binary octet}        ; the encoded payload

with Ada.Streams;
with Interfaces;
with Protobuf.IO;

package GRPC.Framing
  with Pure
is
   use type Ada.Streams.Stream_Element_Offset;

   Header_Size : constant := 5;

   subtype Compression_Flag is Interfaces.Unsigned_8 range 0 .. 1;

   procedure Encode_Header
     (Buffer  : in out Protobuf.IO.Octet_Array;
      Cursor  : in out Protobuf.IO.Write_Cursor;
      Length  : Interfaces.Unsigned_32;
      Flag    : Compression_Flag := 0)
     with Pre => Protobuf.IO.Free (Cursor, Buffer) >= Header_Size;

   procedure Decode_Header
     (Buffer  : Protobuf.IO.Octet_Array;
      Cursor  : in out Protobuf.IO.Read_Cursor;
      Length  : out Interfaces.Unsigned_32;
      Flag    : out Compression_Flag);

   Frame_Format_Error : exception;

end GRPC.Framing;
