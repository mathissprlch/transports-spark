--  Helper for emitting a sub-message field. Lives in its own child
--  package so the codegen `with` clause is independent of the wire
--  primitives and easy to drop into generated bodies.

with Protobuf.IO;

package Protobuf.Wire.Extras is

   --  Encode a length-delimited sub-message field. Sub_Bytes is the
   --  pre-encoded inner message; the caller produced it by calling the
   --  nested type's Encode procedure into a stack buffer.
   procedure Encode_Sub_Message_Field
     (C         : in out Protobuf.IO.Write_Cursor;
      Buffer    : in out Protobuf.IO.Octet_Array;
      Number    : Field_Number;
      Sub_Bytes : Protobuf.IO.Octet_Array);

end Protobuf.Wire.Extras;
