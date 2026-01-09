package body Protobuf.Wire.Extras is

   procedure Encode_Sub_Message_Field
     (C         : in out Protobuf.IO.Write_Cursor;
      Buffer    : in out Protobuf.IO.Octet_Array;
      Number    : Field_Number;
      Sub_Bytes : Protobuf.IO.Octet_Array)
   is
   begin
      Encode_Tag (C, Buffer, Number, Length_Delim);
      Encode_Length_Delim_Bytes (C, Buffer, Sub_Bytes);
   end Encode_Sub_Message_Field;

end Protobuf.Wire.Extras;
