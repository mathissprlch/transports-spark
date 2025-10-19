with Ada.Streams;          use Ada.Streams;
with Interfaces;            use Interfaces;
with Protobuf.Wire;

package body Codegen.Plugin is

   --  Helpers replicated from the descriptor decoder. We could expose
   --  them from Protobuf.Descriptor, but they're tiny and keeping them
   --  local avoids a public-API change.

   function Bytes_To_String (B : Protobuf.IO.Octet_Array) return String is
      Result : String (1 .. Natural (B'Length));
   begin
      for I in Result'Range loop
         Result (I) := Character'Val
           (B (B'First + Stream_Element_Offset (I - 1)));
      end loop;
      return Result;
   end Bytes_To_String;

   function Read_String
     (Buffer : Protobuf.IO.Octet_Array;
      Cursor : in out Protobuf.IO.Read_Cursor) return Unbounded_String
   is
      Length : Protobuf.IO.Octet_Count;
   begin
      Protobuf.Wire.Decode_Length_Delim_Length (Cursor, Buffer, Length);
      return To_Unbounded_String
        (Bytes_To_String
           (Protobuf.IO.Take_Slice (Cursor, Buffer, Length)));
   end Read_String;

   function Read_Sub_Message
     (Buffer : Protobuf.IO.Octet_Array;
      Cursor : in out Protobuf.IO.Read_Cursor) return Protobuf.IO.Octet_Array
   is
      Length : Protobuf.IO.Octet_Count;
   begin
      Protobuf.Wire.Decode_Length_Delim_Length (Cursor, Buffer, Length);
      return Protobuf.IO.Take_Slice (Cursor, Buffer, Length);
   end Read_Sub_Message;

   --------------------
   -- Decode_Request --

   procedure Decode_Request
     (Buffer : Protobuf.IO.Octet_Array;
      Result : out Code_Generator_Request)
   is
      Cursor : Protobuf.IO.Read_Cursor;
      Num    : Protobuf.Wire.Field_Number;
      Wire   : Protobuf.Wire.Wire_Type;
   begin
      while Protobuf.IO.Available (Cursor, Buffer) > 0 loop
         Protobuf.Wire.Decode_Tag (Cursor, Buffer, Num, Wire);
         case Num is
            when 1 =>
               Result.Files_To_Generate.Append (Read_String (Buffer, Cursor));
            when 2 =>
               Result.Parameter := Read_String (Buffer, Cursor);
            when 15 =>
               declare
                  Sub : constant Protobuf.IO.Octet_Array :=
                    Read_Sub_Message (Buffer, Cursor);
                  F   : Protobuf.Descriptor.File_Descriptor;
                  --  Reuse the descriptor decoder by giving it a fake set
                  --  consisting of the single file. Cleaner: factor out
                  --  Decode_File. For now decode by wrapping in a 1-tuple.
                  Set : Protobuf.Descriptor.File_Descriptor_Set;
                  Wrapped_Buf : Protobuf.IO.Octet_Array
                    (1 .. Sub'Length + 16);
                  W : Protobuf.IO.Write_Cursor;
               begin
                  --  Wrap Sub as `FileDescriptorSet { file = Sub }` so the
                  --  existing Decode handles it.
                  Protobuf.Wire.Encode_Tag
                    (W, Wrapped_Buf, 1, Protobuf.Wire.Length_Delim);
                  Protobuf.Wire.Encode_Length_Delim_Bytes
                    (W, Wrapped_Buf, Sub);
                  Protobuf.Descriptor.Decode
                    (Wrapped_Buf (Wrapped_Buf'First ..
                                  Wrapped_Buf'First
                                  + Stream_Element_Offset (W.Position) - 1),
                     Set);
                  if not Set.Files.Is_Empty then
                     F := Set.Files.First_Element;
                     Result.Proto_Files.Append (F);
                  end if;
               end;
            when others =>
               Protobuf.Wire.Skip_Field (Cursor, Buffer, Wire);
         end case;
      end loop;
   end Decode_Request;

   ------------------------------
   -- Encoding helpers (output) --

   --  Write a length-delimited field with field number and bytes. Returns
   --  the new total byte count.
   procedure Write_String_Field
     (Buffer    : in out Protobuf.IO.Octet_Array;
      Cursor    : in out Protobuf.IO.Write_Cursor;
      Number    : Protobuf.Wire.Field_Number;
      Value     : Unbounded_String);

   procedure Write_String_Field
     (Buffer : in out Protobuf.IO.Octet_Array;
      Cursor : in out Protobuf.IO.Write_Cursor;
      Number : Protobuf.Wire.Field_Number;
      Value  : Unbounded_String)
   is
      S     : constant String := To_String (Value);
      Bytes : Protobuf.IO.Octet_Array (1 .. S'Length);
   begin
      for I in S'Range loop
         Bytes (Stream_Element_Offset (I)) :=
           Protobuf.IO.Octet (Character'Pos (S (I)));
      end loop;
      Protobuf.Wire.Encode_Tag
        (Cursor, Buffer, Number, Protobuf.Wire.Length_Delim);
      Protobuf.Wire.Encode_Length_Delim_Bytes (Cursor, Buffer, Bytes);
   end Write_String_Field;

   ---------------------
   -- Encode_Response --

   function Encode_Response
     (Resp : Code_Generator_Response) return Protobuf.IO.Octet_Array
   is
      --  Heap-allocate a generous buffer; codegen output is on the order
      --  of tens of KiB even for moderately sized .proto files.
      type Buf_Ptr is access all Protobuf.IO.Octet_Array;
      Buffer : constant Buf_Ptr :=
        new Protobuf.IO.Octet_Array (1 .. 16 * 1024 * 1024);
      Cursor : Protobuf.IO.Write_Cursor;
   begin
      if Length (Resp.Error) > 0 then
         Write_String_Field (Buffer.all, Cursor, 1, Resp.Error);
      end if;

      if Resp.Supported_Features /= 0 then
         Protobuf.Wire.Encode_Tag
           (Cursor, Buffer.all, 2, Protobuf.Wire.Varint);
         Protobuf.Wire.Encode_Varint_64
           (Cursor, Buffer.all, Resp.Supported_Features);
      end if;

      for F of Resp.Files loop
         declare
            type Inner_Ptr is access all Protobuf.IO.Octet_Array;
            Inner : constant Inner_Ptr :=
              new Protobuf.IO.Octet_Array (1 .. 4 * 1024 * 1024);
            Inner_C    : Protobuf.IO.Write_Cursor;
            Inner_Used : Protobuf.IO.Octet_Count;
         begin
            Write_String_Field (Inner.all, Inner_C, 1, F.File_Name);
            Write_String_Field (Inner.all, Inner_C, 15, F.Content);
            Inner_Used := Inner_C.Position;
            Protobuf.Wire.Encode_Tag
              (Cursor, Buffer.all, 15, Protobuf.Wire.Length_Delim);
            Protobuf.Wire.Encode_Length_Delim_Bytes
              (Cursor, Buffer.all,
               Inner.all (Inner.all'First
                          .. Inner.all'First
                             + Stream_Element_Offset (Inner_Used) - 1));
         end;
      end loop;

      return Buffer.all
        (Buffer.all'First
         .. Buffer.all'First + Stream_Element_Offset (Cursor.Position) - 1);
   end Encode_Response;

end Codegen.Plugin;
