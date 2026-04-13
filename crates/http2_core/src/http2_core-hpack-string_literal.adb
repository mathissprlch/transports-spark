with Http2_Core.Hpack.Int_Codec;
with Http2_Core.Hpack.Huffman;

package body Http2_Core.Hpack.String_Literal
with SPARK_Mode
is

   use type Interfaces.Unsigned_8;

   subtype U8 is Interfaces.Unsigned_8;

   --  Type adapters: the Octet_Array we use here is structurally
   --  identical to the Int_Codec.Octet_Array and Huffman.Octet_Array.
   --  Subprograms that take an array slice and return one ought to
   --  share a single nominal type, but Ada's nominal typing makes
   --  separate per-package types the simplest way to keep coupling
   --  obvious. The conversion is byte-for-byte.

   function To_Int_Codec (A : Octet_Array)
     return Int_Codec.Octet_Array;
   function To_Int_Codec (A : Octet_Array)
     return Int_Codec.Octet_Array
   is
      Result : Int_Codec.Octet_Array (A'Range);
   begin
      for I in A'Range loop
         Result (I) := Int_Codec.Octet (A (I));
      end loop;
      return Result;
   end To_Int_Codec;

   function To_Huffman (A : Octet_Array)
     return Huffman.Octet_Array;
   function To_Huffman (A : Octet_Array)
     return Huffman.Octet_Array
   is
      Result : Huffman.Octet_Array (A'Range);
   begin
      for I in A'Range loop
         Result (I) := Huffman.Octet (A (I));
      end loop;
      return Result;
   end To_Huffman;

   procedure Encode_Raw
     (Input       : Octet_Array;
      Output      : in out Octet_Array;
      Output_Last : out Natural;
      Output_OK   : out Boolean)
   is
      Len_Last  : Natural;
      Len_OK    : Boolean;
      Out_Idx   : Integer;
      Ic_Output : Int_Codec.Octet_Array (Output'Range);
   begin
      --  Set the H bit (= 0) at the first byte. Encode_Integer
      --  ORs the prefix value into Output(First) without touching
      --  the high bit, so we explicitly clear it.
      Output (Output'First) := 0;
      Ic_Output (Output'First) := 0;
      Int_Codec.Encode
        (Value       => Input'Length,
         N           => 7,
         Output      => Ic_Output,
         Output_Last => Len_Last,
         Output_OK   => Len_OK);
      if not Len_OK then
         Output_OK   := False;
         Output_Last := Output'First - 1;
         return;
      end if;
      --  Copy the integer-encoded length prefix back into Output.
      for I in Output'First .. Len_Last loop
         Output (I) := U8 (Ic_Output (I));
      end loop;

      Out_Idx := Len_Last;
      if Input'Length > 0 then
         if Out_Idx + Input'Length > Output'Last then
            Output_OK   := False;
            Output_Last := Output'First - 1;
            return;
         end if;
         for I in Input'Range loop
            Out_Idx := Out_Idx + 1;
            Output (Out_Idx) := Input (I);
         end loop;
      end if;
      Output_Last := Out_Idx;
      Output_OK   := True;
   end Encode_Raw;

   procedure Decode
     (Input       : Octet_Array;
      First       : Positive;
      Output      : in out Octet_Array;
      Last        : out Natural;
      Output_Last : out Natural;
      Output_OK   : out Boolean)
   is
      Huffman_Bit : constant U8 := 16#80#;
      H_Set       : constant Boolean :=
        (Input (First) and Huffman_Bit) /= 0;
      Length      : Natural;
      Len_Last    : Natural;
      Len_OK      : Boolean;
      Data_First  : Positive;
      Data_Last   : Natural;
      Ic_Input    : constant Int_Codec.Octet_Array := To_Int_Codec (Input);
   begin
      Output_OK   := False;
      Last        := First - 1;
      Output_Last := Output'First - 1;

      Int_Codec.Decode
        (Input     => Ic_Input,
         First     => First,
         N         => 7,
         Value     => Length,
         Last      => Len_Last,
         Output_OK => Len_OK);
      if not Len_OK then
         return;
      end if;
      if Length = 0 then
         Last      := Len_Last;
         Output_OK := True;
         return;
      end if;
      Data_First := Len_Last + 1;
      if Data_First > Input'Last then
         return;  --  truncated
      end if;
      Data_Last := Data_First + Length - 1;
      if Data_Last > Input'Last then
         return;  --  truncated
      end if;

      if not H_Set then
         --  Raw bytes — copy straight through.
         if Output'Length < Length then
            return;
         end if;
         declare
            Out_Idx : Integer := Output'First - 1;
         begin
            for I in Data_First .. Data_Last loop
               Out_Idx := Out_Idx + 1;
               Output (Out_Idx) := Input (I);
            end loop;
            Output_Last := Out_Idx;
         end;
      else
         --  Huffman: feed the data bytes through the codec.
         declare
            Hbuf       : constant Huffman.Octet_Array :=
              To_Huffman (Input (Data_First .. Data_Last));
            Hout       : Huffman.Octet_Array (Output'Range);
            H_Last     : Natural;
            H_OK       : Boolean;
         begin
            Huffman.Decode
              (Input       => Hbuf,
               Output      => Hout,
               Output_Last => H_Last,
               Output_OK   => H_OK);
            if not H_OK then
               return;
            end if;
            for I in Output'First .. H_Last loop
               Output (I) := U8 (Hout (I));
            end loop;
            Output_Last := H_Last;
         end;
      end if;

      Last      := Data_Last;
      Output_OK := True;
   end Decode;

end Http2_Core.Hpack.String_Literal;
