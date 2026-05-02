with Interfaces; use Interfaces;

package body Protobuf_Core.Wire
with SPARK_Mode
is

   use type RFLX.RFLX_Types.Index;

   subtype U8 is RFLX.RFLX_Types.Byte;

   ----------------------------------------------------------------
   --  Encode_Varint
   ----------------------------------------------------------------

   procedure Encode_Varint
     (Buffer : in out Bytes;
      First  : Index;
      Value  : Interfaces.Unsigned_64;
      Last   : out Index;
      OK     : out Boolean)
   is
      V   : Unsigned_64 := Value;
      Cur : Index := First;
   begin
      Last := First;
      OK   := False;

      loop
         if Cur > Buffer'Last then
            return;
         end if;

         if V < 16#80# then
            Buffer (Cur) := U8 (V);
            Last := Cur;
            OK   := True;
            return;
         end if;

         Buffer (Cur) := U8 ((V and 16#7F#) or 16#80#);
         V   := Shift_Right (V, 7);
         Cur := Cur + 1;
      end loop;
   end Encode_Varint;

   ----------------------------------------------------------------
   --  Decode_Varint
   ----------------------------------------------------------------

   procedure Decode_Varint
     (Input  : Bytes;
      First  : Index;
      Value  : out Interfaces.Unsigned_64;
      Last   : out Index;
      OK     : out Boolean)
   is
      Cur   : Index := First;
      Shift : Natural := 0;
      Acc   : Unsigned_64 := 0;
      B     : U8;
   begin
      Value := 0;
      Last  := First;
      OK    := False;

      for I in 1 .. Max_Varint_Bytes loop
         pragma Loop_Invariant (Cur >= First);
         if Cur > Input'Last then
            return;
         end if;

         B := Input (Cur);
         Acc := Acc or
           Shift_Left (Unsigned_64 (B) and 16#7F#, Shift);

         if (Unsigned_64 (B) and 16#80#) = 0 then
            Value := Acc;
            Last  := Cur;
            OK    := True;
            return;
         end if;

         Shift := Shift + 7;
         Cur   := Cur + 1;
      end loop;

      --  More than 10 continuation bytes: malformed.
      return;
   end Decode_Varint;

   ----------------------------------------------------------------
   --  Encode_Tag / Decode_Tag
   ----------------------------------------------------------------

   procedure Encode_Tag
     (Buffer    : in out Bytes;
      First     : Index;
      Field_Num : Positive;
      Wire      : Natural;
      Last      : out Index;
      OK        : out Boolean)
   is
      Tag : constant Unsigned_64 :=
        Shift_Left (Unsigned_64 (Field_Num), 3) or Unsigned_64 (Wire);
   begin
      Encode_Varint (Buffer, First, Tag, Last, OK);
   end Encode_Tag;

   procedure Decode_Tag
     (Input     : Bytes;
      First     : Index;
      Field_Num : out Natural;
      Wire      : out Natural;
      Last      : out Index;
      OK        : out Boolean)
   is
      Tag : Unsigned_64;
   begin
      Field_Num := 0;
      Wire      := 0;

      Decode_Varint (Input, First, Tag, Last, OK);
      if not OK then
         return;
      end if;

      Wire      := Natural (Tag and 7);
      Field_Num := Natural (Shift_Right (Tag, 3));
      if Field_Num = 0 then
         OK := False;
      end if;
   end Decode_Tag;

   ----------------------------------------------------------------
   --  Encode_String_Field
   ----------------------------------------------------------------

   procedure Encode_String_Field
     (Buffer    : in out Bytes;
      First     : Index;
      Field_Num : Positive;
      Value     : String;
      Last      : out Index;
      OK        : out Boolean)
   is
      Tag_Last : Index;
      Len_Last : Index;
   begin
      Last := First;
      OK   := False;

      Encode_Tag
        (Buffer, First, Field_Num, Wire_Length_Delim, Tag_Last, OK);
      if not OK then
         return;
      end if;

      if Tag_Last = Buffer'Last then
         OK := False;
         return;
      end if;

      Encode_Varint
        (Buffer, Tag_Last + 1,
         Unsigned_64 (Value'Length), Len_Last, OK);
      if not OK then
         return;
      end if;

      if Value'Length = 0 then
         Last := Len_Last;
         OK   := True;
         return;
      end if;

      if Index (Value'Length) > Buffer'Last - Len_Last then
         OK := False;
         return;
      end if;

      --  Loop from 1 instead of 0: RFLX.RFLX_Types.Index has First = 1,
      --  so Index (0) raises Constraint_Error. Same trap as the
      --  iteration-01 bug in http2_core-connection.adb body copy.
      for I in 1 .. Value'Length loop
         Buffer (Len_Last + Index (I)) :=
           U8 (Character'Pos (Value (Value'First + I - 1)));
      end loop;

      Last := Len_Last + Index (Value'Length);
      OK   := True;
   end Encode_String_Field;

   ----------------------------------------------------------------
   --  Decode_String_Value
   ----------------------------------------------------------------

   procedure Decode_String_Value
     (Input      : Bytes;
      First      : Index;
      Value      : out String;
      Value_Last : out Natural;
      Last       : out Index;
      OK         : out Boolean)
   is
      Len_Val  : Unsigned_64;
      Len_Last : Index;
   begin
      Value      := (others => Character'Val (0));
      Value_Last := 0;
      Last       := First;
      OK         := False;

      Decode_Varint (Input, First, Len_Val, Len_Last, OK);
      if not OK then
         return;
      end if;

      if Len_Val = 0 then
         Last       := Len_Last;
         Value_Last := 0;
         OK         := True;
         return;
      end if;

      if Len_Val > Unsigned_64 (Input'Last - Len_Last) then
         OK := False;
         return;
      end if;
      if Len_Val > Unsigned_64 (Value'Length) then
         OK := False;
         return;
      end if;

      declare
         L : constant Natural := Natural (Len_Val);
      begin
         for I in 1 .. L loop
            Value (Value'First + I - 1) :=
              Character'Val
                (Natural (Input (Len_Last + Index (I))));
         end loop;
         Value_Last := Value'First + L - 1;
         Last       := Len_Last + Index (L);
         OK         := True;
      end;
   end Decode_String_Value;

end Protobuf_Core.Wire;
