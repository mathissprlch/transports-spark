with Interfaces; use Interfaces;

package body Protobuf_Core.Wire
with SPARK_Mode
is

   use type RFLX.RFLX_Types.Length;

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
      OK := False;

      --  Bounded loop: a 64-bit varint never exceeds Max_Varint_Bytes
      --  bytes (the high byte holds at most 1 data bit), so we
      --  always exit either by writing a final non-continuation
      --  byte or by running out of buffer.
      for I in 1 .. Max_Varint_Bytes loop
         pragma Loop_Invariant (Cur >= First);
         pragma Loop_Invariant
           (Cur - First = RFLX.RFLX_Types.Index'Base (I - 1));
         pragma Loop_Invariant (not OK);

         if Cur > Buffer'Last then
            Last := First;
            return;
         end if;

         if V < 16#80# then
            Buffer (Cur) := U8 (V);
            Last := Cur;
            OK   := True;
            return;
         end if;

         Buffer (Cur) := U8 ((V and 16#7F#) or 16#80#);
         V := Shift_Right (V, 7);

         --  Need room to advance for the next byte. If we're at
         --  Buffer'Last and V is still continuation, the value
         --  doesn't fit.
         if Cur = Buffer'Last then
            Last := First;
            return;
         end if;

         exit when I = Max_Varint_Bytes;
         Cur := Cur + 1;  --  safe: Cur < Buffer'Last ≤ Index'Last
      end loop;

      --  Fell through the loop without finding a terminating byte
      --  (would require V > 0 after 10 7-bit shifts, impossible for
      --  a 64-bit value, but we keep the safe-fail branch).
      Last := First;
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
      OK    := False;

      for I in 1 .. Max_Varint_Bytes loop
         pragma Loop_Invariant (Cur >= First);
         pragma Loop_Invariant
           (Cur - First = RFLX.RFLX_Types.Index'Base (I - 1));
         pragma Loop_Invariant (Shift = 7 * (I - 1));
         pragma Loop_Invariant (not OK);

         if Cur > Input'Last then
            Last := First;
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

         --  Cur must advance for the next iteration; if we're at
         --  Input'Last we can't, so the varint is truncated.
         if Cur = Input'Last then
            Last := First;
            return;
         end if;

         Shift := Shift + 7;
         exit when I = Max_Varint_Bytes;
         Cur := Cur + 1;
      end loop;

      --  More than 10 continuation bytes: malformed.
      Last := First;
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

      Wire := Natural (Tag and 7);
      --  Field_Num is bounded above by 2**29-1 (Field_Number range);
      --  varint of any 32-bit value fits in 5 bytes, so the shift
      --  yields at most 2**61-1, which fits Natural on a 64-bit host
      --  but NOT on 32-bit. Cap before converting.
      declare
         Shifted : constant Unsigned_64 := Shift_Right (Tag, 3);
         Max_FN  : constant Unsigned_64 :=
           Unsigned_64 (Natural'Last);
      begin
         if Shifted = 0 or else Shifted > Max_FN then
            --  Reject: zero field number is reserved; > Natural'Last
            --  doesn't fit our public type. Reset Last so the Post's
            --  "OK = False ⇒ Last = First" holds.
            Last := First;
            Wire := 0;
            OK   := False;
            return;
         end if;
         Field_Num := Natural (Shifted);
      end;
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
      --  Every path below assigns Last + OK explicitly, so we don't
      --  pre-initialise here; gnatprove's flow analysis covers it.
      Encode_Tag
        (Buffer, First, Field_Num, Wire_Length_Delim, Tag_Last, OK);
      if not OK then
         Last := First;
         return;
      end if;

      if Tag_Last >= Buffer'Last then
         Last := First;
         OK   := False;
         return;
      end if;

      Encode_Varint
        (Buffer, Tag_Last + 1,
         Unsigned_64 (Value'Length), Len_Last, OK);
      if not OK then
         Last := First;
         return;
      end if;

      if Value'Length = 0 then
         Last := Len_Last;
         OK   := True;
         return;
      end if;

      --  Bounds check: Value'Length must fit in the remaining buffer
      --  AFTER Len_Last. Note Len_Last is in Buffer'Range.
      if RFLX.RFLX_Types.Length (Value'Length) >
           RFLX.RFLX_Types.Length (Buffer'Last - Len_Last)
      then
         Last := First;
         OK   := False;
         return;
      end if;

      --  Loop from 1 instead of 0: RFLX.RFLX_Types.Index has First = 1,
      --  so Index (0) raises Constraint_Error. Same trap as the
      --  iteration-01 bug in http2_core-connection.adb body copy.
      for I in 1 .. Value'Length loop
         pragma Loop_Invariant
           (Len_Last + RFLX.RFLX_Types.Index'Base (I) <= Buffer'Last);
         Buffer (Len_Last + RFLX.RFLX_Types.Index'Base (I)) :=
           U8 (Character'Pos (Value (Value'First + (I - 1))));
      end loop;

      Last := Len_Last + RFLX.RFLX_Types.Index'Base (Value'Length);
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
      --  Every path assigns Last, Value_Last and OK explicitly. Value
      --  is `out String`, must be fully initialised by the procedure.
      Value      := [others => Character'Val (0)];
      Value_Last := 0;

      Decode_Varint (Input, First, Len_Val, Len_Last, OK);
      if not OK then
         Last := First;
         return;
      end if;

      if Len_Val = 0 then
         Last       := Len_Last;
         Value_Last := 0;
         OK         := True;
         return;
      end if;

      --  Two bound checks: encoded length must fit in remaining
      --  Input AND in caller's Value buffer.
      if Len_Val > Unsigned_64
                     (RFLX.RFLX_Types.Length (Input'Last)
                      - RFLX.RFLX_Types.Length (Len_Last))
      then
         Last       := First;
         Value_Last := 0;
         OK         := False;
         return;
      end if;
      if Len_Val > Unsigned_64 (Value'Length) then
         Last       := First;
         Value_Last := 0;
         OK         := False;
         return;
      end if;

      declare
         L : constant Natural := Natural (Len_Val);
      begin
         for I in 1 .. L loop
            pragma Loop_Invariant
              (Len_Last + RFLX.RFLX_Types.Index'Base (I) <= Input'Last);
            pragma Loop_Invariant
              (Value'First + (I - 1) <= Value'Last);
            Value (Value'First + (I - 1)) :=
              Character'Val
                (Natural (Input (Len_Last +
                                   RFLX.RFLX_Types.Index'Base (I))));
         end loop;
         Value_Last := Value'First + (L - 1);
         Last       := Len_Last + RFLX.RFLX_Types.Index'Base (L);
         OK         := True;
      end;
   end Decode_String_Value;

end Protobuf_Core.Wire;
