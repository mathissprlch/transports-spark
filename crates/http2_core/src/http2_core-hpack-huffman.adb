package body Http2_Core.Hpack.Huffman
with SPARK_Mode
is

   use type Interfaces.Unsigned_8;
   use type Interfaces.Unsigned_32;
   use type Interfaces.Unsigned_64;

   subtype U8  is Interfaces.Unsigned_8;
   subtype U32 is Interfaces.Unsigned_32;
   subtype U64 is Interfaces.Unsigned_64;

   --  Encoder: stream bits into a 64-bit accumulator MSB-first.
   --  When >= 8 bits accumulate, emit the high byte to Output.
   procedure Encode
     (Input       : Octet_Array;
      Output      : in out Octet_Array;
      Output_Last : out Natural;
      Output_OK   : out Boolean)
   is
      Buf       : U64 := 0;
      Bits_Used : Natural := 0;
      Out_Idx   : Integer := Output'First - 1;
      --  Out_Idx tracks last-written index; the next write goes to
      --  Out_Idx + 1. Starts one before First so the first write
      --  lands at First.
   begin
      Output_OK := True;

      for B of Input loop
         declare
            Hc       : constant Huffman_Code := Code_Table (Symbol (B));
            Code_64  : constant U64 := U64 (Hc.Code);
            New_Bits : constant Natural := Natural (Hc.Bits);
         begin
            --  Hc.Code is left-aligned in 32 bits: data at bits
            --  31..(32-N). Promote to 64-bit (data at bits 31..(32-N)
            --  of u64), shift left by 32 so data sits at 63..(64-N),
            --  then shift right by Bits_Used to slot in after the
            --  bits already accumulated.
            Buf := Buf or Interfaces.Shift_Right
              (Interfaces.Shift_Left (Code_64, 32), Bits_Used);
            Bits_Used := Bits_Used + New_Bits;

            while Bits_Used >= 8 loop
               if Out_Idx >= Output'Last then
                  Output_OK   := False;
                  Output_Last := Output'First - 1;
                  return;
               end if;
               Out_Idx := Out_Idx + 1;
               Output (Out_Idx) :=
                 U8 (Interfaces.Shift_Right (Buf, 56) and 16#FF#);
               Buf := Interfaces.Shift_Left (Buf, 8);
               Bits_Used := Bits_Used - 8;
            end loop;
         end;
      end loop;

      --  §5.2.4 — pad final byte with high bits of EOS (all 1s).
      if Bits_Used > 0 then
         declare
            Pad_Bits : constant Natural := 8 - Bits_Used;
            Pad_Mask : constant U64 :=
              Interfaces.Shift_Left
                (U64 ((2 ** Pad_Bits) - 1), 64 - Pad_Bits - Bits_Used);
            --  Place Pad_Bits 1-bits in the byte we're about to emit:
            --  the byte sits at Buf bits 63..56; valid data occupies
            --  bits 63..(64-Bits_Used); padding goes in bits
            --  (63-Bits_Used)..(64-8) = (56+Pad_Bits-1)..56.
            --  Equivalently: shift (2^Pad_Bits - 1) left by 56.
            Pad_Final : constant U64 :=
              Interfaces.Shift_Left
                (U64 ((2 ** Pad_Bits) - 1), 56);
            pragma Unreferenced (Pad_Mask);
            --  Pad_Mask was a first attempt; Pad_Final is correct.
         begin
            if Out_Idx >= Output'Last then
               Output_OK   := False;
               Output_Last := Output'First - 1;
               return;
            end if;
            Out_Idx := Out_Idx + 1;
            Output (Out_Idx) :=
              U8 (Interfaces.Shift_Right (Buf or Pad_Final, 56) and 16#FF#);
         end;
      end if;

      Output_Last := Out_Idx;
   end Encode;

   --  Decoder: walk the input bit-by-bit, accumulating a candidate
   --  code, and check after each bit whether it matches any symbol's
   --  full code. Naive (O(257 * 30) per output byte) but easy to
   --  reason about and adequate for short header strings.
   procedure Decode
     (Input       : Octet_Array;
      Output      : in out Octet_Array;
      Output_Last : out Natural;
      Output_OK   : out Boolean)
   is
      Bits_Total : constant Natural := Input'Length * 8;
      Bit_Idx    : Natural := 0;
      Out_Idx    : Integer := Output'First - 1;
      Candidate  : U32 := 0;
      Cand_Bits  : Natural := 0;

      function Read_Bit (At_Index : Natural) return U32
      with Pre => At_Index < Bits_Total;

      function Read_Bit (At_Index : Natural) return U32 is
         Byte_Off : constant Natural := At_Index / 8;
         Bit_Off  : constant Natural := 7 - (At_Index mod 8);
         B        : constant U8     :=
           Input (Input'First + Byte_Off);
      begin
         if (B and U8 (Interfaces.Shift_Left (U8 (1), Bit_Off))) /= 0 then
            return 1;
         else
            return 0;
         end if;
      end Read_Bit;

   begin
      Output_OK := True;

      while Bit_Idx < Bits_Total loop
         --  Read one more bit into Candidate (left-aligned in 32 bits
         --  to match Code_Table format).
         Candidate := Candidate
           or Interfaces.Shift_Left
                (Read_Bit (Bit_Idx), 31 - Cand_Bits);
         Bit_Idx   := Bit_Idx + 1;
         Cand_Bits := Cand_Bits + 1;

         --  Search for a symbol whose code length matches Cand_Bits
         --  AND whose code's high Cand_Bits bits equal Candidate's
         --  high Cand_Bits bits.
         declare
            Mask  : constant U32 := (if Cand_Bits = 32 then 16#FFFFFFFF#
                                     else Interfaces.Shift_Left
                                       (U32'(16#FFFFFFFF#), 32 - Cand_Bits));
            Found : Boolean := False;
            Sym   : Symbol  := 0;
         begin
            for I in Symbol'Range loop
               if Natural (Code_Table (I).Bits) = Cand_Bits
                 and then (Code_Table (I).Code and Mask) = Candidate
               then
                  Found := True;
                  Sym   := I;
                  exit;
               end if;
            end loop;

            if Found then
               if Sym = 256 then
                  --  EOS as an actual emitted symbol is a decoding
                  --  error per §5.2.3.
                  Output_OK   := False;
                  Output_Last := Output'First - 1;
                  return;
               end if;
               if Out_Idx >= Output'Last then
                  Output_OK   := False;
                  Output_Last := Output'First - 1;
                  return;
               end if;
               Out_Idx := Out_Idx + 1;
               Output (Out_Idx) := U8 (Sym);
               Candidate := 0;
               Cand_Bits := 0;
            elsif Cand_Bits >= 30 then
               --  No code longer than 30 bits exists — malformed
               --  input.
               Output_OK   := False;
               Output_Last := Output'First - 1;
               return;
            end if;
         end;
      end loop;

      --  Trailing partial code: per §5.2.3 must be all 1-bits AND
      --  shorter than 8 bits. Anything else is malformed.
      if Cand_Bits > 0 then
         if Cand_Bits >= 8 then
            Output_OK   := False;
            Output_Last := Output'First - 1;
            return;
         end if;
         declare
            Expected : constant U32 :=
              Interfaces.Shift_Left
                (U32'((2 ** Cand_Bits) - 1), 32 - Cand_Bits);
         begin
            if Candidate /= Expected then
               Output_OK   := False;
               Output_Last := Output'First - 1;
               return;
            end if;
         end;
      end if;

      Output_Last := Out_Idx;
   end Decode;

end Http2_Core.Hpack.Huffman;
