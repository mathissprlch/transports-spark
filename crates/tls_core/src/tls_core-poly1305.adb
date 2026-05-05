package body Tls_Core.Poly1305
with SPARK_Mode
is

   use Interfaces;

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   --  We represent 130-bit integers as 5 limbs of 26 bits each
   --  (5 * 26 = 130). Each limb sits in a u64 so we have 38 bits
   --  of carry headroom for one multiply-add before partial
   --  reduction. The arithmetic mirrors HACL\*'s
   --  Hacl.Spec.Poly1305.Field32.
   subtype Limb_Index is Natural range 0 .. 4;
   type Limbs is array (Limb_Index) of U64;

   Mask_26 : constant U64 := 16#03FF_FFFF#;

   ---------------------------------------------------------------------
   --  Pack a 16-byte little-endian integer (with the implicit
   --  trailing 1 bit for full blocks) into the 5-limb form.
   ---------------------------------------------------------------------

   procedure Load_Block
     (B          : Octet_Array;
      Block_Bytes : Natural;
      Final      : Boolean;
      Out_Limbs  : out Limbs)
   with Pre => Block_Bytes in 1 .. 16
               and then Block_Bytes <= B'Length;

   procedure Load_Block
     (B          : Octet_Array;
      Block_Bytes : Natural;
      Final      : Boolean;
      Out_Limbs  : out Limbs)
   is
      Padded : Octet_Array (1 .. 17) := (others => 0);
   begin
      for I in 1 .. Block_Bytes loop
         Padded (I) := B (B'First + I - 1);
      end loop;
      --  Append the implicit "1" bit at byte position Block_Bytes.
      --  For full 16-byte blocks this is byte 17 (i.e. bit 128).
      --  For a partial last block it sits at the byte just past
      --  the message bytes, per §2.5 step 3.
      if Final then
         Padded (Block_Bytes + 1) := 16#01#;
      else
         Padded (17) := 16#01#;
      end if;
      Out_Limbs (0) :=
        U64 (Padded (1))
        or Shift_Left (U64 (Padded (2)),  8)
        or Shift_Left (U64 (Padded (3)), 16)
        or Shift_Left (U64 (Padded (4) and 16#03#), 24);
      Out_Limbs (1) :=
        Shift_Right (U64 (Padded (4)), 2)
        or Shift_Left (U64 (Padded (5)),  6)
        or Shift_Left (U64 (Padded (6)), 14)
        or Shift_Left (U64 (Padded (7) and 16#0F#), 22);
      Out_Limbs (2) :=
        Shift_Right (U64 (Padded (7)), 4)
        or Shift_Left (U64 (Padded (8)),  4)
        or Shift_Left (U64 (Padded (9)), 12)
        or Shift_Left (U64 (Padded (10) and 16#3F#), 20);
      Out_Limbs (3) :=
        Shift_Right (U64 (Padded (10)), 6)
        or Shift_Left (U64 (Padded (11)),  2)
        or Shift_Left (U64 (Padded (12)), 10)
        or Shift_Left (U64 (Padded (13)), 18);
      Out_Limbs (4) :=
        U64 (Padded (14))
        or Shift_Left (U64 (Padded (15)),  8)
        or Shift_Left (U64 (Padded (16)), 16)
        or Shift_Left (U64 (Padded (17)), 24);
   end Load_Block;

   ---------------------------------------------------------------------
   --  Reduce a 5-limb accumulator mod 2^130 - 5 by carry-propagation
   --  + a partial fold of the high bits via × 5.
   ---------------------------------------------------------------------

   procedure Carry (L : in out Limbs);
   procedure Carry (L : in out Limbs) is
      C : U64;
   begin
      --  Propagate carries up.
      C := Shift_Right (L (0), 26); L (0) := L (0) and Mask_26; L (1) := L (1) + C;
      C := Shift_Right (L (1), 26); L (1) := L (1) and Mask_26; L (2) := L (2) + C;
      C := Shift_Right (L (2), 26); L (2) := L (2) and Mask_26; L (3) := L (3) + C;
      C := Shift_Right (L (3), 26); L (3) := L (3) and Mask_26; L (4) := L (4) + C;
      --  Top limb: any bits past 26 fold down with a × 5 (the modulus
      --  trick: 2^130 ≡ 5 mod (2^130 − 5)).
      C := Shift_Right (L (4), 26); L (4) := L (4) and Mask_26;
      L (0) := L (0) + 5 * C;
      C := Shift_Right (L (0), 26); L (0) := L (0) and Mask_26; L (1) := L (1) + C;
   end Carry;

   ---------------------------------------------------------------------
   --  Acc := Acc + N
   ---------------------------------------------------------------------

   procedure Add (Acc : in out Limbs; N : Limbs);
   procedure Add (Acc : in out Limbs; N : Limbs) is
   begin
      for I in Limb_Index loop
         Acc (I) := Acc (I) + N (I);
      end loop;
      Carry (Acc);
   end Add;

   ---------------------------------------------------------------------
   --  Acc := (Acc * R) mod (2^130 - 5)
   --
   --  Schoolbook 5×5 multiply with the modular fold-down. Uses 64-bit
   --  intermediates; safe because each limb is at most 26 bits and we
   --  multiply at most 5 limbs.
   ---------------------------------------------------------------------

   procedure Multiply (Acc : in out Limbs; R : Limbs);
   procedure Multiply (Acc : in out Limbs; R : Limbs) is
      A0 : constant U64 := Acc (0);
      A1 : constant U64 := Acc (1);
      A2 : constant U64 := Acc (2);
      A3 : constant U64 := Acc (3);
      A4 : constant U64 := Acc (4);
      R0 : constant U64 := R (0);
      R1 : constant U64 := R (1);
      R2 : constant U64 := R (2);
      R3 : constant U64 := R (3);
      R4 : constant U64 := R (4);
      S1 : constant U64 := R1 * 5;
      S2 : constant U64 := R2 * 5;
      S3 : constant U64 := R3 * 5;
      S4 : constant U64 := R4 * 5;
      D0, D1, D2, D3, D4 : U64;
   begin
      --  Mod 2^130-5 trick: any limb that "spills past" position 4
      --  folds back down with a × 5.
      D0 := A0 * R0 + A1 * S4 + A2 * S3 + A3 * S2 + A4 * S1;
      D1 := A0 * R1 + A1 * R0 + A2 * S4 + A3 * S3 + A4 * S2;
      D2 := A0 * R2 + A1 * R1 + A2 * R0 + A3 * S4 + A4 * S3;
      D3 := A0 * R3 + A1 * R2 + A2 * R1 + A3 * R0 + A4 * S4;
      D4 := A0 * R4 + A1 * R3 + A2 * R2 + A3 * R1 + A4 * R0;
      Acc (0) := D0;
      Acc (1) := D1;
      Acc (2) := D2;
      Acc (3) := D3;
      Acc (4) := D4;
      Carry (Acc);
   end Multiply;

   ---------------------------------------------------------------------
   --  Mac
   ---------------------------------------------------------------------

   procedure Mac
     (Key     : Key_Array;
      Message : Octet_Array;
      Out_Tag : out Tag_Array)
   is
      R   : Limbs := (others => 0);
      Acc : Limbs := (others => 0);
      Block : Limbs;
      Cursor : Natural := 0;

      --  s as a 17-byte LE integer (upper byte is 0 because s is
      --  128 bits) for the final addition.
      function Get_S_Limb (Idx : Limb_Index) return U64
      with Pre => Idx <= 4;

      function Get_S_Limb (Idx : Limb_Index) return U64 is
         Padded : Octet_Array (1 .. 17) := (others => 0);
      begin
         for I in 1 .. 16 loop
            Padded (I) := Key (16 + I);
         end loop;
         case Idx is
            when 0 =>
               return U64 (Padded (1))
                 or Shift_Left (U64 (Padded (2)),  8)
                 or Shift_Left (U64 (Padded (3)), 16)
                 or Shift_Left (U64 (Padded (4) and 16#03#), 24);
            when 1 =>
               return Shift_Right (U64 (Padded (4)), 2)
                 or Shift_Left (U64 (Padded (5)),  6)
                 or Shift_Left (U64 (Padded (6)), 14)
                 or Shift_Left (U64 (Padded (7) and 16#0F#), 22);
            when 2 =>
               return Shift_Right (U64 (Padded (7)), 4)
                 or Shift_Left (U64 (Padded (8)),  4)
                 or Shift_Left (U64 (Padded (9)), 12)
                 or Shift_Left (U64 (Padded (10) and 16#3F#), 20);
            when 3 =>
               return Shift_Right (U64 (Padded (10)), 6)
                 or Shift_Left (U64 (Padded (11)),  2)
                 or Shift_Left (U64 (Padded (12)), 10)
                 or Shift_Left (U64 (Padded (13)), 18);
            when 4 =>
               return U64 (Padded (14))
                 or Shift_Left (U64 (Padded (15)),  8)
                 or Shift_Left (U64 (Padded (16)), 16);
         end case;
      end Get_S_Limb;

   begin
      --  RFC 8439 §2.5.1 clamp.
      declare
         Clamped : Octet_Array (1 .. 16);
      begin
         for I in 1 .. 16 loop
            Clamped (I) := Key (I);
         end loop;
         Clamped (4)  := Clamped (4)  and 16#0F#;
         Clamped (8)  := Clamped (8)  and 16#0F#;
         Clamped (12) := Clamped (12) and 16#0F#;
         Clamped (16) := Clamped (16) and 16#0F#;
         Clamped (5)  := Clamped (5)  and 16#FC#;
         Clamped (9)  := Clamped (9)  and 16#FC#;
         Clamped (13) := Clamped (13) and 16#FC#;
         --  Load r from clamped key (16 bytes), WITHOUT the
         --  Poly1305 implicit-1 bit. r itself is just an integer.
         declare
            Padded : Octet_Array (1 .. 17) := (others => 0);
         begin
            for I in 1 .. 16 loop
               Padded (I) := Clamped (I);
            end loop;
            R (0) :=
              U64 (Padded (1))
              or Shift_Left (U64 (Padded (2)),  8)
              or Shift_Left (U64 (Padded (3)), 16)
              or Shift_Left (U64 (Padded (4) and 16#03#), 24);
            R (1) :=
              Shift_Right (U64 (Padded (4)), 2)
              or Shift_Left (U64 (Padded (5)),  6)
              or Shift_Left (U64 (Padded (6)), 14)
              or Shift_Left (U64 (Padded (7) and 16#0F#), 22);
            R (2) :=
              Shift_Right (U64 (Padded (7)), 4)
              or Shift_Left (U64 (Padded (8)),  4)
              or Shift_Left (U64 (Padded (9)), 12)
              or Shift_Left (U64 (Padded (10) and 16#3F#), 20);
            R (3) :=
              Shift_Right (U64 (Padded (10)), 6)
              or Shift_Left (U64 (Padded (11)),  2)
              or Shift_Left (U64 (Padded (12)), 10)
              or Shift_Left (U64 (Padded (13)), 18);
            R (4) :=
              U64 (Padded (14))
              or Shift_Left (U64 (Padded (15)),  8)
              or Shift_Left (U64 (Padded (16)), 16);
         end;
      end;

      --  Process all complete 16-byte blocks (Final=False ⇒ implicit
      --  "1" appears at bit 128, the 17th byte).
      while Cursor + 16 <= Message'Length loop
         pragma Loop_Variant (Decreases => Message'Length - Cursor);
         Load_Block
           (Message
              (Message'First + Cursor ..
                 Message'First + Cursor + 15),
            16, Final => False, Out_Limbs => Block);
         Add (Acc, Block);
         Multiply (Acc, R);
         Cursor := Cursor + 16;
      end loop;

      --  Possibly one short trailing block.
      if Cursor < Message'Length then
         declare
            Tail_Len : constant Natural := Message'Length - Cursor;
         begin
            Load_Block
              (Message
                 (Message'First + Cursor .. Message'Last),
               Tail_Len, Final => True, Out_Limbs => Block);
            Add (Acc, Block);
            Multiply (Acc, R);
         end;
      end if;

      --  Final reduction: ensure Acc < 2^130-5. Two extra carries
      --  bring it into canonical form.
      Carry (Acc);
      Carry (Acc);

      --  Acc := Acc + s (mod 2^128). Then serialize as little-endian.
      declare
         Carry_Acc : U64 := 0;
         T : array (Limb_Index) of U64;
         H_Lo, H_Hi : U64 := 0;
      begin
         for I in Limb_Index loop
            T (I) := Acc (I) + Get_S_Limb (I) + Carry_Acc;
            Carry_Acc := Shift_Right (T (I), 26);
            T (I) := T (I) and Mask_26;
         end loop;

         --  Repack into two 64-bit halves of the 130-bit number.
         --  Limb i sits at bit position 26 * i.
         --  H_Lo: bits 0..63   ← T(0)|26 + T(1)|26 + low 12 bits of T(2)
         --  H_Hi: bits 64..127 ← high 14 bits of T(2) + T(3)|26 + low 24 bits of T(4)
         H_Lo := T (0)
           or Shift_Left (T (1), 26)
           or Shift_Left (T (2) and 16#0000_0FFF#, 52);
         H_Hi := Shift_Right (T (2), 12)
           or Shift_Left (T (3), 14)
           or Shift_Left (T (4) and 16#00FF_FFFF#, 40);

         for I in 0 .. 7 loop
            Out_Tag (1 + I) :=
              Octet (Shift_Right (H_Lo, 8 * I) and 16#FF#);
         end loop;
         for I in 0 .. 7 loop
            Out_Tag (9 + I) :=
              Octet (Shift_Right (H_Hi, 8 * I) and 16#FF#);
         end loop;
      end;
   end Mac;

end Tls_Core.Poly1305;
