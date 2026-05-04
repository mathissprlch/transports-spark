package body Http2_Core.Hpack.Int_Codec
with SPARK_Mode
is

   use type Interfaces.Unsigned_8;

   subtype U8 is Interfaces.Unsigned_8;

   --  RFC 7541 §5.1: prefix mask is 2**N - 1. The prover doesn't
   --  unfold `2**N` for non-constant N, so we expand to a case
   --  expression keyed on Prefix_Bits' four values. Result subtype
   --  encodes the 4..127 bound the prover otherwise can't infer.
   subtype Prefix_Mask is Natural range 15 .. 127;
   function Mask_Of (N : Prefix_Bits) return Prefix_Mask is
     (case N is
        when 4 => 15,
        when 5 => 31,
        when 6 => 63,
        when 7 => 127);

   --  Same trick for the continuation-byte multiplier 2**M_b.
   --  HPACK Decode advances M_b by 7 each continuation byte, capped
   --  at 4 bytes total (Step in 1..4). Used values are 0/7/14/21;
   --  the post-loop M_b = 28 case is unreachable (the loop body
   --  would have returned by then), but the subtype + Pow_Of below
   --  must still admit the value so the increment doesn't trip a
   --  range check.
   subtype Shift_Steps is Natural range 0 .. 28;
   subtype Pow_Of_2 is Natural range 1 .. 2_097_152;
   function Pow_Of (M_b : Shift_Steps) return Pow_Of_2 is
     (case M_b is
        when 0  => 1,
        when 7  => 128,
        when 14 => 16_384,
        when 21 => 2_097_152,
        when others => 1);  --  unreachable in well-formed callers

   --  RFC 7541 §5.1 pseudocode mirrored. Encode value V with prefix
   --  width N into the byte stream:
   --     M : prefix mask = 2**N - 1
   --     if V < M:
   --        first byte's low N bits := V       (single byte total)
   --     else:
   --        first byte's low N bits := all 1s
   --        V := V - M
   --        while V >= 128:
   --           emit byte (V mod 128) | 128
   --           V := V / 128
   --        emit byte V
   procedure Encode
     (Value       : Natural;
      N           : Prefix_Bits;
      Output      : in out Octet_Array;
      Output_Last : out Natural;
      Output_OK   : out Boolean)
   is
      Mask    : constant Prefix_Mask := Mask_Of (N);
      Out_Idx : Integer := Output'First;
      V       : Natural := Value;
   begin
      --  First byte's prefix discriminator was set by the caller in
      --  the high (8 - N) bits; we OR in the low N bits.
      if V < Mask then
         Output (Out_Idx) :=
           Output (Out_Idx) or U8 (V);
         Output_Last := Out_Idx;
         Output_OK   := True;
         return;
      end if;

      --  Doesn't fit in prefix: store all-1s mask, emit continuation
      --  bytes for the remainder.
      Output (Out_Idx) := Output (Out_Idx) or U8 (Mask);
      V := V - Mask;

      while V >= 128 loop
         pragma Loop_Invariant (Out_Idx in Output'Range);
         if Out_Idx >= Output'Last then
            Output_OK   := False;
            Output_Last := Output'First - 1;
            return;
         end if;
         Out_Idx := Out_Idx + 1;
         Output (Out_Idx) := U8 (V mod 128) or 16#80#;
         V := V / 128;
      end loop;

      if Out_Idx >= Output'Last then
         Output_OK   := False;
         Output_Last := Output'First - 1;
         return;
      end if;
      Out_Idx := Out_Idx + 1;
      Output (Out_Idx) := U8 (V);
      Output_Last := Out_Idx;
      Output_OK   := True;
   end Encode;

   --  RFC 7541 §5.1 pseudocode mirrored. Decode integer with prefix
   --  width N starting at byte First:
   --     M := 2**N - 1
   --     I := first byte's low N bits
   --     if I < M:
   --        return I
   --     M_b := 0
   --     repeat:
   --        B := next byte
   --        I := I + (B & 127) * 2**M_b
   --        M_b := M_b + 7
   --     until (B & 128) == 0
   --     return I
   procedure Decode
     (Input     : Octet_Array;
      First     : Positive;
      N         : Prefix_Bits;
      Value     : out Natural;
      Last      : out Natural;
      Output_OK : out Boolean)
   is
      Mask : constant Prefix_Mask := Mask_Of (N);
      Idx  : Integer := First;
      I    : Natural := Natural (Input (Idx) and U8 (Mask));
      M_b  : Shift_Steps := 0;
      B    : U8;
   begin
      Value     := 0;
      Last      := First - 1;
      Output_OK := False;

      if I < Mask then
         Value     := I;
         Last      := Idx;
         Output_OK := True;
         return;
      end if;

      --  Read continuation bytes. Bound the loop at the v0.2 cap
      --  (2**21 ≈ 2M needs 3 continuation bytes maximum); reject
      --  any longer input as malformed.
      --
      --  Gold gap: gnatprove can't unfold `2 ** M_b` for non-
      --  constant M_b, so the multiplication on the next line stays
      --  unverified at level 4 even though M_b ∈ {0,7,14,21} by the
      --  iteration count and (B & 0x7F) ≤ 127. Closing this needs
      --  either a precomputed power-of-2 lookup table or a
      --  Lemma_Bounded_Power ghost helper. Tracked.
      for Step in 1 .. 4 loop
         if Idx >= Input'Last then
            return;  --  truncated input
         end if;
         Idx := Idx + 1;
         B   := Input (Idx);
         I   := I + Natural (B and 16#7F#) * Pow_Of (M_b);
         if I > 2 ** 21 - 1 then
            return;  --  exceeds v0.2 cap
         end if;
         if (B and 16#80#) = 0 then
            Value     := I;
            Last      := Idx;
            Output_OK := True;
            return;
         end if;
         M_b := M_b + 7;
      end loop;
      --  Five+ continuation bytes — reject.
   end Decode;

end Http2_Core.Hpack.Int_Codec;
