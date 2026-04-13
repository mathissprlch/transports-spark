package body Http2_Core.Hpack.Int_Codec
with SPARK_Mode
is

   use type Interfaces.Unsigned_8;

   subtype U8 is Interfaces.Unsigned_8;

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
      Mask    : constant Natural := 2 ** N - 1;
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
      Mask : constant Natural := 2 ** N - 1;
      Idx  : Integer := First;
      I    : Natural := Natural (Input (Idx) and U8 (Mask));
      M_b  : Natural := 0;
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
      for Step in 1 .. 4 loop
         if Idx >= Input'Last then
            return;  --  truncated input
         end if;
         Idx := Idx + 1;
         B   := Input (Idx);
         I   := I + Natural (B and 16#7F#) * (2 ** M_b);
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
