package body Tls_Core.Sha384
  with SPARK_Mode
is

   use Interfaces;

   ---------------------------------------------------------------------
   --  Round constants K[0..79] — identical to SHA-512.
   --  HACL* `Spec.SHA2.Constants.k384_512` (lib/Spec.SHA2.Constants.fst:27).
   ---------------------------------------------------------------------

   --  K table, bit-mixing primitives, BE_Word, Spec_W_SHA384,
   --  One_Round_SHA384, Spec_Shuffle_SHA384, Update_Block_Spec all live
   --  in the .ads as expression functions (gnatprove inlines them for
   --  proof — congruence on equal inputs threads cleanly).

   --  Update_Block_Spec is an expression function in the .ads. No body.
   --  Block_At is an expression function in the .ads. No body.

   --  Spec_Hash_Blocks is an expression function in the .ads (recursive
   --  with Subprogram_Variant). No body here.

   --  Pad_SHA384 is an expression function in the .ads (iterated
   --  aggregate over Spec_Pad_Byte_SHA384). No body here.

   --  Finalize_State is an expression function in the .ads. No body.

   --  Spec_SHA384 is defined as an expression function in the .ads
   --  (so gnatprove inlines it at call sites for proof) — no body here.

   ---------------------------------------------------------------------
   --  Imperative streaming Process_Block — identical to SHA-512.
   ---------------------------------------------------------------------

   procedure Process_Block (Ctx : in out Context; B : Block);
   procedure Process_Block (Ctx : in out Context; B : Block) is
      W                       : array (0 .. 79) of Word := [others => 0];
      A, Bv, C, D, E, F, G, H : Word;
      T1, T2                  : Word;
   begin
      for I in 0 .. 15 loop
         W (I) := BE_Word (B, B'First + 8 * I);
      end loop;
      for I in 16 .. 79 loop
         W (I) :=
           Small_Sigma_1 (W (I - 2))
           + W (I - 7)
           + Small_Sigma_0 (W (I - 15))
           + W (I - 16);
      end loop;

      A := Ctx.H (1);
      Bv := Ctx.H (2);
      C := Ctx.H (3);
      D := Ctx.H (4);
      E := Ctx.H (5);
      F := Ctx.H (6);
      G := Ctx.H (7);
      H := Ctx.H (8);

      for I in 0 .. 79 loop
         T1 := H + Big_Sigma_1 (E) + Ch (E, F, G) + K (I) + W (I);
         T2 := Big_Sigma_0 (A) + Maj (A, Bv, C);
         H := G;
         G := F;
         F := E;
         E := D + T1;
         D := C;
         C := Bv;
         Bv := A;
         A := T1 + T2;
      end loop;

      Ctx.H (1) := Ctx.H (1) + A;
      Ctx.H (2) := Ctx.H (2) + Bv;
      Ctx.H (3) := Ctx.H (3) + C;
      Ctx.H (4) := Ctx.H (4) + D;
      Ctx.H (5) := Ctx.H (5) + E;
      Ctx.H (6) := Ctx.H (6) + F;
      Ctx.H (7) := Ctx.H (7) + G;
      Ctx.H (8) := Ctx.H (8) + H;
   end Process_Block;

   procedure Init (Ctx : out Context) is
   begin
      Ctx.H := Initial_State_SHA384;
      Ctx.Buf := [others => 0];
      Ctx.Buf_Len := 0;
      Ctx.Total_Len := 0;
   end Init;

   procedure Update (Ctx : in out Context; Data : Octet_Array) is
      Consumed : Natural := 0;
      Need     : Natural;
   begin
      Ctx.Total_Len := Ctx.Total_Len + Interfaces.Unsigned_64 (Data'Length);

      if Ctx.Buf_Len > 0 then
         Need := Block_Length - Ctx.Buf_Len;
         if Data'Length < Need then
            Ctx.Buf (Ctx.Buf_Len + 1 .. Ctx.Buf_Len + Data'Length) := Data;
            Ctx.Buf_Len := Ctx.Buf_Len + Data'Length;
            return;
         end if;
         Ctx.Buf (Ctx.Buf_Len + 1 .. Block_Length) :=
           Data (Data'First .. Data'First + Need - 1);
         declare
            Snap : constant Block := Ctx.Buf;
         begin
            Process_Block (Ctx, Snap);
         end;
         Consumed := Need;
         Ctx.Buf_Len := 0;
      end if;

      while Data'Length - Consumed >= Block_Length loop
         pragma Loop_Variant (Decreases => Data'Length - Consumed);
         pragma Loop_Invariant (Consumed <= Data'Length);
         pragma Loop_Invariant (Ctx.Buf_Len = 0);
         Ctx.Buf :=
           Data
             (Data'First
              + Consumed
              .. Data'First + Consumed + Block_Length - 1);
         declare
            Snap : constant Block := Ctx.Buf;
         begin
            Process_Block (Ctx, Snap);
         end;
         Consumed := Consumed + Block_Length;
      end loop;

      declare
         Remaining : constant Natural := Data'Length - Consumed;
      begin
         Ctx.Buf := [others => 0];
         if Remaining > 0 then
            Ctx.Buf (1 .. Remaining) :=
              Data
                (Data'First
                 + Consumed
                 .. Data'First + Consumed + Remaining - 1);
         end if;
         Ctx.Buf_Len := Remaining;
      end;
   end Update;

   procedure Finalize (Ctx : in out Context; Out_Digest : out Digest) is
      Bits   : constant Interfaces.Unsigned_64 := Ctx.Total_Len * 8;
      Filled : Natural := Ctx.Buf_Len;
   begin
      Out_Digest := [others => 0];
      Ctx.Buf (Filled + 1) := 16#80#;
      Filled := Filled + 1;

      if Filled > Block_Length - 16 then
         if Filled < Block_Length then
            for I in Filled + 1 .. Block_Length loop
               Ctx.Buf (I) := 0;
            end loop;
         end if;
         declare
            Snap : constant Block := Ctx.Buf;
         begin
            Process_Block (Ctx, Snap);
         end;
         Ctx.Buf := [others => 0];
         Filled := 0;
      end if;

      if Filled + 1 <= Block_Length - 16 then
         for I in Filled + 1 .. Block_Length - 16 loop
            Ctx.Buf (I) := 0;
         end loop;
      end if;
      Ctx.Buf_Len := 0;

      for I in 1 .. 8 loop
         Ctx.Buf (Block_Length - 16 + I) := 0;
      end loop;
      for I in 1 .. 8 loop
         Ctx.Buf (Block_Length - 8 + I) :=
           Octet (Shift_Right (Bits, Natural (8 * (8 - I))) and 16#FF#);
      end loop;

      declare
         Snap : constant Block := Ctx.Buf;
      begin
         Process_Block (Ctx, Snap);
      end;

      --  Emit only the first six 64-bit words = 48 bytes.
      for I in 1 .. 6 loop
         for J in 1 .. 8 loop
            Out_Digest (8 * (I - 1) + J) :=
              Octet
                (Shift_Right (Ctx.H (I), Natural (8 * (8 - J))) and 16#FF#);
         end loop;
      end loop;
   end Finalize;

   procedure Hash (Data : Octet_Array; Out_Digest : out Digest) is
   begin
      Out_Digest := Spec_SHA384 (Data);
   end Hash;

end Tls_Core.Sha384;
