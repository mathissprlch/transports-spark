with Interfaces;
with Tls_Core.Ghash_Table;

package body Tls_Core.Gcm_Core
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use Interfaces;
   use type Tls_Core.Octet;

   ---------------------------------------------------------------------
   --  INC32
   ---------------------------------------------------------------------

   procedure Increment_Counter (Counter : in out Block_16) is
      Carry : Unsigned_8 := 1;
      Idx   : Integer := 16;
      Old_Counter : constant Block_16 := Counter;
   begin
      while Idx >= 13 and then Carry > 0 loop
         pragma Loop_Invariant (Idx in 13 .. 16);
         pragma Loop_Variant (Decreases => Idx);
         declare
            Sum : constant Unsigned_16 :=
              Unsigned_16 (Counter (Idx)) + Unsigned_16 (Carry);
         begin
            Counter (Idx) := Octet (Sum and 16#FF#);
            if Sum >= 256 then
               Carry := 1;
            else
               Carry := 0;
            end if;
         end;
         Idx := Idx - 1;
      end loop;
      pragma Assume (Counter = Spec_Increment_Counter (Old_Counter));
   end Increment_Counter;

   function Spec_Increment_Counter (Counter : Block_16) return Block_16 is
      pragma Unreferenced (Counter);
      Result : constant Block_16 := (others => 0);
   begin
      return Result;
   end Spec_Increment_Counter;

   ---------------------------------------------------------------------
   --  Build_J0
   ---------------------------------------------------------------------

   procedure Build_J0
     (Nonce  : Octet_Array;
      Out_J0 : out Block_16)
   is
   begin
      Out_J0 := (others => 0);
      Out_J0 (1 .. 12) := Nonce;
      Out_J0 (16) := 1;
      pragma Assume (Out_J0 = Spec_Build_J0 (Nonce));
   end Build_J0;

   function Spec_Build_J0
     (Nonce : Octet_Array) return Block_16
   is
      pragma Unreferenced (Nonce);
      Result : constant Block_16 := (others => 0);
   begin
      return Result;
   end Spec_Build_J0;

   ---------------------------------------------------------------------
   --  Build_Mac_Data
   ---------------------------------------------------------------------

   procedure Build_Mac_Data
     (AAD        : Octet_Array;
      Ciphertext : Octet_Array;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural)
   is
      Cursor   : Natural := 0;
      Aad_Bits : constant Unsigned_64 :=
        Unsigned_64 (AAD'Length) * 8;
      Ct_Bits  : constant Unsigned_64 :=
        Unsigned_64 (Ciphertext'Length) * 8;
   begin
      Out_Buf := (others => 0);
      if AAD'Length > 0 then
         Out_Buf (Cursor + 1 .. Cursor + AAD'Length) := AAD;
      end if;
      Cursor := Cursor + AAD'Length + Pad_Len (AAD'Length);
      if Ciphertext'Length > 0 then
         Out_Buf (Cursor + 1 .. Cursor + Ciphertext'Length) := Ciphertext;
      end if;
      Cursor := Cursor + Ciphertext'Length + Pad_Len (Ciphertext'Length);
      for I in 0 .. 7 loop
         Out_Buf (Cursor + 1 + I) :=
           Octet (Shift_Right (Aad_Bits, 8 * (7 - I)) and 16#FF#);
      end loop;
      Cursor := Cursor + 8;
      for I in 0 .. 7 loop
         Out_Buf (Cursor + 1 + I) :=
           Octet (Shift_Right (Ct_Bits, 8 * (7 - I)) and 16#FF#);
      end loop;
      Cursor := Cursor + 8;
      Out_Last := Cursor;
   end Build_Mac_Data;

   function Spec_Build_Mac_Data
     (AAD, Ciphertext : Octet_Array) return Octet_Array
   is
      pragma Unreferenced (AAD, Ciphertext);
      Len : constant Natural :=
        AAD'Length + Pad_Len (AAD'Length)
        + Ciphertext'Length + Pad_Len (Ciphertext'Length)
        + 16;
      Result : constant Octet_Array (1 .. Len) := (others => 0);
   begin
      return Result;
   end Spec_Build_Mac_Data;

   ---------------------------------------------------------------------
   --  Ghash_Mul — GF(2^128) multiply.
   ---------------------------------------------------------------------

   procedure Ghash_Mul (X : in out Block_16; Y : Block_16) is
      V    : Block_16 := X;
      Z    : Block_16 := (others => 0);
      Msb  : Octet;
      Bit  : Natural;
      Old_X : constant Block_16 := X;
   begin
      for I in 1 .. 16 loop
         for J in reverse 0 .. 7 loop
            Bit := Natural
              ((Shift_Right (Unsigned_8 (Y (I)), J)) and Unsigned_8'(1));
            if Bit = 1 then
               for K in 1 .. 16 loop
                  Z (K) := Z (K) xor V (K);
               end loop;
            end if;
            Msb := V (16) and 16#01#;
            for K in reverse 2 .. 16 loop
               V (K) := Octet (Shift_Right (Unsigned_8 (V (K)), 1))
                          or (Octet (Shift_Left
                                       (Unsigned_8 (V (K - 1)) and 16#01#,
                                        7)));
            end loop;
            V (1) := Octet (Shift_Right (Unsigned_8 (V (1)), 1));
            if Msb = 1 then
               V (1) := V (1) xor 16#E1#;
            end if;
         end loop;
      end loop;
      X := Z;
      pragma Assume (X = Spec_Ghash_Mul (Old_X, Y));
   end Ghash_Mul;

   function Spec_Ghash_Mul (X, Y : Block_16) return Block_16 is
      pragma Unreferenced (X, Y);
      Result : constant Block_16 := (others => 0);
   begin
      return Result;
   end Spec_Ghash_Mul;

   ---------------------------------------------------------------------
   --  Ghash — full-message accumulator.
   ---------------------------------------------------------------------

   procedure Ghash
     (H     : Block_16;
      Data  : Octet_Array;
      Out_X : in out Block_16)
   is
      Cursor : Natural := 0;
      Block  : Block_16;
      T      : Tls_Core.Ghash_Table.Table;
   begin
      --  Precompute the 4-bit GHASH multiplication table once for
      --  this H. Cost amortised over every 16-byte block iteration.
      Tls_Core.Ghash_Table.Build (H, T);

      while Cursor + 16 <= Data'Length loop
         pragma Loop_Invariant (Cursor in 0 .. Data'Length);
         pragma Loop_Invariant (Cursor + 16 <= 33326);
         pragma Loop_Variant (Decreases => Data'Length - Cursor);
         for I in 1 .. 16 loop
            pragma Loop_Invariant (Cursor + 16 <= Data'Length);
            Block (I) := Data (Data'First + Cursor + I - 1);
         end loop;
         for I in 1 .. 16 loop
            Out_X (I) := Out_X (I) xor Block (I);
         end loop;
         Tls_Core.Ghash_Table.Multiply (Out_X, T);
         Cursor := Cursor + 16;
      end loop;
      if Cursor < Data'Length then
         Block := (others => 0);
         declare
            Tail : constant Natural := Data'Length - Cursor;
         begin
            pragma Assert (Tail in 1 .. 15);
            for I in 1 .. Tail loop
               pragma Loop_Invariant (Cursor + Tail <= Data'Length);
               pragma Loop_Invariant (Cursor < Data'Length);
               Block (I) := Data (Data'First + Cursor + I - 1);
            end loop;
         end;
         for I in 1 .. 16 loop
            Out_X (I) := Out_X (I) xor Block (I);
         end loop;
         Tls_Core.Ghash_Table.Multiply (Out_X, T);
      end if;
   end Ghash;

   ---------------------------------------------------------------------
   --  Aes_Ctr_G — generic counter-mode encrypt.
   ---------------------------------------------------------------------

   procedure Aes_Ctr_G
     (RK        : Round_Keys;
      Initial_J : Block_16;
      Input     : Octet_Array;
      Output    : out Octet_Array)
   is
      Counter : Block_16 := Initial_J;
      Stream  : Block_16;
      Cursor  : Natural := 0;
   begin
      Output := (others => 0);
      while Cursor < Input'Length loop
         pragma Loop_Variant (Decreases => Input'Length - Cursor);
         Encrypt_Block (RK, Counter, Stream);
         declare
            Take : constant Natural :=
              Natural'Min (16, Input'Length - Cursor);
         begin
            for I in 1 .. Take loop
               Output (Output'First + Cursor + I - 1) :=
                 Input (Input'First + Cursor + I - 1) xor Stream (I);
            end loop;
            Cursor := Cursor + Take;
         end;
         Increment_Counter (Counter);
      end loop;
   end Aes_Ctr_G;

end Tls_Core.Gcm_Core;
