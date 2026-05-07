with Tls_Core.Aes_Core;

package body Tls_Core.Aes128
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use type Tls_Core.Octet;

   ---------------------------------------------------------------------
   --  Expand_Key — FIPS 197 §5.2 KeyExpansion (Nk = 4, Nr = 10).
   --  Uses the shared S-box and Rcon from Tls_Core.Aes_Core.
   ---------------------------------------------------------------------

   procedure Expand_Key
     (Key    : Key_Array;
      Out_RK : out Round_Keys)
   is
      Temp0, Temp1, Temp2, Temp3 : Octet;
      Tmp_T : Octet;
   begin
      Out_RK := (others => 0);
      Out_RK (1 .. 16) := Key;
      for I in 4 .. 43 loop
         Temp0 := Out_RK (4 * (I - 1) + 1);
         Temp1 := Out_RK (4 * (I - 1) + 2);
         Temp2 := Out_RK (4 * (I - 1) + 3);
         Temp3 := Out_RK (4 * (I - 1) + 4);
         if I mod 4 = 0 then
            --  RotWord.
            Tmp_T := Temp0;
            Temp0 := Temp1;
            Temp1 := Temp2;
            Temp2 := Temp3;
            Temp3 := Tmp_T;
            --  SubWord (using shared S-box).
            Temp0 := Tls_Core.Aes_Core.Sub_Byte (Temp0);
            Temp1 := Tls_Core.Aes_Core.Sub_Byte (Temp1);
            Temp2 := Tls_Core.Aes_Core.Sub_Byte (Temp2);
            Temp3 := Tls_Core.Aes_Core.Sub_Byte (Temp3);
            --  Rcon[i/4] applied to first byte (using shared Rcon).
            Temp0 := Temp0 xor Tls_Core.Aes_Core.Rcon (I / 4);
         end if;
         Out_RK (4 * I + 1) := Out_RK (4 * (I - 4) + 1) xor Temp0;
         Out_RK (4 * I + 2) := Out_RK (4 * (I - 4) + 2) xor Temp1;
         Out_RK (4 * I + 3) := Out_RK (4 * (I - 4) + 3) xor Temp2;
         Out_RK (4 * I + 4) := Out_RK (4 * (I - 4) + 4) xor Temp3;
      end loop;
   end Expand_Key;

   ---------------------------------------------------------------------
   --  Encrypt_Block — FIPS 197 §5.1 Cipher (Nr = 10).
   --
   --  Composed from the shared Aes_Core helpers; each round
   --  transformation lives in its own SPARK entity (own gnatprove
   --  worker), so this body's proof obligations stay small.
   ---------------------------------------------------------------------

   procedure Encrypt_Block
     (RK        : Round_Keys;
      Plaintext : Block;
      Out_Block : out Block)
   is
      State : Tls_Core.Aes_Core.Block := Plaintext;
   begin
      Out_Block := (others => 0);
      Tls_Core.Aes_Core.Add_Round_Key (State, RK, 0);
      for Round in 1 .. 9 loop
         Tls_Core.Aes_Core.Full_Round (State, RK, Round);
      end loop;
      Tls_Core.Aes_Core.Final_Round (State, RK, 10);
      Out_Block := State;
   end Encrypt_Block;

end Tls_Core.Aes128;
