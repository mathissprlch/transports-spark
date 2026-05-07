with Tls_Core.Aes_Core;

package body Tls_Core.Aes256
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use type Tls_Core.Octet;

   ---------------------------------------------------------------------
   --  Expand_Key — FIPS 197 §5.2 with Nk = 8, Nr = 14.
   ---------------------------------------------------------------------

   procedure Expand_Key
     (Key    : Key_Array;
      Out_RK : out Round_Keys)
   is
      Temp0, Temp1, Temp2, Temp3 : Octet;
      Tmp_T : Octet;
   begin
      Out_RK := (others => 0);
      Out_RK (1 .. 32) := Key;
      for I in 8 .. 59 loop
         Temp0 := Out_RK (4 * (I - 1) + 1);
         Temp1 := Out_RK (4 * (I - 1) + 2);
         Temp2 := Out_RK (4 * (I - 1) + 3);
         Temp3 := Out_RK (4 * (I - 1) + 4);
         if I mod 8 = 0 then
            Tmp_T := Temp0;
            Temp0 := Temp1;
            Temp1 := Temp2;
            Temp2 := Temp3;
            Temp3 := Tmp_T;
            Temp0 := Tls_Core.Aes_Core.Sub_Byte (Temp0);
            Temp1 := Tls_Core.Aes_Core.Sub_Byte (Temp1);
            Temp2 := Tls_Core.Aes_Core.Sub_Byte (Temp2);
            Temp3 := Tls_Core.Aes_Core.Sub_Byte (Temp3);
            Temp0 := Temp0 xor Tls_Core.Aes_Core.Rcon (I / 8);
         elsif I mod 8 = 4 then
            Temp0 := Tls_Core.Aes_Core.Sub_Byte (Temp0);
            Temp1 := Tls_Core.Aes_Core.Sub_Byte (Temp1);
            Temp2 := Tls_Core.Aes_Core.Sub_Byte (Temp2);
            Temp3 := Tls_Core.Aes_Core.Sub_Byte (Temp3);
         end if;
         Out_RK (4 * I + 1) := Out_RK (4 * (I - 8) + 1) xor Temp0;
         Out_RK (4 * I + 2) := Out_RK (4 * (I - 8) + 2) xor Temp1;
         Out_RK (4 * I + 3) := Out_RK (4 * (I - 8) + 3) xor Temp2;
         Out_RK (4 * I + 4) := Out_RK (4 * (I - 8) + 4) xor Temp3;
      end loop;
   end Expand_Key;

   ---------------------------------------------------------------------
   --  Encrypt_Block — FIPS 197 §5.1, Nr = 14. Body stays tiny by
   --  composing Aes_Core round helpers.
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
      for Round in 1 .. 13 loop
         Tls_Core.Aes_Core.Full_Round (State, RK, Round);
      end loop;
      Tls_Core.Aes_Core.Final_Round (State, RK, 14);
      Out_Block := State;
   end Encrypt_Block;

end Tls_Core.Aes256;
