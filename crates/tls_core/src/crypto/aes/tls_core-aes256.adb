with Tls_Core.Aes_Core;

package body Tls_Core.Aes256
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   ---------------------------------------------------------------------
   --  Expand_Key — body is a one-liner over the platinum spec.
   ---------------------------------------------------------------------

   procedure Expand_Key
     (Key    : Key_Array;
      Out_RK : out Round_Keys)
   is
   begin
      Out_RK := Aes_Spec.Aes256_Key_Expansion (Key);
   end Expand_Key;

   ---------------------------------------------------------------------
   --  Encrypt_Block — gated by Tls_Core_Config.T_Tables_Enabled,
   --  same shape as Tls_Core.Aes128.Encrypt_Block.
   ---------------------------------------------------------------------

   procedure Encrypt_Block
     (RK        : Round_Keys;
      Plaintext : Block;
      Out_Block : out Block)
   is
   begin
      --  T_Tables_Enabled is a static constant; one of the branches
      --  is dead code at compile time.  The "no effect / never
      --  reached" warnings below are expected.
      pragma Warnings (Off, "statement has no effect");
      pragma Warnings (Off, "this statement is never reached");
      pragma Warnings (Off, "unused variable ""Round""");
      if Tls_Core_Config.T_Tables_Enabled then
         declare
            State : Tls_Core.Aes_Core.Block := Plaintext;
         begin
            Tls_Core.Aes_Core.Add_Round_Key (State, RK, 0);
            for Round in 1 .. 13 loop
               Tls_Core.Aes_Core.Full_Round (State, RK, Round);
            end loop;
            Tls_Core.Aes_Core.Final_Round (State, RK, 14);
            Out_Block := State;
         end;
      else
         Out_Block := Aes_Spec.Aes256_Encrypt_Block (Plaintext, RK);
      end if;
      pragma Warnings (On, "unused variable ""Round""");
      pragma Warnings (On, "this statement is never reached");
      pragma Warnings (On, "statement has no effect");
   end Encrypt_Block;

   ---------------------------------------------------------------------
   --  Decrypt_Block — body is a one-liner over the spec; Post
   --  discharges.
   ---------------------------------------------------------------------

   procedure Decrypt_Block
     (RK         : Round_Keys;
      Ciphertext : Block;
      Out_Block  : out Block)
   is
   begin
      Out_Block := Aes_Spec.Aes256_Decrypt_Block (Ciphertext, RK);
   end Decrypt_Block;

end Tls_Core.Aes256;
