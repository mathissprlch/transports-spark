with Tls_Core.Aes_Core;

package body Tls_Core.Aes128
  with SPARK_Mode
is


   ---------------------------------------------------------------------
   --  Expand_Key — FIPS 197 §5.2 KeyExpansion (Nk = 4, Nr = 10).
   --  Body is a one-liner over the platinum spec; the Post
   --  discharges by construction.
   ---------------------------------------------------------------------

   procedure Expand_Key (Key : Key_Array; Out_RK : out Round_Keys) is
   begin
      Out_RK := Aes_Spec.Aes128_Key_Expansion (Key);
   end Expand_Key;

   ---------------------------------------------------------------------
   --  Encrypt_Block — FIPS 197 §5.1 Cipher (Nr = 10).
   --
   --  Two paths, gated by Tls_Core_Config.T_Tables_Enabled:
   --
   --    * False — body calls Aes_Spec.Aes128_Encrypt_Block directly
   --      (the round-by-round HACL\* spec port).  Post discharges.
   --    * True  — body dispatches to the existing T-tables path
   --      via Aes_Core.Full_Round.  Post is gated off; equivalence
   --      lemma deferred to v0.6.
   ---------------------------------------------------------------------

   procedure Encrypt_Block
     (RK : Round_Keys; Plaintext : Block; Out_Block : out Block) is
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
            for Round in 1 .. 9 loop
               Tls_Core.Aes_Core.Full_Round (State, RK, Round);
            end loop;
            Tls_Core.Aes_Core.Final_Round (State, RK, 10);
            Out_Block := State;
         end;
      else
         Out_Block := Aes_Spec.Aes128_Encrypt_Block (Plaintext, RK);
      end if;
      pragma Warnings (On, "unused variable ""Round""");
      pragma Warnings (On, "this statement is never reached");
      pragma Warnings (On, "statement has no effect");
   end Encrypt_Block;

   ---------------------------------------------------------------------
   --  Decrypt_Block — FIPS 197 §5.3 InvCipher.  Body is a one-liner
   --  over the spec; Post discharges.
   ---------------------------------------------------------------------

   procedure Decrypt_Block
     (RK : Round_Keys; Ciphertext : Block; Out_Block : out Block) is
   begin
      Out_Block := Aes_Spec.Aes128_Decrypt_Block (Ciphertext, RK);
   end Decrypt_Block;

end Tls_Core.Aes128;
