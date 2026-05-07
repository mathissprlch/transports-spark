with Interfaces;

package body Tls_Core.Hello_Retry
with SPARK_Mode
is

   use type Interfaces.Unsigned_8;
   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   function Is_Hrr_Random (Random : Octet_Array) return Boolean
   is
      Diff : Octet := 0;
      Result : Boolean;
   begin
      for I in 1 .. 32 loop
         pragma Loop_Invariant (I in 1 .. 32);
         Diff := Diff or
           (Random (Random'First + I - 1) xor Magic_Random (I));
      end loop;
      Result := Diff = 0;
      return Result;
   end Is_Hrr_Random;

   procedure Build_Synthetic_Msg_Sha256
     (Ch1_Hash : Tls_Core.Sha256.Digest;
      Out_Buf  : out Octet_Array)
   is
   begin
      Out_Buf := (others => 0);
      Out_Buf (1) := Synthetic_Type;
      Out_Buf (2) := 16#00#;
      Out_Buf (3) := 16#00#;
      Out_Buf (4) := 16#20#;  --  32 = 0x20, length of SHA-256 digest
      for I in 1 .. 32 loop
         pragma Loop_Invariant (I in 1 .. 32);
         pragma Loop_Invariant (Out_Buf (1) = Synthetic_Type);
         pragma Loop_Invariant (Out_Buf (2) = 0);
         pragma Loop_Invariant (Out_Buf (3) = 0);
         pragma Loop_Invariant (Out_Buf (4) = 32);
         pragma Loop_Invariant
           (for all J in 1 .. I - 1 => Out_Buf (4 + J) = Ch1_Hash (J));
         Out_Buf (4 + I) := Ch1_Hash (I);
      end loop;
   end Build_Synthetic_Msg_Sha256;

end Tls_Core.Hello_Retry;
