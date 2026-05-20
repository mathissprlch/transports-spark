with Tls_Core.Hkdf_Label_Sha384;

package body Tls_Core.Traffic_Keys_Aes256_Sha384
  with SPARK_Mode
is

   Key_Label : constant Octet_Array (1 .. 3) :=
     [16#6B#, 16#65#, 16#79#];  --  "key"
   Iv_Label  : constant Octet_Array (1 .. 2) :=
     [16#69#, 16#76#];          --  "iv"

   procedure Derive
     (Secret_In : Tls_Core.Key_Schedule_Sha384.Secret;
      Out_Key   : out Aead_Key;
      Out_IV    : out Aead_Iv)
   is
      Empty : constant Octet_Array (1 .. 0) := [others => 0];
   begin
      Tls_Core.Hkdf_Label_Sha384.Expand_Label
        (Secret  => Secret_In,
         Label   => Key_Label,
         Context => Empty,
         Output  => Out_Key);
      Tls_Core.Hkdf_Label_Sha384.Expand_Label
        (Secret  => Secret_In,
         Label   => Iv_Label,
         Context => Empty,
         Output  => Out_IV);
   end Derive;

end Tls_Core.Traffic_Keys_Aes256_Sha384;
