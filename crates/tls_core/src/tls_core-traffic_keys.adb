with Tls_Core.Hkdf;
with Tls_Core.Hkdf_Sha256;

package body Tls_Core.Traffic_Keys
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   procedure Hkdf_Expand_Label_Sha256
     is new Tls_Core.Hkdf.Expand_Label
       (Hash_Length      => 32,
        Max_Info         => 512,
        Spec_Hmac_Expand => Tls_Core.Hkdf_Sha256.Spec_HKDF_Expand,
        Hmac_Expand      => Tls_Core.Hkdf_Sha256.Hmac_Expand);

   --  Labels: byte values for "key" and "iv".
   Key_Label : constant Octet_Array (1 .. 3) :=
     (16#6B#, 16#65#, 16#79#);  --  "key"
   Iv_Label  : constant Octet_Array (1 .. 2) :=
     (16#69#, 16#76#);          --  "iv"

   procedure Derive
     (Secret_In : Tls_Core.Key_Schedule.Secret;
      Out_Key   : out Aead_Key;
      Out_IV    : out Aead_Iv)
   is
      Empty : constant Octet_Array (1 .. 0) := (others => 0);
   begin
      Hkdf_Expand_Label_Sha256
        (Secret  => Secret_In,
         Label   => Key_Label,
         Context => Empty,
         Output  => Out_Key);
      Hkdf_Expand_Label_Sha256
        (Secret  => Secret_In,
         Label   => Iv_Label,
         Context => Empty,
         Output  => Out_IV);
   end Derive;

end Tls_Core.Traffic_Keys;
