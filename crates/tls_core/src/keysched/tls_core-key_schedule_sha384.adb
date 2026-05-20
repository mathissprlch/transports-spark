with Tls_Core.Hkdf;
with Tls_Core.Hmac_Sha384;
with Tls_Core.Hkdf_Sha384;

package body Tls_Core.Key_Schedule_Sha384
  with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   procedure Extract
     (Salt : Octet_Array; IKM : Octet_Array; Out_PRK : out Secret) is
   begin
      Tls_Core.Hmac_Sha384.Compute
        (Key => Salt, Message => IKM, Out_Tag => Out_PRK);
   end Extract;

   --  Max_Info = 512 covers worst-case label (249) + context (48)
   --  with headroom.
   procedure Hkdf_Expand_Label_Sha384 is new
     Tls_Core.Hkdf.Expand_Label
       (Hash_Length      => Tls_Core.Sha384.Hash_Length,
        Max_Info         => 512,
        Spec_Hmac_Expand => Tls_Core.Hkdf_Sha384.Spec_HKDF_Expand,
        Hmac_Expand      => Tls_Core.Hkdf_Sha384.Hmac_Expand);

   procedure Derive_Secret
     (Secret_In  : Secret;
      Label      : Octet_Array;
      Messages   : Octet_Array;
      Out_Secret : out Secret)
   is
      Transcript_Hash : Tls_Core.Sha384.Digest;
   begin
      Tls_Core.Sha384.Hash (Messages, Transcript_Hash);
      Hkdf_Expand_Label_Sha384
        (Secret  => Secret_In,
         Label   => Label,
         Context => Transcript_Hash,
         Output  => Out_Secret);
   end Derive_Secret;

end Tls_Core.Key_Schedule_Sha384;
