with Tls_Core.Hkdf;
with Tls_Core.Hmac_Sha256;
with Tls_Core.Hkdf_Sha256;

package body Tls_Core.Key_Schedule
  with SPARK_Mode
is

   ---------------------------------------------------------------------
   --  Extract — HKDF-Extract = HMAC-Hash(salt, IKM).
   ---------------------------------------------------------------------

   procedure Extract
     (Salt : Octet_Array; IKM : Octet_Array; Out_PRK : out Secret) is
   begin
      Tls_Core.Hmac_Sha256.Compute
        (Key => Salt, Message => IKM, Out_Tag => Out_PRK);
   end Extract;

   ---------------------------------------------------------------------
   --  Derive-Secret — Expand-Label with context = SHA-256(Messages).
   ---------------------------------------------------------------------

   --  Max_Info = 512 covers the worst-case label/context shape
   --    (Label'Length=249, Context=32) → Info_Size = 291,
   --  with headroom for SHA-384 contexts later.
   procedure Hkdf_Expand_Label_Sha256 is new
     Tls_Core.Hkdf.Expand_Label
       (Hash_Length      => Tls_Core.Sha256.Hash_Length,
        Max_Info         => 512,
        Spec_Hmac_Expand => Tls_Core.Hkdf_Sha256.Spec_HKDF_Expand,
        Hmac_Expand      => Tls_Core.Hkdf_Sha256.Hmac_Expand);

   procedure Derive_Secret
     (Secret_In  : Secret;
      Label      : Octet_Array;
      Messages   : Octet_Array;
      Out_Secret : out Secret)
   is
      Transcript_Hash : Tls_Core.Sha256.Digest;
   begin
      Tls_Core.Sha256.Hash (Messages, Transcript_Hash);
      Hkdf_Expand_Label_Sha256
        (Secret  => Secret_In,
         Label   => Label,
         Context => Transcript_Hash,
         Output  => Out_Secret);
   end Derive_Secret;

end Tls_Core.Key_Schedule;
