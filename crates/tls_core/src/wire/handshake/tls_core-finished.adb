with Tls_Core.Hkdf;
with Tls_Core.Hkdf_Sha256;
with Tls_Core.Hmac_Sha256;

package body Tls_Core.Finished
  with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   --  Slice 1's Expand_Label generic, instantiated against
   --  slice 7's HMAC-SHA-256 primitive.
   procedure Hkdf_Expand_Label_Sha256 is new
     Tls_Core.Hkdf.Expand_Label
       (Hash_Length      => Tls_Core.Sha256.Hash_Length,
        Max_Info         => 256,
        Spec_Hmac_Expand => Tls_Core.Hkdf_Sha256.Spec_HKDF_Expand,
        Hmac_Expand      => Tls_Core.Hkdf_Sha256.Hmac_Expand);

   procedure Compute
     (Base_Key        : Tls_Core.Key_Schedule.Secret;
      Transcript_Hash : Tls_Core.Sha256.Digest;
      Out_Verify      : out Verify_Data)
   is
      Finished_Key : Tls_Core.Sha256.Digest;
      Empty_Ctx    : constant Octet_Array (1 .. 0) := (others => 0);
      Label        : constant Octet_Array (1 .. 8) :=
      --  "finished"
        (16#66#, 16#69#, 16#6E#, 16#69#, 16#73#, 16#68#, 16#65#, 16#64#);
   begin
      --  finished_key = HKDF-Expand-Label(BaseKey, "finished", "", 32)
      Hkdf_Expand_Label_Sha256
        (Secret  => Base_Key,
         Label   => Label,
         Context => Empty_Ctx,
         Output  => Finished_Key);
      --  verify_data = HMAC(finished_key, transcript_hash)
      Tls_Core.Hmac_Sha256.Compute
        (Key     => Finished_Key,
         Message => Transcript_Hash,
         Out_Tag => Out_Verify);
   end Compute;

end Tls_Core.Finished;
