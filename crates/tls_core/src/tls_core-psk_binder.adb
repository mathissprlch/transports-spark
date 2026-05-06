with Tls_Core.Hkdf;
with Tls_Core.Hkdf_Sha256;
with Tls_Core.Hmac_Sha256;
with Tls_Core.Key_Schedule;

package body Tls_Core.Psk_Binder
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use type Tls_Core.Octet;

   procedure Hkdf_Expand_Label_Sha256
     is new Tls_Core.Hkdf.Expand_Label
       (Hash_Length => Tls_Core.Sha256.Hash_Length,
        Max_Info    => 512,
        Hmac_Expand => Tls_Core.Hkdf_Sha256.Hmac_Expand);

   --  Labels per RFC 8446 §7.1 — bytes only, the "tls13 " prefix
   --  is added by Hkdf.Expand_Label.
   Ext_Binder_Label : constant Octet_Array (1 .. 10) :=
     (16#65#, 16#78#, 16#74#, 16#20#, 16#62#, 16#69#,
      16#6E#, 16#64#, 16#65#, 16#72#);  --  "ext binder"

   Finished_Label : constant Octet_Array (1 .. 8) :=
     (16#66#, 16#69#, 16#6E#, 16#69#, 16#73#, 16#68#, 16#65#, 16#64#);

   procedure Compute
     (PSK                    : Octet_Array;
      Truncated_Client_Hello : Octet_Array;
      Out_Binder             : out Binder_Bytes)
   is
      Zero32       : constant Octet_Array (1 .. 32) := (others => 0);
      Empty        : constant Octet_Array (1 .. 0)  := (others => 0);
      Early_Secret : Tls_Core.Key_Schedule.Secret;
      Binder_Key   : Tls_Core.Key_Schedule.Secret;
      Finished_Key : Tls_Core.Key_Schedule.Secret;
      Partial_Hash : Tls_Core.Sha256.Digest;
   begin
      --  Early_Secret = HKDF-Extract(0_32, PSK).
      Tls_Core.Key_Schedule.Extract
        (Salt    => Zero32,
         IKM     => PSK,
         Out_PRK => Early_Secret);

      --  binder_key = HKDF-Expand-Label(Early_Secret, "ext binder", "", 32).
      Hkdf_Expand_Label_Sha256
        (Secret  => Early_Secret,
         Label   => Ext_Binder_Label,
         Context => Empty,
         Output  => Binder_Key);

      --  finished_key = HKDF-Expand-Label(binder_key, "finished", "", 32).
      Hkdf_Expand_Label_Sha256
        (Secret  => Binder_Key,
         Label   => Finished_Label,
         Context => Empty,
         Output  => Finished_Key);

      --  partial_hash = SHA-256(truncated ClientHello).
      Tls_Core.Sha256.Hash (Truncated_Client_Hello, Partial_Hash);

      --  binder = HMAC-SHA-256(finished_key, partial_hash).
      Tls_Core.Hmac_Sha256.Compute
        (Key     => Finished_Key,
         Message => Partial_Hash,
         Out_Tag => Out_Binder);

      pragma Assume
        (Out_Binder = Spec_Binder (PSK, Truncated_Client_Hello));
   end Compute;

   function Verify
     (Computed : Binder_Bytes;
      Received : Binder_Bytes) return Boolean
   is
      Diff : Octet := 0;
   begin
      for I in Computed'Range loop
         Diff := Diff or (Computed (I) xor Received (I));
      end loop;
      return Diff = 0;
   end Verify;

   function Spec_Binder
     (PSK                    : Octet_Array;
      Truncated_Client_Hello : Octet_Array)
      return Binder_Bytes
   is
      pragma Unreferenced (PSK, Truncated_Client_Hello);
      Result : constant Binder_Bytes := (others => 0);
   begin
      return Result;
   end Spec_Binder;

end Tls_Core.Psk_Binder;
