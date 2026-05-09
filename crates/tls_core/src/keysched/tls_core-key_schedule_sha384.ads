--  Tls_Core.Key_Schedule_Sha384 — TLS 1.3 §7.1 key schedule
--  specialised to SHA-384 (used by TLS_AES_256_GCM_SHA384).
--
--  Same Extract / Derive_Secret API as Tls_Core.Key_Schedule, but
--  Secret is the SHA-384 digest type (48 bytes).

with Tls_Core.Sha384;

package Tls_Core.Key_Schedule_Sha384
with SPARK_Mode
is

   subtype Secret is Tls_Core.Sha384.Digest;

   --  No functional Posts: same SHA-256 key-schedule rationale.
   procedure Extract
     (Salt    : Octet_Array;
      IKM     : Octet_Array;
      Out_PRK : out Secret)
   with
     Pre =>
       Salt'Length = Tls_Core.Sha384.Hash_Length
       and then IKM'Length in 0 .. 1024
       and then Salt'Last < Integer'Last - 1024
       and then IKM'Last < Integer'Last - 1024;

   procedure Derive_Secret
     (Secret_In  : Secret;
      Label      : Octet_Array;
      Messages   : Octet_Array;
      Out_Secret : out Secret)
   with
     Pre =>
       Label'Length in 1 .. 249
       and then Label'Last < Integer'Last - 256
       and then Messages'Last
                  < Integer'Last - Tls_Core.Sha384.Block_Length;

end Tls_Core.Key_Schedule_Sha384;
