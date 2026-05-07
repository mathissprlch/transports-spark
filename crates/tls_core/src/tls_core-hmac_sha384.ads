--  Tls_Core.Hmac_Sha384 — HMAC-SHA-384 (RFC 2104) over Tls_Core.Sha384.
--
--  Same construction as HMAC-SHA-256 but with the SHA-384
--  parameters: blocksize = 128, hashsize = 48. Test vectors:
--  RFC 4231 §4.

with Tls_Core.Sha384;

package Tls_Core.Hmac_Sha384
with SPARK_Mode
is

   subtype Tag is Tls_Core.Sha384.Digest;

   --  No functional Post: HMAC-SHA-384's mathematical content is
   --  not formalized inside this crate. RFC 4231 §4 test vectors in
   --  tls_core_tests are the functional check.
   procedure Compute
     (Key     : Octet_Array;
      Message : Octet_Array;
      Out_Tag : out Tag)
   with
     Pre =>
       Key'Length <= 1024
       and then Key'Last < Integer'Last - 1024
       and then Message'Last < Integer'Last - 1024;

end Tls_Core.Hmac_Sha384;
