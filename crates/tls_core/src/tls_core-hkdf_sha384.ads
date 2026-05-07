--  Tls_Core.Hkdf_Sha384 — RFC 5869 HKDF.Expand specialised to
--  HMAC-SHA-384. Same shape as Tls_Core.Hkdf_Sha256, just with
--  HashLen = 48.

with Tls_Core.Sha384;

package Tls_Core.Hkdf_Sha384
with SPARK_Mode
is

   Hash_Length : constant := Tls_Core.Sha384.Hash_Length;
   Max_Output  : constant := 255 * Hash_Length;

   --  No functional Post: HKDF-Expand-SHA-384 mathematical content
   --  (RFC 5869 §2.3) is not formalized inside this crate. RFC 5869
   --  test vectors (or callsite TLS 1.3 vectors) verify it
   --  functionally.
   procedure Expand
     (PRK  : Octet_Array;
      Info : Octet_Array;
      OKM  : out Octet_Array)
   with
     Pre =>
       PRK'Length = Hash_Length
       and then OKM'Length in 1 .. Max_Output
       and then Info'Length <= 1024
       and then PRK'Last < Integer'Last - 1024
       and then Info'Last < Integer'Last - 1024
       and then OKM'Last < Integer'Last - 1024;

   procedure Hmac_Expand
     (Prk    : Octet_Array;
      Info   : Octet_Array;
      Output : out Octet_Array)
   with
     Pre =>
       Prk'Length = Hash_Length
       and then Output'Length in 1 .. 255 * Hash_Length
       and then Info'Length <= 1024
       and then Prk'Last < Integer'Last - 1024
       and then Info'Last < Integer'Last - 1024
       and then Output'Last < Integer'Last - 1024;

end Tls_Core.Hkdf_Sha384;
