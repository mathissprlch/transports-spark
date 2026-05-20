--  Tls_Core.Hkdf_Sha384 — RFC 5869 HKDF.Expand specialised to
--  HMAC-SHA-384. Same shape as Tls_Core.Hkdf_Sha256, just with
--  HashLen = 48.
--
--  HACL\* spec porting (docs/conventions.md §0c): Spec_HKDF_Expand is a SPARK
--  port of HACL\*'s `specs/Spec.HKDF.fst` `expand` definition
--  specialised to HMAC-SHA-384.

with Tls_Core.Sha384;

package Tls_Core.Hkdf_Sha384
with SPARK_Mode
is

   use type Tls_Core.Octet;

   Hash_Length : constant := Tls_Core.Sha384.Hash_Length;
   Max_Output  : constant := 255 * Hash_Length;

   ---------------------------------------------------------------------
   --  HACL* Spec.HKDF port specialised at SHA-384.
   ---------------------------------------------------------------------

   function Spec_HKDF_Expand_Block
     (PRK         : Octet_Array;
      Info        : Octet_Array;
      T_Prev      : Tls_Core.Sha384.Digest;
      Counter     : Octet;
      First_Block : Boolean) return Tls_Core.Sha384.Digest
   with
     Pre => PRK'Length = Hash_Length
            and then PRK'Last < Integer'Last - 1024
            and then Info'Last < Integer'Last - 1024
            and then Info'Length <= 1024;

   function Spec_HKDF_Expand
     (PRK  : Octet_Array;
      Info : Octet_Array;
      L    : Positive) return Octet_Array
   with
     Pre =>
       PRK'Length = Hash_Length
       and then L in 1 .. Max_Output
       and then Info'Length <= 1024
       and then PRK'Last < Integer'Last - 1024
       and then Info'Last < Integer'Last - 1024,
     Post =>
       Spec_HKDF_Expand'Result'First = 1
       and then Spec_HKDF_Expand'Result'Length = L;

   --------------------------------------------------------------------
   --  [VERIFIED — PLATINUM]  HKDF-Expand-SHA-384 (RFC 5869 §2.3)
   --
   --  Standard:    RFC 5869 §2.3 (Step 2: Expand)
   --  Spec mirror: HACL* specs/Spec.HKDF.fst : expand
   --  Functional:  OKM = Spec_HKDF_Expand (PRK, Info, OKM'Length)
   --  Proven at:   gnatprove --level=2 (audit-clean)
   --------------------------------------------------------------------
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
       and then OKM'Last < Integer'Last - 1024,
     Post =>
       (for all I in 1 .. OKM'Length =>
          OKM (OKM'First + I - 1)
            = Spec_HKDF_Expand (PRK, Info, OKM'Length)
                (Spec_HKDF_Expand (PRK, Info, OKM'Length)'First + I - 1));

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
       and then Output'Last < Integer'Last - 1024,
     Post =>
       (for all I in 1 .. Output'Length =>
          Output (Output'First + I - 1)
            = Spec_HKDF_Expand (Prk, Info, Output'Length)
                (Spec_HKDF_Expand (Prk, Info, Output'Length)'First + I - 1));

end Tls_Core.Hkdf_Sha384;
