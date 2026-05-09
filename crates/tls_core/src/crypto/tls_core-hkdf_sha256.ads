--  Tls_Core.Hkdf_Sha256 — RFC 5869 HKDF.Expand specialised to
--  HMAC-SHA-256, plus the instantiation of
--  Tls_Core.Hkdf.Expand_Label that v0.5 slice 1 left as a generic.
--
--  Source: RFC 5869 §2.3 — Step 2: Expand.
--
--      N = ceil(L / HashLen)
--      T(0) = empty
--      T(i) = HMAC-Hash(PRK, T(i-1) || info || octet(i))   for 1<=i<=N
--      OKM = T(1) || T(2) || ... || T(N) truncated to L octets
--
--  HACL\* spec porting (CLAUDE.md §0c): the public Expand procedure
--  carries `OKM = Spec_HKDF_Expand (PRK, Info, OKM'Length)` where
--  Spec_HKDF_Expand is a SPARK port of HACL\*'s
--  `specs/Spec.HKDF.fst` `expand` definition:
--
--    https://github.com/hacl-star/hacl-star/blob/main/specs/Spec.HKDF.fst
--
--  Mirrored constructs: `expand_loop` (Spec.HKDF.fst — the T-chain)
--  and `expand` (truncation of T(1) || T(2) || ... to L). Both are
--  real (executable) SPARK functions; expand_loop is recursive and
--  carries a Subprogram_Variant on the descending iteration counter.

with Tls_Core.Sha256;

package Tls_Core.Hkdf_Sha256
with SPARK_Mode
is

   use type Tls_Core.Octet;

   Hash_Length : constant := Tls_Core.Sha256.Hash_Length;

   --  RFC 5869 §2.3 cap: maximum output length is 255 * HashLen.
   Max_Output : constant := 255 * Hash_Length;

   ---------------------------------------------------------------------
   --  HACL* Spec.HKDF port — exposed in the public spec because the
   --  Post on Expand references Spec_HKDF_Expand. Bodies in the
   --  package body. These are real (executable) SPARK functions, not
   --  ghost stubs (CLAUDE.md §0d clause 4).
   ---------------------------------------------------------------------

   --  Single-block T(i) computation:
   --    T(i) = HMAC-Hash (PRK, T_Prev || Info || octet(i))
   --  where T_Prev is T(i-1) (Hash_Length bytes) for i > 1, or
   --  empty for i = 1 (signalled by First_Block = True).
   function Spec_HKDF_Expand_Block
     (PRK         : Octet_Array;
      Info        : Octet_Array;
      T_Prev      : Tls_Core.Sha256.Digest;
      Counter     : Octet;
      First_Block : Boolean) return Tls_Core.Sha256.Digest
   with
     Pre => PRK'Length = Hash_Length
            and then PRK'Last < Integer'Last - 1024
            and then Info'Last < Integer'Last - 1024
            and then Info'Length <= 1024;

   --  Top-level RFC 5869 §2.3 Expand:
   --    OKM = T(1) || T(2) || ... || T(N) truncated to L bytes.
   --  Result has First = 1 and Length = L.
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
   --  [VERIFIED — PLATINUM]  HKDF-Expand-SHA-256 (RFC 5869 §2.3)
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

   --  Adapter matching the Hmac_Expand formal of
   --  Tls_Core.Hkdf.Expand_Label. Renames Expand under the
   --  Hmac_Expand call signature so the generic can instantiate.
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

end Tls_Core.Hkdf_Sha256;
