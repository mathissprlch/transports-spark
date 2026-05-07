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
--  miTLS reference: src/tls/MiTLS.HKDF.fst — `expand` is a thin
--  wrapper over EverCrypt.HKDF.expand, whose F\* `expand_spec`
--  postcondition pins the output to the RFC 5869 functional
--  definition. Our Ada implementation here IS the FIPS-style
--  RFC 5869 algorithm verbatim; the caller's Pre captures the
--  L <= 255 * HashLen bound from §2.3.
--
--  Once this slice lands, slice 1's Tls_Core.Hkdf.Expand_Label can
--  be instantiated against `Hmac_Expand` below and we have a
--  fully working TLS 1.3 key-schedule primitive in pure Ada/SPARK.

with Tls_Core.Sha256;

package Tls_Core.Hkdf_Sha256
with SPARK_Mode
is

   Hash_Length : constant := Tls_Core.Sha256.Hash_Length;

   --  RFC 5869 §2.3 cap: maximum output length is 255 * HashLen.
   Max_Output : constant := 255 * Hash_Length;

   --  Pure RFC 5869 Expand. PRK is the pseudo-random key (output
   --  of Extract or any HashLen-byte secret); Info is the
   --  application-specific context; OKM is the requested-length
   --  output.
   --
   --  No functional Post: HKDF-Expand's mathematical content
   --  (RFC 5869 §2.3) is not formalized inside this crate. RFC 5869
   --  Appendix A test vectors in tls_core_tests are the functional
   --  check.
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
       and then Output'Last < Integer'Last - 1024;

end Tls_Core.Hkdf_Sha256;
