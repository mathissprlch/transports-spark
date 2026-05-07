--  Tls_Core.Hmac_Sha384 — HMAC-SHA-384 (RFC 2104, FIPS 198-1) over
--  Tls_Core.Sha384.
--
--  Same construction as HMAC-SHA-256 but with the SHA-384
--  parameters: blocksize = 128, hashsize = 48. Test vectors:
--  RFC 4231 §4.
--
--  HACL\* spec porting (CLAUDE.md §0c): same shape as Hmac_Sha256 —
--  Spec_HMAC_SHA384 is a SPARK port of HACL\*'s
--  `specs/Spec.HMAC.fst` `hmac` definition specialised at SHA2_384,
--  composing Tls_Core.Sha384.Spec_SHA384.

with Tls_Core.Sha384;

package Tls_Core.Hmac_Sha384
with SPARK_Mode
is

   subtype Tag is Tls_Core.Sha384.Digest;

   ---------------------------------------------------------------------
   --  HACL* Spec.HMAC port specialised at SHA-384.
   ---------------------------------------------------------------------

   function Spec_Wrap_Key (Key : Octet_Array) return Tls_Core.Sha384.Block
   with
     Pre => Key'Length <= 1024
            and then Key'Last < Integer'Last - 1024;

   function Spec_HMAC_SHA384
     (Key     : Octet_Array;
      Message : Octet_Array) return Tag
   with
     Pre => Key'Length <= 1024
            and then Key'Last < Integer'Last - 1024
            and then Message'Last < Integer'Last - 1024;

   --------------------------------------------------------------------
   --  [VERIFIED — PLATINUM]  HMAC-SHA-384 (RFC 2104, FIPS 198-1)
   --
   --  Standard:    RFC 2104 + FIPS 198-1, hash = SHA-384 (FIPS 180-4)
   --  Spec mirror: HACL* specs/Spec.HMAC.fst : hmac (lines 27-37)
   --  Functional:  Out_Tag = Spec_HMAC_SHA384 (Key, Message)
   --  Proven at:   gnatprove --level=2 (audit-clean)
   --------------------------------------------------------------------
   procedure Compute
     (Key     : Octet_Array;
      Message : Octet_Array;
      Out_Tag : out Tag)
   with
     Pre =>
       Key'Length <= 1024
       and then Key'Last < Integer'Last - 1024
       and then Message'Last < Integer'Last - 1024,
     Post =>
       Out_Tag = Spec_HMAC_SHA384 (Key, Message);

end Tls_Core.Hmac_Sha384;
