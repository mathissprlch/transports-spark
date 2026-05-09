--  Tls_Core.Hmac_Sha256 — HMAC-SHA-256 (RFC 2104, FIPS 198-1) over
--  Tls_Core.Sha256.
--
--  Source: RFC 2104 — HMAC: Keyed-Hashing for Message Authentication,
--          plus FIPS 198-1 (the NIST recasting).
--
--    HMAC(K, M) = H((K' XOR opad) || H((K' XOR ipad) || M))
--
--    K' = K            if length(K) = blocksize
--       = H(K)         if length(K) > blocksize, padded with zeros
--       = K || 0...    if length(K) < blocksize
--
--  blocksize = 64, hashsize = 32 for SHA-256. opad = 0x5c repeated;
--  ipad = 0x36 repeated.
--
--  RFC 4231 §4 supplies the canonical test vectors which we run in
--  tls_core_tests.
--
--  HACL\* spec porting (CLAUDE.md §0c): the public Compute procedure
--  carries a functional Post `Out_Tag = Spec_HMAC_SHA256 (Key, Message)`
--  where Spec_HMAC_SHA256 is a SPARK port of HACL\*'s
--  `specs/Spec.HMAC.fst` `hmac` definition:
--
--    https://github.com/hacl-star/hacl-star/blob/main/specs/Spec.HMAC.fst
--
--  Mirrored constructs: `wrap_key` (Spec.HMAC.fst:13-25 —
--  K' = if |K| > B then H(K) || 0..0 else K || 0..0), `xor_bytes`
--  (Lib.ByteSequence — bytewise XOR), `hmac` (Spec.HMAC.fst:27-37 —
--  the H((K' XOR opad) || H((K' XOR ipad) || M)) composition).
--
--  Spec_HMAC_SHA256 is a real (executable) SPARK function, not a
--  ghost stub (CLAUDE.md §0d clause 4) — it composes Spec_SHA256.

with Tls_Core.Sha256;

package Tls_Core.Hmac_Sha256
with SPARK_Mode
is

   subtype Tag is Tls_Core.Sha256.Digest;
   --  HMAC-SHA-256 always emits a 32-byte tag (no truncation here).

   ---------------------------------------------------------------------
   --  HACL* Spec.HMAC port — exposed in the public spec because the
   --  Post on Compute references Spec_HMAC_SHA256. Bodies in the
   --  package body. These are real (executable) SPARK functions, not
   --  ghost stubs (CLAUDE.md §0d clause 4).
   --
   --  Both spec functions take arbitrary-base inputs (no First = 1
   --  requirement) so a caller's Pre on Compute can name them
   --  directly.
   ---------------------------------------------------------------------

   --  Build K' = K padded/hashed to Block_Length bytes per RFC 2104
   --  §2 / HACL* `wrap_key` (specs/Spec.HMAC.fst:13-25).
   function Spec_Wrap_Key (Key : Octet_Array) return Tls_Core.Sha256.Block
   with
     Pre => Key'Length <= 1024
            and then Key'Last < Integer'Last - 1024;

   --  Top-level RFC 2104 / FIPS 198-1 / HACL* `hmac`
   --  (specs/Spec.HMAC.fst:27-37):
   --    Spec_HMAC_SHA256 (K, M)
   --      = Spec_SHA256 ((K' XOR opad) || Spec_SHA256 ((K' XOR ipad) || M))
   function Spec_HMAC_SHA256
     (Key     : Octet_Array;
      Message : Octet_Array) return Tag
   with
     Pre => Key'Length <= 1024
            and then Key'Last < Integer'Last - 1024
            and then Message'Last < Integer'Last - 1024;

   --------------------------------------------------------------------
   --  [VERIFIED — PLATINUM]  HMAC-SHA-256 (RFC 2104, FIPS 198-1)
   --
   --  Standard:    RFC 2104 + FIPS 198-1
   --  Spec mirror: HACL* specs/Spec.HMAC.fst : hmac (lines 27-37)
   --  Functional:  Out_Tag = Spec_HMAC_SHA256 (Key, Message)
   --  Proven at:   gnatprove --level=2 (audit-clean)
   --------------------------------------------------------------------
   procedure Compute
     (Key     : Octet_Array;
      Message : Octet_Array;
      Out_Tag : out Tag)
   with
     Pre =>
       --  Key length is unrestricted by RFC 2104, but we cap it at
       --  the buffer size we use to pre-hash overlong keys.
       Key'Length <= 1024
       --  Bound caller's First so the index arithmetic in the body
       --  cannot overflow Integer.
       and then Key'Last < Integer'Last - 1024
       and then Message'Last < Integer'Last - 1024,
     Post =>
       --  Functional correctness: the imperative body computes the
       --  same value as the ported HACL* spec.
       Out_Tag = Spec_HMAC_SHA256 (Key, Message);

end Tls_Core.Hmac_Sha256;
