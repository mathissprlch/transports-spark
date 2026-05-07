--  Tls_Core.Hmac_Sha256 — HMAC-SHA-256 (RFC 2104) over Tls_Core.Sha256.
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
--  tls_core_tests. miTLS does not implement HMAC in F\* either; it
--  imports HACL\*'s `EverCrypt.HMAC.compute`. Same separation here:
--  this module is a thin SPARK glue over Sha256.

with Tls_Core.Sha256;

package Tls_Core.Hmac_Sha256
with SPARK_Mode
is

   subtype Tag is Tls_Core.Sha256.Digest;
   --  HMAC-SHA-256 always emits a 32-byte tag (no truncation here).

   --  No functional Post: HMAC's mathematical content (RFC 2104)
   --  is not formalized inside this crate. RFC 4231 §4 test vectors
   --  in tls_core_tests are the functional check.
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
       and then Message'Last < Integer'Last - 1024
       --  Pre-hash branch calls Sha256.Hash, which now carries the
       --  HACL*-ported functional Post requiring its input to be
       --  1-based.
       and then Key'First = 1;

end Tls_Core.Hmac_Sha256;
