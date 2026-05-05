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

   --  Spec_Hmac is the abstract RFC 2104 keyed-hash treated as an
   --  opaque ghost function. Compute's Post pins its output to the
   --  spec, with one pragma Assume in the body discharging the
   --  equality. This composes upward: HKDF, Key_Schedule, Finished
   --  callers can reason about HMAC's output through Spec_Hmac
   --  without re-axiomatizing the inner SHA-256 transform.
   function Spec_Hmac (Key, Message : Octet_Array) return Tag
   with Ghost;

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
     Post => Out_Tag = Spec_Hmac (Key, Message);

end Tls_Core.Hmac_Sha256;
