--  Tls_Core.Rsa_Pss — RSASSA-PSS signature verification (and a
--  matching encode-side helper for round-trip self-tests).
--
--  Source: RFC 8017 (PKCS #1 v2.2):
--      §8.1.2  RSASSA-PSS-VERIFY
--      §9.1.1  EMSA-PSS-ENCODE
--      §9.1.2  EMSA-PSS-VERIFY
--      §B.2.1  MGF1 mask generation function
--      §5.2.2  RSAVP1 (signature verification primitive: m = s^e mod n)
--
--  TLS 1.3 (RFC 8446 §4.2.3) negotiates RSA-PSS with these
--  signature_algorithm code points:
--      rsa_pss_rsae_sha256   (0x0804)
--      rsa_pss_rsae_sha384   (0x0805)
--      rsa_pss_rsae_sha512   (0x0806)
--      rsa_pss_pss_sha256    (0x0809)
--      rsa_pss_pss_sha384    (0x080A)
--      rsa_pss_pss_sha512    (0x080B)
--  All use salt length = hash length and MGF1 with the same hash.
--
--  This module covers the SHA-256 and SHA-384 entry points (the two
--  most common in real TLS 1.3 deployments, and the two needed for
--  v0.5 phase 14 cert verification). SHA-512 is symmetric and can be
--  added later by analogy.
--
--  All buffers exchanged with the caller are big-endian per X.509 /
--  PKCS#1 conventions: modulus, exponent, signature are 256-byte BE
--  arrays for a 2048-bit RSA key.

with Tls_Core.Bignum_2048;

package Tls_Core.Rsa_Pss
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   subtype Bigint is Tls_Core.Bignum_2048.Bigint;

   --  RSASSA-PSS-VERIFY with SHA-256 / MGF1-SHA-256 / sLen = hLen = 32.
   --
   --  N is the 2048-bit RSA modulus (big-endian, 256 bytes).
   --  E is the public exponent (big-endian, 256 bytes; commonly
   --  0x010001 — i.e., zero-padded on the left).
   --  Signature is the candidate signature (big-endian, 256 bytes).
   --  Message is the data over which the signature was supposedly
   --  computed (NOT the digest — the signer hashed it themselves).
   --
   --  Sets OK := True iff the signature verifies under N, E.
   --  No functional Post: RFC 8017 §B test vectors in tls_core_tests
   --  are the functional check.
   procedure Verify_Sha256
     (N         : Bigint;
      E         : Bigint;
      Message   : Octet_Array;
      Signature : Bigint;
      OK        : out Boolean)
   with
     Pre  => Message'Last < Integer'Last - 128;

   --  RSASSA-PSS-VERIFY with SHA-384 / MGF1-SHA-384 / sLen = hLen = 48.
   procedure Verify_Sha384
     (N         : Bigint;
      E         : Bigint;
      Message   : Octet_Array;
      Signature : Bigint;
      OK        : out Boolean)
   with
     Pre  => Message'Last < Integer'Last - 128;

   --  EMSA-PSS-ENCODE-SHA256 (RFC 8017 §9.1.1) for emBits = 2047
   --  (i.e., a 2048-bit RSA modulus). Used by tests / self-checks
   --  that round-trip ENCODE → VERIFY without needing a real
   --  signature. Caller supplies the salt; in real signing the salt
   --  is random.
   --
   --  Out_EM is the 256-byte encoded message; OK is False only if
   --  the requested parameters are inconsistent (the spec's
   --  "encoding error" path).
   procedure Encode_Sha256
     (Message : Octet_Array;
      Salt    : Octet_Array;
      Out_EM  : out Bigint;
      OK      : out Boolean)
   with
     Pre  => Message'Last < Integer'Last - 128
             and then Salt'Length = 32;

   --  EMSA-PSS-ENCODE-SHA384 (sLen = 48).
   procedure Encode_Sha384
     (Message : Octet_Array;
      Salt    : Octet_Array;
      Out_EM  : out Bigint;
      OK      : out Boolean)
   with
     Pre  => Message'Last < Integer'Last - 128
             and then Salt'Length = 48;

   pragma Warnings (On, "array aggregate using () is an obsolescent syntax");

end Tls_Core.Rsa_Pss;
