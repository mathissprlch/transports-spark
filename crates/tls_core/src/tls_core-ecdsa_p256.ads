--  Tls_Core.Ecdsa_P256 — ECDSA verification (and signing) over
--  NIST P-256 with SHA-256, per FIPS 186-4 §6.4.
--
--  The signature components r, s are 32-byte big-endian scalars in
--  Z_n where n is the order of the P-256 generator. The public key
--  is the SEC 1 §2.3.3 uncompressed form: 0x04 || X (32 BE) ||
--  Y (32 BE).
--
--  Verify implements §6.4.2 verbatim:
--      1. r, s in [1, n-1]
--      2. e = SHA-256 (M) interpreted as a 256-bit big-endian int
--      3. w  = s^-1 mod n
--      4. u1 = e * w mod n
--      5. u2 = r * w mod n
--      6. (x1, y1) = u1*G + u2*Q   (reject if infinity)
--      7. valid iff (x1 mod n) == r
--
--  Sign (RFC 6979 §2.4 with caller-supplied k for determinism in
--  tests) follows §6.4.1.

package Tls_Core.Ecdsa_P256
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   subtype Public_Key_Bytes is Octet_Array (1 .. 65);
   subtype Component        is Octet_Array (1 .. 32);

   --  ECDSA verify (FIPS 186-4 §6.4.2). No functional Post: the
   --  RFC 6979 deterministic-k vectors and §A.2.5 / A.2.6 RFC 6979
   --  vectors in tls_core_tests are the functional check.
   procedure Verify
     (Public_Key : Public_Key_Bytes;
      Message    : Octet_Array;
      R, S       : Component;
      OK         : out Boolean)
   with
     Pre  => Message'Last < Integer'Last - 64;

   --  ECDSA sign (FIPS 186-4 §6.4.1) with a caller-supplied per-
   --  signature scalar K. K must satisfy 1 <= K < n (e.g., the
   --  RFC 6979 deterministic k). On failure (k generates a
   --  degenerate r/s) OK is False.
   procedure Sign
     (Private_Key : Component;
      Message     : Octet_Array;
      K           : Component;
      Out_R       : out Component;
      Out_S       : out Component;
      OK          : out Boolean)
   with
     Pre  => Message'Last < Integer'Last - 64;

   pragma Warnings (On, "array aggregate using () is an obsolescent syntax");

end Tls_Core.Ecdsa_P256;
