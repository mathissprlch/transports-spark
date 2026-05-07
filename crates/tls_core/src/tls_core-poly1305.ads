--  Tls_Core.Poly1305 — Poly1305 one-time MAC (RFC 8439 §2.5).
--
--  Source: RFC 8439 §2.5 — The Poly1305 Algorithm.
--
--    r = clamp(key[0..15])
--    s =       key[16..31]
--    Acc = 0
--    For each 16-byte block n_i (last block possibly partial):
--        Acc = (Acc + n_i + 2^(8*len)) mod (2^130 - 5)
--        Acc = (Acc * r)               mod (2^130 - 5)
--    Tag = (Acc + s) mod 2^128
--
--  We work over a 5-limb representation of 130-bit integers
--  (each limb 26 bits) to keep modular reductions straightforward
--  inside 64-bit accumulators. This is the same layout HACL\*
--  uses for `Hacl.Spec.Poly1305.Field32`.
--
--  RFC 8439 §2.5.2 supplies the test vector that tls_core_tests
--  pins against.

with Interfaces;

package Tls_Core.Poly1305
with SPARK_Mode
is

   subtype U64 is Interfaces.Unsigned_64;
   subtype U32 is Interfaces.Unsigned_32;

   Key_Length : constant := 32;
   Tag_Length : constant := 16;

   subtype Key_Array is Octet_Array (1 .. Key_Length);
   subtype Tag_Array is Octet_Array (1 .. Tag_Length);

   --  No functional Post: Poly1305's mathematical content
   --  (RFC 8439 §2.5) is not formalized inside this crate. The
   --  RFC 8439 §2.5.2 test vector in tls_core_tests is the
   --  functional check.
   procedure Mac
     (Key     : Key_Array;
      Message : Octet_Array;
      Out_Tag : out Tag_Array)
   with
     Pre => Message'Last < Integer'Last - 16;

end Tls_Core.Poly1305;
