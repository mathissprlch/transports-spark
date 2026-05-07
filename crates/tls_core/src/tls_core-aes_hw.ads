--  Tls_Core.Aes_Hw — HW-accelerated AES round operation.
--
--  When Tls_Core_Config.Use_Hw_Crypto = True, Tls_Core.Aes_Core's
--  Full_Round dispatches into Hw_Full_Round here, which is bound
--  (via pragma Import / inline asm) to the platform's AES round
--  instruction:
--
--    x86_64 with AES-NI:  AESENC (xmm, m128/xmm)   — one full
--      AES round (SubBytes + ShiftRows + MixColumns + AddRoundKey)
--      in ~4 cycles.
--    AArch64 with Crypto Extensions:
--      AESE  (vd, vn) + AESMC (vd, vd)             — same one round
--      across two instructions.
--
--  Platinum trust boundary when Use_Hw_Crypto = True:
--      "this body computes AES per FIPS 197" becomes
--      "Intel AES-NI / ARM AESE+AESMC computes AES per FIPS 197"
--  with the relevant Intel/ARM ARM (architectural reference manual)
--  page as the supporting axiom. Narrower than 250 lines of byte
--  arithmetic, defensible — same pattern HACL\* uses for verified
--  Vale-AES integration.
--
--  v0.5 ships SCAFFOLDING ONLY. The body is a stub that falls back
--  to the software path; concrete pragma Import bindings to
--  __builtin_ia32_aesenc128 / vaeseq_u8 + vaesmcq_u8 land in v0.6
--  alongside per-arch CI on x86_64 and aarch64. Until then,
--  Use_Hw_Crypto = True simply re-runs the software path through
--  this indirection (correct, slower than direct, surfaces the
--  build-flag wiring).

with Tls_Core.Aes_Core;

package Tls_Core.Aes_Hw
with SPARK_Mode
is

   --  HW-backed full AES round. Same contract as
   --  Tls_Core.Aes_Core.Full_Round; on platforms with AES-NI / ARM
   --  Crypto Extensions, the body becomes a single instruction.
   --  No functional Post; the SW path and HW path are checked to
   --  agree via FIPS 197 test vectors at the Aes128 / Aes256 layer.
   procedure Hw_Full_Round
     (S     : in out Tls_Core.Aes_Core.Block;
      RK    : Octet_Array;
      Round : Natural)
   with
     Pre  => RK'First = 1
             and then Round * 16 + 16 <= RK'Length;

   --  HW-backed final round (no MixColumns).
   procedure Hw_Final_Round
     (S     : in out Tls_Core.Aes_Core.Block;
      RK    : Octet_Array;
      Round : Natural)
   with
     Pre  => RK'First = 1
             and then Round * 16 + 16 <= RK'Length;

end Tls_Core.Aes_Hw;
