--  Tls_Core_Config — build-time switches for the TLS core crate.
--
--  These are simple Ada constants rather than gpr scenario variables
--  so they're trivially patchable per-target without rebuilding the
--  alire toolchain. Each constant has a default that's right for
--  Linux/macOS hosts; bare-metal users edit this file and rebuild.
--
--  Why a separate root package: gpr scenario vars would couple
--  every consumer crate to a -X flag. Constants centralize the
--  switches in one auditable file.

package Tls_Core_Config
  with SPARK_Mode, Pure
is

   --  AES T-tables (FIPS 197 §5.1 round transformation as four
   --  256×4-byte lookup tables). 4 KB of constant data per build.
   --
   --  TRUE  — Encrypt_Block uses the T-table path (~4× runtime,
   --          standard for any host with > 32 KB code memory).
   --  FALSE — Falls back to the byte-by-byte SubBytes / ShiftRows
   --          / MixColumns path. No T-table memory cost. Use on
   --          extremely constrained bare-metal where every KB of
   --          flash matters.
   --
   --  Either path is checked equivalent against the FIPS 197
   --  test vectors at the Aes128 / Aes256 layer.
   T_Tables_Enabled : constant Boolean := True;

   --  Hardware crypto acceleration (AES-NI on x86_64,
   --  ARM Crypto Extensions on aarch64).
   --
   --  TRUE  — Encrypt_Block dispatches into Tls_Core.Aes_Hw, which
   --          binds AES-NI / ARM AESE intrinsics. Trust boundary
   --          shifts from "Ada body translates FIPS 197" to
   --          "Intel/ARM silicon implements FIPS 197" — same
   --          pattern HACL\* uses for verified platform-specific
   --          primitives.
   --  FALSE — Pure-Ada body (default). Audit surface is the Ada
   --          source of Aes_Core; no silicon trust required.
   --
   --  Default FALSE: the hand-audited Ada body is the v0.5
   --  baseline. Flip to TRUE for production loads where AES-NI
   --  speed matters.
   Use_Hw_Crypto : constant Boolean := False;

end Tls_Core_Config;
