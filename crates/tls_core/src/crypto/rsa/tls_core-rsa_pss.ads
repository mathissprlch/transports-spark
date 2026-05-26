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
--  Spec mirror (docs/conventions.md §0c, HACL* port):
--      hacl-star/specs/Spec.RSAPSS.fst (commit main, ~438 lines).
--      Mirrored constructs:
--        - mgf_hash_f / mgf_hash  (lines 39-68)   → Spec_MGF1_*
--        - db_zero                (lines 91-104)  → Spec_DB_Zero_2047
--        - pss_verify_            (lines 150-187) → Spec_Pss_Verify_*
--        - pss_verify             (lines 190-212) → Spec_Pss_Verify_*
--      The verify pipeline is split:
--        EM = RSAVP1 (N, E, Signature)         (Bignum_2048.Mod_Exp;
--                                              AoRTE-proven only)
--        OK = pss_verify (..., EM)             (this module; PLATINUM)
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

with Interfaces;
with Tls_Core.Bignum_2048;
with Tls_Core.Sha256;
with Tls_Core.Sha384;

package Tls_Core.Rsa_Pss
  with SPARK_Mode
is

   --  Make bitwise/relational operators on Octet (Unsigned_8) and the
   --  MGF1 counter (Unsigned_32) visible in Pre/Post expressions below.
   use type Interfaces.Unsigned_8;
   use type Interfaces.Unsigned_32;

   subtype Bigint is Tls_Core.Bignum_2048.Bigint;

   ---------------------------------------------------------------------
   --  Fixed sizes for our 2048-bit / emBits=2047 / emLen=256 setup.
   ---------------------------------------------------------------------
   EM_Length    : constant := 256;
   --  emBits = 2047 ⇒ msBits = emBits mod 8 = 7. The HACL* db_zero
   --  spec (Spec.RSAPSS.fst:97-104) zeros the topmost (8 - msBits)
   --  bits of EM[0]; for msBits=7 that's the topmost 1 bit, i.e.
   --  AND with 0x7F. We expose the constant so the spec ghost and
   --  the imperative body share one definition.
   EM_High_Mask : constant Octet := 16#7F#;

   ---------------------------------------------------------------------
   --  HACL* Spec.RSAPSS port — ghost functions referenced by the
   --  Posts on Emsa_Pss_Verify_*. These are real, executable SPARK
   --  functions (docs/conventions.md §0d B3). The bodies MUST compute
   --  the function — no stub returning False.
   ---------------------------------------------------------------------

   --  Hash determinism as an explicit congruence lemma. gnatprove's Why3
   --  encoding does not expose UF congruence on Spec_SHA{256,384} when the
   --  function has a body in SPARK (even with Global => null), so we make
   --  the trivially-true property — equal byte arrays hashed by the same
   --  function produce equal digests — an explicit ghost lemma the prover
   --  can use by name. Same idiom as chacha20's Lemma_Rounds_Cong (task
   --  #107). The body's proof obligation is just SHA's own determinism;
   --  if SMT discharges it (via inlining of Spec_SHA's pure body on equal
   --  inputs), null body suffices — otherwise the body is filled in with
   --  inductive sub-lemmas down through Pad / Hash_Blocks / Finalize.
   procedure Lemma_Sha256_Cong (X, Y : Octet_Array)
   with
     Ghost,
     Global => null,
     Pre    =>
       X'First = 1
       and then Y'First = 1
       and then X'Length = Y'Length
       and then X'Length <= Natural'Last - 9 - 64
       and then (for all I in 1 .. X'Length => X (I) = Y (I)),
     Post   => Tls_Core.Sha256.Spec_SHA256 (X) = Tls_Core.Sha256.Spec_SHA256 (Y);

   procedure Lemma_Sha384_Cong (X, Y : Octet_Array)
   with
     Ghost,
     Global => null,
     Pre    =>
       X'First = 1
       and then Y'First = 1
       and then X'Length = Y'Length
       and then X'Length <= Natural'Last - 17 - 128
       and then (for all I in 1 .. X'Length => X (I) = Y (I)),
     Post   => Tls_Core.Sha384.Spec_SHA384 (X) = Tls_Core.Sha384.Spec_SHA384 (Y);

   --  Inductive lemma: equal Seeds give byte-wise equal MGF1 masks.
   --
   --  The loop body computes the block counter in Ada, calls
   --  Lemma_Sha256_Cong on the per-counter Buf inputs, and accumulates
   --  per-byte mask equality through the Loop_Invariant. This avoids
   --  the symbolic-integer-division case-split that defeats SMT in the
   --  unrolled-loop + per-range form (gnatprove cannot evaluate
   --  (I - 1) / 32 for symbolic I even with bounded range).
   procedure Lemma_MGF1_Cong_Sha256
     (Seed_X, Seed_Y : Octet_Array; Mask_Len : Natural)
   with
     Ghost,
     Global => null,
     Pre    =>
       Seed_X'First = 1
       and then Seed_Y'First = 1
       and then Seed_X'Length = Seed_Y'Length
       and then Seed_X'Length <= Natural'Last - 4 - 9 - 64
       and then (for all I in 1 .. Seed_X'Length => Seed_X (I) = Seed_Y (I))
       and then Mask_Len > 0
       and then Mask_Len <= Natural'Last - 32,
     Post   =>
       (for all I in 1 .. Mask_Len =>
          Spec_MGF1_Sha256 (Seed_X, Mask_Len) (I)
          = Spec_MGF1_Sha256 (Seed_Y, Mask_Len) (I));

   procedure Lemma_MGF1_Cong_Sha384
     (Seed_X, Seed_Y : Octet_Array; Mask_Len : Natural)
   with
     Ghost,
     Global => null,
     Pre    =>
       Seed_X'First = 1
       and then Seed_Y'First = 1
       and then Seed_X'Length = Seed_Y'Length
       and then Seed_X'Length <= Natural'Last - 4 - 17 - 128
       and then (for all I in 1 .. Seed_X'Length => Seed_X (I) = Seed_Y (I))
       and then Mask_Len > 0
       and then Mask_Len <= Natural'Last - 48,
     Post   =>
       (for all I in 1 .. Mask_Len =>
          Spec_MGF1_Sha384 (Seed_X, Mask_Len) (I)
          = Spec_MGF1_Sha384 (Seed_Y, Mask_Len) (I));

   --  Per-byte M_Prime equality from per-byte Salt equality. Walks
   --  bytes 1..72 (resp. 1..104) and discharges each iteration via
   --  case-analysis on I against M_Prime's three Post conjuncts —
   --  avoiding the universal-I cross-range case-split that defeats
   --  SMT in a single shot.
   procedure Lemma_M_Prime_Cong_Sha256
     (Message     : Octet_Array;
      EM_X, EM_Y  : Bigint)
   with
     Ghost,
     Global => null,
     Pre    =>
       Message'First = 1
       and then Message'Length <= Natural'Last - 9 - 64
       and then Message'Last < Integer'Last - 128
       and then
         (for all I in 1 .. 32 =>
            Spec_PSS_Salt_Sha256 (EM_X) (I)
            = Spec_PSS_Salt_Sha256 (EM_Y) (I)),
     Post   =>
       (for all I in 1 .. 72 =>
          Spec_PSS_M_Prime_Sha256 (Message, EM_X) (I)
          = Spec_PSS_M_Prime_Sha256 (Message, EM_Y) (I));

   procedure Lemma_M_Prime_Cong_Sha384
     (Message     : Octet_Array;
      EM_X, EM_Y  : Bigint)
   with
     Ghost,
     Global => null,
     Pre    =>
       Message'First = 1
       and then Message'Length <= Natural'Last - 17 - 128
       and then Message'Last < Integer'Last - 128
       and then
         (for all I in 1 .. 48 =>
            Spec_PSS_Salt_Sha384 (EM_X) (I)
            = Spec_PSS_Salt_Sha384 (EM_Y) (I)),
     Post   =>
       (for all I in 1 .. 104 =>
          Spec_PSS_M_Prime_Sha384 (Message, EM_X) (I)
          = Spec_PSS_M_Prime_Sha384 (Message, EM_Y) (I));

   --  Pure UF congruence wrappers: equal EM arrays give equal
   --  Pss_Verify Booleans. Null bodies — gnatprove discharges the
   --  Post via the SMT congruence axiom on the function symbol.
   --  The named lemma form keeps the proof-step budget down at call
   --  sites where inlining Spec_Pss_Verify's full defining Post would
   --  exceed level=2's instantiation limit.
   procedure Lemma_Pss_Verify_Cong_Sha256
     (Message : Octet_Array; EM_X, EM_Y : Bigint)
   with
     Ghost,
     Global => null,
     Pre    =>
       Message'First = 1
       and then Message'Length <= Natural'Last - 9 - 64
       and then Message'Last < Integer'Last - 128
       and then EM_X = EM_Y,
     Post   =>
       Spec_Pss_Verify_Sha256 (Message, EM_X)
       = Spec_Pss_Verify_Sha256 (Message, EM_Y);

   procedure Lemma_Pss_Verify_Cong_Sha384
     (Message : Octet_Array; EM_X, EM_Y : Bigint)
   with
     Ghost,
     Global => null,
     Pre    =>
       Message'First = 1
       and then Message'Length <= Natural'Last - 17 - 128
       and then Message'Last < Integer'Last - 128
       and then EM_X = EM_Y,
     Post   =>
       Spec_Pss_Verify_Sha384 (Message, EM_X)
       = Spec_Pss_Verify_Sha384 (Message, EM_Y);

   --  MGF1 per-counter buffer = Seed || I2OSP (Counter, 4).
   --  Defining pointwise Post — congruence threads via byte-wise equality.
   function Spec_MGF1_Sha256_Buf
     (Seed : Octet_Array; Counter : Interfaces.Unsigned_32)
      return Octet_Array
   with
     Global => null,
     Pre    =>
       Seed'First = 1 and then Seed'Length <= Natural'Last - 4 - 9 - 64,
     Post   =>
       Spec_MGF1_Sha256_Buf'Result'First = 1
       and then Spec_MGF1_Sha256_Buf'Result'Length = Seed'Length + 4
       and then (for all I in 1 .. Seed'Length =>
                   Spec_MGF1_Sha256_Buf'Result (I) = Seed (I))
       and then Spec_MGF1_Sha256_Buf'Result (Seed'Length + 1)
                = Octet (Interfaces.Shift_Right (Counter, 24) and 16#FF#)
       and then Spec_MGF1_Sha256_Buf'Result (Seed'Length + 2)
                = Octet (Interfaces.Shift_Right (Counter, 16) and 16#FF#)
       and then Spec_MGF1_Sha256_Buf'Result (Seed'Length + 3)
                = Octet (Interfaces.Shift_Right (Counter, 8) and 16#FF#)
       and then Spec_MGF1_Sha256_Buf'Result (Seed'Length + 4)
                = Octet (Counter and 16#FF#);

   function Spec_MGF1_Sha384_Buf
     (Seed : Octet_Array; Counter : Interfaces.Unsigned_32)
      return Octet_Array
   with
     Global => null,
     Pre    =>
       Seed'First = 1 and then Seed'Length <= Natural'Last - 4 - 17 - 128,
     Post   =>
       Spec_MGF1_Sha384_Buf'Result'First = 1
       and then Spec_MGF1_Sha384_Buf'Result'Length = Seed'Length + 4
       and then (for all I in 1 .. Seed'Length =>
                   Spec_MGF1_Sha384_Buf'Result (I) = Seed (I))
       and then Spec_MGF1_Sha384_Buf'Result (Seed'Length + 1)
                = Octet (Interfaces.Shift_Right (Counter, 24) and 16#FF#)
       and then Spec_MGF1_Sha384_Buf'Result (Seed'Length + 2)
                = Octet (Interfaces.Shift_Right (Counter, 16) and 16#FF#)
       and then Spec_MGF1_Sha384_Buf'Result (Seed'Length + 3)
                = Octet (Interfaces.Shift_Right (Counter, 8) and 16#FF#)
       and then Spec_MGF1_Sha384_Buf'Result (Seed'Length + 4)
                = Octet (Counter and 16#FF#);

   --  MGF1 per-counter SHA primitive: SHA256/384 of the Buf above.
   --  Expression function so gnatprove inlines for congruence threading.
   function Spec_MGF1_Sha256_Block
     (Seed : Octet_Array; Counter : Interfaces.Unsigned_32)
      return Tls_Core.Sha256.Digest
   is (Tls_Core.Sha256.Spec_SHA256
         (Spec_MGF1_Sha256_Buf (Seed, Counter)))
   with
     Global => null,
     Pre    =>
       Seed'First = 1 and then Seed'Length <= Natural'Last - 4 - 9 - 64;

   function Spec_MGF1_Sha384_Block
     (Seed : Octet_Array; Counter : Interfaces.Unsigned_32)
      return Tls_Core.Sha384.Digest
   is (Tls_Core.Sha384.Spec_SHA384
         (Spec_MGF1_Sha384_Buf (Seed, Counter)))
   with
     Global => null,
     Pre    =>
       Seed'First = 1 and then Seed'Length <= Natural'Last - 4 - 17 - 128;

   --  Mirrors Spec.RSAPSS.fst:46-50  (mgf_hash_f) +
   --  Spec.RSAPSS.fst:61-68          (mgf_hash) for SHA-256.
   --  Returns the first Mask_Len bytes of
   --      H (Seed || I2OSP (0, 4)) || H (Seed || I2OSP (1, 4)) || ...
   --  with H = SHA-256.
   --
   --  Iterated-aggregate expression function — congruence threads
   --  per-byte through Spec_MGF1_Sha256_Block (which itself has a
   --  defining Post `Result = Spec_SHA256 (Spec_MGF1_Sha256_Buf ...)`).
   function Spec_MGF1_Sha256
     (Seed : Octet_Array; Mask_Len : Natural) return Octet_Array
   is
     ([for I in 1 .. Mask_Len =>
         Spec_MGF1_Sha256_Block
           (Seed, Interfaces.Unsigned_32 ((I - 1) / 32))
           (((I - 1) mod 32) + 1)])
   with
     Global => null,
     Pre  =>
       Seed'First = 1
       and then Seed'Length <= Natural'Last - 4 - 9 - 64
       and then Mask_Len > 0
       and then Mask_Len <= Natural'Last - 32,
     Post =>
       Spec_MGF1_Sha256'Result'First = 1
       and then Spec_MGF1_Sha256'Result'Length = Mask_Len
       and then
         (for all I in 1 .. Mask_Len =>
            Spec_MGF1_Sha256'Result (I)
            = Spec_MGF1_Sha256_Block
                (Seed, Interfaces.Unsigned_32 ((I - 1) / 32))
                (((I - 1) mod 32) + 1));

   --  SHA-384 variant (block size 48 instead of 32).
   function Spec_MGF1_Sha384
     (Seed : Octet_Array; Mask_Len : Natural) return Octet_Array
   is
     ([for I in 1 .. Mask_Len =>
         Spec_MGF1_Sha384_Block
           (Seed, Interfaces.Unsigned_32 ((I - 1) / 48))
           (((I - 1) mod 48) + 1)])
   with
     Global => null,
     Pre  =>
       Seed'First = 1
       and then Seed'Length <= Natural'Last - 4 - 17 - 128
       and then Mask_Len > 0
       and then Mask_Len <= Natural'Last - 48,
     Post =>
       Spec_MGF1_Sha384'Result'First = 1
       and then Spec_MGF1_Sha384'Result'Length = Mask_Len
       and then
         (for all I in 1 .. Mask_Len =>
            Spec_MGF1_Sha384'Result (I)
            = Spec_MGF1_Sha384_Block
                (Seed, Interfaces.Unsigned_32 ((I - 1) / 48))
                (((I - 1) mod 48) + 1));

   --  Mirrors Spec.RSAPSS.fst:97-104 (db_zero) for our fixed
   --  emBits = 2047 case (msBits = 7, mask = 0x7F).
   function Spec_DB_Zero_2047 (DB : Octet_Array) return Octet_Array
   with
     Pre  => DB'First = 1 and then DB'Length >= 1,
     Post =>
       Spec_DB_Zero_2047'Result'First = 1
       and then Spec_DB_Zero_2047'Result'Length = DB'Length
       and then Spec_DB_Zero_2047'Result (1) = (DB (1) and EM_High_Mask)
       and then (for all I in 2 .. DB'Length =>
                   Spec_DB_Zero_2047'Result (I) = DB (I));

   ---------------------------------------------------------------------
   --  PSS-Verify decomposition helpers (v0.6 §0e closure).
   --
   --  Spec_Pss_Verify_* is decomposed into compositional ghost helpers
   --  each carrying a *defining* Post (pointwise equation tying the
   --  result back to the inputs via existing ports — Spec_MGF1_*,
   --  Spec_DB_Zero_2047, Spec_SHA256, Spec_SHA384).
   --
   --  Why: gnatprove's UF congruence does NOT fire on a function whose
   --  Post is non-defining (`Post => True` or size-only). The body is
   --  summarized by the Post; two calls on equal arguments give
   --  Skolem results that are NOT automatically equated. With a
   --  *defining* Post — Result = explicit expression in the inputs —
   --  substituting equal inputs into the same equation yields equal
   --  Results by contract, not by UF axiom. This is the ChaCha20
   --  Spec_Block_Bytes pattern (task #107).
   --
   --  Verify-side congruence (M = Spec_Em_From_Pubkey_Sig (N, E, S))
   --  then threads conjunct-by-conjunct through Spec_Pss_Verify's
   --  defining Post: EM accesses match by Bigint equality; helper
   --  calls f (M) = f (Spec_Em) match by their own defining Posts
   --  substituted with equal arguments.
   ---------------------------------------------------------------------

   --  EM tail = EM (224 .. 255) — the H field (32 bytes) extracted from
   --  the encoded message for SHA-256 PSS. (DB_Len = EM_Length - hLen - 1
   --  = 223 for hLen = 32, so the tail starts at byte 224.)
   function EM_Tail_Sha256 (EM : Bigint) return Octet_Array
   with
     Global => null,
     Post   =>
       EM_Tail_Sha256'Result'First = 1
       and then EM_Tail_Sha256'Result'Length = 32
       and then (for all I in 1 .. 32 =>
                   EM_Tail_Sha256'Result (I) = EM (223 + I));

   --  EM tail = EM (208 .. 255) for SHA-384 PSS (DB_Len = 207, hLen = 48).
   function EM_Tail_Sha384 (EM : Bigint) return Octet_Array
   with
     Global => null,
     Post   =>
       EM_Tail_Sha384'Result'First = 1
       and then EM_Tail_Sha384'Result'Length = 48
       and then (for all I in 1 .. 48 =>
                   EM_Tail_Sha384'Result (I) = EM (207 + I));

   --  DB = (EM (1 .. 223) xor MGF1_Sha256 (H, 223)) with top bit zeroed
   --  per db_zero (Spec.RSAPSS.fst:97-104). 223 bytes.
   function Spec_PSS_DB_Sha256 (EM : Bigint) return Octet_Array
   with
     Global => null,
     Post   =>
       Spec_PSS_DB_Sha256'Result'First = 1
       and then Spec_PSS_DB_Sha256'Result'Length = 223
       and then Spec_PSS_DB_Sha256'Result (1)
                = ((EM (1)
                    xor Spec_MGF1_Sha256 (EM_Tail_Sha256 (EM), 223) (1))
                   and EM_High_Mask)
       and then (for all I in 2 .. 223 =>
                   Spec_PSS_DB_Sha256'Result (I)
                   = (EM (I)
                      xor Spec_MGF1_Sha256 (EM_Tail_Sha256 (EM), 223) (I)));

   --  DB for SHA-384 PSS (DB_Len = 207).
   function Spec_PSS_DB_Sha384 (EM : Bigint) return Octet_Array
   with
     Global => null,
     Post   =>
       Spec_PSS_DB_Sha384'Result'First = 1
       and then Spec_PSS_DB_Sha384'Result'Length = 207
       and then Spec_PSS_DB_Sha384'Result (1)
                = ((EM (1)
                    xor Spec_MGF1_Sha384 (EM_Tail_Sha384 (EM), 207) (1))
                   and EM_High_Mask)
       and then (for all I in 2 .. 207 =>
                   Spec_PSS_DB_Sha384'Result (I)
                   = (EM (I)
                      xor Spec_MGF1_Sha384 (EM_Tail_Sha384 (EM), 207) (I)));

   --  Salt = DB (192 .. 223) for SHA-256 (S_Len = 32, PS_Len = 190).
   function Spec_PSS_Salt_Sha256 (EM : Bigint) return Octet_Array
   with
     Global => null,
     Post   =>
       Spec_PSS_Salt_Sha256'Result'First = 1
       and then Spec_PSS_Salt_Sha256'Result'Length = 32
       and then (for all I in 1 .. 32 =>
                   Spec_PSS_Salt_Sha256'Result (I)
                   = Spec_PSS_DB_Sha256 (EM) (191 + I));

   --  Salt = DB (160 .. 207) for SHA-384 (S_Len = 48, PS_Len = 158).
   function Spec_PSS_Salt_Sha384 (EM : Bigint) return Octet_Array
   with
     Global => null,
     Post   =>
       Spec_PSS_Salt_Sha384'Result'First = 1
       and then Spec_PSS_Salt_Sha384'Result'Length = 48
       and then (for all I in 1 .. 48 =>
                   Spec_PSS_Salt_Sha384'Result (I)
                   = Spec_PSS_DB_Sha384 (EM) (159 + I));

   --  M' = (00)^8 || SHA-256 (Message) || Salt — 72 bytes.
   function Spec_PSS_M_Prime_Sha256
     (Message : Octet_Array; EM : Bigint) return Octet_Array
   with
     Global => null,
     Pre    =>
       Message'First = 1
       and then Message'Length <= Natural'Last - 9 - 64
       and then Message'Last < Integer'Last - 128,
     Post   =>
       Spec_PSS_M_Prime_Sha256'Result'First = 1
       and then Spec_PSS_M_Prime_Sha256'Result'Length = 72
       and then (for all I in 1 .. 8 =>
                   Spec_PSS_M_Prime_Sha256'Result (I) = 0)
       and then (for all I in 1 .. 32 =>
                   Spec_PSS_M_Prime_Sha256'Result (8 + I)
                   = Tls_Core.Sha256.Spec_SHA256 (Message) (I))
       and then (for all I in 1 .. 32 =>
                   Spec_PSS_M_Prime_Sha256'Result (8 + 32 + I)
                   = Spec_PSS_Salt_Sha256 (EM) (I));

   --  M' = (00)^8 || SHA-384 (Message) || Salt — 104 bytes.
   function Spec_PSS_M_Prime_Sha384
     (Message : Octet_Array; EM : Bigint) return Octet_Array
   with
     Global => null,
     Pre    =>
       Message'First = 1
       and then Message'Length <= Natural'Last - 17 - 128
       and then Message'Last < Integer'Last - 128,
     Post   =>
       Spec_PSS_M_Prime_Sha384'Result'First = 1
       and then Spec_PSS_M_Prime_Sha384'Result'Length = 104
       and then (for all I in 1 .. 8 =>
                   Spec_PSS_M_Prime_Sha384'Result (I) = 0)
       and then (for all I in 1 .. 48 =>
                   Spec_PSS_M_Prime_Sha384'Result (8 + I)
                   = Tls_Core.Sha384.Spec_SHA384 (Message) (I))
       and then (for all I in 1 .. 48 =>
                   Spec_PSS_M_Prime_Sha384'Result (8 + 48 + I)
                   = Spec_PSS_Salt_Sha384 (EM) (I));

   --  Mirrors Spec.RSAPSS.fst:160-187 (pss_verify_) +
   --  Spec.RSAPSS.fst:200-212 (pss_verify), specialized to:
   --     a       = SHA-256
   --     emBits  = 2047 (so msBits=7, em_0-mask = 0x80)
   --     emLen   = 256
   --     sLen    = hLen = 32
   --  Returns True iff the encoded message EM is a valid PSS
   --  encoding of Message under SHA-256/MGF1-SHA-256/sLen=32.
   function Spec_Pss_Verify_Sha256
     (Message : Octet_Array; EM : Bigint) return Boolean
   with
     Global => null,
     Pre    =>
       Message'First = 1
       and then Message'Length <= Natural'Last - 9 - 64
       and then Message'Last < Integer'Last - 128,
     Post   =>
       Spec_Pss_Verify_Sha256'Result
       = (EM (EM_Length) = 16#BC#
          and then (EM (1) and 16#80#) = 0
          and then (for all I in 1 .. 190 =>
                      Spec_PSS_DB_Sha256 (EM) (I) = 0)
          and then Spec_PSS_DB_Sha256 (EM) (191) = 16#01#
          and then (for all I in 1 .. 32 =>
                      Tls_Core.Sha256.Spec_SHA256
                        (Spec_PSS_M_Prime_Sha256 (Message, EM)) (I)
                      = EM_Tail_Sha256 (EM) (I)));

   --  SHA-384 variant (sLen = hLen = 48).
   function Spec_Pss_Verify_Sha384
     (Message : Octet_Array; EM : Bigint) return Boolean
   with
     Global => null,
     Pre    =>
       Message'First = 1
       and then Message'Length <= Natural'Last - 17 - 128
       and then Message'Last < Integer'Last - 128,
     Post   =>
       Spec_Pss_Verify_Sha384'Result
       = (EM (EM_Length) = 16#BC#
          and then (EM (1) and 16#80#) = 0
          and then (for all I in 1 .. 158 =>
                      Spec_PSS_DB_Sha384 (EM) (I) = 0)
          and then Spec_PSS_DB_Sha384 (EM) (159) = 16#01#
          and then (for all I in 1 .. 48 =>
                      Tls_Core.Sha384.Spec_SHA384
                        (Spec_PSS_M_Prime_Sha384 (Message, EM)) (I)
                      = EM_Tail_Sha384 (EM) (I)));

   ---------------------------------------------------------------------
   --  Public entry points
   ---------------------------------------------------------------------

   --------------------------------------------------------------------
   --  [VERIFIED — PLATINUM]  EMSA-PSS-VERIFY with SHA-256.
   --
   --  Standard:    RFC 8017 §9.1.2
   --  Spec mirror: HACL* specs/Spec.RSAPSS.fst : pss_verify
   --                                            (lines 200-212)
   --  Functional:  OK = Spec_Pss_Verify_Sha256 (Message, EM)
   --  Proven at:   gnatprove --level=2 (audit-clean per §0d)
   --
   --  EM is the 256-byte encoded message that came out of RSAVP1
   --  (i.e. Mod_Exp (Signature, E, N)). hLen = sLen = 32.
   --------------------------------------------------------------------
   procedure Emsa_Pss_Verify_Sha256
     (Message : Octet_Array; EM : Bigint; OK : out Boolean)
   with
     Pre  =>
       Message'First = 1
       and then Message'Length <= Natural'Last - 9 - 64
       and then Message'Last < Integer'Last - 128,
     Post => OK = Spec_Pss_Verify_Sha256 (Message, EM);

   --------------------------------------------------------------------
   --  [VERIFIED — PLATINUM]  EMSA-PSS-VERIFY with SHA-384.
   --
   --  Standard:    RFC 8017 §9.1.2
   --  Spec mirror: HACL* specs/Spec.RSAPSS.fst : pss_verify
   --                                            (lines 200-212)
   --  Functional:  OK = Spec_Pss_Verify_Sha384 (Message, EM)
   --  Proven at:   gnatprove --level=2 (audit-clean per §0d)
   --
   --  hLen = sLen = 48.
   --------------------------------------------------------------------
   procedure Emsa_Pss_Verify_Sha384
     (Message : Octet_Array; EM : Bigint; OK : out Boolean)
   with
     Pre  =>
       Message'First = 1
       and then Message'Length <= Natural'Last - 17 - 128
       and then Message'Last < Integer'Last - 128,
     Post => OK = Spec_Pss_Verify_Sha384 (Message, EM);

   --------------------------------------------------------------------
   --  [VERIFIED — PLATINUM]  RSASSA-PSS-VERIFY with SHA-256.
   --
   --  Standard:    RFC 8017 §8.1.2
   --  Spec mirror: HACL* specs/Spec.RSAPSS.fst : rsapss_verify_
   --                                            (lines 319-335)
   --
   --  Functional:  EM := Bignum_2048.Mod_Exp (Signature, E, N);
   --               OK := Spec_Pss_Verify_Sha256 (Message, EM)
   --
   --  Post (composed):
   --      OK = Spec_Pss_Verify_Sha256
   --             (Message,
   --              Bignum_2048.Spec_Em_From_Pubkey_Sig (N, E, Signature))
   --  where `Spec_Em_From_Pubkey_Sig` is the canonical RSAVP1 step:
   --  `Big_To_Bigint (Spec_Mod_Exp (Bn_V (Sig), Bn_V (E), Bn_V (N)))`.
   --
   --  Proof structure: M = Spec_Em via Mod_Exp Post + Lemma_Bigint_
   --  Roundtrip; then UF congruence on Spec_Pss_Verify via
   --  Lemma_Pss_Verify_Cong_Sha256 (the lemma walks DB → MGF1 →
   --  M_Prime → SHA(M_Prime) → EM_Tail cong layer by layer to keep
   --  each SMT obligation within level=2's quantifier budget).
   --
   --  N, E, Signature are 2048-bit big-endian buffers (Bigint).
   --  Message is the data over which the signature was computed (NOT
   --  the digest — the signer hashed it themselves).
   --------------------------------------------------------------------
   procedure Verify_Sha256
     (N         : Bigint;
      E         : Bigint;
      Message   : Octet_Array;
      Signature : Bigint;
      OK        : out Boolean)
   with
     Pre  =>
       Message'First = 1
       and then Message'Length <= Natural'Last - 9 - 64
       and then Message'Last < Integer'Last - 128,
     Post =>
       OK
       = Spec_Pss_Verify_Sha256
           (Message,
            Tls_Core.Bignum_2048.Spec_Em_From_Pubkey_Sig (N, E, Signature));

   --------------------------------------------------------------------
   --  [VERIFIED — PLATINUM]  RSASSA-PSS-VERIFY with SHA-384.
   --
   --  Standard:    RFC 8017 §8.1.2
   --  Spec mirror: HACL* specs/Spec.RSAPSS.fst : rsapss_verify_
   --                                            (lines 319-335)
   --
   --  Same shape as Verify_Sha256: the Post composes Spec_Mod_Exp
   --  (HACL* `bn_mod_exp`) with Spec_Pss_Verify_Sha384. Proof structure
   --  mirrors SHA-256 via Lemma_Pss_Verify_Cong_Sha384.
   --------------------------------------------------------------------
   procedure Verify_Sha384
     (N         : Bigint;
      E         : Bigint;
      Message   : Octet_Array;
      Signature : Bigint;
      OK        : out Boolean)
   with
     Pre  =>
       Message'First = 1
       and then Message'Length <= Natural'Last - 17 - 128
       and then Message'Last < Integer'Last - 128,
     Post =>
       OK
       = Spec_Pss_Verify_Sha384
           (Message,
            Tls_Core.Bignum_2048.Spec_Em_From_Pubkey_Sig (N, E, Signature));

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  EMSA-PSS-ENCODE with SHA-256.
   --
   --  Standard:    RFC 8017 §9.1.1
   --  Spec mirror: HACL* specs/Spec.RSAPSS.fst : pss_encode
   --                                            (lines 119-148)
   --
   --  Used by tests / self-checks that round-trip ENCODE → VERIFY
   --  without needing a real signature. Caller supplies the salt;
   --  in real signing the salt is random.
   --
   --  Out_EM is the 256-byte encoded message; OK is False only if
   --  the requested parameters are inconsistent (the spec's
   --  "encoding error" path).
   --
   --  AoRTE-only (verify path is the v0.5 platinum target; the encode
   --  path is a tests scaffold only and the symmetric Spec_Pss_Encode
   --  is not yet ported — out of v0.5 scope per docs/conventions.md "verify-only
   --  is in v0.5; sign isn't").
   --------------------------------------------------------------------
   procedure Encode_Sha256
     (Message : Octet_Array;
      Salt    : Octet_Array;
      Out_EM  : out Bigint;
      OK      : out Boolean)
   with
     Pre =>
       Message'First = 1
       and then Message'Length <= Natural'Last - 9 - 64
       and then Message'Last < Integer'Last - 128
       and then Salt'Length = 32;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  EMSA-PSS-ENCODE with SHA-384 (sLen = 48).
   --  Same AoRTE caveat as Encode_Sha256.
   --------------------------------------------------------------------
   procedure Encode_Sha384
     (Message : Octet_Array;
      Salt    : Octet_Array;
      Out_EM  : out Bigint;
      OK      : out Boolean)
   with
     Pre =>
       Message'First = 1
       and then Message'Length <= Natural'Last - 17 - 128
       and then Message'Last < Integer'Last - 128
       and then Salt'Length = 48;

end Tls_Core.Rsa_Pss;
