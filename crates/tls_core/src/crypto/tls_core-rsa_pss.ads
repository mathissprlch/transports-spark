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

package Tls_Core.Rsa_Pss
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   --  Make bitwise/relational operators on Octet (Unsigned_8) visible
   --  in Pre/Post expressions below.
   use type Interfaces.Unsigned_8;

   subtype Bigint is Tls_Core.Bignum_2048.Bigint;

   ---------------------------------------------------------------------
   --  Fixed sizes for our 2048-bit / emBits=2047 / emLen=256 setup.
   ---------------------------------------------------------------------
   EM_Length : constant := 256;
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

   --  Mirrors Spec.RSAPSS.fst:46-50  (mgf_hash_f) +
   --  Spec.RSAPSS.fst:61-68          (mgf_hash) for SHA-256.
   --  Returns the first Mask_Len bytes of
   --      H (Seed || I2OSP (0, 4)) || H (Seed || I2OSP (1, 4)) || ...
   --  with H = SHA-256.
   --
   --  Real (executable) function — same pattern as
   --  Tls_Core.Sha256.Spec_SHA256: the function IS the spec, and the
   --  imperative entry point's body is a thin call to it so the
   --  functional Post discharges by construction.
   function Spec_MGF1_Sha256
     (Seed     : Octet_Array;
      Mask_Len : Natural) return Octet_Array
   with
     Pre  => Seed'First = 1
             and then Seed'Length <= Natural'Last - 4 - 9 - 64
             and then Mask_Len > 0
             and then Mask_Len <= Natural'Last - 32,
     Post => Spec_MGF1_Sha256'Result'First = 1
             and then Spec_MGF1_Sha256'Result'Length = Mask_Len;

   --  SHA-384 variant (same shape as MGF1_Sha256).
   function Spec_MGF1_Sha384
     (Seed     : Octet_Array;
      Mask_Len : Natural) return Octet_Array
   with
     Pre  => Seed'First = 1
             and then Seed'Length <= Natural'Last - 4 - 17 - 128
             and then Mask_Len > 0
             and then Mask_Len <= Natural'Last - 48,
     Post => Spec_MGF1_Sha384'Result'First = 1
             and then Spec_MGF1_Sha384'Result'Length = Mask_Len;

   --  Mirrors Spec.RSAPSS.fst:97-104 (db_zero) for our fixed
   --  emBits = 2047 case (msBits = 7, mask = 0x7F).
   function Spec_DB_Zero_2047 (DB : Octet_Array) return Octet_Array
   with
     Pre  => DB'First = 1 and then DB'Length >= 1,
     Post => Spec_DB_Zero_2047'Result'First = 1
             and then Spec_DB_Zero_2047'Result'Length = DB'Length
             and then Spec_DB_Zero_2047'Result (1) = (DB (1) and EM_High_Mask)
             and then (for all I in 2 .. DB'Length =>
                          Spec_DB_Zero_2047'Result (I) = DB (I));

   --  Mirrors Spec.RSAPSS.fst:160-187 (pss_verify_) +
   --  Spec.RSAPSS.fst:200-212 (pss_verify), specialized to:
   --     a       = SHA-256
   --     emBits  = 2047 (so msBits=7, em_0-mask = 0x80)
   --     emLen   = 256
   --     sLen    = hLen = 32
   --  Returns True iff the encoded message EM is a valid PSS
   --  encoding of Message under SHA-256/MGF1-SHA-256/sLen=32.
   function Spec_Pss_Verify_Sha256
     (Message : Octet_Array;
      EM      : Bigint) return Boolean
   with
     Pre  => Message'First = 1
             and then Message'Length <= Natural'Last - 9 - 64
             and then Message'Last < Integer'Last - 128;

   --  SHA-384 variant (sLen = hLen = 48).
   function Spec_Pss_Verify_Sha384
     (Message : Octet_Array;
      EM      : Bigint) return Boolean
   with
     Pre  => Message'First = 1
             and then Message'Length <= Natural'Last - 17 - 128
             and then Message'Last < Integer'Last - 128;

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
     (Message : Octet_Array;
      EM      : Bigint;
      OK      : out Boolean)
   with
     Pre  => Message'First = 1
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
     (Message : Octet_Array;
      EM      : Bigint;
      OK      : out Boolean)
   with
     Pre  => Message'First = 1
             and then Message'Length <= Natural'Last - 17 - 128
             and then Message'Last < Integer'Last - 128,
     Post => OK = Spec_Pss_Verify_Sha384 (Message, EM);

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  RSASSA-PSS-VERIFY with SHA-256.
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
   --  Both ghost components have real, computable bodies (docs/conventions.md
   --  §0d B3 & A4). The Post is real functional, not a length-
   --  only shape — it pushes the unproven obligation down to (a) the
   --  functional Post of `Bignum_2048.Mod_Exp` (the Montgomery ↔
   --  Big_Integer square-and-multiply equivalence) and (b) the
   --  round-trip lemma `Big_To_Bigint (Bn_V (M)) = M`. Both are
   --  invoked by the body — see `Lemma_Bigint_Roundtrip (M)` after
   --  `Mod_Exp` — so when those underlying obligations close, the
   --  Verify Post discharges automatically.
   --
   --  Status: honest unproven (clause 1 not satisfied — the chain
   --  through Mod_Exp's functional Post is not yet discharged at
   --  level=2). Clause-6 clean: no SPARK_Mode (Off), no pragma
   --  Assume, no annotation. RFC 8017 §A.2 test vectors and the
   --  Encode → Verify round-trip in tls_core_tests exercise the
   --  chain end-to-end.
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
     Pre  => Message'First = 1
             and then Message'Length <= Natural'Last - 9 - 64
             and then Message'Last < Integer'Last - 128,
     Post =>
       OK = Spec_Pss_Verify_Sha256
              (Message,
               Tls_Core.Bignum_2048.Spec_Em_From_Pubkey_Sig
                 (N, E, Signature));

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  RSASSA-PSS-VERIFY with SHA-384.
   --
   --  Standard:    RFC 8017 §8.1.2
   --  Spec mirror: HACL* specs/Spec.RSAPSS.fst : rsapss_verify_
   --                                            (lines 319-335)
   --
   --  Same shape as Verify_Sha256: the Post composes Spec_Mod_Exp
   --  (HACL* `bn_mod_exp`) with Spec_Pss_Verify_Sha384 (HACL*
   --  `pss_verify` for SHA-384). Honest unproven (the Mod_Exp
   --  functional Post is the choke point) — B4 clean.
   --------------------------------------------------------------------
   procedure Verify_Sha384
     (N         : Bigint;
      E         : Bigint;
      Message   : Octet_Array;
      Signature : Bigint;
      OK        : out Boolean)
   with
     Pre  => Message'First = 1
             and then Message'Length <= Natural'Last - 17 - 128
             and then Message'Last < Integer'Last - 128,
     Post =>
       OK = Spec_Pss_Verify_Sha384
              (Message,
               Tls_Core.Bignum_2048.Spec_Em_From_Pubkey_Sig
                 (N, E, Signature));

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
     Pre  => Message'First = 1
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
     Pre  => Message'First = 1
             and then Message'Length <= Natural'Last - 17 - 128
             and then Message'Last < Integer'Last - 128
             and then Salt'Length = 48;

   pragma Warnings (On, "array aggregate using () is an obsolescent syntax");

end Tls_Core.Rsa_Pss;
