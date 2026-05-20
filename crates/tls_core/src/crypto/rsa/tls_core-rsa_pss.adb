with Tls_Core.Sha256;
with Tls_Core.Sha384;

pragma Warnings (Off, "redundant with clause in body");

package body Tls_Core.Rsa_Pss
  with SPARK_Mode
is


   use Interfaces;

   ---------------------------------------------------------------------
   --  EM_Length / em_Bits constants (RFC 8017 §9.1).
   --
   --  For a 2048-bit RSA modulus, modBits = 2048, so
   --      emBits = modBits - 1 = 2047
   --      emLen  = ceil (emBits / 8) = 256
   --
   --  After OS2IP / I2OSP at the EMSA boundary, EM is exactly 256
   --  bytes — i.e., a Bigint. The "high 8*emLen - emBits = 1 bit
   --  of EM[0]" must be zero.
   --
   --  EM_Length / EM_High_Mask are exposed in the package spec so
   --  the spec ghost (Spec_DB_Zero_2047) and the imperative body
   --  share one definition.
   ---------------------------------------------------------------------

   ---------------------------------------------------------------------
   --  Spec ports — ported from HACL* specs/Spec.RSAPSS.fst.
   --  These are real (executable) SPARK functions referenced by the
   --  Posts on Emsa_Pss_Verify_*. The imperative entry points call
   --  them directly, so the functional Posts discharge by
   --  construction (mirror of Sha256.Hash → Spec_SHA256).
   ---------------------------------------------------------------------

   --  Build a 4-byte big-endian counter at the tail of a buffer.
   --  Mirrors the `nat_to_intseq_be 4 i` step of mgf_hash_f
   --  (Spec.RSAPSS.fst:47-48).
   procedure Put_Counter_BE (Buf : in out Octet_Array; Counter : Unsigned_32)
   with
     Pre  => Buf'Length >= 4,
     Post =>
       Buf (Buf'Last - 3) = Octet (Shift_Right (Counter, 24) and 16#FF#)
       and then Buf (Buf'Last - 2)
                = Octet (Shift_Right (Counter, 16) and 16#FF#)
       and then Buf (Buf'Last - 1)
                = Octet (Shift_Right (Counter, 8) and 16#FF#)
       and then Buf (Buf'Last) = Octet (Counter and 16#FF#);

   procedure Put_Counter_BE (Buf : in out Octet_Array; Counter : Unsigned_32)
   is
   begin
      Buf (Buf'Last - 3) := Octet (Shift_Right (Counter, 24) and 16#FF#);
      Buf (Buf'Last - 2) := Octet (Shift_Right (Counter, 16) and 16#FF#);
      Buf (Buf'Last - 1) := Octet (Shift_Right (Counter, 8) and 16#FF#);
      Buf (Buf'Last) := Octet (Counter and 16#FF#);
   end Put_Counter_BE;

   ---------------------------------------------------------------------
   --  Spec_MGF1_Sha256 — port of mgf_hash for SHA-256.
   --  Spec.RSAPSS.fst:61-68.
   ---------------------------------------------------------------------

   function Spec_MGF1_Sha256
     (Seed : Octet_Array; Mask_Len : Natural) return Octet_Array
   is
      Buf_Len : constant Natural := Seed'Length + 4;
      Buf     : Octet_Array (1 .. Buf_Len) := [others => 0];
      Result  : Octet_Array (1 .. Mask_Len) := (others => 0);
      Counter : Unsigned_32 := 0;
      Filled  : Natural := 0;
      Take    : Natural;
      Digest  : Tls_Core.Sha256.Digest;
   begin
      --  Copy Seed into prefix of Buf (counter trailing zeros).
      for I in 0 .. Seed'Length - 1 loop
         Buf (1 + I) := Seed (Seed'First + I);
         pragma
           Loop_Invariant
             (for all K in 0 .. I => Buf (1 + K) = Seed (Seed'First + K));
      end loop;

      while Filled < Mask_Len loop
         pragma Loop_Invariant (Filled <= Mask_Len);
         pragma Loop_Variant (Increases => Filled);

         Put_Counter_BE (Buf, Counter);
         Tls_Core.Sha256.Hash (Buf, Digest);

         Take := Mask_Len - Filled;
         if Take > 32 then
            Take := 32;
         end if;

         for I in 0 .. Take - 1 loop
            Result (1 + Filled + I) := Digest (1 + I);
            pragma Loop_Invariant (1 + Filled + I in Result'Range);
         end loop;

         Filled := Filled + Take;
         exit when Counter = Unsigned_32'Last;
         Counter := Counter + 1;
      end loop;
      return Result;
   end Spec_MGF1_Sha256;

   ---------------------------------------------------------------------
   --  Spec_MGF1_Sha384 — same shape, SHA-384 hash.
   ---------------------------------------------------------------------

   function Spec_MGF1_Sha384
     (Seed : Octet_Array; Mask_Len : Natural) return Octet_Array
   is
      Buf_Len : constant Natural := Seed'Length + 4;
      Buf     : Octet_Array (1 .. Buf_Len) := [others => 0];
      Result  : Octet_Array (1 .. Mask_Len) := (others => 0);
      Counter : Unsigned_32 := 0;
      Filled  : Natural := 0;
      Take    : Natural;
      Digest  : Tls_Core.Sha384.Digest;
   begin
      for I in 0 .. Seed'Length - 1 loop
         Buf (1 + I) := Seed (Seed'First + I);
         pragma
           Loop_Invariant
             (for all K in 0 .. I => Buf (1 + K) = Seed (Seed'First + K));
      end loop;

      while Filled < Mask_Len loop
         pragma Loop_Invariant (Filled <= Mask_Len);
         pragma Loop_Variant (Increases => Filled);

         Put_Counter_BE (Buf, Counter);
         Tls_Core.Sha384.Hash (Buf, Digest);

         Take := Mask_Len - Filled;
         if Take > 48 then
            Take := 48;
         end if;

         for I in 0 .. Take - 1 loop
            Result (1 + Filled + I) := Digest (1 + I);
            pragma Loop_Invariant (1 + Filled + I in Result'Range);
         end loop;

         Filled := Filled + Take;
         exit when Counter = Unsigned_32'Last;
         Counter := Counter + 1;
      end loop;
      return Result;
   end Spec_MGF1_Sha384;

   ---------------------------------------------------------------------
   --  Spec_DB_Zero_2047 — Spec.RSAPSS.fst:97-104 specialized.
   --  For our fixed emBits=2047, msBits=7 ⇒ mask the top bit.
   ---------------------------------------------------------------------

   function Spec_DB_Zero_2047 (DB : Octet_Array) return Octet_Array is
      --  Pre guarantees DB'First = 1, so DB'Last = DB'Length.
      R : Octet_Array (1 .. DB'Length) := (others => 0);
   begin
      R (1) := DB (1) and EM_High_Mask;
      for I in 2 .. DB'Length loop
         R (I) := DB (I);
         pragma Loop_Invariant (R (1) = (DB (1) and EM_High_Mask));
         pragma Loop_Invariant (for all K in 2 .. I => R (K) = DB (K));
      end loop;
      return R;
   end Spec_DB_Zero_2047;

   ---------------------------------------------------------------------
   --  Spec_Pss_Verify_Sha256 — Spec.RSAPSS.fst:200-212 + 160-187,
   --  specialized to emBits=2047, hLen=sLen=32.
   --
   --  Steps mirror RFC 8017 §9.1.2:
   --   2. emLen >= hLen + sLen + 2  (256 >= 66 ✓)
   --   3. trailer EM[emLen-1] = 0xBC
   --   3'. (HACL pss_verify) top byte sanity: em[0] & 0x80 = 0
   --       (i.e., em[0] high bit is zero — encodes the emBits mask).
   --   4. maskedDB = EM[0..223), H = EM[223..255)  (0-based)
   --   5. dbMask = MGF1 (H, 223)
   --   6. DB = maskedDB XOR dbMask
   --   7. DB = db_zero (DB, emBits)
   --   8. DB[0..190) all zeros, DB[190] = 0x01     (PS pad)
   --   9. salt = DB[191..223)
   --  10. M' = 0x00 x 8 || mHash || salt
   --  11. H' = SHA256 (M')
   --  12. consistent iff H' = H.
   ---------------------------------------------------------------------

   function Spec_Pss_Verify_Sha256
     (Message : Octet_Array; EM : Bigint) return Boolean
   is
      H_Len   : constant Natural := 32;
      S_Len   : constant Natural := 32;
      DB_Len  : constant Natural := EM_Length - H_Len - 1;  -- 223
      PS_Len  : constant Natural := EM_Length - S_Len - H_Len - 2;  -- 190
      M_Hash  : Tls_Core.Sha256.Digest;
      H_Bytes : Octet_Array (1 .. H_Len);
      Db_Mask : Octet_Array (1 .. DB_Len);
      DB      : Octet_Array (1 .. DB_Len);
      Salt    : Octet_Array (1 .. S_Len);
      --  M_Prime: positions 1..8 stay 0 per RFC step 10; init for SPARK
      --  flow analysis (only positions 9..72 are written explicitly).
      M_Prime : Octet_Array (1 .. 8 + H_Len + S_Len) := [others => 0];
      H_Prime : Tls_Core.Sha256.Digest;
      Diff    : Octet := 0;
      Bad     : Octet := 0;
   begin
      --  Step 3' (HACL): em high bit must be zero.
      if (EM (1) and 16#80#) /= 0 then
         return False;
      end if;

      --  Step 3: trailer.
      if EM (EM_Length) /= 16#BC# then
         return False;
      end if;

      --  Step 1 (RFC) / mHash.
      Tls_Core.Sha256.Hash (Message, M_Hash);

      --  Step 4: split.
      for I in 1 .. H_Len loop
         H_Bytes (I) := EM (DB_Len + I);
      end loop;

      --  Step 5: dbMask.
      Db_Mask := Spec_MGF1_Sha256 (H_Bytes, DB_Len);

      --  Step 6: DB = maskedDB XOR dbMask.
      for I in 1 .. DB_Len loop
         DB (I) := EM (I) xor Db_Mask (I);
      end loop;

      --  Step 7: zero top bit.
      DB := Spec_DB_Zero_2047 (DB);

      --  Step 8: PS check (constant-time).
      for I in 1 .. PS_Len loop
         Bad := Bad or DB (I);
      end loop;
      if Bad /= 0 then
         return False;
      end if;
      if DB (PS_Len + 1) /= 16#01# then
         return False;
      end if;

      --  Step 9: salt.
      for I in 1 .. S_Len loop
         Salt (I) := DB (PS_Len + 1 + I);
      end loop;

      --  Step 10: M' (M_Prime is already 0-initialized at decl;
      --  positions 1..8 stay zero per RFC).
      for I in 1 .. H_Len loop
         M_Prime (8 + I) := M_Hash (I);
      end loop;
      for I in 1 .. S_Len loop
         M_Prime (8 + H_Len + I) := Salt (I);
      end loop;

      --  Step 11: H' = SHA256 (M').
      Tls_Core.Sha256.Hash (M_Prime, H_Prime);

      --  Step 12: constant-time compare.
      for I in 1 .. H_Len loop
         Diff := Diff or (H_Prime (I) xor H_Bytes (I));
      end loop;
      return Diff = 0;
   end Spec_Pss_Verify_Sha256;

   ---------------------------------------------------------------------
   --  Spec_Pss_Verify_Sha384 — same structure, hLen=sLen=48.
   ---------------------------------------------------------------------

   function Spec_Pss_Verify_Sha384
     (Message : Octet_Array; EM : Bigint) return Boolean
   is
      H_Len   : constant Natural := 48;
      S_Len   : constant Natural := 48;
      DB_Len  : constant Natural := EM_Length - H_Len - 1;  -- 207
      PS_Len  : constant Natural := EM_Length - S_Len - H_Len - 2;  -- 158
      M_Hash  : Tls_Core.Sha384.Digest;
      H_Bytes : Octet_Array (1 .. H_Len);
      Db_Mask : Octet_Array (1 .. DB_Len);
      DB      : Octet_Array (1 .. DB_Len);
      Salt    : Octet_Array (1 .. S_Len);
      --  M_Prime: positions 1..8 stay 0 per RFC step 10; init for SPARK
      --  flow analysis (only positions 9..104 are written explicitly).
      M_Prime : Octet_Array (1 .. 8 + H_Len + S_Len) := [others => 0];
      H_Prime : Tls_Core.Sha384.Digest;
      Diff    : Octet := 0;
      Bad     : Octet := 0;
   begin
      if (EM (1) and 16#80#) /= 0 then
         return False;
      end if;

      if EM (EM_Length) /= 16#BC# then
         return False;
      end if;

      Tls_Core.Sha384.Hash (Message, M_Hash);

      for I in 1 .. H_Len loop
         H_Bytes (I) := EM (DB_Len + I);
      end loop;

      Db_Mask := Spec_MGF1_Sha384 (H_Bytes, DB_Len);

      for I in 1 .. DB_Len loop
         DB (I) := EM (I) xor Db_Mask (I);
      end loop;

      DB := Spec_DB_Zero_2047 (DB);

      for I in 1 .. PS_Len loop
         Bad := Bad or DB (I);
      end loop;
      if Bad /= 0 then
         return False;
      end if;
      if DB (PS_Len + 1) /= 16#01# then
         return False;
      end if;

      for I in 1 .. S_Len loop
         Salt (I) := DB (PS_Len + 1 + I);
      end loop;

      --  M_Prime is already 0-initialized at decl; positions 1..8 stay zero.
      for I in 1 .. H_Len loop
         M_Prime (8 + I) := M_Hash (I);
      end loop;
      for I in 1 .. S_Len loop
         M_Prime (8 + H_Len + I) := Salt (I);
      end loop;

      Tls_Core.Sha384.Hash (M_Prime, H_Prime);

      for I in 1 .. H_Len loop
         Diff := Diff or (H_Prime (I) xor H_Bytes (I));
      end loop;
      return Diff = 0;
   end Spec_Pss_Verify_Sha384;

   ---------------------------------------------------------------------
   --  Public Emsa_Pss_Verify entry points — thin wrappers around the
   --  spec, so the Post `OK = Spec_Pss_Verify_Sha*(Message, EM)`
   --  discharges by construction (mirror of Sha256.Hash →
   --  Spec_SHA256). [VERIFIED — PLATINUM]
   ---------------------------------------------------------------------

   procedure Emsa_Pss_Verify_Sha256
     (Message : Octet_Array; EM : Bigint; OK : out Boolean) is
   begin
      OK := Spec_Pss_Verify_Sha256 (Message, EM);
   end Emsa_Pss_Verify_Sha256;

   procedure Emsa_Pss_Verify_Sha384
     (Message : Octet_Array; EM : Bigint; OK : out Boolean) is
   begin
      OK := Spec_Pss_Verify_Sha384 (Message, EM);
   end Emsa_Pss_Verify_Sha384;

   ---------------------------------------------------------------------
   --  EMSA-PSS-ENCODE (RFC 8017 §9.1.1) for round-trip self-tests.
   --  AoRTE-only — encode side is not in v0.5 platinum scope (verify
   --  is the headline; encoding is here for the round-trip test).
   --
   --  Steps:
   --    1. mHash = Hash (M).
   --    2. If emLen < hLen + sLen + 2 — encoding error.
   --    3. Generate salt (caller supplies it).
   --    4. M' = 0x00 x 8 || mHash || salt.
   --    5. H = Hash (M').
   --    6. PS = (emLen - sLen - hLen - 2) zero bytes.
   --    7. DB = PS || 0x01 || salt.    (length = emLen - hLen - 1)
   --    8. dbMask = MGF1 (H, emLen - hLen - 1).
   --    9. maskedDB = DB XOR dbMask.
   --   10. Set the leftmost (8*emLen - emBits) bits of maskedDB to 0.
   --   11. EM = maskedDB || H || 0xBC.
   ---------------------------------------------------------------------

   procedure Encode_Sha256
     (Message : Octet_Array;
      Salt    : Octet_Array;
      Out_EM  : out Bigint;
      OK      : out Boolean)
   is
      H_Len   : constant Natural := 32;
      S_Len   : constant Natural := 32;
      DB_Len  : constant Natural := EM_Length - H_Len - 1;
      M_Hash  : Tls_Core.Sha256.Digest;
      M_Prime : Octet_Array (1 .. 8 + H_Len + S_Len) := [others => 0];
      H_Bytes : Tls_Core.Sha256.Digest;
      DB      : Octet_Array (1 .. DB_Len) := [others => 0];
      Db_Mask : Octet_Array (1 .. DB_Len);
      PS_Len  : constant Natural := EM_Length - S_Len - H_Len - 2;
   begin
      Out_EM := [others => 0];
      pragma Assert (Salt'Length = S_Len);

      Tls_Core.Sha256.Hash (Message, M_Hash);

      --  M' = 8 zero bytes || mHash || salt.
      --  M_Prime is already zeroed at declaration; only fill the
      --  non-zero tail (positions 9 .. 72).
      for I in 1 .. H_Len loop
         M_Prime (8 + I) := M_Hash (I);
      end loop;
      for I in 0 .. S_Len - 1 loop
         M_Prime (9 + H_Len + I) := Salt (Salt'First + I);
      end loop;
      Tls_Core.Sha256.Hash (M_Prime, H_Bytes);

      --  DB = 0x00 .. 0x00 || 0x01 || salt.
      --  DB is already zeroed; just place the 0x01 separator and salt.
      DB (PS_Len + 1) := 16#01#;
      for I in 0 .. S_Len - 1 loop
         DB (PS_Len + 2 + I) := Salt (Salt'First + I);
      end loop;

      Db_Mask := Spec_MGF1_Sha256 (H_Bytes, DB_Len);

      for I in 1 .. DB_Len loop
         DB (I) := DB (I) xor Db_Mask (I);
      end loop;

      --  Zero top bit of DB(1) per emBits=2047.
      DB (1) := DB (1) and EM_High_Mask;

      --  EM = maskedDB || H || 0xBC.
      for I in 1 .. DB_Len loop
         Out_EM (I) := DB (I);
      end loop;
      for I in 1 .. H_Len loop
         Out_EM (DB_Len + I) := H_Bytes (I);
      end loop;
      Out_EM (EM_Length) := 16#BC#;
      OK := True;
   end Encode_Sha256;

   procedure Encode_Sha384
     (Message : Octet_Array;
      Salt    : Octet_Array;
      Out_EM  : out Bigint;
      OK      : out Boolean)
   is
      H_Len   : constant Natural := 48;
      S_Len   : constant Natural := 48;
      DB_Len  : constant Natural := EM_Length - H_Len - 1;
      M_Hash  : Tls_Core.Sha384.Digest;
      M_Prime : Octet_Array (1 .. 8 + H_Len + S_Len) := [others => 0];
      H_Bytes : Tls_Core.Sha384.Digest;
      DB      : Octet_Array (1 .. DB_Len) := [others => 0];
      Db_Mask : Octet_Array (1 .. DB_Len);
      PS_Len  : constant Natural := EM_Length - S_Len - H_Len - 2;
   begin
      Out_EM := [others => 0];
      pragma Assert (Salt'Length = S_Len);

      Tls_Core.Sha384.Hash (Message, M_Hash);

      for I in 1 .. H_Len loop
         M_Prime (8 + I) := M_Hash (I);
      end loop;
      for I in 0 .. S_Len - 1 loop
         M_Prime (9 + H_Len + I) := Salt (Salt'First + I);
      end loop;
      Tls_Core.Sha384.Hash (M_Prime, H_Bytes);

      DB (PS_Len + 1) := 16#01#;
      for I in 0 .. S_Len - 1 loop
         DB (PS_Len + 2 + I) := Salt (Salt'First + I);
      end loop;

      Db_Mask := Spec_MGF1_Sha384 (H_Bytes, DB_Len);

      for I in 1 .. DB_Len loop
         DB (I) := DB (I) xor Db_Mask (I);
      end loop;

      DB (1) := DB (1) and EM_High_Mask;

      for I in 1 .. DB_Len loop
         Out_EM (I) := DB (I);
      end loop;
      for I in 1 .. H_Len loop
         Out_EM (DB_Len + I) := H_Bytes (I);
      end loop;
      Out_EM (EM_Length) := 16#BC#;
      OK := True;
   end Encode_Sha384;

   ---------------------------------------------------------------------
   --  RSASSA-PSS-VERIFY (RFC 8017 §8.1.2):
   --    1. Length check: signature is k = emLen octets (here 256).
   --    2. m := signature^E mod N         (RSAVP1 §5.2.2;
   --                                        AoRTE-only)
   --    3. EMSA-PSS-VERIFY (M, EM=m, emBits)  (PLATINUM via
   --                                        Emsa_Pss_Verify_Sha*)
   ---------------------------------------------------------------------

   procedure Verify_Sha256
     (N         : Bigint;
      E         : Bigint;
      Message   : Octet_Array;
      Signature : Bigint;
      OK        : out Boolean)
   is
      M : Bigint;
   begin
      Tls_Core.Bignum_2048.Mod_Exp (Signature, E, N, M);
      --  Bring the round-trip identity Big_To_Bigint (Bn_V (M)) = M
      --  into local scope so the chain
      --    Spec_Em_From_Pubkey_Sig (N, E, Signature)
      --      = Big_To_Bigint (Spec_Mod_Exp (Bn_V (Sig), Bn_V (E), Bn_V (N)))  [defn]
      --      = Big_To_Bigint (Bn_V (M))                                        [Mod_Exp Post]
      --      = M                                                               [round-trip lemma]
      --  is visible to SMT when discharging the Verify_Sha256 Post.
      Tls_Core.Bignum_2048.Lemma_Bigint_Roundtrip (M);
      Emsa_Pss_Verify_Sha256 (Message, M, OK);
   end Verify_Sha256;

   procedure Verify_Sha384
     (N         : Bigint;
      E         : Bigint;
      Message   : Octet_Array;
      Signature : Bigint;
      OK        : out Boolean)
   is
      M : Bigint;
   begin
      Tls_Core.Bignum_2048.Mod_Exp (Signature, E, N, M);
      Tls_Core.Bignum_2048.Lemma_Bigint_Roundtrip (M);
      Emsa_Pss_Verify_Sha384 (Message, M, OK);
   end Verify_Sha384;


end Tls_Core.Rsa_Pss;
