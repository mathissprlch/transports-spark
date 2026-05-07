with Interfaces;

with Tls_Core.Sha256;
with Tls_Core.Sha384;

package body Tls_Core.Rsa_Pss
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

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
   ---------------------------------------------------------------------

   EM_Length : constant := 256;
   --  High mask of EM[0]: top (8*emLen - emBits) bits zero. For our
   --  fixed 2048-bit / emBits=2047 case that's the topmost bit:
   --      mask = 0xFF >> (8*emLen - emBits) = 0xFF >> 1 = 0x7F
   EM_High_Mask : constant Octet := 16#7F#;

   ---------------------------------------------------------------------
   --  Generic hash dispatch: a small wrapper that lets the EMSA-PSS
   --  body call "the chosen hash" without code duplication. We avoid
   --  generics here for SPARK simplicity and just write two parallel
   --  procedures (Verify_Sha256, Verify_Sha384) sharing internal
   --  helpers parameterised by hash length.
   ---------------------------------------------------------------------

   ---------------------------------------------------------------------
   --  MGF1 (RFC 8017 §B.2.1) with SHA-256 as the hash.
   --
   --  For mask length L bytes, output T = first L bytes of
   --      H(seed||I2OSP(0,4)) || H(seed||I2OSP(1,4)) || ...
   ---------------------------------------------------------------------

   procedure MGF1_Sha256
     (Seed     : Octet_Array;
      Mask_Len : Natural;
      Out_Mask : out Octet_Array)
   is
      Counter   : Unsigned_32 := 0;
      Buf_Len   : constant Natural := Seed'Length + 4;
      Buf       : Octet_Array (1 .. Buf_Len) := (others => 0);
      Digest    : Tls_Core.Sha256.Digest;
      Filled    : Natural := 0;
      Take      : Natural;
   begin
      pragma Assert (Out_Mask'Length = Mask_Len);
      --  Copy seed into the prefix of Buf.
      for I in 0 .. Seed'Length - 1 loop
         Buf (1 + I) := Seed (Seed'First + I);
      end loop;
      while Filled < Mask_Len loop
         --  Append I2OSP(counter, 4) — 4-byte big-endian.
         Buf (Buf_Len - 3) := Octet (Shift_Right (Counter, 24) and 16#FF#);
         Buf (Buf_Len - 2) := Octet (Shift_Right (Counter, 16) and 16#FF#);
         Buf (Buf_Len - 1) := Octet (Shift_Right (Counter,  8) and 16#FF#);
         Buf (Buf_Len)     := Octet (Counter and 16#FF#);
         Tls_Core.Sha256.Hash (Buf, Digest);
         Take := Mask_Len - Filled;
         if Take > 32 then
            Take := 32;
         end if;
         for I in 0 .. Take - 1 loop
            Out_Mask (Out_Mask'First + Filled + I) := Digest (1 + I);
         end loop;
         Filled := Filled + Take;
         Counter := Counter + 1;
      end loop;
   end MGF1_Sha256;

   ---------------------------------------------------------------------
   --  MGF1 with SHA-384.
   ---------------------------------------------------------------------

   procedure MGF1_Sha384
     (Seed     : Octet_Array;
      Mask_Len : Natural;
      Out_Mask : out Octet_Array)
   is
      Counter   : Unsigned_32 := 0;
      Buf_Len   : constant Natural := Seed'Length + 4;
      Buf       : Octet_Array (1 .. Buf_Len) := (others => 0);
      Digest    : Tls_Core.Sha384.Digest;
      Filled    : Natural := 0;
      Take      : Natural;
   begin
      pragma Assert (Out_Mask'Length = Mask_Len);
      for I in 0 .. Seed'Length - 1 loop
         Buf (1 + I) := Seed (Seed'First + I);
      end loop;
      while Filled < Mask_Len loop
         Buf (Buf_Len - 3) := Octet (Shift_Right (Counter, 24) and 16#FF#);
         Buf (Buf_Len - 2) := Octet (Shift_Right (Counter, 16) and 16#FF#);
         Buf (Buf_Len - 1) := Octet (Shift_Right (Counter,  8) and 16#FF#);
         Buf (Buf_Len)     := Octet (Counter and 16#FF#);
         Tls_Core.Sha384.Hash (Buf, Digest);
         Take := Mask_Len - Filled;
         if Take > 48 then
            Take := 48;
         end if;
         for I in 0 .. Take - 1 loop
            Out_Mask (Out_Mask'First + Filled + I) := Digest (1 + I);
         end loop;
         Filled := Filled + Take;
         Counter := Counter + 1;
      end loop;
   end MGF1_Sha384;

   ---------------------------------------------------------------------
   --  EMSA-PSS-VERIFY (RFC 8017 §9.1.2) — SHA-256 variant.
   --
   --  EM is 256 bytes (emLen). hLen = sLen = 32. mHash = SHA-256(M).
   --
   --  Steps (numbered per the RFC):
   --    1. mHash := Hash (M).                     (already done)
   --    2. If emLen < hLen + sLen + 2, output "inconsistent".
   --       For our fixed sizes 256 >= 32+32+2 = 66 ✓.
   --    3. If the rightmost octet of EM is not 0xBC, "inconsistent".
   --    4. Let maskedDB = EM (1 .. emLen - hLen - 1)
   --              H = EM (emLen - hLen .. emLen - 1)
   --              (last byte 0xBC).
   --    5. dbMask = MGF1 (H, emLen - hLen - 1).
   --    6. DB = maskedDB XOR dbMask.
   --    7. Set the high bit of DB (8*emLen - emBits = 1 bit) to zero.
   --    8. If DB does not start with (emLen-hLen-sLen-2) zero bytes
   --       followed by 0x01, "inconsistent".
   --    9. Salt = DB (last sLen bytes).
   --   10. M' = (eight zero bytes) || mHash || salt.
   --   11. H' = Hash (M').
   --   12. If H = H' output "consistent"; else "inconsistent".
   ---------------------------------------------------------------------

   procedure Emsa_Pss_Verify_Sha256
     (Message : Octet_Array;
      EM      : Bigint;
      OK      : out Boolean)
   is
      H_Len    : constant Natural := 32;
      S_Len    : constant Natural := 32;
      DB_Len   : constant Natural := EM_Length - H_Len - 1;  -- 223
      M_Hash   : Tls_Core.Sha256.Digest;
      H_Bytes  : Octet_Array (1 .. H_Len);
      Db_Mask  : Octet_Array (1 .. DB_Len);
      DB       : Octet_Array (1 .. DB_Len);
      Salt     : Octet_Array (1 .. S_Len);
      M_Prime  : Octet_Array (1 .. 8 + H_Len + S_Len);
      H_Prime  : Tls_Core.Sha256.Digest;
      Diff     : Octet := 0;
   begin
      OK := False;

      --  Step 1: mHash = Hash (M).
      Tls_Core.Sha256.Hash (Message, M_Hash);

      --  Step 2: emLen >= hLen + sLen + 2 (always true here).

      --  Step 3: trailing 0xBC.
      if EM (EM_Length) /= 16#BC# then
         return;
      end if;

      --  Step 4: split EM = maskedDB || H || 0xBC.
      --  EM is 1-indexed, length 256. maskedDB = EM (1 .. 223),
      --  H = EM (224 .. 255), trailer = EM (256).
      for I in 1 .. H_Len loop
         H_Bytes (I) := EM (DB_Len + I);
      end loop;

      --  Step 5: dbMask = MGF1 (H, DB_Len).
      MGF1_Sha256 (H_Bytes, DB_Len, Db_Mask);

      --  Step 6: DB = maskedDB XOR dbMask.
      for I in 1 .. DB_Len loop
         DB (I) := EM (I) xor Db_Mask (I);
      end loop;

      --  Step 7: zero the top (8*emLen - emBits) bits of DB[0].
      --  For emBits=2047: zero the top bit → AND with 0x7F.
      DB (1) := DB (1) and EM_High_Mask;

      --  Step 8: DB must look like 00..00 || 01 || salt of sLen bytes.
      --  PS length = emLen - sLen - hLen - 2 = 256 - 32 - 32 - 2 = 190.
      --  So DB (1 .. 190) = zeros, DB (191) = 0x01, DB (192 .. 223) = salt.
      declare
         PS_Len : constant Natural := EM_Length - S_Len - H_Len - 2;
         Bad    : Octet := 0;
      begin
         for I in 1 .. PS_Len loop
            Bad := Bad or DB (I);
         end loop;
         if Bad /= 0 then
            return;
         end if;
         if DB (PS_Len + 1) /= 16#01# then
            return;
         end if;

         --  Step 9: salt.
         for I in 1 .. S_Len loop
            Salt (I) := DB (PS_Len + 1 + I);
         end loop;
      end;

      --  Step 10: M' = 0x00 x 8 || mHash || salt.
      for I in 1 .. 8 loop
         M_Prime (I) := 0;
      end loop;
      for I in 1 .. H_Len loop
         M_Prime (8 + I) := M_Hash (I);
      end loop;
      for I in 1 .. S_Len loop
         M_Prime (8 + H_Len + I) := Salt (I);
      end loop;

      --  Step 11: H' = Hash (M').
      Tls_Core.Sha256.Hash (M_Prime, H_Prime);

      --  Step 12: H' = H ?
      for I in 1 .. H_Len loop
         Diff := Diff or (H_Prime (I) xor H_Bytes (I));
      end loop;
      OK := Diff = 0;
   end Emsa_Pss_Verify_Sha256;

   ---------------------------------------------------------------------
   --  EMSA-PSS-VERIFY — SHA-384 variant. Same structure as the
   --  SHA-256 path; hLen = sLen = 48 and the hash / MGF1 hash is
   --  SHA-384.
   ---------------------------------------------------------------------

   procedure Emsa_Pss_Verify_Sha384
     (Message : Octet_Array;
      EM      : Bigint;
      OK      : out Boolean)
   is
      H_Len    : constant Natural := 48;
      S_Len    : constant Natural := 48;
      DB_Len   : constant Natural := EM_Length - H_Len - 1;  -- 207
      M_Hash   : Tls_Core.Sha384.Digest;
      H_Bytes  : Octet_Array (1 .. H_Len);
      Db_Mask  : Octet_Array (1 .. DB_Len);
      DB       : Octet_Array (1 .. DB_Len);
      Salt     : Octet_Array (1 .. S_Len);
      M_Prime  : Octet_Array (1 .. 8 + H_Len + S_Len);
      H_Prime  : Tls_Core.Sha384.Digest;
      Diff     : Octet := 0;
   begin
      OK := False;

      Tls_Core.Sha384.Hash (Message, M_Hash);

      if EM (EM_Length) /= 16#BC# then
         return;
      end if;

      for I in 1 .. H_Len loop
         H_Bytes (I) := EM (DB_Len + I);
      end loop;

      MGF1_Sha384 (H_Bytes, DB_Len, Db_Mask);

      for I in 1 .. DB_Len loop
         DB (I) := EM (I) xor Db_Mask (I);
      end loop;

      DB (1) := DB (1) and EM_High_Mask;

      declare
         PS_Len : constant Natural := EM_Length - S_Len - H_Len - 2;
         --  256 - 48 - 48 - 2 = 158.
         Bad    : Octet := 0;
      begin
         for I in 1 .. PS_Len loop
            Bad := Bad or DB (I);
         end loop;
         if Bad /= 0 then
            return;
         end if;
         if DB (PS_Len + 1) /= 16#01# then
            return;
         end if;

         for I in 1 .. S_Len loop
            Salt (I) := DB (PS_Len + 1 + I);
         end loop;
      end;

      for I in 1 .. 8 loop
         M_Prime (I) := 0;
      end loop;
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
      OK := Diff = 0;
   end Emsa_Pss_Verify_Sha384;

   ---------------------------------------------------------------------
   --  EMSA-PSS-ENCODE (RFC 8017 §9.1.1) for round-trip self-tests.
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
      H_Len    : constant Natural := 32;
      S_Len    : constant Natural := 32;
      DB_Len   : constant Natural := EM_Length - H_Len - 1;
      M_Hash   : Tls_Core.Sha256.Digest;
      M_Prime  : Octet_Array (1 .. 8 + H_Len + S_Len);
      H_Bytes  : Tls_Core.Sha256.Digest;
      DB       : Octet_Array (1 .. DB_Len);
      Db_Mask  : Octet_Array (1 .. DB_Len);
      PS_Len   : constant Natural := EM_Length - S_Len - H_Len - 2;
   begin
      Out_EM := (others => 0);
      OK := False;
      pragma Assert (Salt'Length = S_Len);

      Tls_Core.Sha256.Hash (Message, M_Hash);

      --  M' = 8 zero bytes || mHash || salt.
      for I in 1 .. 8 loop
         M_Prime (I) := 0;
      end loop;
      for I in 1 .. H_Len loop
         M_Prime (8 + I) := M_Hash (I);
      end loop;
      for I in 1 .. S_Len loop
         M_Prime (8 + H_Len + I) := Salt (Salt'First + I - 1);
      end loop;
      Tls_Core.Sha256.Hash (M_Prime, H_Bytes);

      --  DB = 0x00 .. 0x00 || 0x01 || salt.
      for I in 1 .. PS_Len loop
         DB (I) := 0;
      end loop;
      DB (PS_Len + 1) := 16#01#;
      for I in 1 .. S_Len loop
         DB (PS_Len + 1 + I) := Salt (Salt'First + I - 1);
      end loop;

      MGF1_Sha256 (H_Bytes, DB_Len, Db_Mask);

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
      H_Len    : constant Natural := 48;
      S_Len    : constant Natural := 48;
      DB_Len   : constant Natural := EM_Length - H_Len - 1;
      M_Hash   : Tls_Core.Sha384.Digest;
      M_Prime  : Octet_Array (1 .. 8 + H_Len + S_Len);
      H_Bytes  : Tls_Core.Sha384.Digest;
      DB       : Octet_Array (1 .. DB_Len);
      Db_Mask  : Octet_Array (1 .. DB_Len);
      PS_Len   : constant Natural := EM_Length - S_Len - H_Len - 2;
   begin
      Out_EM := (others => 0);
      OK := False;
      pragma Assert (Salt'Length = S_Len);

      Tls_Core.Sha384.Hash (Message, M_Hash);

      for I in 1 .. 8 loop
         M_Prime (I) := 0;
      end loop;
      for I in 1 .. H_Len loop
         M_Prime (8 + I) := M_Hash (I);
      end loop;
      for I in 1 .. S_Len loop
         M_Prime (8 + H_Len + I) := Salt (Salt'First + I - 1);
      end loop;
      Tls_Core.Sha384.Hash (M_Prime, H_Bytes);

      for I in 1 .. PS_Len loop
         DB (I) := 0;
      end loop;
      DB (PS_Len + 1) := 16#01#;
      for I in 1 .. S_Len loop
         DB (PS_Len + 1 + I) := Salt (Salt'First + I - 1);
      end loop;

      MGF1_Sha384 (H_Bytes, DB_Len, Db_Mask);

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
   --    2. m := signature^E mod N         (RSAVP1 §5.2.2)
   --    3. EMSA-PSS-VERIFY (M, EM=m, emBits)
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
      Emsa_Pss_Verify_Sha384 (Message, M, OK);
   end Verify_Sha384;

end Tls_Core.Rsa_Pss;
