with Tls_Core.Ghost_Bignum.Value;
with Tls_Core.Poly1305.Encode;
with Tls_Core.Poly1305.Spec_BN;

package body Tls_Core.Poly1305
  with SPARK_Mode
is

   use Interfaces;

   package GB renames Tls_Core.Ghost_Bignum;
   package GBV renames Tls_Core.Ghost_Bignum.Value;
   package Enc renames Tls_Core.Poly1305.Encode;
   package SB renames Tls_Core.Poly1305.Spec_BN;

   --  Limb_Index / Limbs are now declared in the spec so functional
   --  Posts on the private helpers can reference As_Nat5 / Feval5.

   Mask_26 : constant U64 := 16#03FF_FFFF#;

   ---------------------------------------------------------------------
   --  Spec_* ghost function bodies (HACL\* port)
   ---------------------------------------------------------------------

   ---------------------------------------------------------------------
   --  Spec_* lemma bodies
   ---------------------------------------------------------------------

   --  With Spec_Pow2 now an expression function in the spec, the
   --  identity `Spec_Pow2 (N + 1) = 2 * Spec_Pow2 (N)` is true by
   --  inline-expansion of the definition; the lemma body is empty.
   procedure Lemma_Pow2_Step (N : Natural) is
   begin
      null;
   end Lemma_Pow2_Step;

   --  Spec_Pow2 (N + 8) = 256 * Spec_Pow2 (N). Eight applications
   --  of Lemma_Pow2_Step plus simple commutative-associative algebra
   --  on the literal 2^8 = 256.
   procedure Lemma_Pow2_Plus_8 (N : Natural) is
      Two : constant Big.Big_Natural := Big.To_Big_Integer (2);
      P0  : constant Big.Big_Natural := Spec_Pow2 (N);
      P1  : constant Big.Big_Natural := Spec_Pow2 (N + 1);
      P2  : constant Big.Big_Natural := Spec_Pow2 (N + 2);
      P3  : constant Big.Big_Natural := Spec_Pow2 (N + 3);
      P4  : constant Big.Big_Natural := Spec_Pow2 (N + 4);
      P5  : constant Big.Big_Natural := Spec_Pow2 (N + 5);
      P6  : constant Big.Big_Natural := Spec_Pow2 (N + 6);
      P7  : constant Big.Big_Natural := Spec_Pow2 (N + 7);
      P8  : constant Big.Big_Natural := Spec_Pow2 (N + 8);
   begin
      Lemma_Pow2_Step (N);      --  P1 = 2 * P0
      Lemma_Pow2_Step (N + 1);  --  P2 = 2 * P1
      Lemma_Pow2_Step (N + 2);
      Lemma_Pow2_Step (N + 3);
      Lemma_Pow2_Step (N + 4);
      Lemma_Pow2_Step (N + 5);
      Lemma_Pow2_Step (N + 6);
      Lemma_Pow2_Step (N + 7);
      pragma Assert (P1 = Two * P0);
      pragma Assert (P2 = Two * P1);
      pragma Assert (P3 = Two * P2);
      pragma Assert (P4 = Two * P3);
      pragma Assert (P5 = Two * P4);
      pragma Assert (P6 = Two * P5);
      pragma Assert (P7 = Two * P6);
      pragma Assert (P8 = Two * P7);
      pragma Assert (P8 = Big.To_Big_Integer (256) * P0);
   end Lemma_Pow2_Plus_8;

   procedure Lemma_Pow2_Monotone (M, N : Natural) is
   begin
      if M = N then
         return;
      end if;
      --  Strict M < N; chain unit-step lemma along M..N-1.
      for K in M .. N - 1 loop
         Lemma_Pow2_Step (K);
         pragma Loop_Invariant (Spec_Pow2 (M) <= Spec_Pow2 (K + 1));
      end loop;
   end Lemma_Pow2_Monotone;

   procedure Lemma_Pow2_128_Lt_Prime is
   begin
      --  Spec_Prime = Spec_Pow2 (130) - 5
      --             = 4 * Spec_Pow2 (128) - 5
      --  So Spec_Pow2 (128) < Spec_Prime  ⇔  Spec_Pow2 (128) > 5/3,
      --  trivially since Spec_Pow2 (128) >= 128.
      Lemma_Pow2_Step (128);  --  2^129 = 2 * 2^128
      Lemma_Pow2_Step (129);  --  2^130 = 2 * 2^129 = 4 * 2^128
      pragma
        Assert (Spec_Pow2 (130) = Big.To_Big_Integer (4) * Spec_Pow2 (128));
      pragma Assert (Spec_Pow2 (128) >= Big.To_Big_Integer (128));
   end Lemma_Pow2_128_Lt_Prime;

   procedure Lemma_Limb_Split_26 (X : U64) is
      Hi : constant U64 := Shift_Right (X, 26);
      Lo : constant U64 := X and 16#03FF_FFFF#;
   begin
      --  At the U64 level: X = Hi * 2^26 + Lo, with Lo < 2^26.
      --  This is the standard "shift+mask = quot+rem" decomposition;
      --  modular-arithmetic provers handle it natively when the shift
      --  amount and mask agree on the same power of two.
      pragma Assert (Lo < 2**26);
      pragma Assert (X = Shift_Left (Hi, 26) + Lo);
      pragma Assert (Shift_Left (Hi, 26) = Hi * 2**26);
      pragma Assert (X = Hi * 2**26 + Lo);
   end Lemma_Limb_Split_26;

   procedure Lemma_Pow2_Add (M, N : Natural) is
   begin
      if N = 0 then
         --  2^(M+0) = 2^M = 2^M * 1 = 2^M * 2^0
         pragma Assert (Spec_Pow2 (0) = Big.To_Big_Integer (1));
         return;
      end if;
      --  Inductive step: 2^(M + N) = 2 * 2^(M + N - 1)
      --                            = 2 * (2^M * 2^(N-1))   [IH]
      --                            = 2^M * (2 * 2^(N-1))
      --                            = 2^M * 2^N
      Lemma_Pow2_Add (M, N - 1);     --  IH
      Lemma_Pow2_Step (M + N - 1);   --  2^(M+N) = 2 * 2^(M+N-1)
      Lemma_Pow2_Step (N - 1);       --  2^N     = 2 * 2^(N-1)
   end Lemma_Pow2_Add;

   procedure Lemma_Pow2_52_Eq_26x26 is
   begin
      Lemma_Pow2_Add (26, 26);
   end Lemma_Pow2_52_Eq_26x26;

   procedure Lemma_Pow2_78_Eq_52x26 is
   begin
      Lemma_Pow2_Add (52, 26);
   end Lemma_Pow2_78_Eq_52x26;

   procedure Lemma_Pow2_104_Eq_78x26 is
   begin
      Lemma_Pow2_Add (78, 26);
   end Lemma_Pow2_104_Eq_78x26;

   procedure Lemma_Pow2_130_Mod_Prime is
   begin
      --  Spec_Prime = Spec_Pow2 (130) - 5  ⇒  Spec_Pow2 (130) = Spec_Prime + 5
      --  Hence Spec_Pow2 (130) mod Spec_Prime = 5 mod Spec_Prime = 5
      --  (since Spec_Prime > 5).
      Lemma_Pow2_128_Lt_Prime;  --  pulls in 2^128 < Prime, so Prime > 5
   end Lemma_Pow2_130_Mod_Prime;

   --  Lemma_As_Nat5_Linear body deferred (see ads-side TODO).

   procedure Lemma_To_Big_Nat_Reduced (L : Limbs) is null;

   procedure Lemma_To_Big_Nat_Mul_Cap (L : Limbs) is null;

   procedure Lemma_Feval_BN_Lt_P (L : Limbs) is
   begin
      --  Establish Normalize's precondition (In_Bounds (To_Big_Nat (L),
      --  Mul_Cap)); the Post then follows from Reduce_Canonical's Post
      --  (In_Bounds (In_Cap) + zero from 5 + not Sub_Cond, i.e. < p).
      Lemma_To_Big_Nat_Mul_Cap (L);
   end Lemma_Feval_BN_Lt_P;

   procedure Lemma_Add_Embed (A, B : Limbs) is null;

   procedure Lemma_Shift_Mask_26 (X : U64) is
   begin
      pragma Assert (Interfaces.Shift_Right (X, 26) = X / 2**26);
      pragma Assert ((X and 16#03FF_FFFF#) = X mod 2**26);
   end Lemma_Shift_Mask_26;

   procedure Lemma_Bytes_Bound (B : Octet_Array) is
   begin
      if B'Length = 0 then
         return;
      end if;
      declare
         L_Minus_1 : constant Natural := B'Length - 1;
         Front     : constant Octet_Array := B (B'First .. B'Last - 1);
         Pow_Hi    : constant Big.Big_Natural := Spec_Pow2 (8 * L_Minus_1);
         Last_Byte : constant Big.Big_Natural :=
           Octet_Bigint.To_Big_Integer (B (B'Last));
         Front_Val : constant Big.Big_Natural :=
           Spec_Nat_From_Bytes_Le (Front);
      begin
         Lemma_Bytes_Bound (Front);
         --  IH: Front_Val < Spec_Pow2 (8 * L_Minus_1) = Pow_Hi.
         pragma Assert (Front_Val < Pow_Hi);
         pragma Assert (Last_Byte <= Big.To_Big_Integer (255));
         --  Result of Spec_Nat_From_Bytes_Le (B) = Front_Val + Last_Byte * Pow_Hi
         pragma
           Assert
             (Spec_Nat_From_Bytes_Le (B) = Front_Val + Last_Byte * Pow_Hi);
         --  Last_Byte * Pow_Hi <= 255 * Pow_Hi
         pragma
           Assert (Last_Byte * Pow_Hi <= Big.To_Big_Integer (255) * Pow_Hi);
         --  Sum bound: Front_Val + Last_Byte * Pow_Hi
         --           < Pow_Hi + 255 * Pow_Hi = 256 * Pow_Hi
         pragma
           Assert
             (Front_Val + Last_Byte * Pow_Hi
                < Pow_Hi + Big.To_Big_Integer (255) * Pow_Hi);
         pragma
           Assert
             (Pow_Hi + Big.To_Big_Integer (255) * Pow_Hi
                = Big.To_Big_Integer (256) * Pow_Hi);
         --  Now connect 256 * Pow_Hi = Spec_Pow2 (8 * B'Length).
         Lemma_Pow2_Plus_8 (8 * L_Minus_1);
         pragma
           Assert
             (Spec_Pow2 (8 * L_Minus_1 + 8)
                = Big.To_Big_Integer (256) * Pow_Hi);
         pragma Assert (8 * L_Minus_1 + 8 = 8 * B'Length);
      end;
   end Lemma_Bytes_Bound;

   --  Spec_Nat_From_Bytes_Le is an expression function in the spec.

   --  Spec_Encode_R — port of HACL\* `poly1305_encode_r`.
   --
   --  Operationally identical to `nat_from_bytes_le (clamp(rb))`.
   --  We construct it as (clamped low 64 bits) + 2^64 * (clamped high
   --  64 bits) — exactly the F\* version.
   function Spec_Encode_R (Rb : Octet_Array) return Big.Big_Natural is
      --  HACL\* mask0 = 0x0ffffffc0fffffff (LE form)
      --      → bytes[0..7] = FF FF FF 0F FC FF FF 0F (low 64 bits)
      --  HACL\* mask1 = 0x0ffffffc0ffffffc
      --      → bytes[8..15] = FC FF FF 0F FC FF FF 0F (high 64 bits)
      Clamped : Octet_Array (1 .. 16);
   begin
      for I in 1 .. 16 loop
         Clamped (I) := Rb (Rb'First + I - 1);
      end loop;
      --  Apply the byte-level clamp pattern from RFC 8439 §2.5.1.
      Clamped (4) := Clamped (4) and 16#0F#;
      Clamped (8) := Clamped (8) and 16#0F#;
      Clamped (12) := Clamped (12) and 16#0F#;
      Clamped (16) := Clamped (16) and 16#0F#;
      Clamped (5) := Clamped (5) and 16#FC#;
      Clamped (9) := Clamped (9) and 16#FC#;
      Clamped (13) := Clamped (13) and 16#FC#;
      --  Discharge Post < 2^128 via the generic-array byte-bound lemma.
      Lemma_Bytes_Bound (Clamped);
      return Spec_Nat_From_Bytes_Le (Clamped);
   end Spec_Encode_R;

   --  Spec_Encode_Block — port of HACL\* `encode`:
   --     2^(8*len) + nat_from_bytes_le b
   function Spec_Encode_Block
     (B : Octet_Array; Len : Natural) return Big.Big_Natural is
   begin
      return Spec_Pow2 (8 * Len) + Spec_Nat_From_Bytes_Le (B);
   end Spec_Encode_Block;

   --  Spec_Update1 — port of HACL\* `poly1305_update1`:
   --     (encode b len + acc) * r mod prime
   function Spec_Update1
     (Acc, R : Big.Big_Natural; B : Octet_Array; Len : Natural)
      return Big.Big_Natural
   is
      Encoded : constant Big.Big_Natural := Spec_Encode_Block (B, Len);
      Sum     : constant Big.Big_Natural := Encoded + Acc;
      Prod    : constant Big.Big_Natural := Sum * R;
   begin
      return Prod mod Spec_Prime;
   end Spec_Update1;

   --  Spec_Update_Last — port of HACL\* `poly1305_update_last`.
   --  Empty trailing block leaves acc unchanged (RFC 8439 §2.5
   --  step 4 says trailing zero-byte blocks are skipped).
   function Spec_Update_Last
     (Acc, R : Big.Big_Natural; B : Octet_Array; Len : Natural)
      return Big.Big_Natural is
   begin
      if Len = 0 then
         return Acc;
      else
         return Spec_Update1 (Acc, R, B, Len);
      end if;
   end Spec_Update_Last;

   --  Spec_Update_All — port of HACL\* `poly1305_update`:
   --  process all 16-byte blocks then a partial tail. Recursive on
   --  Text length to make the structure-translation to gnatprove
   --  decidable.
   function Spec_Update_All
     (Text : Octet_Array; Acc, R : Big.Big_Natural) return Big.Big_Natural
   is
      Acc1 : Big.Big_Natural;
   begin
      if Text'Length < 16 then
         return Spec_Update_Last (Acc, R, Text, Text'Length);
      end if;
      Acc1 := Spec_Update1 (Acc, R, Text (Text'First .. Text'First + 15), 16);
      return Spec_Update_All (Text (Text'First + 16 .. Text'Last), Acc1, R);
   end Spec_Update_All;

   --  Spec_Finish — port of HACL\* `poly1305_finish`:
   --    s = nat_from_bytes_le (slice key 16 32)
   --    n = (acc + s) mod 2^128
   --    tag = nat_to_bytes_le 16 n
   function Spec_Finish
     (Key : Key_Array; Acc : Big.Big_Natural) return Tag_Array
   is
      S_Bytes : constant Octet_Array (1 .. 16) := Octet_Array (Key (17 .. 32));
      S_Val   : constant Big.Big_Natural := Spec_Nat_From_Bytes_Le (S_Bytes);
      --  Result is fully overwritten by the loop below; gnatprove
      --  flow-tracks the per-index assignment so we don't need a
      --  default-init aggregate.
      Result  : Tag_Array;
      Cur     : Big.Big_Natural := (Acc + S_Val) mod Spec_Pow2 (128);
      package Big_U64 is new Big.Unsigned_Conversions (Int => U64);
   begin
      --  Serialise Cur as 16-byte little-endian: byte i = (Cur mod 256).
      for I in Tag_Array'Range loop
         declare
            Lo   : constant Big.Big_Natural :=
              Cur mod Big.To_Big_Integer (256);
            Lo_U : constant U64 := Big_U64.From_Big_Integer (Lo);
         begin
            Result (I) := Octet (Lo_U and 16#FF#);
            Cur := Cur / Big.To_Big_Integer (256);
         end;
      end loop;
      return Result;
   end Spec_Finish;

   --  Spec_Poly1305_Mac — top-level port of HACL\* `poly1305_mac`.
   function Spec_Poly1305_Mac
     (Key : Key_Array; Message : Octet_Array) return Tag_Array
   is
      R_Bytes : constant Octet_Array (1 .. 16) := Octet_Array (Key (1 .. 16));
      R_Val   : constant Big.Big_Natural := Spec_Encode_R (R_Bytes);
      Acc0    : constant Big.Big_Natural := Big.To_Big_Integer (0);
      Acc_F   : constant Big.Big_Natural :=
        Spec_Update_All (Message, Acc0, R_Val);
   begin
      return Spec_Finish (Key, Acc_F);
   end Spec_Poly1305_Mac;

   ---------------------------------------------------------------------
   --  Pack a 16-byte little-endian integer (with the implicit
   --  trailing 1 bit for full blocks) into the 5-limb form.
   ---------------------------------------------------------------------

   procedure Load_Block
     (B           : Octet_Array;
      Block_Bytes : Natural;
      Final       : Boolean;
      Out_Limbs   : out Limbs)
   with
     Pre  =>
       Block_Bytes in 1 .. 16
       and then Block_Bytes <= B'Length
       and then B'Last < Integer'Last - 16,
     Post =>
       (for all I in Limb_Index => Out_Limbs (I) < 2**26)
       and then GB."="
                  (To_Big_Nat (Out_Limbs),
                   Enc.Encode_BN (B, Block_Bytes, Final));

   procedure Load_Block
     (B           : Octet_Array;
      Block_Bytes : Natural;
      Final       : Boolean;
      Out_Limbs   : out Limbs)
   is
      Padded : Octet_Array (1 .. 17) := [others => 0];
   begin
      Out_Limbs := [others => 0];
      for I in 1 .. Block_Bytes loop
         Padded (I) := B (B'First + I - 1);
         pragma Loop_Invariant (I <= 16);
         pragma
           Loop_Invariant
             (for all J in 1 .. I => Padded (J) = B (B'First + J - 1));
         pragma Loop_Invariant (for all J in I + 1 .. 17 => Padded (J) = 0);
      end loop;
      --  Append the implicit "1" bit at byte position Block_Bytes.
      --  For full 16-byte blocks this is byte 17 (i.e. bit 128).
      --  For a partial last block it sits at the byte just past
      --  the message bytes, per §2.5 step 3.
      if Final then
         Padded (Block_Bytes + 1) := 16#01#;
      else
         Padded (17) := 16#01#;
      end if;
      Out_Limbs (0) :=
        U64 (Padded (1))
        or Shift_Left (U64 (Padded (2)), 8)
        or Shift_Left (U64 (Padded (3)), 16)
        or Shift_Left (U64 (Padded (4) and 16#03#), 24);
      Out_Limbs (1) :=
        Shift_Right (U64 (Padded (4)), 2)
        or Shift_Left (U64 (Padded (5)), 6)
        or Shift_Left (U64 (Padded (6)), 14)
        or Shift_Left (U64 (Padded (7) and 16#0F#), 22);
      Out_Limbs (2) :=
        Shift_Right (U64 (Padded (7)), 4)
        or Shift_Left (U64 (Padded (8)), 4)
        or Shift_Left (U64 (Padded (9)), 12)
        or Shift_Left (U64 (Padded (10) and 16#3F#), 20);
      Out_Limbs (3) :=
        Shift_Right (U64 (Padded (10)), 6)
        or Shift_Left (U64 (Padded (11)), 2)
        or Shift_Left (U64 (Padded (12)), 10)
        or Shift_Left (U64 (Padded (13)), 18);
      Out_Limbs (4) :=
        U64 (Padded (14))
        or Shift_Left (U64 (Padded (15)), 8)
        or Shift_Left (U64 (Padded (16)), 16)
        or Shift_Left (U64 (Padded (17)), 24);

      --  Functional correspondence: the imperative packing equals the pure
      --  Encode_BN model (Padded matches Padded_Byte byte-for-byte, so each
      --  limb expression coincides).
      pragma
        Assert
          (for all I in 1 .. 17 =>
             Padded (I) = Enc.Padded_Byte (B, Block_Bytes, Final, I));
      pragma Assert (Out_Limbs (0) = Enc.Enc_Limb0 (B, Block_Bytes, Final));
      pragma Assert (Out_Limbs (1) = Enc.Enc_Limb1 (B, Block_Bytes, Final));
      pragma Assert (Out_Limbs (2) = Enc.Enc_Limb2 (B, Block_Bytes, Final));
      pragma Assert (Out_Limbs (3) = Enc.Enc_Limb3 (B, Block_Bytes, Final));
      pragma Assert (Out_Limbs (4) = Enc.Enc_Limb4 (B, Block_Bytes, Final));
      declare
         TB : constant GB.Big_Nat := To_Big_Nat (Out_Limbs)
         with Ghost;
         EB : constant GB.Big_Nat := Enc.Encode_BN (B, Block_Bytes, Final)
         with Ghost;
      begin
         pragma Assert (TB (0) = EB (0));
         pragma Assert (TB (1) = EB (1));
         pragma Assert (TB (2) = EB (2));
         pragma Assert (TB (3) = EB (3));
         pragma Assert (TB (4) = EB (4));
         pragma
           Assert
             (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
                TB (I) = 0 and then EB (I) = 0);
         pragma Assert (GB."=" (TB, EB));
      end;
   end Load_Block;

   ---------------------------------------------------------------------
   --  Load the clamped r (16 bytes, no implicit-1) into 5x26-bit limbs.
   --  Same packing as Load_Block minus the implicit-1 byte; its Big_Nat
   --  embedding is the pure Encode.R_BN model.
   ---------------------------------------------------------------------
   procedure Load_R (Clamped : Octet_Array; R : out Limbs)
   with
     Pre  => Clamped'Length = 16 and then Clamped'Last < Integer'Last - 16,
     Post =>
       (for all I in Limb_Index => R (I) < 2**26)
       and then GB."=" (To_Big_Nat (R), Enc.R_BN (Clamped));

   procedure Load_R (Clamped : Octet_Array; R : out Limbs) is
      Padded : Octet_Array (1 .. 17) := [others => 0];
   begin
      R := [others => 0];
      for I in 1 .. 16 loop
         Padded (I) := Clamped (Clamped'First + I - 1);
         pragma
           Loop_Invariant
             (for all J in 1 .. I =>
                Padded (J) = Clamped (Clamped'First + J - 1));
         pragma Loop_Invariant (for all J in I + 1 .. 17 => Padded (J) = 0);
      end loop;
      R (0) :=
        U64 (Padded (1))
        or Shift_Left (U64 (Padded (2)), 8)
        or Shift_Left (U64 (Padded (3)), 16)
        or Shift_Left (U64 (Padded (4) and 16#03#), 24);
      R (1) :=
        Shift_Right (U64 (Padded (4)), 2)
        or Shift_Left (U64 (Padded (5)), 6)
        or Shift_Left (U64 (Padded (6)), 14)
        or Shift_Left (U64 (Padded (7) and 16#0F#), 22);
      R (2) :=
        Shift_Right (U64 (Padded (7)), 4)
        or Shift_Left (U64 (Padded (8)), 4)
        or Shift_Left (U64 (Padded (9)), 12)
        or Shift_Left (U64 (Padded (10) and 16#3F#), 20);
      R (3) :=
        Shift_Right (U64 (Padded (10)), 6)
        or Shift_Left (U64 (Padded (11)), 2)
        or Shift_Left (U64 (Padded (12)), 10)
        or Shift_Left (U64 (Padded (13)), 18);
      R (4) :=
        U64 (Padded (14))
        or Shift_Left (U64 (Padded (15)), 8)
        or Shift_Left (U64 (Padded (16)), 16);

      pragma
        Assert
          (for all I in 1 .. 16 =>
             Padded (I) = Enc.Padded_Byte (Clamped, 16, False, I));
      pragma Assert (R (0) = Enc.Enc_Limb0 (Clamped, 16, False));
      pragma Assert (R (1) = Enc.Enc_Limb1 (Clamped, 16, False));
      pragma Assert (R (2) = Enc.Enc_Limb2 (Clamped, 16, False));
      pragma Assert (R (3) = Enc.Enc_Limb3 (Clamped, 16, False));
      pragma Assert (R (4) = Enc.R_Limb4 (Clamped));
      declare
         TB : constant GB.Big_Nat := To_Big_Nat (R)
         with Ghost;
         EB : constant GB.Big_Nat := Enc.R_BN (Clamped)
         with Ghost;
      begin
         pragma Assert (TB (0) = EB (0));
         pragma Assert (TB (1) = EB (1));
         pragma Assert (TB (2) = EB (2));
         pragma Assert (TB (3) = EB (3));
         pragma Assert (TB (4) = EB (4));
         pragma
           Assert
             (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
                TB (I) = 0 and then EB (I) = 0);
         pragma Assert (GB."=" (TB, EB));
      end;
   end Load_R;

   ---------------------------------------------------------------------
   --  Reduce a 5-limb accumulator mod 2^130 - 5 by carry-propagation
   --  + a partial fold of the high bits via × 5.
   ---------------------------------------------------------------------

   --  Carry correspondence: viewed through To_Big_Nat, the impl Carry computes
   --  exactly GB.Carry_Model (sweep limbs 0..4, fold the limb-4 top carry into
   --  limb 0 x5, one normalising 0->1 step). With inputs < 2**58 every U64
   --  intermediate stays < 2**59, so Lemma_Shift_Mask_26 bridges each
   --  Shift_Right/and to the Big_Nat Hi26/Lo26 split, step by step.
   procedure Carry (L : in out Limbs)
   with
     Pre  => (for all I in Limb_Index => L (I) < 2**58),
     Post =>
       (for all I in Limb_Index => L (I) < 2**27)
       and then GB."=" (To_Big_Nat (L), GB.Carry_Model (To_Big_Nat (L'Old)));

   procedure Carry (L : in out Limbs) is
      C  : U64;
      B0 : constant GB.Big_Nat := To_Big_Nat (L)
      with Ghost;
   begin
      pragma Assert (GB.In_Bounds (B0, GB.Carry_In_Cap));
      GB.Lemma_Bounds_Mono (B0, GB.Carry_In_Cap, GB.Prod_Cap);
      GB.Lemma_Sweep5_Tight_Carry (B0);

      --  step 1: sweep limb 0 -> 1
      Lemma_Shift_Mask_26 (L (0));
      C := Shift_Right (L (0), 26);
      pragma Assert (C < 2**33);
      L (0) := L (0) and Mask_26;
      L (1) := L (1) + C;
      pragma Assert (GB.LLI (C) = GB.Sw_C0 (B0));
      pragma Assert (GB.LLI (L (0)) = GB.Sweep5_Out (B0) (0));
      pragma Assert (GB.LLI (L (1)) = B0 (1) + GB.Sw_C0 (B0));
      pragma Assert (L (1) < 2**59);

      --  step 2: sweep limb 1 -> 2
      Lemma_Shift_Mask_26 (L (1));
      C := Shift_Right (L (1), 26);
      pragma Assert (C < 2**33);
      L (1) := L (1) and Mask_26;
      L (2) := L (2) + C;
      pragma Assert (GB.LLI (C) = GB.Sw_C1 (B0));
      pragma Assert (GB.LLI (L (1)) = GB.Sweep5_Out (B0) (1));
      pragma Assert (GB.LLI (L (2)) = B0 (2) + GB.Sw_C1 (B0));
      pragma Assert (L (2) < 2**59);
      pragma Assert (GB.LLI (L (3)) = B0 (3));
      pragma Assert (GB.LLI (L (4)) = B0 (4));

      --  step 3: sweep limb 2 -> 3
      Lemma_Shift_Mask_26 (L (2));
      C := Shift_Right (L (2), 26);
      pragma Assert (C < 2**33);
      L (2) := L (2) and Mask_26;
      L (3) := L (3) + C;
      pragma Assert (GB.LLI (C) = GB.Sw_C2 (B0));
      pragma Assert (GB.LLI (L (2)) = GB.Lo26 (B0 (2) + GB.Sw_C1 (B0)));
      pragma
        Assert (GB.Sweep5_Out (B0) (2) = GB.Lo26 (B0 (2) + GB.Sw_C1 (B0)));
      pragma Assert (GB.LLI (L (2)) = GB.Sweep5_Out (B0) (2));
      pragma Assert (GB.LLI (L (3)) = B0 (3) + GB.Sw_C2 (B0));
      pragma Assert (L (3) < 2**59);
      pragma Assert (GB.LLI (L (4)) = B0 (4));

      pragma Assert (GB.LLI (L (0)) = GB.Sweep5_Out (B0) (0));
      pragma Assert (GB.LLI (L (1)) = GB.Sweep5_Out (B0) (1));

      --  step 4: sweep limb 3 -> 4
      Lemma_Shift_Mask_26 (L (3));
      C := Shift_Right (L (3), 26);
      pragma Assert (C < 2**33);
      L (3) := L (3) and Mask_26;
      pragma Assert (GB.LLI (L (4)) = B0 (4));
      pragma Assert (L (4) < 2**58);
      L (4) := L (4) + C;
      pragma Assert (GB.LLI (C) = GB.Sw_C3 (B0));
      pragma Assert (GB.LLI (L (3)) = GB.Lo26 (B0 (3) + GB.Sw_C2 (B0)));
      pragma
        Assert (GB.Sweep5_Out (B0) (3) = GB.Lo26 (B0 (3) + GB.Sw_C2 (B0)));
      pragma Assert (GB.LLI (L (3)) = GB.Sweep5_Out (B0) (3));
      pragma Assert (GB.LLI (L (4)) = B0 (4) + GB.Sw_C3 (B0));
      pragma Assert (L (4) < 2**59);
      pragma Assert (GB.LLI (L (0)) = GB.Sweep5_Out (B0) (0));
      pragma Assert (GB.LLI (L (1)) = GB.Sweep5_Out (B0) (1));
      pragma Assert (GB.LLI (L (2)) = GB.Sweep5_Out (B0) (2));

      --  step 5: top limb 4 folds into limb 0 x5 (2^130 == 5 mod p)
      Lemma_Shift_Mask_26 (L (4));
      C := Shift_Right (L (4), 26);
      pragma Assert (C < 2**33);
      L (4) := L (4) and Mask_26;
      pragma Assert (GB.LLI (C) = GB.Sw_C4 (B0));
      pragma Assert (GB.LLI (C) = GB.Sweep5_Out (B0) (5));
      pragma Assert (GB.LLI (L (4)) = GB.Lo26 (B0 (4) + GB.Sw_C3 (B0)));
      pragma
        Assert (GB.Sweep5_Out (B0) (4) = GB.Lo26 (B0 (4) + GB.Sw_C3 (B0)));
      pragma Assert (GB.LLI (L (4)) = GB.Sweep5_Out (B0) (4));
      --  L (0) still holds Sweep5_Out (B0) (0) (untouched since step 1)
      pragma Assert (GB.LLI (L (0)) = GB.Sweep5_Out (B0) (0));
      pragma Assert (L (0) < 2**26);
      L (0) := L (0) + 5 * C;
      pragma
        Assert
          (GB.LLI (L (0))
             = GB.Sweep5_Out (B0) (0) + 5 * GB.Sweep5_Out (B0) (5));
      pragma
        Assert
          (GB.Fold_Out (GB.Sweep5_Out (B0)) (0)
             = GB.Sweep5_Out (B0) (0) + 5 * GB.Sweep5_Out (B0) (5));
      pragma Assert (GB.LLI (L (0)) = GB.Fold_Out (GB.Sweep5_Out (B0)) (0));
      pragma Assert (L (0) < 2**38);
      --  Reduced limbs 1..4 (= Sweep5_Out (B0) (1..4)) survive untouched here.
      pragma Assert (GB.LLI (L (1)) = GB.Sweep5_Out (B0) (1));
      pragma Assert (GB.LLI (L (2)) = GB.Sweep5_Out (B0) (2));
      pragma Assert (GB.LLI (L (3)) = GB.Sweep5_Out (B0) (3));
      pragma Assert (GB.LLI (L (4)) = GB.Sweep5_Out (B0) (4));
      pragma Assert (L (1) < 2**26);

      --  step 6: one normalising carry limb 0 -> 1
      Lemma_Shift_Mask_26 (L (0));
      C := Shift_Right (L (0), 26);
      pragma Assert (C < 2**33);
      L (0) := L (0) and Mask_26;
      L (1) := L (1) + C;
      --  Carry_Model = Step_Out (Fold_Out (Sweep5_Out (B0)), 0): limb 0 is
      --  Lo26 of the folded limb 0; limb 1 gains its Hi26; 2..4 unchanged.
      pragma
        Assert
          (GB.Carry_Model (B0) (0)
             = GB.Lo26 (GB.Fold_Out (GB.Sweep5_Out (B0)) (0)));
      pragma
        Assert
          (GB.Carry_Model (B0) (1)
             = GB.Sweep5_Out (B0) (1)
               + GB.Hi26 (GB.Fold_Out (GB.Sweep5_Out (B0)) (0)));
      pragma Assert (GB.Carry_Model (B0) (2) = GB.Sweep5_Out (B0) (2));
      pragma Assert (GB.Carry_Model (B0) (3) = GB.Sweep5_Out (B0) (3));
      pragma Assert (GB.Carry_Model (B0) (4) = GB.Sweep5_Out (B0) (4));
      pragma Assert (GB.LLI (L (0)) = GB.Carry_Model (B0) (0));
      pragma Assert (GB.LLI (L (1)) = GB.Carry_Model (B0) (1));
      pragma Assert (GB.LLI (L (2)) = GB.Carry_Model (B0) (2));
      pragma Assert (GB.LLI (L (3)) = GB.Carry_Model (B0) (3));
      pragma Assert (GB.LLI (L (4)) = GB.Carry_Model (B0) (4));

      pragma
        Assert
          (for all I in Limb_Index =>
             GB.LLI (L (I)) = GB.Carry_Model (B0) (I));
      pragma Assert (GB."=" (To_Big_Nat (L), GB.Carry_Model (B0)));
   end Carry;

   ---------------------------------------------------------------------
   --  Acc := Acc + N
   ---------------------------------------------------------------------

   --  Add correspondence: limbwise sum (each input limb < 2**27, so the sum
   --  < 2**28) then Carry. Through To_Big_Nat the result is Carry_Model of the
   --  Big_Nat sum of the embeddings (Carry_Model = reduce mod p).
   procedure Add (Acc : in out Limbs; N : Limbs)
   with
     Pre  =>
       (for all I in Limb_Index => Acc (I) < 2**27 and then N (I) < 2**26),
     Post =>
       (for all I in Limb_Index => Acc (I) < 2**27)
       and then GB."="
                  (To_Big_Nat (Acc),
                   GB.Carry_Model
                     (GB."+" (To_Big_Nat (Acc'Old), To_Big_Nat (N))))
       --  Clean field-add form for the Mac loop invariant: the field element of
       --  the result is the field sum of the (canonical) accumulator and block.
       and then GB."="
                  (GB.Canonical (To_Big_Nat (Acc)),
                   GB.Field_Add
                     (GB.Canonical (To_Big_Nat (Acc'Old)), To_Big_Nat (N)));

   procedure Add (Acc : in out Limbs; N : Limbs) is
      Acc0 : constant GB.Big_Nat := To_Big_Nat (Acc)
      with Ghost;
      Nn   : constant GB.Big_Nat := To_Big_Nat (N)
      with Ghost;
   begin
      Lemma_To_Big_Nat_Mul_Cap
        (Acc);   --  Acc0 embeds <= Mul_Cap, zero from 5.
      Lemma_To_Big_Nat_Reduced (N);     --  Nn embeds <= In_Cap, zero from 5.
      for I in Limb_Index loop
         Acc (I) := Acc (I) + N (I);
         pragma
           Loop_Invariant
             (for all J in Limb_Index =>
                (if J <= I
                 then Acc (J) = Acc'Loop_Entry (J) + N (J)
                 else Acc (J) = Acc'Loop_Entry (J)));
         pragma Loop_Invariant (for all J in Limb_Index => Acc (J) < 2**28);
      end loop;
      --  Acc now holds the limbwise sum; its embedding is Acc0 + Nn.
      pragma
        Assert
          (for all I in Limb_Index => GB.LLI (Acc (I)) = Acc0 (I) + Nn (I));
      pragma Assert (GB."=" (To_Big_Nat (Acc), GB."+" (Acc0, Nn)));
      GB.Lemma_Sweep5_Tight_Carry (GB."+" (Acc0, Nn));
      Carry (Acc);

      --  Clean field-add form: Acc now holds Carry_Model (Acc0 + Nn); the Add
      --  bridge canonicalises it to Field_Add (Canonical (Acc0), Nn).
      Lemma_To_Big_Nat_Mul_Cap
        (Acc);   --  new Acc (post-carry) Mul_Cap, zero5.
      pragma
        Assert (GB."=" (To_Big_Nat (Acc), GB.Carry_Model (GB."+" (Acc0, Nn))));
      pragma Assert (GB.In_Bounds (GB."+" (Acc0, Nn), GB.Round1_Out_Cap));
      GB.Lemma_Sweep5_Chain_Tight (GB."+" (Acc0, Nn));
      GB.Lemma_Field_Add_Bridge (Acc0, Nn, To_Big_Nat (Acc));
   end Add;

   ---------------------------------------------------------------------
   --  Acc := (Acc * R) mod (2^130 - 5)
   --
   --  Schoolbook 5×5 multiply with the modular fold-down. Uses 64-bit
   --  intermediates; safe because each limb is at most 26 bits and we
   --  multiply at most 5 limbs.
   ---------------------------------------------------------------------

   --  Conv_Of — the nine convolution columns embedded as a Big_Nat (limbs
   --  0..8, zero above). A ghost helper so Reduce_Conv9 can state its
   --  contract over the columns without a ghost parameter.
   function Conv_Of
     (C0, C1, C2, C3, C4, C5, C6, C7, C8 : U64) return GB.Big_Nat
   is ([0      => GB.LLI (C0),
        1      => GB.LLI (C1),
        2      => GB.LLI (C2),
        3      => GB.LLI (C3),
        4      => GB.LLI (C4),
        5      => GB.LLI (C5),
        6      => GB.LLI (C6),
        7      => GB.LLI (C7),
        8      => GB.LLI (C8),
        others => 0])
   with
     Ghost,
     Pre =>
       C0 < 2**63
       and then C1 < 2**63
       and then C2 < 2**63
       and then C3 < 2**63
       and then C4 < 2**63
       and then C5 < 2**63
       and then C6 < 2**63
       and then C7 < 2**63
       and then C8 < 2**63;

   --  Reduce_Conv9 — the §0e-provable mod-p reduce of a nine-limb
   --  convolution. Sweeps carries across columns 0..8 (Sweep9) then folds
   --  the high positions 5..9 back into 0..4 (x5, Fold_High_9). Through
   --  To_Big_Nat the five-limb result equals
   --  Fold_High_9_Out (Sweep9_Out (Conv)). Isolated from Multiply so the
   --  bridge proof runs in a small, stable SMT context (don't be
   --  monolithic — §0e proof conventions).
   procedure Reduce_Conv9
     (C0, C1, C2, C3, C4, C5, C6, C7, C8 : U64; R1L : out Limbs)
   with
     Pre  =>
       C0 < 2**58
       and then C1 < 2**58
       and then C2 < 2**58
       and then C3 < 2**58
       and then C4 < 2**58
       and then C5 < 2**58
       and then C6 < 2**58
       and then C7 < 2**58
       and then C8 < 2**58
       and then GB.In_Bounds
                  (Conv_Of (C0, C1, C2, C3, C4, C5, C6, C7, C8), GB.Prod_Cap)
       and then GB.Sweep9_Out (Conv_Of (C0, C1, C2, C3, C4, C5, C6, C7, C8))
                  (9)
                in 0 .. GB.Fold9_Top_Cap,
     Post =>
       (for all I in Limb_Index => R1L (I) < 2**58)
       and then GB."="
                  (To_Big_Nat (R1L),
                   GB.Fold_High_9_Out
                     (GB.Sweep9_Out
                        (Conv_Of (C0, C1, C2, C3, C4, C5, C6, C7, C8))));

   procedure Reduce_Conv9
     (C0, C1, C2, C3, C4, C5, C6, C7, C8 : U64; R1L : out Limbs)
   is
      Conv : constant GB.Big_Nat :=
        Conv_Of (C0, C1, C2, C3, C4, C5, C6, C7, C8)
      with Ghost;

      --  Sweep add (column + carry-in): Post carries the U64->LLI
      --  distribution so the sweep bridge needn't re-derive it.
      function Sweep_Add (X, Cy : U64) return U64
      is (X + Cy)
      with
        Pre  => X < 2**58 and then Cy < 2**33,
        Post =>
          Sweep_Add'Result < 2**59
          and then GB.LLI (Sweep_Add'Result) = GB.LLI (X) + GB.LLI (Cy);

      --  Fold add (low limb + 5 * high limb): the Fold_High_9 step. Post
      --  carries the U64->LLI distribution.
      function Fold_Add (X, Y : U64) return U64
      is (X + 5 * Y)
      with
        Pre  => X < 2**33 and then Y < 2**33,
        Post =>
          Fold_Add'Result < 2**37
          and then GB.LLI (Fold_Add'Result) = GB.LLI (X) + 5 * GB.LLI (Y);

      S0, S1, S2, S3, S4, S5, S6, S7, S8 : U64;
      F0, F1, F2, F3, F4                 : U64;
      Cf                                 : U64;
   begin
      GB.Lemma_Sweep9_Cols (Conv);

      --  Sweep9: propagate carries across the nine columns; Cf holds the
      --  running carry (= the matching Sw9_C of Conv), landing at limb 9.
      Lemma_Shift_Mask_26 (C0);
      S0 := C0 and Mask_26;
      Cf := Shift_Right (C0, 26);
      pragma Assert (Cf < 2**33);
      pragma Assert (GB.LLI (Cf) = GB.Sw9_C0 (Conv));
      pragma Assert (GB.LLI (S0) = GB.Sweep9_Out (Conv) (0));

      S1 := Sweep_Add (C1, Cf);
      pragma Assert (GB.LLI (S1) = Conv (1) + GB.Sw9_C0 (Conv));
      Lemma_Shift_Mask_26 (S1);
      Cf := Shift_Right (S1, 26);
      S1 := S1 and Mask_26;
      pragma Assert (Cf < 2**33);
      pragma Assert (GB.LLI (Cf) = GB.Sw9_C1 (Conv));
      pragma Assert (GB.LLI (S1) = GB.Sweep9_Out (Conv) (1));

      S2 := Sweep_Add (C2, Cf);
      pragma Assert (GB.LLI (S2) = Conv (2) + GB.Sw9_C1 (Conv));
      Lemma_Shift_Mask_26 (S2);
      Cf := Shift_Right (S2, 26);
      S2 := S2 and Mask_26;
      pragma Assert (Cf < 2**33);
      pragma Assert (GB.LLI (Cf) = GB.Sw9_C2 (Conv));
      pragma Assert (GB.LLI (S2) = GB.Sweep9_Out (Conv) (2));

      S3 := Sweep_Add (C3, Cf);
      pragma Assert (GB.LLI (S3) = Conv (3) + GB.Sw9_C2 (Conv));
      Lemma_Shift_Mask_26 (S3);
      Cf := Shift_Right (S3, 26);
      S3 := S3 and Mask_26;
      pragma Assert (Cf < 2**33);
      pragma Assert (GB.LLI (Cf) = GB.Sw9_C3 (Conv));
      pragma Assert (GB.LLI (S3) = GB.Sweep9_Out (Conv) (3));

      S4 := Sweep_Add (C4, Cf);
      pragma Assert (GB.LLI (S4) = Conv (4) + GB.Sw9_C3 (Conv));
      Lemma_Shift_Mask_26 (S4);
      Cf := Shift_Right (S4, 26);
      S4 := S4 and Mask_26;
      pragma Assert (Cf < 2**33);
      pragma Assert (GB.LLI (Cf) = GB.Sw9_C4 (Conv));
      pragma Assert (GB.LLI (S4) = GB.Sweep9_Out (Conv) (4));

      S5 := Sweep_Add (C5, Cf);
      pragma Assert (GB.LLI (S5) = Conv (5) + GB.Sw9_C4 (Conv));
      Lemma_Shift_Mask_26 (S5);
      Cf := Shift_Right (S5, 26);
      S5 := S5 and Mask_26;
      pragma Assert (Cf < 2**33);
      pragma Assert (GB.LLI (Cf) = GB.Sw9_C5 (Conv));
      pragma Assert (GB.LLI (S5) = GB.Sweep9_Out (Conv) (5));

      S6 := Sweep_Add (C6, Cf);
      pragma Assert (GB.LLI (S6) = Conv (6) + GB.Sw9_C5 (Conv));
      Lemma_Shift_Mask_26 (S6);
      Cf := Shift_Right (S6, 26);
      S6 := S6 and Mask_26;
      pragma Assert (Cf < 2**33);
      pragma Assert (GB.LLI (Cf) = GB.Sw9_C6 (Conv));
      pragma Assert (GB.LLI (S6) = GB.Sweep9_Out (Conv) (6));

      S7 := Sweep_Add (C7, Cf);
      pragma Assert (GB.LLI (S7) = Conv (7) + GB.Sw9_C6 (Conv));
      Lemma_Shift_Mask_26 (S7);
      Cf := Shift_Right (S7, 26);
      S7 := S7 and Mask_26;
      pragma Assert (Cf < 2**33);
      pragma Assert (GB.LLI (Cf) = GB.Sw9_C7 (Conv));
      pragma Assert (GB.LLI (S7) = GB.Sweep9_Out (Conv) (7));

      S8 := Sweep_Add (C8, Cf);
      pragma Assert (GB.LLI (S8) = Conv (8) + GB.Sw9_C7 (Conv));
      Lemma_Shift_Mask_26 (S8);
      Cf := Shift_Right (S8, 26);
      S8 := S8 and Mask_26;
      pragma Assert (Cf < 2**33);
      pragma Assert (GB.LLI (Cf) = GB.Sweep9_Out (Conv) (9));
      pragma Assert (GB.LLI (S8) = GB.Sweep9_Out (Conv) (8));

      --  Keep all swept limbs alive for the fold (gnatprove drops facts
      --  about untouched variables across many statements).
      pragma Assert (GB.LLI (S0) = GB.Sweep9_Out (Conv) (0));
      pragma Assert (GB.LLI (S1) = GB.Sweep9_Out (Conv) (1));
      pragma Assert (GB.LLI (S2) = GB.Sweep9_Out (Conv) (2));
      pragma Assert (GB.LLI (S3) = GB.Sweep9_Out (Conv) (3));
      pragma Assert (GB.LLI (S4) = GB.Sweep9_Out (Conv) (4));
      pragma Assert (GB.LLI (S5) = GB.Sweep9_Out (Conv) (5));
      pragma Assert (GB.LLI (S6) = GB.Sweep9_Out (Conv) (6));
      pragma Assert (GB.LLI (S7) = GB.Sweep9_Out (Conv) (7));
      pragma Assert (S0 < 2**26 and S1 < 2**26 and S2 < 2**26);
      pragma Assert (S3 < 2**26 and S4 < 2**26 and S5 < 2**26);
      pragma Assert (S6 < 2**26 and S7 < 2**26 and S8 < 2**26);

      --  Fold_High_9 into separate locals (facts on separate variables
      --  survive; an array element's fact gets dropped on later writes).
      F0 := Fold_Add (S0, S5);
      F1 := Fold_Add (S1, S6);
      F2 := Fold_Add (S2, S7);
      F3 := Fold_Add (S3, S8);
      F4 := Fold_Add (S4, Cf);
      pragma
        Assert (GB.LLI (F0) = GB.Fold_High_9_Out (GB.Sweep9_Out (Conv)) (0));
      pragma
        Assert (GB.LLI (F1) = GB.Fold_High_9_Out (GB.Sweep9_Out (Conv)) (1));
      pragma
        Assert (GB.LLI (F2) = GB.Fold_High_9_Out (GB.Sweep9_Out (Conv)) (2));
      pragma
        Assert (GB.LLI (F3) = GB.Fold_High_9_Out (GB.Sweep9_Out (Conv)) (3));
      pragma
        Assert (GB.LLI (F4) = GB.Fold_High_9_Out (GB.Sweep9_Out (Conv)) (4));
      pragma
        Assert
          (F0 < 2**37
             and then F1 < 2**37
             and then F2 < 2**37
             and then F3 < 2**37
             and then F4 < 2**37);
      R1L := [0 => F0, 1 => F1, 2 => F2, 3 => F3, 4 => F4];
      pragma
        Assert
          (for all I in Limb_Index =>
             GB.LLI (R1L (I)) = GB.Fold_High_9_Out (GB.Sweep9_Out (Conv)) (I));
      pragma
        Assert
          (R1L (0) < 2**58
             and then R1L (1) < 2**58
             and then R1L (2) < 2**58
             and then R1L (3) < 2**58
             and then R1L (4) < 2**58);
      pragma
        Assert
          (GB."="
             (To_Big_Nat (R1L), GB.Fold_High_9_Out (GB.Sweep9_Out (Conv))));
   end Reduce_Conv9;

   --  Equal nine-limb convolutions reduce identically. Isolated so the
   --  array-extensionality + function-congruence step runs in a minimal
   --  context (the body's Conv = Prod is exactly such an equality).
   procedure Lemma_Reduce_Cong (X, Y : GB.Big_Nat)
   with
     Ghost,
     Global => null,
     Pre    =>
       GB."=" (X, Y)
       and then GB.In_Bounds (X, GB.Prod_Cap)
       and then GB.In_Bounds (Y, GB.Prod_Cap)
       and then GB.Sweep9_Out (X) (9) in 0 .. GB.Fold9_Top_Cap
       and then GB.Sweep9_Out (Y) (9) in 0 .. GB.Fold9_Top_Cap,
     Post   =>
       GB."="
         (GB.Fold_High_9_Out (GB.Sweep9_Out (X)),
          GB.Fold_High_9_Out (GB.Sweep9_Out (Y)));

   procedure Lemma_Reduce_Cong (X, Y : GB.Big_Nat) is null;

   --  Equal Carry_Model inputs carry to equal results. Isolated for the same
   --  reason as Lemma_Reduce_Cong: gnatprove does not propagate an array
   --  equality through the Carry_Model expression chain on its own.
   procedure Lemma_Carry_Model_Cong (X, Y : GB.Big_Nat)
   with
     Ghost,
     Global => null,
     Pre    =>
       GB."=" (X, Y)
       and then GB.In_Bounds (X, GB.Carry_In_Cap)
       and then (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
                   X (I) = 0)
       and then GB.Sweep5_Out (X) (5) in 0 .. GB.Fold_C_Cap
       and then GB.In_Bounds (Y, GB.Carry_In_Cap)
       and then (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
                   Y (I) = 0)
       and then GB.Sweep5_Out (Y) (5) in 0 .. GB.Fold_C_Cap,
     Post   => GB."=" (GB.Carry_Model (X), GB.Carry_Model (Y));

   procedure Lemma_Carry_Model_Cong (X, Y : GB.Big_Nat) is null;

   --  Equal accumulator-sized inputs canonicalise to equal results. Isolated
   --  (opaque Big_Nat params) so the Canonical expression-function congruence
   --  proves in a tiny context rather than inside the Multiply Post chain.
   procedure Lemma_Canon_Cong (X, Y : GB.Big_Nat)
   with
     Ghost,
     Global => null,
     Pre    =>
       GB."=" (X, Y)
       and then GB.In_Bounds (X, GB.Mul_Cap)
       and then (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
                   X (I) = 0)
       and then GB.In_Bounds (Y, GB.Mul_Cap)
       and then (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
                   Y (I) = 0),
     Post   => GB."=" (GB.Canonical (X), GB.Canonical (Y));

   procedure Lemma_Canon_Cong (X, Y : GB.Big_Nat) is
      Kf_X : GBV.BI.Big_Integer;
      Kf_Y : GBV.BI.Big_Integer;
   begin
      --  Route the canonical congruence through the value layer (avoids the
      --  Normalize record / Reduce_Canonical expression-function congruence,
      --  which the SMT does not discharge directly). X = Y => Val (X) = Val (Y);
      --  each canonical residue is the unique < p representative of that value,
      --  so the two canonicals coincide (Lemma_Val_Canonical_Eq).
      GB.Lemma_Bounds_Mono (X, GB.Mul_Cap, GBV.Val_Cap);
      GB.Lemma_Bounds_Mono (Y, GB.Mul_Cap, GBV.Val_Cap);
      GBV.Lemma_Val_Cong (X, Y);
      GBV.Lemma_Canonical_Val_Cong (X, Kf_X);
      GBV.Lemma_Canonical_Val_Cong (Y, Kf_Y);
      GBV.Lemma_Val_Canonical_Eq
        (GB.Canonical (X), GB.Canonical (Y), Kf_X, Kf_Y);
   end Lemma_Canon_Cong;

   --  Feval_BN (L) and Canonical (To_Big_Nat (L)) are the same expression
   --  (Reduce_Canonical (Normalize (To_Big_Nat (L)).Val)); expose the equality
   --  so the Mac loop can switch between the two forms.
   procedure Lemma_Feval_Eq_Canon (L : Limbs)
   with
     Ghost,
     Global => null,
     Pre    => (for all I in Limb_Index => L (I) < 2**27),
     Post   => GB."=" (Feval_BN (L), GB.Canonical (To_Big_Nat (L)));

   procedure Lemma_Feval_Eq_Canon (L : Limbs) is
   begin
      Lemma_To_Big_Nat_Mul_Cap (L);
   end Lemma_Feval_Eq_Canon;

   --  Congruence helpers for the field ops (isolated, value-routed because SMT
   --  will not do congruence on the ghost field functions directly).
   --  A is the accumulator (Mul_Cap), B the key element (In_Cap).
   procedure Lemma_FMul_Cong (A, A2, B, B2 : GB.Big_Nat)
   with
     Ghost,
     Global => null,
     Pre    =>
       GB."=" (A, A2)
       and then GB."=" (B, B2)
       and then GB.In_Bounds (A, GB.Mul_Cap)
       and then GB.In_Bounds (B, GB.In_Cap)
       and then GB.In_Bounds (A2, GB.Mul_Cap)
       and then GB.In_Bounds (B2, GB.In_Cap)
       and then (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
                   A (I) = 0
                   and then B (I) = 0
                   and then A2 (I) = 0
                   and then B2 (I) = 0),
     Post   => GB."=" (GB.Field_Mul (A, B), GB.Field_Mul (A2, B2));

   procedure Lemma_FMul_Cong (A, A2, B, B2 : GB.Big_Nat) is
      Kg1 : GBV.BI.Big_Integer;
      Kg2 : GBV.BI.Big_Integer;
   begin
      --  A*B = A2*B2 (per limb), so Field_Mul (A,B) and Field_Mul (A2,B2) are
      --  canonical residues of the same value; close via value-injectivity.
      GB.Lemma_Bounds_Mono (B, GB.In_Cap, GB.Mul_Cap);
      GB.Lemma_Bounds_Mono (B2, GB.In_Cap, GB.Mul_Cap);
      GBV.Lemma_Mul_Cong_LR (A, A2, B, B2);   --  A*B = A2*B2.
      GBV.Lemma_Field_Mul_Reduce_Cong (A, B, Kg1);
      GBV.Lemma_Field_Mul_Reduce_Cong (A2, B2, Kg2);
      GBV.Lemma_Val_Cong (GB."*" (A, B), GB."*" (A2, B2));
      GBV.Lemma_Val_Canonical_Eq
        (GB.Field_Mul (A, B), GB.Field_Mul (A2, B2), Kg1, Kg2);
   end Lemma_FMul_Cong;

   procedure Lemma_FAdd_Cong (A, A2, B, B2 : GB.Big_Nat)
   with
     Ghost,
     Global => null,
     Pre    =>
       GB."=" (A, A2)
       and then GB."=" (B, B2)
       and then GB.In_Bounds (A, GB.In_Cap)
       and then GB.In_Bounds (B, GB.In_Cap)
       and then GB.In_Bounds (A2, GB.In_Cap)
       and then GB.In_Bounds (B2, GB.In_Cap)
       and then (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
                   A (I) = 0
                   and then B (I) = 0
                   and then A2 (I) = 0
                   and then B2 (I) = 0),
     Post   => GB."=" (GB.Field_Add (A, B), GB.Field_Add (A2, B2));

   procedure Lemma_FAdd_Cong (A, A2, B, B2 : GB.Big_Nat) is
   begin
      --  Field_Add (X, Y) = Canonical (X + Y); A+B = A2+B2 (per limb), so the
      --  two canonical reduces coincide (Lemma_Canon_Cong).
      pragma
        Assert
          (for all I in GB.Limb_Index =>
             GB."+" (A, B) (I) = GB."+" (A2, B2) (I));
      pragma Assert (GB."=" (GB."+" (A, B), GB."+" (A2, B2)));
      pragma Assert (GB.In_Bounds (GB."+" (A, B), GB.Mul_Cap));
      pragma
        Assert
          (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
             GB."+" (A, B) (I) = 0);
      Lemma_Canon_Cong (GB."+" (A, B), GB."+" (A2, B2));
   end Lemma_FAdd_Cong;

   --  Multiply correspondence (conv-then-reduce, the §0e-provable form). The
   --  full nine-limb convolution Acc*R is reduced sweep-before-fold: Sweep9,
   --  Fold_High_9 (limbs 5..9 fold into 0..4 x5), then the proven Carry
   --  (= Sweep5 + Fold + normalising step). Through To_Big_Nat the result is
   --  exactly Carry_Model (Fold_High_9_Out (Sweep9_Out (Acc_bn * R_bn))). The
   --  mod-p equivalence to Acc_bn * R_bn is applied at the Mac use site via
   --  Lemma_Mul_Reduce; here the contract is the exact computation.
   procedure Multiply (Acc : in out Limbs; R : Limbs)
   with
     Pre  =>
       (for all I in Limb_Index => Acc (I) < 2**27 and then R (I) < 2**26),
     Post =>
       (for all I in Limb_Index => Acc (I) < 2**27)
       and then GB."="
                  (To_Big_Nat (Acc),
                   GB.Carry_Model
                     (GB.Fold_High_9_Out
                        (GB.Sweep9_Out
                           (GB."*" (To_Big_Nat (Acc'Old), To_Big_Nat (R))))))
       --  Clean field-multiply form for the Mac loop invariant: the field
       --  element of the result is the field product of the (canonical) inputs.
       and then GB."="
                  (GB.Canonical (To_Big_Nat (Acc)),
                   GB.Field_Mul
                     (GB.Canonical (To_Big_Nat (Acc'Old)), To_Big_Nat (R)));

   procedure Multiply (Acc : in out Limbs; R : Limbs) is
      --  Range-constrained limbs so gnatprove bounds every product
      --  (Acc_Limb * R_Limb < 2**53) by interval propagation.
      subtype Acc_Limb is U64 range 0 .. 2**27 - 1;
      subtype R_Limb is U64 range 0 .. 2**26 - 1;
      A0 : constant Acc_Limb := Acc (0);
      A1 : constant Acc_Limb := Acc (1);
      A2 : constant Acc_Limb := Acc (2);
      A3 : constant Acc_Limb := Acc (3);
      A4 : constant Acc_Limb := Acc (4);
      R0 : constant R_Limb := R (0);
      R1 : constant R_Limb := R (1);
      R2 : constant R_Limb := R (2);
      R3 : constant R_Limb := R (3);
      R4 : constant R_Limb := R (4);

      A_Bn : constant GB.Big_Nat := To_Big_Nat (Acc)
      with Ghost;
      R_Bn : constant GB.Big_Nat := To_Big_Nat (R)
      with Ghost;
      Prod : constant GB.Big_Nat := GB."*" (A_Bn, R_Bn)
      with Ghost;

      --  Dot-product helpers (1..5 terms) whose Post carries the U64->LLI
      --  distribution: each product is < 2**54 and the sum < 2**57, so LLI is
      --  exact and distributes. This encapsulates the convolution-limb bridge.
      function Mul1 (X0, Y0 : U64) return U64
      is (X0 * Y0)
      with
        Pre  => X0 < 2**27 and then Y0 < 2**27,
        Post => GB.LLI (Mul1'Result) = GB.LLI (X0) * GB.LLI (Y0);

      function Mul2 (X0, Y0, X1, Y1 : U64) return U64
      is (X0 * Y0 + X1 * Y1)
      with
        Pre  =>
          X0 < 2**27
          and then Y0 < 2**27
          and then X1 < 2**27
          and then Y1 < 2**27,
        Post =>
          GB.LLI (Mul2'Result)
          = GB.LLI (X0) * GB.LLI (Y0) + GB.LLI (X1) * GB.LLI (Y1);

      function Mul3 (X0, Y0, X1, Y1, X2, Y2 : U64) return U64
      is (X0 * Y0 + X1 * Y1 + X2 * Y2)
      with
        Pre  =>
          X0 < 2**27
          and then Y0 < 2**27
          and then X1 < 2**27
          and then Y1 < 2**27
          and then X2 < 2**27
          and then Y2 < 2**27,
        Post =>
          GB.LLI (Mul3'Result)
          = GB.LLI (X0)
            * GB.LLI (Y0)
            + GB.LLI (X1) * GB.LLI (Y1)
            + GB.LLI (X2) * GB.LLI (Y2);

      function Mul4 (X0, Y0, X1, Y1, X2, Y2, X3, Y3 : U64) return U64
      is (X0 * Y0 + X1 * Y1 + X2 * Y2 + X3 * Y3)
      with
        Pre  =>
          X0 < 2**27
          and then Y0 < 2**27
          and then X1 < 2**27
          and then Y1 < 2**27
          and then X2 < 2**27
          and then Y2 < 2**27
          and then X3 < 2**27
          and then Y3 < 2**27,
        Post =>
          GB.LLI (Mul4'Result)
          = GB.LLI (X0)
            * GB.LLI (Y0)
            + GB.LLI (X1) * GB.LLI (Y1)
            + GB.LLI (X2) * GB.LLI (Y2)
            + GB.LLI (X3) * GB.LLI (Y3);

      function Mul5 (X0, Y0, X1, Y1, X2, Y2, X3, Y3, X4, Y4 : U64) return U64
      is (X0 * Y0 + X1 * Y1 + X2 * Y2 + X3 * Y3 + X4 * Y4)
      with
        Pre  =>
          X0 < 2**27
          and then Y0 < 2**27
          and then X1 < 2**27
          and then Y1 < 2**27
          and then X2 < 2**27
          and then Y2 < 2**27
          and then X3 < 2**27
          and then Y3 < 2**27
          and then X4 < 2**27
          and then Y4 < 2**27,
        Post =>
          GB.LLI (Mul5'Result)
          = GB.LLI (X0)
            * GB.LLI (Y0)
            + GB.LLI (X1) * GB.LLI (Y1)
            + GB.LLI (X2) * GB.LLI (Y2)
            + GB.LLI (X3) * GB.LLI (Y3)
            + GB.LLI (X4) * GB.LLI (Y4);

      --  Nine-limb convolution columns (no fold): C (k) = sum A_i*R_j, i+j=k.
      C0 : constant U64 := Mul1 (A0, R0);
      C1 : constant U64 := Mul2 (A0, R1, A1, R0);
      C2 : constant U64 := Mul3 (A0, R2, A1, R1, A2, R0);
      C3 : constant U64 := Mul4 (A0, R3, A1, R2, A2, R1, A3, R0);
      C4 : constant U64 := Mul5 (A0, R4, A1, R3, A2, R2, A3, R1, A4, R0);
      C5 : constant U64 := Mul4 (A1, R4, A2, R3, A3, R2, A4, R1);
      C6 : constant U64 := Mul3 (A2, R4, A3, R3, A4, R2);
      C7 : constant U64 := Mul2 (A3, R4, A4, R3);
      C8 : constant U64 := Mul1 (A4, R4);

      Conv : constant GB.Big_Nat :=
        Conv_Of (C0, C1, C2, C3, C4, C5, C6, C7, C8)
      with Ghost;

      R1L : Limbs;
   begin
      --  The convolution embeds to the Big_Nat product Prod = A_Bn * R_Bn.
      Lemma_To_Big_Nat_Mul_Cap (Acc);
      Lemma_To_Big_Nat_Mul_Cap (R);
      GB.Lemma_Mul5_Cols (A_Bn, R_Bn, Prod);
      --  Connection facts: each U64 limb constant embeds to the Big_Nat limb.
      pragma Assert (GB.LLI (A0) = A_Bn (0));
      pragma Assert (GB.LLI (A1) = A_Bn (1));
      pragma Assert (GB.LLI (A2) = A_Bn (2));
      pragma Assert (GB.LLI (A3) = A_Bn (3));
      pragma Assert (GB.LLI (A4) = A_Bn (4));
      pragma Assert (GB.LLI (R0) = R_Bn (0));
      pragma Assert (GB.LLI (R1) = R_Bn (1));
      pragma Assert (GB.LLI (R2) = R_Bn (2));
      pragma Assert (GB.LLI (R3) = R_Bn (3));
      pragma Assert (GB.LLI (R4) = R_Bn (4));
      --  Each convolution column equals the matching product limb: the Mul
      --  helper Post gives LLI (C_k) as the LLI-product sum; the connection
      --  facts and Lemma_Mul5_Cols equate that to Prod (k).
      pragma Assert (GB.LLI (C0) = Prod (0));
      pragma Assert (GB.LLI (C1) = Prod (1));
      pragma Assert (GB.LLI (C2) = Prod (2));
      pragma Assert (GB.LLI (C3) = Prod (3));
      pragma Assert (GB.LLI (C4) = Prod (4));
      pragma Assert (GB.LLI (C5) = Prod (5));
      pragma Assert (GB.LLI (C6) = Prod (6));
      pragma Assert (GB.LLI (C7) = Prod (7));
      pragma Assert (GB.LLI (C8) = Prod (8));
      pragma Assert (GB."=" (Conv, Prod));
      pragma Assert (GB.In_Bounds (Conv, GB.Conv_Col_Cap));
      pragma
        Assert
          (for all I in GB.Limb_Index range 9 .. GB.Max_Limbs - 1 =>
             Conv (I) = 0);
      --  Conv = Prod, so the Post's Prod-side bounds hold too.
      pragma Assert (GB.In_Bounds (Prod, GB.Conv_Col_Cap));
      GB.Lemma_Bounds_Mono (Conv, GB.Conv_Col_Cap, GB.Prod_Cap);
      GB.Lemma_Bounds_Mono (Prod, GB.Conv_Col_Cap, GB.Prod_Cap);
      pragma
        Assert
          (for all I in GB.Limb_Index range 9 .. GB.Max_Limbs - 1 =>
             Prod (I) = 0);
      GB.Lemma_Sweep9_Conv (Conv);
      GB.Lemma_Sweep9_Conv (Prod);
      pragma
        Assert
          (for all I in GB.Limb_Index range 0 .. 8 =>
             GB.Sweep9_Out (Prod) (I) in 0 .. GB.In_Cap);
      pragma Assert (GB.Sweep9_Out (Prod) (9) in 0 .. GB.Fold9_Top_Cap);
      pragma Assert (GB.Sweep9_Out (Conv) (9) in 0 .. GB.Fold9_Top_Cap);
      --  Each conv column is < 2**58 (<= Conv_Col_Cap), feeding Reduce_Conv9.
      pragma Assert (C0 < 2**58 and C1 < 2**58 and C2 < 2**58);
      pragma Assert (C3 < 2**58 and C4 < 2**58 and C5 < 2**58);
      pragma Assert (C6 < 2**58 and C7 < 2**58 and C8 < 2**58);

      --  Reduce the convolution mod p (Sweep9 + Fold_High_9), isolated for
      --  proof stability: R1L = Fold_High_9_Out (Sweep9_Out (Conv)).
      Reduce_Conv9 (C0, C1, C2, C3, C4, C5, C6, C7, C8, R1L);
      --  Conv = Prod, so the reduced value is equally the Prod-side form the
      --  Post names; the congruence is discharged in an isolated lemma.
      Lemma_Reduce_Cong (Conv, Prod);

      --  Carry_Model precondition (tight top carry) on the Prod-side reduced
      --  value, for the Multiply Post. Fold_High_9_Out is Round1_Out_Cap-
      --  bounded; widen to Carry_In_Cap then take the tight Sweep5 top carry.
      GB.Lemma_Bounds_Mono
        (GB.Fold_High_9_Out (GB.Sweep9_Out (Prod)),
         GB.Round1_Out_Cap,
         GB.Carry_In_Cap);
      GB.Lemma_Sweep5_Tight_Carry (GB.Fold_High_9_Out (GB.Sweep9_Out (Prod)));

      --  Final normalising carry (the proven Sweep5 + Fold + step). Capture
      --  the pre-carry value as a flat ghost so Carry's Post chains by a
      --  shallow congruence; R1L_Pre = Fold_High_9_Out (Sweep9_Out (Prod)).
      declare
         R1L_Pre : constant GB.Big_Nat := To_Big_Nat (R1L)
         with Ghost;
      begin
         pragma
           Assert
             (GB."=" (R1L_Pre, GB.Fold_High_9_Out (GB.Sweep9_Out (Prod))));
         GB.Lemma_Sweep5_Tight_Carry (R1L_Pre);
         Carry (R1L);
         --  Carry Post: To_Big_Nat (R1L) = Carry_Model (R1L_Pre). The flat
         --  R1L_Pre equals the Prod-side reduced form, so the isolated
         --  Carry_Model congruence rewrites to the form the Post names.
         pragma Assert (GB."=" (To_Big_Nat (R1L), GB.Carry_Model (R1L_Pre)));
         Lemma_Carry_Model_Cong
           (R1L_Pre, GB.Fold_High_9_Out (GB.Sweep9_Out (Prod)));
         pragma
           Assert
             (GB."="
                (To_Big_Nat (R1L),
                 GB.Carry_Model (GB.Fold_High_9_Out (GB.Sweep9_Out (Prod)))));
      end;
      Acc := R1L;
      --  To_Big_Nat (Acc) = Carry_Model (Fold_High_9_Out (Sweep9_Out (Prod)))
      --  and Prod = Acc'Old * R, which is the Multiply Post.
      pragma
        Assert
          (GB."="
             (To_Big_Nat (Acc),
              GB.Carry_Model (GB.Fold_High_9_Out (GB.Sweep9_Out (Prod)))));
      Lemma_To_Big_Nat_Mul_Cap (Acc);   --  new Acc (= R1L) embeds <= Mul_Cap.

      --  Clean field-multiply form for the Mac loop invariant. Field_Mul's
      --  definitional Post is over Sweep9/Fold of A_Bn*R_Bn; route that through
      --  the reduction-congruence lemmas to Prod (= A_Bn*R_Bn, the body's
      --  reduced value), then apply the Mul bridge to canonicalise the operand.
      Lemma_To_Big_Nat_Reduced (R);   --  R_Bn limbs <= In_Cap.
      pragma Assert (GB.In_Bounds (A_Bn, GB.Mul_Cap));
      pragma Assert (GB.In_Bounds (R_Bn, GB.Mul_Cap));
      pragma Assert (GB.In_Bounds (R_Bn, GB.In_Cap));
      pragma
        Assert
          (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
             A_Bn (I) = 0);
      pragma
        Assert
          (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
             R_Bn (I) = 0);
      Lemma_Reduce_Cong (GB."*" (A_Bn, R_Bn), Prod);
      Lemma_Carry_Model_Cong
        (GB.Fold_High_9_Out (GB.Sweep9_Out (GB."*" (A_Bn, R_Bn))),
         GB.Fold_High_9_Out (GB.Sweep9_Out (Prod)));
      pragma
        Assert
          (GB."="
             (GB.Carry_Model
                (GB.Fold_High_9_Out (GB.Sweep9_Out (GB."*" (A_Bn, R_Bn)))),
              To_Big_Nat (Acc)));
      pragma
        Assert
          (GB."="
             (GB.Field_Mul (A_Bn, R_Bn),
              GB.Canonical
                (GB.Carry_Model
                   (GB.Fold_High_9_Out
                      (GB.Sweep9_Out (GB."*" (A_Bn, R_Bn)))))));
      Lemma_Canon_Cong
        (GB.Carry_Model
           (GB.Fold_High_9_Out (GB.Sweep9_Out (GB."*" (A_Bn, R_Bn)))),
         To_Big_Nat (Acc));
      pragma
        Assert
          (GB."="
             (GB.Field_Mul (A_Bn, R_Bn), GB.Canonical (To_Big_Nat (Acc))));
      GBV.Lemma_Field_Mul_Bridge (A_Bn, R_Bn);
      pragma
        Assert
          (GB."="
             (GB.Canonical (To_Big_Nat (Acc)),
              GB.Field_Mul (GB.Canonical (A_Bn), R_Bn)));
   end Multiply;

   ---------------------------------------------------------------------
   --  Fold_Blocks — fold the whole message into the field accumulator.
   --
   --  Extracted from Mac so the heavy ghost reasoning (loop invariant +
   --  tail correspondence) proves in a small, isolated context.  Produces
   --  the post-message accumulator: Feval_BN (Acc) = Spec_Mac_Acc.
   ---------------------------------------------------------------------

   procedure Fold_Blocks (Message : Octet_Array; R : Limbs; Acc : out Limbs)
   with
     Pre  =>
       (for all I in Limb_Index => R (I) < 2**26)
       and then GB.In_Bounds (To_Big_Nat (R), GB.In_Cap)
       and then (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
                   To_Big_Nat (R) (I) = 0)
       and then Message'Last < Integer'Last - 16,
     Post =>
       (for all I in Limb_Index => Acc (I) < 2**27)
       and then GB."="
                  (Feval_BN (Acc), SB.Spec_Mac_Acc (Message, To_Big_Nat (R)))
   is
      Cursor : Natural := 0;
      Block  : Limbs;
      RB     : constant GB.Big_Nat := To_Big_Nat (R)
      with Ghost;
   begin
      Acc := [others => 0];
      Lemma_To_Big_Nat_Reduced (R);          --  RB: In_Cap, zero from 5.
      Lemma_To_Big_Nat_Mul_Cap (Acc);        --  To_Big_Nat (Acc=0).
      pragma Assert (GB."=" (To_Big_Nat (Acc), GB.Zero));
      GB.Lemma_Canonical_Zero;               --  Canonical (Zero) = Zero.
      Lemma_Canon_Cong (To_Big_Nat (Acc), GB.Zero);
      pragma Assert (GB."=" (Feval_BN (Acc), GB.Zero));
      pragma Assert (GB."=" (SB.Spec_Fold (Message, 0, RB), GB.Zero));
      pragma Assert (GB."=" (Feval_BN (Acc), SB.Spec_Fold (Message, 0, RB)));

      while Cursor + 16 <= Message'Length loop
         pragma Loop_Invariant (Cursor mod 16 = 0);
         pragma Loop_Invariant (Cursor <= Message'Length);
         pragma Loop_Invariant (for all I in Limb_Index => Acc (I) < 2**27);
         pragma Loop_Invariant (for all I in Limb_Index => R (I) < 2**26);
         pragma Loop_Invariant (GB."=" (To_Big_Nat (R), RB));
         pragma
           Loop_Invariant
             (GB."="
                (Feval_BN (Acc), SB.Spec_Fold (Message, Cursor / 16, RB)));
         pragma Loop_Variant (Decreases => Message'Length - Cursor);
         declare
            F0 : constant GB.Big_Nat := Feval_BN (Acc)
            with Ghost;
            K  : constant Natural := Cursor / 16
            with Ghost;
         begin
            pragma Assert (16 * K = Cursor);
            pragma Assert (GB."=" (F0, SB.Spec_Fold (Message, K, RB)));
            pragma Assert (GB.In_Bounds (F0, GB.In_Cap));  --  Spec_Fold Post.
            --  F0 in Canonical form (the shape the op clean Posts produce).
            Lemma_To_Big_Nat_Mul_Cap (Acc);
            Lemma_Feval_Eq_Canon (Acc);
            pragma Assert (GB."=" (GB.Canonical (To_Big_Nat (Acc)), F0));
            Load_Block
              (Message (Message'First + Cursor .. Message'First + Cursor + 15),
               16,
               Final     => False,
               Out_Limbs => Block);
            Lemma_To_Big_Nat_Reduced (Block);  --  To_Big_Nat (Block) In_Cap.
            --  Block = the K-th Spec_Fold block (16 * K = Cursor).
            pragma
              Assert
                (GB."="
                   (To_Big_Nat (Block),
                    Enc.Encode_BN
                      (Message
                         (Message'First
                          + 16 * K
                          .. Message'First + 16 * (K + 1) - 1),
                       16,
                       False)));
            Add (Acc, Block);
            Lemma_To_Big_Nat_Mul_Cap (Acc);   --  after-Add Acc: Mul_Cap.
            declare
               FA   : constant GB.Big_Nat :=
                 GB.Field_Add (F0, To_Big_Nat (Block))
               with Ghost;
               BlkK : constant GB.Big_Nat :=
                 Enc.Encode_BN
                   (Message
                      (Message'First
                       + 16 * K
                       .. Message'First + 16 * (K + 1) - 1),
                    16,
                    False)
               with Ghost;
               --  Capture the after-Add field value in a stable constant so
               --  it survives the Multiply call as Canonical (..Acc'Old..).
               C1   : constant GB.Big_Nat := GB.Canonical (To_Big_Nat (Acc))
               with Ghost;
            begin
               --  Add clean Post (Canonical form): Acc folds to FA = C1.
               pragma Assert (GB."=" (C1, FA));
               GB.Lemma_Bounds_Mono (C1, GB.In_Cap, GB.Mul_Cap);
               Lemma_To_Big_Nat_Reduced (R);
               GB.Lemma_Bounds_Mono (To_Big_Nat (R), GB.In_Cap, GB.Mul_Cap);
               Multiply (Acc, R);
               --  Re-establish operand bounds after the call for Field_Mul.
               Lemma_To_Big_Nat_Mul_Cap (Acc);
               GB.Lemma_Bounds_Mono (C1, GB.In_Cap, GB.Mul_Cap);
               Lemma_To_Big_Nat_Reduced (R);
               GB.Lemma_Bounds_Mono (To_Big_Nat (R), GB.In_Cap, GB.Mul_Cap);
               --  Multiply clean Post: Acc folds to C1 * r = FA * r.
               pragma
                 Assert
                   (GB."="
                      (GB.Canonical (To_Big_Nat (Acc)),
                       GB.Field_Mul (C1, To_Big_Nat (R))));
               Lemma_Feval_Eq_Canon (Acc);
               pragma
                 Assert
                   (GB."="
                      (Feval_BN (Acc), GB.Field_Mul (C1, To_Big_Nat (R))));
               --  C1 = FA, To_Big_Nat (R) = RB: rewrite to Field_Mul (FA, RB).
               GB.Lemma_Bounds_Mono (FA, GB.In_Cap, GB.Mul_Cap);
               GB.Lemma_Bounds_Mono (RB, GB.In_Cap, GB.Mul_Cap);
               GB.Lemma_Bounds_Mono (C1, GB.In_Cap, GB.Mul_Cap);
               GB.Lemma_Bounds_Mono (To_Big_Nat (R), GB.In_Cap, GB.Mul_Cap);
               Lemma_FMul_Cong (C1, FA, To_Big_Nat (R), RB);
               pragma Assert (GB."=" (Feval_BN (Acc), GB.Field_Mul (FA, RB)));
               --  FA = Field_Add (Spec_Fold (K), block K); so FA * r is the
               --  Spec_Fold (K+1) unfolding.
               pragma Assert (GB."=" (To_Big_Nat (Block), BlkK));
               pragma Assert (GB."=" (F0, SB.Spec_Fold (Message, K, RB)));
               Lemma_FAdd_Cong
                 (F0, SB.Spec_Fold (Message, K, RB), To_Big_Nat (Block), BlkK);
               pragma
                 Assert
                   (GB."="
                      (FA,
                       GB.Field_Add (SB.Spec_Fold (Message, K, RB), BlkK)));
               --  Spec_Fold (K+1) unfolds to Field_Mul (Field_Add (Spec_Fold
               --  (K), block K), RB); swap Field_Add (..) = FA via FMul_Cong.
               GB.Lemma_Bounds_Mono
                 (GB.Field_Add (SB.Spec_Fold (Message, K, RB), BlkK),
                  GB.In_Cap,
                  GB.Mul_Cap);
               GB.Lemma_Bounds_Mono (FA, GB.In_Cap, GB.Mul_Cap);
               Lemma_FMul_Cong
                 (GB.Field_Add (SB.Spec_Fold (Message, K, RB), BlkK),
                  FA,
                  RB,
                  RB);
               pragma
                 Assert
                   (GB."="
                      (SB.Spec_Fold (Message, K + 1, RB),
                       GB.Field_Mul (FA, RB)));
               pragma
                 Assert
                   (GB."="
                      (Feval_BN (Acc), SB.Spec_Fold (Message, K + 1, RB)));
            end;
            Cursor := Cursor + 16;
            pragma Assert (Cursor / 16 = K + 1);
         end;
      end loop;

      --  After the loop: Cursor = 16 * (Message'Length / 16) and
      --  Feval_BN (Acc) = Spec_Fold (Message, Message'Length / 16, RB).
      Lemma_To_Big_Nat_Mul_Cap (Acc);
      Lemma_Feval_Eq_Canon (Acc);
      pragma
        Assert
          (GB."=" (Feval_BN (Acc), SB.Spec_Fold (Message, Cursor / 16, RB)));
      pragma Assert (Cursor = 16 * (Message'Length / 16));
      pragma Assert (Cursor / 16 = Message'Length / 16);
      pragma
        Assert
          (GB."="
             (SB.Spec_Fold (Message, Cursor / 16, RB),
              SB.Spec_Fold (Message, Message'Length / 16, RB)));
      pragma
        Assert
          (GB."="
             (Feval_BN (Acc),
              SB.Spec_Fold (Message, Message'Length / 16, RB)));

      --  Possibly one short trailing block (length not a multiple of 16).
      if Cursor < Message'Length then
         declare
            Tail_Len : constant Natural := Message'Length - Cursor;
            F0       : constant GB.Big_Nat := Feval_BN (Acc)
            with Ghost;
         begin
            pragma Assert (Cursor = 16 * (Message'Length / 16));
            pragma Assert (Message'Length mod 16 /= 0);
            pragma Assert (Tail_Len = Message'Length mod 16);
            pragma Assert (Tail_Len in 1 .. 15);
            pragma
              Assert
                (GB."=" (F0, SB.Spec_Fold (Message, Message'Length / 16, RB)));
            Lemma_To_Big_Nat_Mul_Cap (Acc);
            Lemma_Feval_Eq_Canon (Acc);
            pragma Assert (GB."=" (GB.Canonical (To_Big_Nat (Acc)), F0));
            pragma Assert (GB.In_Bounds (F0, GB.In_Cap));
            Load_Block
              (Message (Message'First + Cursor .. Message'Last),
               Tail_Len,
               Final     => True,
               Out_Limbs => Block);
            Lemma_To_Big_Nat_Reduced (Block);
            --  Block = the final partial Spec_Mac_Acc block. The Load_Block
            --  slice (from Cursor) equals the spec slice (from
            --  16 * (Message'Length / 16)); Tail_Len = Message'Length mod 16.
            pragma
              Assert
                (GB."="
                   (To_Big_Nat (Block),
                    Enc.Encode_BN
                      (Message (Message'First + Cursor .. Message'Last),
                       Tail_Len,
                       True)));
            pragma
              Assert
                (GB."="
                   (To_Big_Nat (Block),
                    Enc.Encode_BN
                      (Message
                         (Message'First
                          + 16 * (Message'Length / 16)
                          .. Message'Last),
                       Message'Length mod 16,
                       True)));
            Add (Acc, Block);
            Lemma_To_Big_Nat_Mul_Cap (Acc);   --  after-Add Acc: Mul_Cap.
            declare
               SF    : constant GB.Big_Nat :=
                 SB.Spec_Fold (Message, Message'Length / 16, RB)
               with Ghost;
               TailK : constant GB.Big_Nat :=
                 Enc.Encode_BN
                   (Message
                      (Message'First
                       + 16 * (Message'Length / 16)
                       .. Message'Last),
                    Message'Length mod 16,
                    True)
               with Ghost;
               FA    : constant GB.Big_Nat :=
                 GB.Field_Add (F0, To_Big_Nat (Block))
               with Ghost;
               --  Snapshot the after-Add field value so it survives Multiply
               --  as Canonical (..Acc'Old..).
               C1    : constant GB.Big_Nat := GB.Canonical (To_Big_Nat (Acc))
               with Ghost;
            begin
               pragma Assert (GB."=" (To_Big_Nat (Block), TailK));
               --  Add clean Post: Acc folds to FA = C1.
               pragma Assert (GB."=" (C1, FA));
               GB.Lemma_Bounds_Mono (C1, GB.In_Cap, GB.Mul_Cap);
               Lemma_To_Big_Nat_Reduced (R);
               GB.Lemma_Bounds_Mono (To_Big_Nat (R), GB.In_Cap, GB.Mul_Cap);
               Multiply (Acc, R);
               --  Re-establish operand bounds after the call for Field_Mul.
               Lemma_To_Big_Nat_Mul_Cap (Acc);
               GB.Lemma_Bounds_Mono (C1, GB.In_Cap, GB.Mul_Cap);
               Lemma_To_Big_Nat_Reduced (R);
               GB.Lemma_Bounds_Mono (To_Big_Nat (R), GB.In_Cap, GB.Mul_Cap);
               --  Multiply clean Post: Acc folds to C1 * r = FA * r.
               pragma
                 Assert
                   (GB."="
                      (GB.Canonical (To_Big_Nat (Acc)),
                       GB.Field_Mul (C1, To_Big_Nat (R))));
               Lemma_Feval_Eq_Canon (Acc);
               pragma
                 Assert
                   (GB."="
                      (Feval_BN (Acc), GB.Field_Mul (C1, To_Big_Nat (R))));
               --  C1 = FA, To_Big_Nat (R) = RB: rewrite to Field_Mul (FA, RB).
               GB.Lemma_Bounds_Mono (FA, GB.In_Cap, GB.Mul_Cap);
               GB.Lemma_Bounds_Mono (RB, GB.In_Cap, GB.Mul_Cap);
               Lemma_FMul_Cong (C1, FA, To_Big_Nat (R), RB);
               pragma Assert (GB."=" (Feval_BN (Acc), GB.Field_Mul (FA, RB)));
               --  FA = Field_Add (Spec_Fold (..), final block).
               pragma Assert (GB."=" (To_Big_Nat (Block), TailK));
               pragma Assert (GB."=" (F0, SF));
               Lemma_FAdd_Cong (F0, SF, To_Big_Nat (Block), TailK);
               pragma Assert (GB."=" (FA, GB.Field_Add (SF, TailK)));
               --  Spec_Mac_Acc (mod16 /= 0) unfolds to Field_Mul (Field_Add
               --  (Spec_Fold, final block), RB); swap Field_Add (..) = FA.
               GB.Lemma_Bounds_Mono
                 (GB.Field_Add (SF, TailK), GB.In_Cap, GB.Mul_Cap);
               GB.Lemma_Bounds_Mono (FA, GB.In_Cap, GB.Mul_Cap);
               Lemma_FMul_Cong (GB.Field_Add (SF, TailK), FA, RB, RB);
               pragma
                 Assert
                   (GB."="
                      (SB.Spec_Mac_Acc (Message, RB),
                       GB.Field_Mul (GB.Field_Add (SF, TailK), RB)));
               pragma
                 Assert
                   (GB."="
                      (SB.Spec_Mac_Acc (Message, RB), GB.Field_Mul (FA, RB)));
               pragma
                 Assert
                   (GB."=" (Feval_BN (Acc), SB.Spec_Mac_Acc (Message, RB)));
            end;
         end;
      else
         --  Length is a multiple of 16: no trailing block, the post-loop
         --  fold already equals Spec_Mac_Acc.
         pragma Assert (Cursor = Message'Length);
         pragma Assert (Message'Length mod 16 = 0);
         pragma
           Assert
             (GB."="
                (SB.Spec_Mac_Acc (Message, RB),
                 SB.Spec_Fold (Message, Message'Length / 16, RB)));
         pragma
           Assert (GB."=" (Feval_BN (Acc), SB.Spec_Mac_Acc (Message, RB)));
      end if;

      --  Post-message accumulator now matches the Big_Nat MAC spec.
      pragma Assert (GB."=" (Feval_BN (Acc), SB.Spec_Mac_Acc (Message, RB)));
   end Fold_Blocks;

   ---------------------------------------------------------------------
   --  Mac
   ---------------------------------------------------------------------

   procedure Mac
     (Key : Key_Array; Message : Octet_Array; Out_Tag : out Tag_Array)
   is
      R   : Limbs;
      Acc : Limbs;

      --  s as a 17-byte LE integer (upper byte is 0 because s is
      --  128 bits) for the final addition.
      function Get_S_Limb (Idx : Limb_Index) return U64
      with Pre => Idx <= 4;

      function Get_S_Limb (Idx : Limb_Index) return U64 is
         Padded : Octet_Array (1 .. 17) := [others => 0];
      begin
         for I in 1 .. 16 loop
            Padded (I) := Key (16 + I);
         end loop;
         case Idx is
            when 0 =>
               return
                 U64 (Padded (1))
                 or Shift_Left (U64 (Padded (2)), 8)
                 or Shift_Left (U64 (Padded (3)), 16)
                 or Shift_Left (U64 (Padded (4) and 16#03#), 24);

            when 1 =>
               return
                 Shift_Right (U64 (Padded (4)), 2)
                 or Shift_Left (U64 (Padded (5)), 6)
                 or Shift_Left (U64 (Padded (6)), 14)
                 or Shift_Left (U64 (Padded (7) and 16#0F#), 22);

            when 2 =>
               return
                 Shift_Right (U64 (Padded (7)), 4)
                 or Shift_Left (U64 (Padded (8)), 4)
                 or Shift_Left (U64 (Padded (9)), 12)
                 or Shift_Left (U64 (Padded (10) and 16#3F#), 20);

            when 3 =>
               return
                 Shift_Right (U64 (Padded (10)), 6)
                 or Shift_Left (U64 (Padded (11)), 2)
                 or Shift_Left (U64 (Padded (12)), 10)
                 or Shift_Left (U64 (Padded (13)), 18);

            when 4 =>
               return
                 U64 (Padded (14))
                 or Shift_Left (U64 (Padded (15)), 8)
                 or Shift_Left (U64 (Padded (16)), 16);
         end case;
      end Get_S_Limb;

   begin
      Out_Tag := [others => 0];
      --  RFC 8439 §2.5.1 clamp.
      declare
         Clamped : Octet_Array (1 .. 16);
      begin
         for I in 1 .. 16 loop
            Clamped (I) := Key (I);
         end loop;
         Clamped (4) := Clamped (4) and 16#0F#;
         Clamped (8) := Clamped (8) and 16#0F#;
         Clamped (12) := Clamped (12) and 16#0F#;
         Clamped (16) := Clamped (16) and 16#0F#;
         Clamped (5) := Clamped (5) and 16#FC#;
         Clamped (9) := Clamped (9) and 16#FC#;
         Clamped (13) := Clamped (13) and 16#FC#;
         --  Load r from clamped key (16 bytes), WITHOUT the Poly1305
         --  implicit-1 bit. r itself is just an integer.
         Load_R (Clamped, R);
      end;

      --  r is a 26-bit-limb integer (no implicit-1 bit): every limb < 2**26,
      --  so it meets Multiply's R-side precondition. r is never modified after
      --  this point, so the bound persists across the block loop.
      pragma Assert (for all I in Limb_Index => R (I) < 2**26);

      --  Fold the whole message into the accumulator. Fold_Blocks proves
      --  Feval_BN (Acc) = Spec_Mac_Acc (Message, To_Big_Nat (R)).
      Lemma_To_Big_Nat_Reduced (R);   --  To_Big_Nat (R): In_Cap, zero from 5.
      Fold_Blocks (Message, R, Acc);

      --  Partial reduction: the two carry-folds bring Acc into [0, 2^130).
      --  Each Carry only reduces mod p (Lemma_Carry_Canonical), so the field
      --  element Feval_BN (Acc) = Spec_Mac_Acc is preserved across both.
      declare
         FB : constant GB.Big_Nat := SB.Spec_Mac_Acc (Message, To_Big_Nat (R))
         with Ghost;
      begin
         pragma Assert (GB."=" (Feval_BN (Acc), FB));   --  Fold_Blocks Post.

         --  Carry 1: Feval_BN (Acc) preserved.
         declare
            A0 : constant GB.Big_Nat := To_Big_Nat (Acc)
            with Ghost;
         begin
            Lemma_To_Big_Nat_Mul_Cap (Acc);     --  A0: Mul_Cap, zero from 5.
            Lemma_Feval_Eq_Canon (Acc);
            pragma Assert (GB."=" (GB.Canonical (A0), FB));
            GB.Lemma_Sweep5_Acc_Carry (A0);     --  Sweep5_Out (A0)(5) <= 2.
            GB.Lemma_Carry_Canonical
              (A0);      --  Canon (CM (A0)) = Canon (A0).
            Carry (Acc);
            Lemma_To_Big_Nat_Mul_Cap (Acc);
            --  To_Big_Nat (Acc) == Carry_Model (A0); canonical-route it.
            pragma Assert (GB.In_Bounds (GB.Carry_Model (A0), GB.Mul_Cap));
            pragma
              Assert
                (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
                   GB.Carry_Model (A0) (I) = 0);
            Lemma_Canon_Cong (To_Big_Nat (Acc), GB.Carry_Model (A0));
            Lemma_Feval_Eq_Canon (Acc);
            pragma Assert (GB."=" (GB.Canonical (GB.Carry_Model (A0)), FB));
            pragma Assert (GB."=" (Feval_BN (Acc), FB));
         end;

         --  Carry 2: same recipe.
         declare
            A1 : constant GB.Big_Nat := To_Big_Nat (Acc)
            with Ghost;
         begin
            Lemma_To_Big_Nat_Mul_Cap (Acc);
            Lemma_Feval_Eq_Canon (Acc);
            pragma Assert (GB."=" (GB.Canonical (A1), FB));
            GB.Lemma_Sweep5_Acc_Carry (A1);
            GB.Lemma_Carry_Canonical (A1);
            Carry (Acc);
            Lemma_To_Big_Nat_Mul_Cap (Acc);
            pragma Assert (GB.In_Bounds (GB.Carry_Model (A1), GB.Mul_Cap));
            pragma
              Assert
                (for all I in GB.Limb_Index range 5 .. GB.Max_Limbs - 1 =>
                   GB.Carry_Model (A1) (I) = 0);
            Lemma_Canon_Cong (To_Big_Nat (Acc), GB.Carry_Model (A1));
            Lemma_Feval_Eq_Canon (Acc);
            pragma Assert (GB."=" (GB.Canonical (GB.Carry_Model (A1)), FB));
            pragma Assert (GB."=" (Feval_BN (Acc), FB));
         end;

         pragma
           Assert
             (GB."="
                (Feval_BN (Acc), SB.Spec_Mac_Acc (Message, To_Big_Nat (R))));
      end;

      --  RFC 8439 §2.5.1 final reduction ("freeze"). The carry-fold above
      --  only guarantees Acc < 2^130, NOT Acc < p (= 2^130 - 5): the five
      --  values in [2^130 - 5, 2^130) are a fixed point of Carry, so they
      --  reach this point un-reduced. Conditionally subtract p to land on
      --  the canonical representative < p (matching HACL* poly1305_finish).
      --  Without this step (acc + s) mod 2^128 disagrees with the spec's
      --  (acc mod p + s) mod 2^128 by p mod 2^128 = 2^128 - 5 whenever Acc
      --  falls in that window. Constant-time: no data-dependent branch.
      declare
         G    : Limbs := [others => 0];
         C    : U64;
         Tmp  : U64;
         Mask : U64;
      begin
         --  Clean carry so each limb < 2**26 (Acc < 2^130 ⇒ no carry out).
         C := 0;
         for I in Limb_Index loop
            Tmp := Acc (I) + C;
            Acc (I) := Tmp and Mask_26;
            C := Shift_Right (Tmp, 26);
            pragma
              Loop_Invariant
                (for all J in Limb_Index =>
                   (if J <= I then Acc (J) < 2**26 else Acc (J) < 2**27));
            pragma Loop_Invariant (C <= 2);
         end loop;

         --  g = Acc + 5, carry-propagated. The carry out of limb 4 lands at
         --  weight 2^130 and is 1 iff Acc + 5 >= 2^130, i.e. iff Acc >= p.
         C := 5;
         for I in Limb_Index loop
            Tmp := Acc (I) + C;
            G (I) := Tmp and Mask_26;
            C := Shift_Right (Tmp, 26);
            pragma Loop_Invariant (C <= 1);
            pragma Loop_Invariant (for all J in Limb_Index => G (J) < 2**26);
         end loop;

         --  Mask = all-ones iff Acc >= p (select g = Acc - p), else 0 (keep
         --  Acc). Branchless select.
         Mask := U64'(0) - (C and 1);
         for I in Limb_Index loop
            Acc (I) := (Acc (I) and not Mask) or (G (I) and Mask);
         end loop;
      end;

      --  Acc := Acc + s (mod 2^128). Then serialize as little-endian.
      declare
         Carry_Acc : U64 := 0;
         T         : array (Limb_Index) of U64 := [others => 0];
         H_Lo      : U64;
         H_Hi      : U64;
      begin
         for I in Limb_Index loop
            T (I) := Acc (I) + Get_S_Limb (I) + Carry_Acc;
            Carry_Acc := Shift_Right (T (I), 26);
            T (I) := T (I) and Mask_26;
         end loop;

         --  Repack into two 64-bit halves of the 130-bit number.
         --  Limb i sits at bit position 26 * i.
         --  H_Lo: bits 0..63   ← T(0)|26 + T(1)|26 + low 12 bits of T(2)
         --  H_Hi: bits 64..127 ← high 14 bits of T(2) + T(3)|26 + low 24 bits of T(4)
         H_Lo :=
           T (0)
           or Shift_Left (T (1), 26)
           or Shift_Left (T (2) and 16#0000_0FFF#, 52);
         H_Hi :=
           Shift_Right (T (2), 12)
           or Shift_Left (T (3), 14)
           or Shift_Left (T (4) and 16#00FF_FFFF#, 40);

         for I in 0 .. 7 loop
            Out_Tag (1 + I) := Octet (Shift_Right (H_Lo, 8 * I) and 16#FF#);
         end loop;
         for I in 0 .. 7 loop
            Out_Tag (9 + I) := Octet (Shift_Right (H_Hi, 8 * I) and 16#FF#);
         end loop;
      end;
   end Mac;

end Tls_Core.Poly1305;
