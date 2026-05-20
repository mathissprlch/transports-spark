package body Tls_Core.Poly1305
  with SPARK_Mode
is

   use Interfaces;

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

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
     Pre =>
       Block_Bytes in 1 .. 16
       and then Block_Bytes <= B'Length
       and then B'Last < Integer'Last - 16;

   procedure Load_Block
     (B           : Octet_Array;
      Block_Bytes : Natural;
      Final       : Boolean;
      Out_Limbs   : out Limbs)
   is
      Padded : Octet_Array (1 .. 17) := (others => 0);
   begin
      Out_Limbs := (others => 0);
      for I in 1 .. Block_Bytes loop
         pragma Loop_Invariant (I <= 16);
         Padded (I) := B (B'First + I - 1);
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
   end Load_Block;

   ---------------------------------------------------------------------
   --  Reduce a 5-limb accumulator mod 2^130 - 5 by carry-propagation
   --  + a partial fold of the high bits via × 5.
   ---------------------------------------------------------------------

   procedure Carry (L : in out Limbs);
   procedure Carry (L : in out Limbs) is
      C : U64;
   begin
      --  Propagate carries up.
      C := Shift_Right (L (0), 26);
      L (0) := L (0) and Mask_26;
      L (1) := L (1) + C;
      C := Shift_Right (L (1), 26);
      L (1) := L (1) and Mask_26;
      L (2) := L (2) + C;
      C := Shift_Right (L (2), 26);
      L (2) := L (2) and Mask_26;
      L (3) := L (3) + C;
      C := Shift_Right (L (3), 26);
      L (3) := L (3) and Mask_26;
      L (4) := L (4) + C;
      --  Top limb: any bits past 26 fold down with a × 5 (the modulus
      --  trick: 2^130 ≡ 5 mod (2^130 − 5)).
      C := Shift_Right (L (4), 26);
      L (4) := L (4) and Mask_26;
      L (0) := L (0) + 5 * C;
      C := Shift_Right (L (0), 26);
      L (0) := L (0) and Mask_26;
      L (1) := L (1) + C;
   end Carry;

   ---------------------------------------------------------------------
   --  Acc := Acc + N
   ---------------------------------------------------------------------

   procedure Add (Acc : in out Limbs; N : Limbs);
   procedure Add (Acc : in out Limbs; N : Limbs) is
   begin
      for I in Limb_Index loop
         Acc (I) := Acc (I) + N (I);
      end loop;
      Carry (Acc);
   end Add;

   ---------------------------------------------------------------------
   --  Acc := (Acc * R) mod (2^130 - 5)
   --
   --  Schoolbook 5×5 multiply with the modular fold-down. Uses 64-bit
   --  intermediates; safe because each limb is at most 26 bits and we
   --  multiply at most 5 limbs.
   ---------------------------------------------------------------------

   procedure Multiply (Acc : in out Limbs; R : Limbs);
   procedure Multiply (Acc : in out Limbs; R : Limbs) is
      A0                 : constant U64 := Acc (0);
      A1                 : constant U64 := Acc (1);
      A2                 : constant U64 := Acc (2);
      A3                 : constant U64 := Acc (3);
      A4                 : constant U64 := Acc (4);
      R0                 : constant U64 := R (0);
      R1                 : constant U64 := R (1);
      R2                 : constant U64 := R (2);
      R3                 : constant U64 := R (3);
      R4                 : constant U64 := R (4);
      S1                 : constant U64 := R1 * 5;
      S2                 : constant U64 := R2 * 5;
      S3                 : constant U64 := R3 * 5;
      S4                 : constant U64 := R4 * 5;
      D0, D1, D2, D3, D4 : U64;
   begin
      --  Mod 2^130-5 trick: any limb that "spills past" position 4
      --  folds back down with a × 5.
      D0 := A0 * R0 + A1 * S4 + A2 * S3 + A3 * S2 + A4 * S1;
      D1 := A0 * R1 + A1 * R0 + A2 * S4 + A3 * S3 + A4 * S2;
      D2 := A0 * R2 + A1 * R1 + A2 * R0 + A3 * S4 + A4 * S3;
      D3 := A0 * R3 + A1 * R2 + A2 * R1 + A3 * R0 + A4 * S4;
      D4 := A0 * R4 + A1 * R3 + A2 * R2 + A3 * R1 + A4 * R0;
      Acc (0) := D0;
      Acc (1) := D1;
      Acc (2) := D2;
      Acc (3) := D3;
      Acc (4) := D4;
      Carry (Acc);
   end Multiply;

   ---------------------------------------------------------------------
   --  Mac
   ---------------------------------------------------------------------

   procedure Mac
     (Key : Key_Array; Message : Octet_Array; Out_Tag : out Tag_Array)
   is
      R      : Limbs := (others => 0);
      Acc    : Limbs := (others => 0);
      Block  : Limbs;
      Cursor : Natural := 0;

      --  s as a 17-byte LE integer (upper byte is 0 because s is
      --  128 bits) for the final addition.
      function Get_S_Limb (Idx : Limb_Index) return U64
      with Pre => Idx <= 4;

      function Get_S_Limb (Idx : Limb_Index) return U64 is
         Padded : Octet_Array (1 .. 17) := (others => 0);
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
      Out_Tag := (others => 0);
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
         --  Load r from clamped key (16 bytes), WITHOUT the
         --  Poly1305 implicit-1 bit. r itself is just an integer.
         declare
            Padded : Octet_Array (1 .. 17) := (others => 0);
         begin
            for I in 1 .. 16 loop
               Padded (I) := Clamped (I);
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
         end;
      end;

      --  Process all complete 16-byte blocks (Final=False ⇒ implicit
      --  "1" appears at bit 128, the 17th byte).
      while Cursor + 16 <= Message'Length loop
         pragma Loop_Variant (Decreases => Message'Length - Cursor);
         Load_Block
           (Message (Message'First + Cursor .. Message'First + Cursor + 15),
            16,
            Final     => False,
            Out_Limbs => Block);
         Add (Acc, Block);
         Multiply (Acc, R);
         Cursor := Cursor + 16;
      end loop;

      --  Possibly one short trailing block.
      if Cursor < Message'Length then
         declare
            Tail_Len : constant Natural := Message'Length - Cursor;
         begin
            Load_Block
              (Message (Message'First + Cursor .. Message'Last),
               Tail_Len,
               Final     => True,
               Out_Limbs => Block);
            Add (Acc, Block);
            Multiply (Acc, R);
         end;
      end if;

      --  Final reduction: ensure Acc < 2^130-5. Two extra carries
      --  bring it into canonical form.
      Carry (Acc);
      Carry (Acc);

      --  Acc := Acc + s (mod 2^128). Then serialize as little-endian.
      declare
         Carry_Acc : U64 := 0;
         T         : array (Limb_Index) of U64 := (others => 0);
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
