with Ada.Unchecked_Conversion;
with Interfaces;

package body Tls_Core.P256_Field
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use Interfaces;

   ---------------------------------------------------------------------
   --  Internal limb representation.
   --
   --  An element is held as eight 32-bit limbs in little-endian
   --  order: Limbs (0) is the least significant 32-bit word, Limbs (7)
   --  the most significant. The associated 256-bit integer is
   --      sum_{i=0..7} Limbs (i) * 2^(32*i).
   ---------------------------------------------------------------------

   subtype Limb_Index is Natural range 0 .. 7;
   type Limbs8 is array (Limb_Index) of Unsigned_32;

   --  One extra limb of headroom for the carry coming out of an
   --  add / fast-reduction step (we never need more than 3 bits, but
   --  carrying a full 32-bit limb keeps the carry-propagation loop
   --  uniform with the multiply path).
   subtype Limb9_Index is Natural range 0 .. 8;
   type Limbs9 is array (Limb9_Index) of Unsigned_32;

   --  Sixteen-limb intermediate produced by schoolbook 8x8 multiply.
   subtype Limb16_Index is Natural range 0 .. 15;
   type Limbs16 is array (Limb16_Index) of Unsigned_32;

   --  Signed 9-limb accumulator used by the fast-reduction step:
   --  the NIST formula adds five Si terms and subtracts four, so
   --  the per-limb partial sum is signed. Integer_64 has ample
   --  headroom (each Si is < 2^32, weighted by at most 2 in the
   --  formula, summed with at most nine Si's: < 2^36).
   subtype Acc9_Index is Natural range 0 .. 8;
   type Acc9 is array (Acc9_Index) of Integer_64;

   function To_U64 is new Ada.Unchecked_Conversion
     (Integer_64, Unsigned_64);
   function To_I64 is new Ada.Unchecked_Conversion
     (Unsigned_64, Integer_64);

   --  Arithmetic right shift on Integer_64.
   function Asr (X : Integer_64; N : Natural) return Integer_64
   is (To_I64 (Shift_Right_Arithmetic (To_U64 (X), N)));

   --  NIST P-256 prime p = 2^256 - 2^224 + 2^192 + 2^96 - 1
   --  expressed as eight 32-bit little-endian limbs:
   --      0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
   --      0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF
   P_Limbs : constant Limbs8 :=
     (16#FFFFFFFF#, 16#FFFFFFFF#, 16#FFFFFFFF#, 16#00000000#,
      16#00000000#, 16#00000000#, 16#00000001#, 16#FFFFFFFF#);

   ---------------------------------------------------------------------
   --  Encoding / decoding between 32 BE bytes and limbs.
   ---------------------------------------------------------------------

   procedure From_Bytes (B : Field; L : out Limbs8) is
   begin
      for I in Limb_Index loop
         --  Limb i covers bytes 32-4*i-3 .. 32-4*i (BE input).
         L (I) :=
             Shift_Left (Unsigned_32 (B (32 - 4 * I - 3)), 24)
           or Shift_Left (Unsigned_32 (B (32 - 4 * I - 2)), 16)
           or Shift_Left (Unsigned_32 (B (32 - 4 * I - 1)),  8)
           or            Unsigned_32 (B (32 - 4 * I));
      end loop;
   end From_Bytes;

   procedure To_Bytes (L : Limbs8; B : out Field) is
   begin
      for I in Limb_Index loop
         B (32 - 4 * I - 3) := Octet (Shift_Right (L (I), 24) and 16#FF#);
         B (32 - 4 * I - 2) := Octet (Shift_Right (L (I), 16) and 16#FF#);
         B (32 - 4 * I - 1) := Octet (Shift_Right (L (I),  8) and 16#FF#);
         B (32 - 4 * I)     := Octet (L (I) and 16#FF#);
      end loop;
   end To_Bytes;

   ---------------------------------------------------------------------
   --  Conditional subtract of P from an 8-limb value. If A < P the
   --  routine leaves A unchanged. Constant-time-ish (branch on the
   --  borrow only after the speculative subtraction).
   ---------------------------------------------------------------------

   procedure Cond_Sub_P (A : in out Limbs8) is
      Borrow : Unsigned_64 := 0;
      T      : Limbs8;
      Diff   : Unsigned_64;
   begin
      for I in Limb_Index loop
         Diff :=
             Unsigned_64 (A (I))
           - Unsigned_64 (P_Limbs (I))
           - Borrow;
         T (I) := Unsigned_32 (Diff and 16#FFFFFFFF#);
         Borrow := Shift_Right (Diff, 63) and 1;
      end loop;
      if Borrow = 0 then
         A := T;
      end if;
   end Cond_Sub_P;

   ---------------------------------------------------------------------
   --  Add two 8-limb values producing a 9-limb result.
   ---------------------------------------------------------------------

   procedure Limb_Add (A, B : Limbs8; R : out Limbs9) is
      Carry : Unsigned_64 := 0;
      Sum   : Unsigned_64;
   begin
      for I in Limb_Index loop
         Sum := Unsigned_64 (A (I)) + Unsigned_64 (B (I)) + Carry;
         R (I) := Unsigned_32 (Sum and 16#FFFFFFFF#);
         Carry := Shift_Right (Sum, 32);
      end loop;
      R (8) := Unsigned_32 (Carry);
   end Limb_Add;

   ---------------------------------------------------------------------
   --  Fully reduce a 9-limb non-negative value modulo p. The high
   --  limb R (8) holds at most a small constant (we use this for the
   --  add path where R (8) <= 1, and for the fast-reduction path
   --  where R (8) <= 9 after the per-limb carry settles). Subtract p
   --  while the value is >= p; bounded above by R (8) + 1 iterations.
   ---------------------------------------------------------------------

   procedure Reduce_Once_If_Top (A : in out Limbs9) is
      Borrow : Unsigned_64 := 0;
      Diff   : Unsigned_64;
      T      : Limbs9;
   begin
      for I in Limb_Index loop
         Diff :=
             Unsigned_64 (A (I))
           - Unsigned_64 (P_Limbs (I))
           - Borrow;
         T (I) := Unsigned_32 (Diff and 16#FFFFFFFF#);
         Borrow := Shift_Right (Diff, 63) and 1;
      end loop;
      Diff := Unsigned_64 (A (8)) - Borrow;
      T (8) := Unsigned_32 (Diff and 16#FFFFFFFF#);
      Borrow := Shift_Right (Diff, 63) and 1;
      if Borrow = 0 then
         A := T;
      end if;
   end Reduce_Once_If_Top;

   procedure Final_Reduce (A : in out Limbs9; Out_R : out Limbs8) is
   begin
      --  After the fast-reduction folding, the value fits in
      --  approximately 9 limbs with the top limb a small constant.
      --  At most ~6 subtractions of p are needed to bring it into
      --  [0, p). We loop a fixed number of times for predictability.
      for K in 1 .. 10 loop
         Reduce_Once_If_Top (A);
      end loop;
      for I in Limb_Index loop
         Out_R (I) := A (I);
      end loop;
      --  Final canonicalisation: A may still be in [p, 2p).
      Cond_Sub_P (Out_R);
   end Final_Reduce;

   ---------------------------------------------------------------------
   --  Modular Add / Sub.
   ---------------------------------------------------------------------

   procedure Limb_Add_Mod (A, B : Limbs8; R : out Limbs8) is
      Sum : Limbs9;
   begin
      Limb_Add (A, B, Sum);
      Final_Reduce (Sum, R);
   end Limb_Add_Mod;

   procedure Limb_Sub_Mod (A, B : Limbs8; R : out Limbs8) is
      Borrow : Unsigned_64 := 0;
      Carry  : Unsigned_64;
      Diff   : Unsigned_64;
      T      : Limbs8;
   begin
      for I in Limb_Index loop
         Diff :=
             Unsigned_64 (A (I))
           - Unsigned_64 (B (I))
           - Borrow;
         T (I) := Unsigned_32 (Diff and 16#FFFFFFFF#);
         Borrow := Shift_Right (Diff, 63) and 1;
      end loop;
      if Borrow = 0 then
         R := T;
      else
         --  Add p back to recover the modular result.
         Carry := 0;
         for I in Limb_Index loop
            Diff :=
                Unsigned_64 (T (I))
              + Unsigned_64 (P_Limbs (I))
              + Carry;
            R (I) := Unsigned_32 (Diff and 16#FFFFFFFF#);
            Carry := Shift_Right (Diff, 32);
         end loop;
      end if;
   end Limb_Sub_Mod;

   ---------------------------------------------------------------------
   --  Schoolbook 8x8 multiplication producing a 16-limb intermediate.
   ---------------------------------------------------------------------

   procedure Limb_Mul (A, B : Limbs8; T : out Limbs16) is
      Acc   : Unsigned_64 := 0;
      Carry : Unsigned_64 := 0;
   begin
      for I in Limb16_Index loop
         T (I) := 0;
      end loop;
      for I in Limb_Index loop
         Carry := 0;
         for J in Limb_Index loop
            Acc :=
                Unsigned_64 (T (I + J))
              + Unsigned_64 (A (I)) * Unsigned_64 (B (J))
              + Carry;
            T (I + J) := Unsigned_32 (Acc and 16#FFFFFFFF#);
            Carry := Shift_Right (Acc, 32);
         end loop;
         T (I + 8) := Unsigned_32 (Carry and 16#FFFFFFFF#);
      end loop;
   end Limb_Mul;

   ---------------------------------------------------------------------
   --  NIST P-256 fast reduction (FIPS 186-4 §D.1.4 / SP 800-186).
   --  Input T = T15..T0 (little-endian: T0 is the LSB 32-bit word).
   --
   --     S1 = (T7,  T6,  T5,  T4,  T3,  T2,  T1,  T0)
   --     S2 = (T15, T14, T13, T12, T11, 0,   0,   0)   -- doubled
   --     S3 = (0,   T15, T14, T13, T12, 0,   0,   0)   -- doubled
   --     S4 = (T15, T14, 0,   0,   0,   T10, T9,  T8)
   --     S5 = (T8,  T13, T15, T14, T13, T11, T10, T9)
   --     S6 = (T10, T8,  0,   0,   0,   T13, T12, T11)
   --     S7 = (T11, T9,  0,   0,   T15, T14, T13, T12)
   --     S8 = (T12, 0,   T10, T9,  T8,  T15, T14, T13)
   --     S9 = (T13, 0,   T11, T10, T9,  0,   T15, T14)
   --
   --     R = S1 + 2*S2 + 2*S3 + S4 + S5 - S6 - S7 - S8 - S9 (mod p)
   ---------------------------------------------------------------------

   procedure Fast_Reduce (T : Limbs16; Out_R : out Limbs8) is
      Acc : Acc9 := (others => 0);
      Carry : Integer_64;

      function I64 (X : Unsigned_32) return Integer_64
      is (Integer_64 (X));

      Final : Limbs9;
   begin
      --  Limb 0..7: positive contributions from S1, 2*S2, 2*S3, S4, S5.
      --  We then subtract S6, S7, S8, S9.
      --
      --  Each limb is written here as a sum of named tuple slots
      --  from the table above. Positive (added) terms first, then
      --  subtracted terms.

      --  Limb 0 (LSB):
      --    +S1.0=T0 +2*S2.0=0 +2*S3.0=0 +S4.0=T8 +S5.0=T9
      --    -S6.0=T11 -S7.0=T12 -S8.0=T13 -S9.0=T14
      Acc (0) := I64 (T (0)) + I64 (T (8)) + I64 (T (9))
                 - I64 (T (11)) - I64 (T (12))
                 - I64 (T (13)) - I64 (T (14));

      --  Limb 1:
      --    +T1 +T9 +T10 -T12 -T13 -T14 -T15
      Acc (1) := I64 (T (1)) + I64 (T (9)) + I64 (T (10))
                 - I64 (T (12)) - I64 (T (13))
                 - I64 (T (14)) - I64 (T (15));

      --  Limb 2:
      --    +T2 +T10 +T11 -T13 -T14 -T15 (S6.2=0, S8.2=0, S9.2=0)
      --  Wait — re-derive. S6=(T10,T8,0,0,0,T13,T12,T11):
      --     S6.0=T11, S6.1=T12, S6.2=T13, S6.3=0, S6.4=0,
      --     S6.5=0,   S6.6=T8,  S6.7=T10.
      --  S7=(T11,T9,0,0,T15,T14,T13,T12):
      --     S7.0=T12, S7.1=T13, S7.2=T14, S7.3=T15, S7.4=0,
      --     S7.5=0,   S7.6=T9,  S7.7=T11.
      --  S8=(T12,0,T10,T9,T8,T15,T14,T13):
      --     S8.0=T13, S8.1=T14, S8.2=T15, S8.3=T8, S8.4=T9,
      --     S8.5=T10, S8.6=0,   S8.7=T12.
      --  S9=(T13,0,T11,T10,T9,0,T15,T14):
      --     S9.0=T14, S9.1=T15, S9.2=0,   S9.3=T9, S9.4=T10,
      --     S9.5=T11, S9.6=0,   S9.7=T13.
      --  S5=(T8,T13,T15,T14,T13,T11,T10,T9):
      --     S5.0=T9,  S5.1=T10, S5.2=T11, S5.3=T13, S5.4=T14,
      --     S5.5=T15, S5.6=T13, S5.7=T8.
      --  S4=(T15,T14,0,0,0,T10,T9,T8):
      --     S4.0=T8,  S4.1=T9,  S4.2=T10, S4.3=0,   S4.4=0,
      --     S4.5=0,   S4.6=T14, S4.7=T15.
      --  S3=(0,T15,T14,T13,T12,0,0,0):
      --     S3.0=0, S3.1=0, S3.2=0, S3.3=T12, S3.4=T13, S3.5=T14,
      --     S3.6=T15, S3.7=0.
      --  S2=(T15,T14,T13,T12,T11,0,0,0):
      --     S2.0=0, S2.1=0, S2.2=0, S2.3=T11, S2.4=T12, S2.5=T13,
      --     S2.6=T14, S2.7=T15.
      --
      --  Limb 2:
      --    +T2 +T10 +T11 -T13 -T14 -T15
      Acc (2) := I64 (T (2)) + I64 (T (10)) + I64 (T (11))
                 - I64 (T (13)) - I64 (T (14)) - I64 (T (15));

      --  Limb 3:
      --    +S1.3=T3 +2*S2.3=2*T11 +2*S3.3=2*T12 +S4.3=0 +S5.3=T13
      --    -S6.3=0 -S7.3=T15 -S8.3=T8 -S9.3=T9
      Acc (3) := I64 (T (3))
                 + 2 * I64 (T (11))
                 + 2 * I64 (T (12))
                 + I64 (T (13))
                 - I64 (T (15)) - I64 (T (8)) - I64 (T (9));

      --  Limb 4:
      --    +T4 +2*T12 +2*T13 +0 +T14
      --    -0 -0 -T9 -T10
      Acc (4) := I64 (T (4))
                 + 2 * I64 (T (12))
                 + 2 * I64 (T (13))
                 + I64 (T (14))
                 - I64 (T (9)) - I64 (T (10));

      --  Limb 5:
      --    +T5 +2*T13 +2*T14 +0 +T15
      --    -0 -0 -T10 -T11
      Acc (5) := I64 (T (5))
                 + 2 * I64 (T (13))
                 + 2 * I64 (T (14))
                 + I64 (T (15))
                 - I64 (T (10)) - I64 (T (11));

      --  Limb 6:
      --    +T6 +2*T14 +2*T15 +T14 +T13
      --    -T8 -T9 -0 -0
      Acc (6) := I64 (T (6))
                 + 2 * I64 (T (14))
                 + 2 * I64 (T (15))
                 + I64 (T (14))
                 + I64 (T (13))
                 - I64 (T (8)) - I64 (T (9));

      --  Limb 7:
      --    +T7 +2*T15 +0 +T15 +T8
      --    -T10 -T11 -T12 -T13
      Acc (7) := I64 (T (7))
                 + 2 * I64 (T (15))
                 + I64 (T (15))
                 + I64 (T (8))
                 - I64 (T (10)) - I64 (T (11))
                 - I64 (T (12)) - I64 (T (13));

      --  Limb 8 starts at zero (overflow accumulator).
      Acc (8) := 0;

      --  Carry-propagate signed accumulator.
      for I in 0 .. 7 loop
         Carry := Asr (Acc (I), 32);
         Acc (I) := Acc (I) - To_I64 (Shift_Left (To_U64 (Carry), 32));
         Acc (I + 1) := Acc (I + 1) + Carry;
      end loop;

      --  Now Acc (0..7) are in [0, 2^32) and Acc (8) is signed,
      --  with magnitude bounded by the formula coefficients (a few
      --  bits beyond zero). Add multiples of p until non-negative.
      --
      --  Each "add p" bumps Acc (8) by ~ +1 (since p < 2^256 means
      --  carrying p into the 9-limb representation does not
      --  increment limb 8 by more than 1). We need at most 4
      --  additions of p (Acc (8) >= -4 from the formula).
      while Acc (8) < 0 loop
         declare
            C : Unsigned_64 := 0;
            S : Unsigned_64;
         begin
            for I in Limb_Index loop
               S := Unsigned_64 (Acc (I))
                    + Unsigned_64 (P_Limbs (I))
                    + C;
               Acc (I) := Integer_64 (S and 16#FFFFFFFF#);
               C := Shift_Right (S, 32);
            end loop;
            Acc (8) := Acc (8) + Integer_64 (C);
         end;
         --  Acc (8) drops by 1 in absolute value because adding p
         --  shifts the value up by p, equivalently up by 2^256 - X
         --  for small X — net result for the limb 8 counter is "-1
         --  modulo the carry chain".
         --
         --  In practice, after adding p once, the represented
         --  256-bit number wraps once more: the limb-8 accumulator
         --  reads the 257th bit, so adding p (which has the
         --  high bit set: 0xFFFFFFFF...) produces a +1 carry into
         --  limb 8. Acc (8) thus increases by 1 per add. Net: we
         --  loop until Acc (8) >= 0.
         exit when Acc (8) >= 0;
      end loop;

      --  Acc (8) is now non-negative and at most a small constant.
      for I in 0 .. 8 loop
         Final (I) := Unsigned_32 (To_U64 (Acc (I)) and 16#FFFFFFFF#);
      end loop;

      Final_Reduce (Final, Out_R);
   end Fast_Reduce;

   ---------------------------------------------------------------------
   --  Modular multiply.
   ---------------------------------------------------------------------

   procedure Limb_Mul_Mod (A, B : Limbs8; R : out Limbs8) is
      T : Limbs16;
   begin
      Limb_Mul (A, B, T);
      Fast_Reduce (T, R);
   end Limb_Mul_Mod;

   procedure Limb_Square_Mod (A : Limbs8; R : out Limbs8) is
   begin
      Limb_Mul_Mod (A, A, R);
   end Limb_Square_Mod;

   ---------------------------------------------------------------------
   --  Public Add / Sub / Mul / Square.
   ---------------------------------------------------------------------

   procedure Add (A, B : Field; Out_C : out Field) is
      AL, BL, RL : Limbs8;
   begin
      From_Bytes (A, AL);
      From_Bytes (B, BL);
      Limb_Add_Mod (AL, BL, RL);
      To_Bytes (RL, Out_C);
   end Add;

   procedure Sub (A, B : Field; Out_C : out Field) is
      AL, BL, RL : Limbs8;
   begin
      From_Bytes (A, AL);
      From_Bytes (B, BL);
      Limb_Sub_Mod (AL, BL, RL);
      To_Bytes (RL, Out_C);
   end Sub;

   procedure Mul (A, B : Field; Out_C : out Field) is
      AL, BL, RL : Limbs8;
   begin
      From_Bytes (A, AL);
      From_Bytes (B, BL);
      Limb_Mul_Mod (AL, BL, RL);
      To_Bytes (RL, Out_C);
   end Mul;

   procedure Square (A : Field; Out_C : out Field) is
      AL, RL : Limbs8;
   begin
      From_Bytes (A, AL);
      Limb_Square_Mod (AL, RL);
      To_Bytes (RL, Out_C);
   end Square;

   ---------------------------------------------------------------------
   --  Invert via Fermat: a^(p-2) mod p.
   --
   --  p   = 2^256 - 2^224 + 2^192 + 2^96 - 1
   --  p-2 = 2^256 - 2^224 + 2^192 + 2^96 - 3
   --  Bytes of (p-2), big-endian:
   --    FFFFFFFF 00000001 00000000 00000000
   --    00000000 FFFFFFFF FFFFFFFF FFFFFFFD
   --
   --  Square-and-multiply MSB-first over those 256 bits.
   ---------------------------------------------------------------------

   P_Minus_2 : constant Field :=
     (16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#00#, 16#00#, 16#00#, 16#01#,
      16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
      16#00#, 16#00#, 16#00#, 16#00#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FD#);

   procedure Invert (A : Field; Out_C : out Field) is
      Result : Limbs8 := (others => 0);  --  represents 1
      Base   : Limbs8;
      Tmp    : Limbs8;
      Bit    : Unsigned_8;
      Started : Boolean := False;
   begin
      Result (0) := 1;
      From_Bytes (A, Base);

      --  Walk exponent bits from MSB to LSB. Skip leading zeros
      --  (Started flag) so we don't square the identity 256 times
      --  for nothing — the canonical p-2 has the topmost bit set,
      --  so this just guards against a degenerate exponent and is
      --  free in the common path.
      for Byte_Idx in 1 .. 32 loop
         Bit := Unsigned_8 (P_Minus_2 (Byte_Idx));
         for I in reverse 0 .. 7 loop
            if Started then
               Limb_Square_Mod (Result, Tmp);
               Result := Tmp;
            end if;
            if (Shift_Right (Bit, I) and 1) = 1 then
               if not Started then
                  Result := Base;
                  Started := True;
               else
                  Limb_Mul_Mod (Result, Base, Tmp);
                  Result := Tmp;
               end if;
            end if;
         end loop;
      end loop;

      To_Bytes (Result, Out_C);
   end Invert;

   ---------------------------------------------------------------------
   --  Equal_CT — constant-time field equality.
   ---------------------------------------------------------------------

   function Equal_CT (A, B : Field) return Boolean is
      Diff : Octet := 0;
   begin
      for I in Field'Range loop
         Diff := Diff or (A (I) xor B (I));
      end loop;
      return Diff = 0;
   end Equal_CT;

end Tls_Core.P256_Field;
