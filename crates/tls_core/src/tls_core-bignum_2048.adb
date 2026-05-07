with Interfaces;

package body Tls_Core.Bignum_2048
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use Interfaces;

   ---------------------------------------------------------------------
   --  Internal limb representation.
   --
   --  The 2048-bit value is held as 64 32-bit limbs in little-endian
   --  order: Limbs (0) is the least significant 32-bit word,
   --  Limbs (63) the most significant. The associated unsigned
   --  integer is sum_{i=0..63} Limbs (i) * 2^(32*i).
   ---------------------------------------------------------------------

   N_Limbs : constant := 64;

   subtype Limb_Index   is Natural range 0 .. N_Limbs - 1;
   subtype Limb2_Index  is Natural range 0 .. 2 * N_Limbs - 1;
   subtype Limb_Plus_Index is Natural range 0 .. N_Limbs;
   subtype Limb66_Index is Natural range 0 .. N_Limbs + 1;

   type Limbs64  is array (Limb_Index)      of Unsigned_32;
   type Limbs128 is array (Limb2_Index)     of Unsigned_32;
   type Limbs65  is array (Limb_Plus_Index) of Unsigned_32;
   type Limbs66  is array (Limb66_Index)    of Unsigned_32;

   ---------------------------------------------------------------------
   --  Encoding / decoding between 256 BE bytes and limbs.
   --
   --  Limb i (0 <= i < 64) covers the four bytes whose big-endian
   --  positions are (255 - 4*i - 3) .. (255 - 4*i). Translating the
   --  1-based index: bytes (256 - 4*i - 3) .. (256 - 4*i).
   --  The high byte of the limb is at the lower 1-based index.
   ---------------------------------------------------------------------

   procedure From_Bytes (B : Bigint; L : out Limbs64) is
   begin
      for I in Limb_Index loop
         L (I) :=
             Shift_Left (Unsigned_32 (B (Byte_Length - 4 * I - 3)), 24)
           or Shift_Left (Unsigned_32 (B (Byte_Length - 4 * I - 2)), 16)
           or Shift_Left (Unsigned_32 (B (Byte_Length - 4 * I - 1)),  8)
           or            Unsigned_32 (B (Byte_Length - 4 * I));
      end loop;
   end From_Bytes;

   procedure To_Bytes (L : Limbs64; B : out Bigint) is
   begin
      for I in Limb_Index loop
         B (Byte_Length - 4 * I - 3) :=
           Octet (Shift_Right (L (I), 24) and 16#FF#);
         B (Byte_Length - 4 * I - 2) :=
           Octet (Shift_Right (L (I), 16) and 16#FF#);
         B (Byte_Length - 4 * I - 1) :=
           Octet (Shift_Right (L (I),  8) and 16#FF#);
         B (Byte_Length - 4 * I)     :=
           Octet (L (I) and 16#FF#);
      end loop;
   end To_Bytes;

   ---------------------------------------------------------------------
   --  Comparison: returns +1 if A > B, 0 if equal, -1 if A < B.
   --  Operates on 65-limb values so it can be reused for the
   --  shifted-modulus comparisons inside Reduce.
   ---------------------------------------------------------------------

   function Compare65 (A, B : Limbs65) return Integer is
   begin
      for I in reverse Limb_Plus_Index loop
         if A (I) > B (I) then
            return 1;
         elsif A (I) < B (I) then
            return -1;
         end if;
      end loop;
      return 0;
   end Compare65;

   function Compare64 (A, B : Limbs64) return Integer is
   begin
      for I in reverse Limb_Index loop
         if A (I) > B (I) then
            return 1;
         elsif A (I) < B (I) then
            return -1;
         end if;
      end loop;
      return 0;
   end Compare64;

   function Is_Zero64 (A : Limbs64) return Boolean is
   begin
      for I in Limb_Index loop
         if A (I) /= 0 then
            return False;
         end if;
      end loop;
      return True;
   end Is_Zero64;

   ---------------------------------------------------------------------
   --  Shift a 64-limb value left by one bit, producing a 65-limb
   --  result. Used as the inner operation of the schoolbook reducer.
   ---------------------------------------------------------------------

   procedure Shl1_65 (A : Limbs65; R : out Limbs65) is
      Carry : Unsigned_32 := 0;
      Hi    : Unsigned_32;
   begin
      for I in Limb_Plus_Index loop
         Hi := Shift_Right (A (I), 31) and 1;
         R (I) := Shift_Left (A (I), 1) or Carry;
         Carry := Hi;
      end loop;
   end Shl1_65;

   ---------------------------------------------------------------------
   --  Subtract: R := A - B (65-limb minus 65-limb).
   --  Caller must guarantee A >= B (no borrow out).
   ---------------------------------------------------------------------

   procedure Sub65 (A, B : Limbs65; R : out Limbs65) is
      Borrow : Unsigned_64 := 0;
      Diff   : Unsigned_64;
   begin
      for I in Limb_Plus_Index loop
         Diff :=
             Unsigned_64 (A (I))
           - Unsigned_64 (B (I))
           - Borrow;
         R (I) := Unsigned_32 (Diff and 16#FFFFFFFF#);
         Borrow := Shift_Right (Diff, 63) and 1;
      end loop;
   end Sub65;

   ---------------------------------------------------------------------
   --  Schoolbook 64x64 multiply producing a 128-limb result.
   ---------------------------------------------------------------------

   procedure Mul128 (A, B : Limbs64; T : out Limbs128) is
      Acc   : Unsigned_64;
      Carry : Unsigned_64;
   begin
      for I in Limb2_Index loop
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
         --  I + 64 is in range 64 .. 127 — i.e., always inside Limbs128.
         T (I + N_Limbs) := Unsigned_32 (Carry and 16#FFFFFFFF#);
      end loop;
   end Mul128;

   ---------------------------------------------------------------------
   --  Reduce a 128-limb value modulo a 64-limb non-zero modulus N.
   --
   --  Strategy: schoolbook long division by repeated shift-and-
   --  subtract. Maintain a 65-limb running remainder R, scan the
   --  numerator from MSB toward LSB one bit at a time:
   --     R := (R << 1) | next_bit
   --     if R >= N: R := R - N
   --  After 64*32 = 2048 (top half) + 64*32 (bottom half) = 4096
   --  bit-iterations the running remainder is the residue. We do
   --  this in two passes: first absorb the top 64 limbs (= 2048
   --  bits), then the bottom 64 limbs.
   --
   --  Cost: ~4096 * (shift + compare + maybe-subtract). That's slow
   --  but correct, and SPARK-friendly.
   ---------------------------------------------------------------------

   procedure Reduce (T : Limbs128; N : Limbs64; Out_R : out Limbs64) is
      R         : Limbs65 := (others => 0);
      N65       : Limbs65 := (others => 0);
      Bit       : Unsigned_32;
      Limb_Word : Unsigned_32;
   begin
      --  Promote N into a 65-limb form (limb 64 = 0).
      for I in Limb_Index loop
         N65 (I) := N (I);
      end loop;
      N65 (N_Limbs) := 0;

      --  Walk the numerator MSB-first. Limb index 127 is the highest;
      --  bit 31 of that limb is the absolute MSB of the 4096-bit
      --  numerator.
      for I in reverse Limb2_Index loop
         Limb_Word := T (I);
         for B in reverse 0 .. 31 loop
            Bit := Shift_Right (Limb_Word, B) and 1;
            --  R := (R << 1) | Bit
            declare
               Shifted : Limbs65;
            begin
               Shl1_65 (R, Shifted);
               R := Shifted;
               R (0) := R (0) or Bit;
            end;
            --  If R >= N, subtract N.
            if Compare65 (R, N65) >= 0 then
               declare
                  Diff : Limbs65;
               begin
                  Sub65 (R, N65, Diff);
                  R := Diff;
               end;
            end if;
         end loop;
      end loop;

      --  Result fits in 64 limbs (since R < N < 2^2048, the high
      --  limb of R is zero by induction).
      for I in Limb_Index loop
         Out_R (I) := R (I);
      end loop;
   end Reduce;

   ---------------------------------------------------------------------
   --  Promote a 64-limb value into a 128-limb value.
   ---------------------------------------------------------------------

   procedure Widen (A : Limbs64; T : out Limbs128) is
   begin
      for I in Limb_Index loop
         T (I) := A (I);
      end loop;
      for I in N_Limbs .. 2 * N_Limbs - 1 loop
         T (I) := 0;
      end loop;
   end Widen;

   ---------------------------------------------------------------------
   --  Mod_Mul kernel on limb representation.
   ---------------------------------------------------------------------

   procedure Limb_Mod_Mul
     (A, B, N : Limbs64; R : out Limbs64)
   is
      T : Limbs128;
      A_Red : Limbs64 := A;
      B_Red : Limbs64 := B;
      Tmp   : Limbs128;
   begin
      --  If A or B is already >= N, reduce first. Cheap special-case.
      if Compare64 (A_Red, N) >= 0 then
         Widen (A_Red, Tmp);
         Reduce (Tmp, N, A_Red);
      end if;
      if Compare64 (B_Red, N) >= 0 then
         Widen (B_Red, Tmp);
         Reduce (Tmp, N, B_Red);
      end if;

      Mul128 (A_Red, B_Red, T);
      Reduce (T, N, R);
   end Limb_Mod_Mul;

   ---------------------------------------------------------------------
   --  Montgomery layer.
   --
   --  R = 2^2048. For a modulus N coprime with R (any odd N), we can
   --  do modular arithmetic in "Montgomery form" — represent x as
   --  x_bar = x * R mod N. Multiplications become Mont_Mul:
   --      Mont_Mul (a_bar, b_bar) = a_bar * b_bar * R^-1 mod N
   --                              = (a*b) * R mod N
   --                              = (a*b)_bar.
   --  No expensive bitwise reduction is needed inside Mont_Mul: the
   --  CIOS algorithm interleaves the 64 limb-multiplies with 64
   --  cheap "kill the low limb" reductions.
   ---------------------------------------------------------------------

   --  Newton-Raphson inverse mod 2^32. Five iterations are enough for
   --  any odd input (each iteration doubles the number of correct
   --  bits, starting from 1; after 5 we have at least 32 correct
   --  bits). Returns x such that x * N0 = 1 (mod 2^32).
   function Inverse_Mod_2_32 (N0 : Unsigned_32) return Unsigned_32 is
      X : Unsigned_32 := 1;
   begin
      for K in 1 .. 5 loop
         --  x := x * (2 - N0 * x) mod 2^32
         X := X * (2 - N0 * X);
      end loop;
      return X;
   end Inverse_Mod_2_32;

   --  n0_inv := -N0^-1 mod 2^32, where N0 = N (0).
   function N0_Inv (N : Limbs64) return Unsigned_32 is
      Inv : constant Unsigned_32 := Inverse_Mod_2_32 (N (0));
   begin
      --  Two's complement negation modulo 2^32.
      return (not Inv) + 1;
   end N0_Inv;

   --  Compute R^2 mod N where R = 2^2048. R^2 = 2^4096, which has its
   --  single set bit at position 4096 — i.e., one bit above the top of
   --  the 128-limb (=4096-bit) buffer. We compute it as
   --  (2^2048 mod N)^2 mod N using the existing Reduce path.
   --
   --  Concretely: build T128 = 2^2048 (so T (64) = 1, others = 0),
   --  reduce to get R mod N, then square and reduce again.
   procedure R_Sq_Mod_N (N : Limbs64; Out_R : out Limbs64) is
      T128   : Limbs128 := (others => 0);
      R_Mod  : Limbs64;
      Sq128  : Limbs128;
   begin
      --  T128 represents 2^2048 (one in limb position 64 of a 128-bit
      --  numerator). Reduction by N yields R mod N.
      T128 (N_Limbs) := 1;
      Reduce (T128, N, R_Mod);

      --  Square and reduce again: R^2 mod N.
      Mul128 (R_Mod, R_Mod, Sq128);
      Reduce (Sq128, N, Out_R);
   end R_Sq_Mod_N;

   ---------------------------------------------------------------------
   --  Mont_Mul: CIOS algorithm (Coarsely Integrated Operand Scanning).
   --  Computes R := A * B * R^-1 mod N where R = 2^2048 and
   --  Inv32 = -N (0)^-1 mod 2^32.
   --
   --  Pre: A < N and B < N (both reduced, in Montgomery domain).
   --  Post: R < N.
   ---------------------------------------------------------------------

   procedure Mont_Mul
     (A, B, N : Limbs64;
      Inv32   : Unsigned_32;
      Out_R   : out Limbs64)
   is
      T     : Limbs66 := (others => 0);
      Acc   : Unsigned_64;
      Carry : Unsigned_64;
      M     : Unsigned_32;
   begin
      for I in Limb_Index loop
         --  T := T + A * B (I)
         Carry := 0;
         for J in Limb_Index loop
            Acc :=
                Unsigned_64 (T (J))
              + Unsigned_64 (A (J)) * Unsigned_64 (B (I))
              + Carry;
            T (J) := Unsigned_32 (Acc and 16#FFFFFFFF#);
            Carry := Shift_Right (Acc, 32);
         end loop;
         Acc := Unsigned_64 (T (N_Limbs)) + Carry;
         T (N_Limbs) := Unsigned_32 (Acc and 16#FFFFFFFF#);
         T (N_Limbs + 1) :=
           T (N_Limbs + 1) + Unsigned_32 (Shift_Right (Acc, 32));

         --  m := T (0) * Inv32 mod 2^32. This is the multiplier that
         --  makes T + m*N divisible by 2^32, so T (0) becomes zero
         --  and we can shift right by one limb.
         M := T (0) * Inv32;

         --  T := (T + M * N) / 2^32 (the division is the limb shift).
         Carry := 0;
         --  J = 0: low half of T (0) + M * N (0) + carry. Result's low
         --  half is discarded (it is zero by construction); only the
         --  carry into the next limb matters.
         Acc :=
             Unsigned_64 (T (0))
           + Unsigned_64 (M) * Unsigned_64 (N (0))
           + Carry;
         Carry := Shift_Right (Acc, 32);
         for J in 1 .. N_Limbs - 1 loop
            Acc :=
                Unsigned_64 (T (J))
              + Unsigned_64 (M) * Unsigned_64 (N (J))
              + Carry;
            T (J - 1) := Unsigned_32 (Acc and 16#FFFFFFFF#);
            Carry := Shift_Right (Acc, 32);
         end loop;
         Acc := Unsigned_64 (T (N_Limbs)) + Carry;
         T (N_Limbs - 1) := Unsigned_32 (Acc and 16#FFFFFFFF#);
         Carry := Shift_Right (Acc, 32);
         T (N_Limbs) := T (N_Limbs + 1) + Unsigned_32 (Carry);
         T (N_Limbs + 1) := 0;
      end loop;

      --  T now holds A*B*R^-1 mod N, possibly with one extra N. The
      --  value lives in T (0 .. N_Limbs); the top word (T (N_Limbs))
      --  is at most 1.
      declare
         T64    : Limbs64;
         Top    : constant Unsigned_32 := T (N_Limbs);
         Need_Sub : Boolean;
      begin
         for K in Limb_Index loop
            T64 (K) := T (K);
         end loop;
         Need_Sub := Top /= 0 or else Compare64 (T64, N) >= 0;
         if Need_Sub then
            --  T := T - N (in 64 limbs, ignoring the overflow word).
            declare
               Borrow : Unsigned_64 := 0;
               Diff   : Unsigned_64;
            begin
               for J in Limb_Index loop
                  Diff :=
                      Unsigned_64 (T64 (J))
                    - Unsigned_64 (N (J))
                    - Borrow;
                  T64 (J) := Unsigned_32 (Diff and 16#FFFFFFFF#);
                  Borrow := Shift_Right (Diff, 63) and 1;
               end loop;
               --  Borrow may equal Top (cancellation); we discard it.
               pragma Unreferenced (Borrow);
            end;
         end if;
         Out_R := T64;
      end;
   end Mont_Mul;

   ---------------------------------------------------------------------
   --  Public API
   ---------------------------------------------------------------------

   procedure Mod_Mul (A, B, N : Bigint; Out_R : out Bigint) is
      AL, BL, NL, RL : Limbs64;
   begin
      From_Bytes (A, AL);
      From_Bytes (B, BL);
      From_Bytes (N, NL);
      if Is_Zero64 (NL) then
         --  Degenerate: modulus is zero. Return zero (per ads).
         RL := (others => 0);
      else
         Limb_Mod_Mul (AL, BL, NL, RL);
      end if;
      To_Bytes (RL, Out_R);
   end Mod_Mul;

   ---------------------------------------------------------------------
   --  Mod_Exp: Montgomery square-and-multiply.
   --
   --  Total cost: 1 schoolbook reduction (for R^2 mod N) + ~3072
   --  Mont_Muls (2048 squarings + an average of 1024 multiplies).
   --  Each Mont_Mul is 64*64 + 64*64 mul-add = ~8192 word multiplies,
   --  no bitwise reduction. Net: ~50× faster than the previous
   --  shift-and-subtract Mod_Exp.
   ---------------------------------------------------------------------

   procedure Mod_Exp (Base, Exp, N : Bigint; Out_R : out Bigint) is
      BL, EL, NL : Limbs64;
      Result     : Limbs64 := (others => 0);
      Tmp        : Limbs64;
      Bit        : Unsigned_32;
      Limb_Word  : Unsigned_32;
   begin
      From_Bytes (Base, BL);
      From_Bytes (Exp,  EL);
      From_Bytes (N,    NL);

      --  Edge cases: N = 0 (illegal — return zero per the ads), or
      --  N = 1 (everything is 0 mod 1), or N even (Montgomery needs
      --  gcd(N, R)=1; RSA moduli are odd, but be defensive). For an
      --  even N we have no fast path; return zero rather than risk
      --  a divergent computation. (Callers verify the modulus shape
      --  earlier in the RSA pipeline.)
      if Is_Zero64 (NL) or else (NL (0) and 1) = 0 then
         Result := (others => 0);
         To_Bytes (Result, Out_R);
         return;
      end if;

      --  N = 1 detection: low limb is 1, all others zero.
      declare
         Is_One : Boolean := NL (0) = 1;
      begin
         if Is_One then
            for I in 1 .. N_Limbs - 1 loop
               if NL (I) /= 0 then
                  Is_One := False;
                  exit;
               end if;
            end loop;
         end if;
         if Is_One then
            Result := (others => 0);
            To_Bytes (Result, Out_R);
            return;
         end if;
      end;

      --  Reduce Base mod N so we can convert to Montgomery form
      --  cleanly (Mont_Mul precondition is operands < N).
      if Compare64 (BL, NL) >= 0 then
         declare
            Wide : Limbs128;
         begin
            Widen (BL, Wide);
            Reduce (Wide, NL, BL);
         end;
      end if;

      declare
         Inv32   : constant Unsigned_32 := N0_Inv (NL);
         R2      : Limbs64;
         One_L   : Limbs64 := (others => 0);
         Base_M  : Limbs64;
         Result_M : Limbs64;
      begin
         One_L (0) := 1;

         --  R^2 mod N — sole remaining slow step (one schoolbook
         --  reduction per Mod_Exp call).
         R_Sq_Mod_N (NL, R2);

         --  Convert Base to Montgomery form: Base_M = Base * R mod N
         --  = Mont_Mul (Base, R^2).
         Mont_Mul (BL, R2, NL, Inv32, Base_M);

         --  Montgomery form of 1: 1_M = R mod N = Mont_Mul (1, R^2).
         Mont_Mul (One_L, R2, NL, Inv32, Result_M);

         --  Square-and-multiply, MSB-first scan of Exp. We always
         --  start from MontForm(1) and square+conditionally-multiply
         --  for every bit (no "Started" optimisation needed: squaring
         --  MontForm(1) is still MontForm(1)).
         for I in reverse Limb_Index loop
            Limb_Word := EL (I);
            for B in reverse 0 .. 31 loop
               Bit := Shift_Right (Limb_Word, B) and 1;
               Mont_Mul (Result_M, Result_M, NL, Inv32, Tmp);
               Result_M := Tmp;
               if Bit = 1 then
                  Mont_Mul (Result_M, Base_M, NL, Inv32, Tmp);
                  Result_M := Tmp;
               end if;
            end loop;
         end loop;

         --  Convert out of Montgomery form: x = Mont_Mul (x_M, 1).
         Mont_Mul (Result_M, One_L, NL, Inv32, Result);
      end;

      To_Bytes (Result, Out_R);
   end Mod_Exp;

   ---------------------------------------------------------------------
   --  Equal_CT — fixed-loop, OR-accumulator compare. No early exit.
   ---------------------------------------------------------------------

   function Equal_CT (A, B : Bigint) return Boolean is
      Diff : Octet := 0;
   begin
      for I in Bigint'Range loop
         Diff := Diff or (A (I) xor B (I));
      end loop;
      return Diff = 0;
   end Equal_CT;

end Tls_Core.Bignum_2048;
