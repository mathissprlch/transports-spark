pragma Warnings (Off, "redundant with clause in body");
with Interfaces;
pragma Warnings (On, "redundant with clause in body");

with Tls_Core.Ghost_Bignum;
with Tls_Core.Ghost_Bignum.Value;

package body Tls_Core.Bignum_2048
  with SPARK_Mode
is

   use Interfaces;

   package GB renames Tls_Core.Ghost_Bignum;
   package GBV renames Tls_Core.Ghost_Bignum.Value;

   ---------------------------------------------------------------------
   --  Ghost spec layer bodies. Real, computable Big_Integer arithmetic
   --  (docs/conventions.md §0d B3: no `return False` / placeholder bodies).
   --
   --  `Byte_Big` and `Pow_2_8` are simple lifters. `Spec_Mod_Exp` is
   --  the canonical recursive square-and-multiply on Big_Integer: it
   --  IS the spec of what Mod_Exp should compute, expressed as
   --  Big_Integer code that gnatprove can step through.
   ---------------------------------------------------------------------

   package Octet_Bigint is new Big.Signed_Conversions (Int => Integer);

   function Byte_Big (X : Octet) return Big.Big_Integer is
   begin
      return Octet_Bigint.To_Big_Integer (Integer (X));
   end Byte_Big;

   function Pow_2_8 (N : Natural) return Big.Big_Integer is
   begin
      return Big.To_Big_Integer (2)**(8 * N);
   end Pow_2_8;

   --  Square-and-multiply on Big_Integer. Mirror of HACL\*'s `pow_mod`
   --  in `Lib.NatMod.fst`:
   --      val pow #t : a:t -> b:nat -> Tot t (decreases b)
   --      let rec pow #t a b =
   --        if b = 0 then one
   --        else mul a (pow a (b - 1))
   --  We then take the result mod N at the top level. The recursion
   --  on Exp is well-founded (decreasing nat), and the body is purely
   --  a Big_Integer computation — no representation hooks.
   function Spec_Mod_Exp
     (Base, Exp, N : Big.Big_Integer) return Big.Big_Integer
   is
      One    : constant Big.Big_Integer := Big.To_Big_Integer (1);
      Two    : constant Big.Big_Integer := Big.To_Big_Integer (2);
      Zero_B : constant Big.Big_Integer := Big.To_Big_Integer (0);
      Result : Big.Big_Integer := One;
      B      : Big.Big_Integer;
      E      : Big.Big_Integer := Exp;
   begin
      --  Spec degenerate cases mirror the imperative ads:
      if N <= One then
         return Zero_B;
      end if;
      if N mod Two = Zero_B then
         return Zero_B;
      end if;
      B := Base mod N;
      --  Iterative square-and-multiply, LSB-first. Equivalent to
      --  HACL\*'s `pow` viewed through binary expansion of Exp.
      while E > Zero_B loop
         pragma Loop_Invariant (Result >= Zero_B and then Result < N);
         pragma Loop_Invariant (B >= Zero_B and then B < N);
         pragma Loop_Variant (Decreases => E);
         if E mod Two = One then
            Result := (Result * B) mod N;
         end if;
         E := E / Two;
         B := (B * B) mod N;
      end loop;
      return Result;
   end Spec_Mod_Exp;

   --  HACL\*'s `nat_to_bytes_be 256`. Walks 256 bytes high-to-low,
   --  extracting (X / 2^(8*(255-i))) mod 256 into Bigint(i+1).
   --  Real, computable body — uses Big_Integer mod / div arithmetic.
   function Big_To_Bigint (X : Big.Big_Integer) return Bigint is
      --  Init suppresses an "initialization has no effect" gnat
      --  warning; flow analysis still needs the unconditional write.
      Result   : Bigint := [others => 0];
      Base_256 : constant Big.Big_Integer := Big.To_Big_Integer (256);
      Acc      : Big.Big_Integer := X;
      package Octet_Big is new Big.Signed_Conversions (Int => Integer);
   begin
      --  LSB-first extraction: Bigint (256), Bigint (255), ... Bigint (1).
      for K in reverse 1 .. Byte_Length loop
         pragma Loop_Invariant (Acc >= Big.To_Big_Integer (0));
         --  Byte_Big_Val (in [0, 256) by definition of mod with positive
         --  divisor) reduced to Integer for the conversion to Octet.
         Result (K) := Octet (Octet_Big.From_Big_Integer (Acc mod Base_256));
         Acc := Acc / Base_256;
      end loop;
      return Result;
   end Big_To_Bigint;

   procedure Lemma_Bigint_Roundtrip (B : Bigint) is
   begin
      --  Inductive over Byte_Length steps: each iteration of
      --  Big_To_Bigint extracts the byte that Bn_V would have weighted
      --  by 2^(8*k) at index Byte_Length - k. The detailed lemma is
      --  out of scope for this session (multi-day inductive proof);
      --  the procedure body is empty so the Post is left as honest
      --  unproven (docs/conventions.md §0d A1) — B4 clean (no
      --  pragma Assume, no annotation).
      null;
   end Lemma_Bigint_Roundtrip;

   ---------------------------------------------------------------------
   --  Internal limb representation.
   --
   --  The 2048-bit value is held as 64 32-bit limbs in little-endian
   --  order: Limbs (0) is the least significant 32-bit word,
   --  Limbs (63) the most significant. The associated unsigned
   --  integer is sum_{i=0..63} Limbs (i) * 2^(32*i).
   ---------------------------------------------------------------------

   N_Limbs : constant := 64;

   subtype Limb_Index is Natural range 0 .. N_Limbs - 1;
   subtype Limb2_Index is Natural range 0 .. 2 * N_Limbs - 1;
   subtype Limb_Plus_Index is Natural range 0 .. N_Limbs;
   subtype Limb2_Plus_Index is Natural range 0 .. 2 * N_Limbs;
   subtype Limb66_Index is Natural range 0 .. N_Limbs + 1;
   subtype Limb66_Plus_Index is Natural range 0 .. N_Limbs + 2;

   type Limbs64 is array (Limb_Index) of Unsigned_32;
   type Limbs128 is array (Limb2_Index) of Unsigned_32;
   type Limbs65 is array (Limb_Plus_Index) of Unsigned_32;
   type Limbs66 is array (Limb66_Index) of Unsigned_32;

   ---------------------------------------------------------------------
   --  §0e value bridge (ghost). Maps the little-endian 32-bit limb arrays
   --  to their integer value WITHOUT the opaque To_Big_Integer: each limb
   --  enters through Tls_Core.Ghost_Bignum.Value's unit-recursion ingress
   --  (Limb_Val), whose +/-/* algebra is provable. A 32-bit limb (< 2**32)
   --  sits well inside Val_Cap (2**110); the 2**(32*K) positional weights
   --  are built by native Big_Integer multiplication (P32). This is the
   --  base-2**32 analogue of Ghost_Bignum.Value's base-2**26 Horner Val.
   ---------------------------------------------------------------------

   --  2**32 as a Big_Integer, via the §0e-clean ingress.
   Base32 : constant Big.Big_Integer := GBV.Limb_Val (2**32)
   with Ghost;

   --  2**(32*K).
   function P32 (K : Natural) return Big.Big_Integer
   is (if K = 0 then GBV.Limb_Val (1) else P32 (K - 1) * Base32)
   with Ghost, Subprogram_Variant => (Decreases => K);

   --  Value of the low K limbs (little-endian) of a 64-limb array.
   function LV64 (L : Limbs64; K : Limb_Plus_Index) return Big.Big_Integer
   is (if K = 0
       then GBV.Limb_Val (0)
       else LV64 (L, K - 1) + GBV.Limb_Val (GB.LLI (L (K - 1))) * P32 (K - 1))
   with Ghost, Subprogram_Variant => (Decreases => K);

   --  P32 (K) is strictly positive (a positive power of two).
   procedure Lemma_P32_Pos (K : Natural)
   with Ghost, Post => P32 (K) > 0, Subprogram_Variant => (Decreases => K);

   procedure Lemma_P32_Pos (K : Natural) is
   begin
      if K = 0 then
         GBV.Lemma_Limb_Val_Succ
           (0);   --  Limb_Val (1) = Limb_Val (0) + 1 = 1.

      else
         Lemma_P32_Pos (K - 1);                      --  P32 (K-1) > 0.
         GBV.Lemma_Limb_Val_Nonneg
           (2**32 - 1);      --  Limb_Val (2^32-1) >= 0.
         GBV.Lemma_Limb_Val_Succ
           (2**32 - 1);        --  Base32 = that + 1 >= 1.
      end if;
   end Lemma_P32_Pos;

   --  The limb valuation is non-negative.
   procedure Lemma_LV64_Nonneg (L : Limbs64; K : Limb_Plus_Index)
   with
     Ghost,
     Post               => LV64 (L, K) >= 0,
     Subprogram_Variant => (Decreases => K);

   procedure Lemma_LV64_Nonneg (L : Limbs64; K : Limb_Plus_Index) is
   begin
      if K = 0 then
         null;   --  LV64 (L, 0) = Limb_Val (0) = 0.

      else
         Lemma_LV64_Nonneg (L, K - 1);                       --  tail >= 0.
         GBV.Lemma_Limb_Val_Nonneg (GB.LLI (L (K - 1)));     --  limb >= 0.
         Lemma_P32_Pos (K - 1);                              --  weight > 0.
      end if;
   end Lemma_LV64_Nonneg;

   --  The low-K limb value is below the K-limb radix: LV64 (L, K) < 2**(32*K).
   procedure Lemma_LV64_Upper (L : Limbs64; K : Limb_Plus_Index)
   with
     Ghost,
     Post               => LV64 (L, K) < P32 (K),
     Subprogram_Variant => (Decreases => K);

   procedure Lemma_LV64_Upper (L : Limbs64; K : Limb_Plus_Index) is
   begin
      if K = 0 then
         GBV.Lemma_Limb_Val_Succ (0);   --  P32 (0) = Limb_Val (1) = 1 > 0.

      else
         declare
            W : constant Big.Big_Integer := P32 (K - 1)
            with Ghost;
            V : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (L (K - 1)))
            with Ghost;
         begin
            Lemma_LV64_Upper (L, K - 1);             --  LV64 (L, K-1) < W.
            Lemma_P32_Pos (K - 1);                   --  W > 0.
            GBV.Lemma_Limb_Val_Nonneg (GB.LLI (L (K - 1)));   --  V >= 0.
            --  V <= Limb_Val (2^32-1) = Base32 - 1 (top limb value).
            GBV.Lemma_Limb_Val_Mono (GB.LLI (L (K - 1)), 2**32 - 1);
            GBV.Lemma_Limb_Val_Succ (2**32 - 1);     --  Base32 = that + 1.
            pragma Assert (V <= Base32 - 1);
            --  Monotone multiply by the positive weight, then assemble.
            pragma Assert (V * W <= (Base32 - 1) * W);
            pragma Assert (P32 (K) = W * Base32);
            pragma Assert ((Base32 - 1) * W + W = W * Base32);
         end;
      end if;
   end Lemma_LV64_Upper;

   --  Value of the low K limbs (little-endian) of a 65-limb array -- the
   --  running remainder width used by the schoolbook Reduce. Same base-2**32
   --  Horner form as LV64; K ranges up to N_Limbs + 1 (all 65 limbs).
   function LV65 (L : Limbs65; K : Limb66_Index) return Big.Big_Integer
   is (if K = 0
       then GBV.Limb_Val (0)
       else LV65 (L, K - 1) + GBV.Limb_Val (GB.LLI (L (K - 1))) * P32 (K - 1))
   with Ghost, Subprogram_Variant => (Decreases => K);

   --  The 65-limb valuation is non-negative.
   procedure Lemma_LV65_Nonneg (L : Limbs65; K : Limb66_Index)
   with
     Ghost,
     Post               => LV65 (L, K) >= 0,
     Subprogram_Variant => (Decreases => K);

   procedure Lemma_LV65_Nonneg (L : Limbs65; K : Limb66_Index) is
   begin
      if K = 0 then
         null;
      else
         Lemma_LV65_Nonneg (L, K - 1);
         GBV.Lemma_Limb_Val_Nonneg (GB.LLI (L (K - 1)));
         Lemma_P32_Pos (K - 1);
      end if;
   end Lemma_LV65_Nonneg;

   --  LV65 (L, K) < 2**(32*K).
   procedure Lemma_LV65_Upper (L : Limbs65; K : Limb66_Index)
   with
     Ghost,
     Post               => LV65 (L, K) < P32 (K),
     Subprogram_Variant => (Decreases => K);

   procedure Lemma_LV65_Upper (L : Limbs65; K : Limb66_Index) is
   begin
      if K = 0 then
         GBV.Lemma_Limb_Val_Succ (0);
      else
         declare
            W : constant Big.Big_Integer := P32 (K - 1)
            with Ghost;
            V : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (L (K - 1)))
            with Ghost;
         begin
            Lemma_LV65_Upper (L, K - 1);
            Lemma_P32_Pos (K - 1);
            GBV.Lemma_Limb_Val_Nonneg (GB.LLI (L (K - 1)));
            GBV.Lemma_Limb_Val_Mono (GB.LLI (L (K - 1)), 2**32 - 1);
            GBV.Lemma_Limb_Val_Succ (2**32 - 1);
            pragma Assert (V <= Base32 - 1);
            pragma Assert (V * W <= (Base32 - 1) * W);
            pragma Assert (P32 (K) = W * Base32);
            pragma Assert ((Base32 - 1) * W + W = W * Base32);
         end;
      end if;
   end Lemma_LV65_Upper;

   --  Definitional one-step unfold of LV65 (gnatprove stalls at symbolic K+1).
   procedure Lemma_LV65_Unfold (L : Limbs65; K : Limb66_Index)
   with
     Ghost,
     Pre  => K >= 1,
     Post =>
       LV65 (L, K)
       = LV65 (L, K - 1) + GBV.Limb_Val (GB.LLI (L (K - 1))) * P32 (K - 1);

   procedure Lemma_LV65_Unfold (L : Limbs65; K : Limb66_Index) is
   begin
      null;
   end Lemma_LV65_Unfold;

   --  High-part equality: if A and B agree on every limb at or above K, their
   --  valuations differ only in the low K limbs.
   procedure Lemma_LV65_Hi_Eq (A, B : Limbs65; K : Limb66_Index)
   with
     Ghost,
     Pre                =>
       (for all I in Limb_Plus_Index => (if I >= K then A (I) = B (I))),
     Post               =>
       LV65 (A, N_Limbs + 1) - LV65 (A, K)
       = LV65 (B, N_Limbs + 1) - LV65 (B, K),
     Subprogram_Variant => (Decreases => N_Limbs + 1 - K);

   procedure Lemma_LV65_Hi_Eq (A, B : Limbs65; K : Limb66_Index) is
   begin
      if K <= N_Limbs then
         Lemma_LV65_Hi_Eq (A, B, K + 1);
         Lemma_LV65_Unfold (A, K + 1);
         Lemma_LV65_Unfold (B, K + 1);
      end if;
   end Lemma_LV65_Hi_Eq;

   --  Lexicographic dominance: at the most-significant differing limb I (all
   --  higher limbs equal), the limb-I order decides the value order.
   procedure Lemma_LV65_Cmp_Limb (A, B : Limbs65; I : Limb_Plus_Index)
   with
     Ghost,
     Pre  => (for all K in Limb_Plus_Index => (if K > I then A (K) = B (K))),
     Post =>
       (if A (I) > B (I) then LV65 (A, N_Limbs + 1) > LV65 (B, N_Limbs + 1))
       and then (if A (I) < B (I)
                 then LV65 (A, N_Limbs + 1) < LV65 (B, N_Limbs + 1));

   procedure Lemma_LV65_Cmp_Limb (A, B : Limbs65; I : Limb_Plus_Index) is
      AvI : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (A (I)))
      with Ghost;
      BvI : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (B (I)))
      with Ghost;
      W   : constant Big.Big_Integer := P32 (I)
      with Ghost;
   begin
      Lemma_LV65_Hi_Eq (A, B, I + 1);
      Lemma_LV65_Unfold (A, I + 1);
      Lemma_LV65_Unfold (B, I + 1);
      Lemma_LV65_Nonneg (A, I);
      Lemma_LV65_Nonneg (B, I);
      Lemma_LV65_Upper (A, I);
      Lemma_LV65_Upper (B, I);
      Lemma_P32_Pos (I);
      --  LV65(A,65) - LV65(B,65) = (LV65(A,I) - LV65(B,I)) + (AvI - BvI) * W.
      pragma
        Assert
          (LV65 (A, N_Limbs + 1) - LV65 (B, N_Limbs + 1)
             = (LV65 (A, I) - LV65 (B, I)) + (AvI - BvI) * W);
      if A (I) > B (I) then
         GBV.Lemma_Limb_Val_Mono (GB.LLI (B (I)) + 1, GB.LLI (A (I)));
         GBV.Lemma_Limb_Val_Succ (GB.LLI (B (I)));
         pragma Assert (AvI >= BvI + 1);
         pragma Assert ((AvI - BvI) * W >= W);
      elsif A (I) < B (I) then
         GBV.Lemma_Limb_Val_Mono (GB.LLI (A (I)) + 1, GB.LLI (B (I)));
         GBV.Lemma_Limb_Val_Succ (GB.LLI (A (I)));
         pragma Assert (BvI >= AvI + 1);
         pragma Assert ((BvI - AvI) * W >= W);
      end if;
   end Lemma_LV65_Cmp_Limb;

   --  Value of the low K limbs (little-endian) of a 128-limb array -- the
   --  product/accumulator width. Same base-2**32 Horner form as LV64.
   function LV128 (T : Limbs128; K : Limb2_Plus_Index) return Big.Big_Integer
   is (if K = 0
       then GBV.Limb_Val (0)
       else LV128 (T, K - 1) + GBV.Limb_Val (GB.LLI (T (K - 1))) * P32 (K - 1))
   with Ghost, Subprogram_Variant => (Decreases => K);

   procedure Lemma_LV128_Nonneg (T : Limbs128; K : Limb2_Plus_Index)
   with
     Ghost,
     Post               => LV128 (T, K) >= 0,
     Subprogram_Variant => (Decreases => K);

   procedure Lemma_LV128_Nonneg (T : Limbs128; K : Limb2_Plus_Index) is
   begin
      if K = 0 then
         null;
      else
         Lemma_LV128_Nonneg (T, K - 1);
         GBV.Lemma_Limb_Val_Nonneg (GB.LLI (T (K - 1)));
         Lemma_P32_Pos (K - 1);
      end if;
   end Lemma_LV128_Nonneg;

   procedure Lemma_LV128_Upper (T : Limbs128; K : Limb2_Plus_Index)
   with
     Ghost,
     Post               => LV128 (T, K) < P32 (K),
     Subprogram_Variant => (Decreases => K);

   procedure Lemma_LV128_Upper (T : Limbs128; K : Limb2_Plus_Index) is
   begin
      if K = 0 then
         GBV.Lemma_Limb_Val_Succ (0);
      else
         declare
            W : constant Big.Big_Integer := P32 (K - 1)
            with Ghost;
            V : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (T (K - 1)))
            with Ghost;
         begin
            Lemma_LV128_Upper (T, K - 1);
            Lemma_P32_Pos (K - 1);
            GBV.Lemma_Limb_Val_Nonneg (GB.LLI (T (K - 1)));
            GBV.Lemma_Limb_Val_Mono (GB.LLI (T (K - 1)), 2**32 - 1);
            GBV.Lemma_Limb_Val_Succ (2**32 - 1);
            pragma Assert (V <= Base32 - 1);
            pragma Assert (V * W <= (Base32 - 1) * W);
            pragma Assert (P32 (K) = W * Base32);
            pragma Assert ((Base32 - 1) * W + W = W * Base32);
         end;
      end if;
   end Lemma_LV128_Upper;

   --  Frame: LV128 (T, K) reads only limbs 0 .. K-1.
   procedure Lemma_LV128_Frame (T1, T2 : Limbs128; K : Limb2_Plus_Index)
   with
     Ghost,
     Pre                =>
       (for all I in Limb2_Index => (if I < K then T1 (I) = T2 (I))),
     Post               => LV128 (T1, K) = LV128 (T2, K),
     Subprogram_Variant => (Decreases => K);

   procedure Lemma_LV128_Frame (T1, T2 : Limbs128; K : Limb2_Plus_Index) is
   begin
      if K /= 0 then
         Lemma_LV128_Frame (T1, T2, K - 1);
      end if;
   end Lemma_LV128_Frame;

   --  Definitional one-step unfold (gnatprove stalls unfolding LV128 at a
   --  symbolic index like I+J+1 inside a heavy VC).
   procedure Lemma_LV128_Unfold (T : Limbs128; K : Limb2_Plus_Index)
   with
     Ghost,
     Pre  => K >= 1,
     Post =>
       LV128 (T, K)
       = LV128 (T, K - 1) + GBV.Limb_Val (GB.LLI (T (K - 1))) * P32 (K - 1);

   procedure Lemma_LV128_Unfold (T : Limbs128; K : Limb2_Plus_Index) is
   begin
      null;
   end Lemma_LV128_Unfold;

   --  An all-zero prefix has zero valuation (Mul128 outer accumulation base
   --  case: T starts all-zero so LV128 (T, .) = 0).
   procedure Lemma_LV128_Zero (T : Limbs128; K : Limb2_Plus_Index)
   with
     Ghost,
     Pre                =>
       (for all I in Limb2_Index => (if I < K then T (I) = 0)),
     Post               => LV128 (T, K) = 0,
     Subprogram_Variant => (Decreases => K);

   procedure Lemma_LV128_Zero (T : Limbs128; K : Limb2_Plus_Index) is
   begin
      if K /= 0 then
         Lemma_LV128_Zero (T, K - 1);
      end if;
   end Lemma_LV128_Zero;

   --  One-step P32 successor: P32 (K+1) = P32 (K) * Base32.
   procedure Lemma_P32_Succ (K : Natural)
   with Ghost, Pre => K <= 2 * N_Limbs, Post => P32 (K + 1) = P32 (K) * Base32;

   procedure Lemma_P32_Succ (K : Natural) is
   begin
      null;
   end Lemma_P32_Succ;

   --  Power additivity: 2**(32*(A+B)) = 2**(32*A) * 2**(32*B). Body below (uses
   --  the BI ring lemmas, which are declared later in this body).
   procedure Lemma_P32_Add (A, B : Natural)
   with
     Ghost,
     Pre                => A <= 2 * N_Limbs and then B <= 2 * N_Limbs,
     Post               => P32 (A + B) = P32 (A) * P32 (B),
     Subprogram_Variant => (Decreases => B);

   --  Mul128 inner-loop convolution preservation (bn_mul1 at offset I), proved
   --  in a clean context (only its Pre as hypotheses). Spec here so the early
   --  Mul128 can call it; body below, after the shared ring/convolution toolkit.
   --  Writing T (I+J) := low (T_Inner (I+J) + A(I)*B(J) + C_Old), carry-out
   --  Carry, advances the running product by A(I)*B(J)*2**(32*(I+J)).
   procedure Lemma_Mul128_Preserve
     (T_Pre, T_After, T_Inner : Limbs128;
      A, B                    : Limbs64;
      I, J                    : Limb_Index;
      C_Old, Acc, Carry       : Unsigned_64)
   with
     Ghost,
     Pre  =>
       C_Old <= 16#FFFF_FFFF#
       and then Acc
                = Unsigned_64 (T_Pre (I + J))
                  + Unsigned_64 (A (I)) * Unsigned_64 (B (J))
                  + C_Old
       and then Carry = Shift_Right (Acc, 32)
       and then T_After (I + J) = Unsigned_32 (Acc and 16#FFFF_FFFF#)
       and then (for all K in Limb2_Index =>
                   (if K /= I + J then T_After (K) = T_Pre (K)))
       and then T_Pre (I + J) = T_Inner (I + J)
       and then LV128 (T_Pre, I + J)
                + GBV.Limb_Val (GB.LLI (C_Old)) * P32 (I + J)
                = LV128 (T_Inner, I + J)
                  + (P32 (I) * LV64 (B, J)) * GBV.Limb_Val (GB.LLI (A (I))),
     Post =>
       LV128 (T_After, I + J + 1)
       + GBV.Limb_Val (GB.LLI (Carry)) * P32 (I + J + 1)
       = LV128 (T_Inner, I + J + 1)
         + (P32 (I) * LV64 (B, J + 1)) * GBV.Limb_Val (GB.LLI (A (I)));

   --  Mul128 OUTER accumulation step, clean context. Given the inner-loop exit
   --  (active prefix at J = N_Limbs) on T_AI plus the running accumulation
   --  invariant on T_Inner, the final carry write (T_AI -> T_Final, limb
   --  I+N_Limbs := Carry) advances the product by one A limb. Spec here so the
   --  early Mul128 can call it; body below, after the toolkit.
   procedure Lemma_Mul128_Outer
     (T_Inner, T_AI, T_Final : Limbs128;
      A, B                   : Limbs64;
      I                      : Limb_Index;
      Carry                  : Unsigned_64)
   with
     Ghost,
     Pre  =>
       Carry <= 16#FFFF_FFFF#
       and then LV128 (T_AI, I + N_Limbs)
                + GBV.Limb_Val (GB.LLI (Carry)) * P32 (I + N_Limbs)
                = LV128 (T_Inner, I + N_Limbs)
                  + (P32 (I) * LV64 (B, N_Limbs))
                    * GBV.Limb_Val (GB.LLI (A (I)))
       and then LV128 (T_Inner, I + N_Limbs) = LV64 (A, I) * LV64 (B, N_Limbs)
       and then T_Final (I + N_Limbs) = Unsigned_32 (Carry and 16#FFFF_FFFF#)
       and then (for all K in Limb2_Index =>
                   (if K /= I + N_Limbs then T_Final (K) = T_AI (K))),
     Post =>
       LV128 (T_Final, I + N_Limbs + 1) = LV64 (A, I + 1) * LV64 (B, N_Limbs);

   --  Value of the low K limbs of a 66-limb array -- the CIOS Mont_Mul
   --  accumulator width (64 + 2 carry words). Same base-2**32 Horner form.
   function LV66 (T : Limbs66; K : Limb66_Plus_Index) return Big.Big_Integer
   is (if K = 0
       then GBV.Limb_Val (0)
       else LV66 (T, K - 1) + GBV.Limb_Val (GB.LLI (T (K - 1))) * P32 (K - 1))
   with Ghost, Subprogram_Variant => (Decreases => K);

   procedure Lemma_LV66_Nonneg (T : Limbs66; K : Limb66_Plus_Index)
   with
     Ghost,
     Post               => LV66 (T, K) >= 0,
     Subprogram_Variant => (Decreases => K);

   procedure Lemma_LV66_Nonneg (T : Limbs66; K : Limb66_Plus_Index) is
   begin
      if K = 0 then
         null;
      else
         Lemma_LV66_Nonneg (T, K - 1);
         GBV.Lemma_Limb_Val_Nonneg (GB.LLI (T (K - 1)));
         Lemma_P32_Pos (K - 1);
      end if;
   end Lemma_LV66_Nonneg;

   procedure Lemma_LV66_Upper (T : Limbs66; K : Limb66_Plus_Index)
   with
     Ghost,
     Post               => LV66 (T, K) < P32 (K),
     Subprogram_Variant => (Decreases => K);

   procedure Lemma_LV66_Upper (T : Limbs66; K : Limb66_Plus_Index) is
   begin
      if K = 0 then
         GBV.Lemma_Limb_Val_Succ (0);
      else
         declare
            W : constant Big.Big_Integer := P32 (K - 1)
            with Ghost;
            V : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (T (K - 1)))
            with Ghost;
         begin
            Lemma_LV66_Upper (T, K - 1);
            Lemma_P32_Pos (K - 1);
            GBV.Lemma_Limb_Val_Nonneg (GB.LLI (T (K - 1)));
            GBV.Lemma_Limb_Val_Mono (GB.LLI (T (K - 1)), 2**32 - 1);
            GBV.Lemma_Limb_Val_Succ (2**32 - 1);
            pragma Assert (V <= Base32 - 1);
            pragma Assert (V * W <= (Base32 - 1) * W);
            pragma Assert (P32 (K) = W * Base32);
            pragma Assert ((Base32 - 1) * W + W = W * Base32);
         end;
      end if;
   end Lemma_LV66_Upper;

   --  An all-zero prefix has zero valuation (the outer Montgomery invariant's
   --  I = 0 base case: T starts all-zero so LV66 (T, .) = 0).
   procedure Lemma_LV66_Zero (T : Limbs66; K : Limb66_Plus_Index)
   with
     Ghost,
     Pre                =>
       (for all I in Limb66_Index => (if I < K then T (I) = 0)),
     Post               => LV66 (T, K) = 0,
     Subprogram_Variant => (Decreases => K);

   procedure Lemma_LV66_Zero (T : Limbs66; K : Limb66_Plus_Index) is
   begin
      if K /= 0 then
         Lemma_LV66_Zero (T, K - 1);
      end if;
   end Lemma_LV66_Zero;

   ---------------------------------------------------------------------
   --  Big_Integer ring helpers. The value layer (GBV.Limb_Val images) is the
   --  mathematical integers, so these are pure polynomial identities; the
   --  nonlinear solver discharges the null bodies. Distinct from the
   --  Unsigned_32 (mod 2**32) helpers Lemma_Mul3 / Lemma_Mul_Comm below.
   ---------------------------------------------------------------------

   procedure Lemma_BI_Assoc (A, B, C : Big.Big_Integer)
   with Ghost, Post => A * (B * C) = (A * B) * C;

   procedure Lemma_BI_Assoc (A, B, C : Big.Big_Integer) is
   begin
      null;
   end Lemma_BI_Assoc;

   procedure Lemma_BI_Comm (A, B : Big.Big_Integer)
   with Ghost, Post => A * B = B * A;

   procedure Lemma_BI_Comm (A, B : Big.Big_Integer) is
   begin
      null;
   end Lemma_BI_Comm;

   procedure Lemma_BI_Distrib (A, B, C : Big.Big_Integer)
   with Ghost, Post => A * (B + C) = A * B + A * C;

   procedure Lemma_BI_Distrib (A, B, C : Big.Big_Integer) is
   begin
      null;
   end Lemma_BI_Distrib;

   ---------------------------------------------------------------------
   --  Horner low-split of the 66-limb valuation. The Montgomery reduce step
   --  kills the bottom limb and shifts the array down one place (a divide by
   --  2**32). Shift1 is that down-shift; Lemma_LV66_Low_Split is its value
   --  meaning: LV66 (T, K) = Limb_Val (T (0)) + Base32 * LV66 (Shift1 (T), K-1).
   --  At K = N_Limbs + 2 with T (0) killed, this gives the exact /2**32.
   ---------------------------------------------------------------------

   --  One-limb down-shift: Shift1 (T)(j) = T (j+1), zero in the vacated top.
   function Shift1 (T : Limbs66) return Limbs66
   is ([for J in Limb66_Index => (if J < N_Limbs + 1 then T (J + 1) else 0)])
   with Ghost;

   procedure Lemma_LV66_Low_Split (T : Limbs66; K : Limb66_Plus_Index)
   with
     Ghost,
     Pre                => K >= 1,
     Post               =>
       LV66 (T, K)
       = GBV.Limb_Val (GB.LLI (T (0))) + Base32 * LV66 (Shift1 (T), K - 1),
     Subprogram_Variant => (Decreases => K);

   procedure Lemma_LV66_Low_Split (T : Limbs66; K : Limb66_Plus_Index) is
   begin
      if K = 1 then
         GBV.Lemma_Limb_Val_Succ (0);   --  P32 (0) = Limb_Val (1) = 1.

      else
         declare
            S  : constant Limbs66 := Shift1 (T)
            with Ghost;
            X  : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (T (K - 1)))
            with Ghost;
            W  : constant Big.Big_Integer := P32 (K - 2)
            with Ghost;
            L2 : constant Big.Big_Integer := LV66 (S, K - 2)
            with Ghost;
         begin
            Lemma_LV66_Low_Split (T, K - 1);              --  IH.
            --  Top unfold of the LHS: LV66 (T, K) = LV66 (T, K-1) + X*P32(K-1).
            pragma Assert (LV66 (T, K) = LV66 (T, K - 1) + X * P32 (K - 1));
            --  IH, restated in S / L2 terms (Shift1 (T) = S, LV66 (S,K-2)=L2).
            pragma
              Assert
                (LV66 (T, K - 1)
                   = GBV.Limb_Val (GB.LLI (T (0))) + Base32 * L2);
            pragma Assert (S (K - 2) = T (K - 1));        --  shift index.
            pragma Assert (LV66 (S, K - 1) = L2 + X * W); --  LV66 def at S.
            pragma Assert (P32 (K - 1) = W * Base32);     --  P32 def.
            Lemma_BI_Assoc (X, W, Base32);                --  X*(W*B)=(X*W)*B.
            Lemma_BI_Comm (X * W, Base32);                --  (X*W)*B=B*(X*W).
            pragma Assert (X * P32 (K - 1) = Base32 * (X * W));
            Lemma_BI_Distrib (Base32, L2, X * W);         --  B*(L2+X*W).
            pragma
              Assert
                (Base32 * LV66 (S, K - 1) = Base32 * L2 + Base32 * (X * W));
            --  Assemble the Post (S = Shift1 (T)).
            pragma
              Assert
                (LV66 (T, K)
                   = GBV.Limb_Val (GB.LLI (T (0))) + Base32 * LV66 (S, K - 1));
         end;
      end if;
   end Lemma_LV66_Low_Split;

   ---------------------------------------------------------------------
   --  Encoding / decoding between 256 BE bytes and limbs.
   --
   --  Limb i (0 <= i < 64) covers the four bytes whose big-endian
   --  positions are (255 - 4*i - 3) .. (255 - 4*i). Translating the
   --  1-based index: bytes (256 - 4*i - 3) .. (256 - 4*i).
   --  The high byte of the limb is at the lower 1-based index.
   ---------------------------------------------------------------------

   --  Arithmetic value of limb I from its four big-endian bytes (each < 256,
   --  so the weighted sum is exact in Unsigned_32 -- no wrap).
   function Limb_Of_Bytes (B : Bigint; I : Limb_Index) return Unsigned_32
   is (Unsigned_32 (B (Byte_Length - 4 * I - 3))
       * 2**24
       + Unsigned_32 (B (Byte_Length - 4 * I - 2)) * 2**16
       + Unsigned_32 (B (Byte_Length - 4 * I - 1)) * 2**8
       + Unsigned_32 (B (Byte_Length - 4 * I)))
   with Ghost;

   procedure From_Bytes (B : Bigint; L : out Limbs64)
   with Post => (for all I in Limb_Index => L (I) = Limb_Of_Bytes (B, I))
   is
   begin
      --  Unconditional init so flow analysis sees L initialized when the loop
      --  invariant reads the already-written prefix; the loop overwrites all.
      L := [others => 0];
      for I in Limb_Index loop
         L (I) :=
           Shift_Left (Unsigned_32 (B (Byte_Length - 4 * I - 3)), 24)
           or Shift_Left (Unsigned_32 (B (Byte_Length - 4 * I - 2)), 16)
           or Shift_Left (Unsigned_32 (B (Byte_Length - 4 * I - 1)), 8)
           or Unsigned_32 (B (Byte_Length - 4 * I));
         --  The four shifted bytes occupy disjoint 8-bit fields, so OR = sum.
         pragma Assert (L (I) = Limb_Of_Bytes (B, I));
         pragma
           Loop_Invariant
             (for all J in Limb_Index range 0 .. I =>
                L (J) = Limb_Of_Bytes (B, J));
      end loop;
   end From_Bytes;

   procedure To_Bytes (L : Limbs64; B : out Bigint) is
   begin
      --  Pre-zero the whole buffer so flow analysis sees an
      --  unconditional initialisation; the limb-walk below overwrites
      --  every byte but the prover otherwise can't see that the
      --  4×I+k indices cover [1..256] exactly.
      B := [others => 0];
      for I in Limb_Index loop
         B (Byte_Length - 4 * I - 3) :=
           Octet (Shift_Right (L (I), 24) and 16#FF#);
         B (Byte_Length - 4 * I - 2) :=
           Octet (Shift_Right (L (I), 16) and 16#FF#);
         B (Byte_Length - 4 * I - 1) :=
           Octet (Shift_Right (L (I), 8) and 16#FF#);
         B (Byte_Length - 4 * I) := Octet (L (I) and 16#FF#);
      end loop;
   end To_Bytes;

   ---------------------------------------------------------------------
   --  Comparison: returns +1 if A > B, 0 if equal, -1 if A < B.
   --  Operates on 65-limb values so it can be reused for the
   --  shifted-modulus comparisons inside Reduce.
   ---------------------------------------------------------------------

   function Compare65 (A, B : Limbs65) return Integer
   with
     Post =>
       (Compare65'Result >= 0)
       = (LV65 (A, N_Limbs + 1) >= LV65 (B, N_Limbs + 1))
       and then (Compare65'Result <= 0)
                = (LV65 (A, N_Limbs + 1) <= LV65 (B, N_Limbs + 1))
   is
   begin
      for I in reverse Limb_Plus_Index loop
         pragma
           Loop_Invariant
             (for all K in Limb_Plus_Index => (if K > I then A (K) = B (K)));
         if A (I) > B (I) then
            Lemma_LV65_Cmp_Limb (A, B, I);
            return 1;
         elsif A (I) < B (I) then
            Lemma_LV65_Cmp_Limb (A, B, I);
            return -1;
         end if;
      end loop;
      --  All limbs equal: equal valuations (Hi_Eq from K = 0; LV65 (-, 0) = 0).
      Lemma_LV65_Hi_Eq (A, B, 0);
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

   --  Frame: LV65 (L, K) reads only limbs 0 .. K-1.
   procedure Lemma_LV65_Frame (L1, L2 : Limbs65; K : Limb66_Index)
   with
     Ghost,
     Pre                =>
       (for all I in Limb_Plus_Index => (if I < K then L1 (I) = L2 (I))),
     Post               => LV65 (L1, K) = LV65 (L2, K),
     Subprogram_Variant => (Decreases => K);

   procedure Lemma_LV65_Frame (L1, L2 : Limbs65; K : Limb66_Index) is
   begin
      if K /= 0 then
         Lemma_LV65_Frame (L1, L2, K - 1);
      end if;
   end Lemma_LV65_Frame;

   --  Per-limb subtract-with-borrow value identity (§0e image of one Sub65
   --  step): low word + b + borrow_in = a + borrow_out * 2^32.
   procedure Lemma_Sub_Step
     (Ai, Bi : Unsigned_32; Bin, Diff, Bout : Unsigned_64; Ri : Unsigned_32)
   with
     Ghost,
     Pre  =>
       Bin <= 1
       and then Diff = Unsigned_64 (Ai) - Unsigned_64 (Bi) - Bin
       and then Ri = Unsigned_32 (Diff and 16#FFFFFFFF#)
       and then Bout = (Shift_Right (Diff, 63) and 1),
     Post =>
       GBV.Limb_Val (GB.LLI (Ri))
       + GBV.Limb_Val (GB.LLI (Bi))
       + GBV.Limb_Val (GB.LLI (Bin))
       = GBV.Limb_Val (GB.LLI (Ai)) + GBV.Limb_Val (GB.LLI (Bout)) * Base32;

   procedure Lemma_Sub_Step
     (Ai, Bi : Unsigned_32; Bin, Diff, Bout : Unsigned_64; Ri : Unsigned_32) is
   begin
      if Unsigned_64 (Ai) >= Unsigned_64 (Bi) + Bin then
         --  No borrow: Diff is the exact difference and is below 2^32.
         pragma Assert (Diff = Unsigned_64 (Ai) - Unsigned_64 (Bi) - Bin);
         pragma Assert (Diff < 2**32);
         pragma Assert (Bout = 0);
         pragma Assert (Unsigned_64 (Ri) = Diff);
         pragma
           Assert (GB.LLI (Ri) = GB.LLI (Ai) - GB.LLI (Bi) - GB.LLI (Bin));
      else
         --  Borrow: the subtraction wrapped. With deficit D = Bi+Bin-Ai in
         --  [1, 2^32], Diff = 2^64 - D, so Ri = 2^32 - D and bit 63 is set.
         declare
            D : constant Unsigned_64 :=
              Unsigned_64 (Bi) + Bin - Unsigned_64 (Ai)
            with Ghost;
         begin
            pragma Assert (D >= 1 and then D <= 2**32);
            pragma Assert (Diff = Unsigned_64 (0) - D);
            pragma Assert (Diff >= 2**64 - 2**32);
            pragma Assert (Bout = 1);
            pragma Assert (Unsigned_64 (Ri) = 2**32 - D);
            pragma
              Assert (GB.LLI (D) = GB.LLI (Bi) + GB.LLI (Bin) - GB.LLI (Ai));
            pragma
              Assert
                (GB.LLI (Ri)
                   = GB.LLI (Ai) - GB.LLI (Bi) - GB.LLI (Bin) + 2**32);
         end;
      end if;
      pragma
        Assert
          (GB.LLI (Ri) + GB.LLI (Bi) + GB.LLI (Bin)
             = GB.LLI (Ai) + GB.LLI (Bout) * 2**32);
      --  Lift the integer identity to the Limb_Val layer.
      GBV.Lemma_Limb_Val_Mul32 (GB.LLI (Bout), 2**32);
      GBV.Lemma_Limb_Val_Add (GB.LLI (Ai), GB.LLI (Bout) * 2**32);
      GBV.Lemma_Limb_Val_Add (GB.LLI (Ri), GB.LLI (Bi));
      GBV.Lemma_Limb_Val_Add (GB.LLI (Ri) + GB.LLI (Bi), GB.LLI (Bin));
   end Lemma_Sub_Step;

   --  Sub65 loop preservation (clean context; body after the toolkit since it
   --  multiplies the per-step identity through P32 (I) via Lemma_BI_Mul_Eq).
   procedure Lemma_Sub65_Preserve
     (A, B, R_Pre, R_After : Limbs65;
      I                    : Limb_Plus_Index;
      Bin, Diff, Bout      : Unsigned_64)
   with
     Ghost,
     Pre  =>
       Bin <= 1
       and then Diff = Unsigned_64 (A (I)) - Unsigned_64 (B (I)) - Bin
       and then R_After (I) = Unsigned_32 (Diff and 16#FFFFFFFF#)
       and then Bout = (Shift_Right (Diff, 63) and 1)
       and then (for all K in Limb_Plus_Index =>
                   (if K /= I then R_After (K) = R_Pre (K)))
       and then LV65 (A, I) + GBV.Limb_Val (GB.LLI (Bin)) * P32 (I)
                = LV65 (R_Pre, I) + LV65 (B, I),
     Post =>
       LV65 (A, I + 1) + GBV.Limb_Val (GB.LLI (Bout)) * P32 (I + 1)
       = LV65 (R_After, I + 1) + LV65 (B, I + 1);

   --  Per-limb shift-left-by-1 value identity: low word + carry_out*2^32
   --  = 2*a + carry_in.
   procedure Lemma_Shl_Step (Ai, Cin, Ri, Cout : Unsigned_32)
   with
     Ghost,
     Pre  =>
       Cin <= 1
       and then Ri = (Shift_Left (Ai, 1) or Cin)
       and then Cout = (Shift_Right (Ai, 31) and 1),
     Post =>
       GBV.Limb_Val (GB.LLI (Ri)) + GBV.Limb_Val (GB.LLI (Cout)) * Base32
       = GBV.Limb_Val (GB.LLI (Ai))
         + GBV.Limb_Val (GB.LLI (Ai))
         + GBV.Limb_Val (GB.LLI (Cin));

   procedure Lemma_Shl_Step (Ai, Cin, Ri, Cout : Unsigned_32) is
   begin
      pragma Assert ((Shift_Left (Ai, 1) and 1) = 0);
      pragma Assert (GB.LLI (Ri) = GB.LLI (Shift_Left (Ai, 1)) + GB.LLI (Cin));
      pragma
        Assert
          (GB.LLI (Shift_Left (Ai, 1))
             = 2 * GB.LLI (Ai) - GB.LLI (Cout) * 2**32);
      pragma
        Assert
          (GB.LLI (Ri) + GB.LLI (Cout) * 2**32
             = GB.LLI (Ai) + GB.LLI (Ai) + GB.LLI (Cin));
      GBV.Lemma_Limb_Val_Mul32 (GB.LLI (Cout), 2**32);
      GBV.Lemma_Limb_Val_Add (GB.LLI (Ai), GB.LLI (Ai));
      GBV.Lemma_Limb_Val_Add (GB.LLI (Ai) + GB.LLI (Ai), GB.LLI (Cin));
      GBV.Lemma_Limb_Val_Add (GB.LLI (Ri), GB.LLI (Cout) * 2**32);
   end Lemma_Shl_Step;

   --  Shl1_65 loop preservation (clean context; body after the toolkit).
   procedure Lemma_Shl65_Preserve
     (A, R_Pre, R_After : Limbs65;
      I                 : Limb_Plus_Index;
      Cin, Cout         : Unsigned_32)
   with
     Ghost,
     Pre  =>
       Cin <= 1
       and then R_After (I) = (Shift_Left (A (I), 1) or Cin)
       and then Cout = (Shift_Right (A (I), 31) and 1)
       and then (for all K in Limb_Plus_Index =>
                   (if K /= I then R_After (K) = R_Pre (K)))
       and then LV65 (R_Pre, I) + GBV.Limb_Val (GB.LLI (Cin)) * P32 (I)
                = 2 * LV65 (A, I),
     Post =>
       LV65 (R_After, I + 1) + GBV.Limb_Val (GB.LLI (Cout)) * P32 (I + 1)
       = 2 * LV65 (A, I + 1);

   ---------------------------------------------------------------------
   --  Shift a 64-limb value left by one bit, producing a 65-limb
   --  result. Used as the inner operation of the schoolbook reducer.
   ---------------------------------------------------------------------

   procedure Shl1_65 (A : Limbs65; R : out Limbs65)
   with
     Post =>
       (if A (N_Limbs) < 2**31
        then LV65 (R, N_Limbs + 1) = 2 * LV65 (A, N_Limbs + 1))
   is
      Carry : Unsigned_32 := 0;
      Hi    : Unsigned_32;
   begin
      R := [others => 0];
      for I in Limb_Plus_Index loop
         pragma Loop_Invariant (Carry <= 1);
         pragma
           Loop_Invariant
             (LV65 (R, I) + GBV.Limb_Val (GB.LLI (Carry)) * P32 (I)
                = 2 * LV65 (A, I));
         declare
            R_Pre : constant Limbs65 := R
            with Ghost;
            C_In  : constant Unsigned_32 := Carry
            with Ghost;
         begin
            Hi := Shift_Right (A (I), 31) and 1;
            R (I) := Shift_Left (A (I), 1) or Carry;
            Carry := Hi;
            Lemma_Shl65_Preserve (A, R_Pre, R, I, C_In, Carry);
         end;
      end loop;
   end Shl1_65;

   ---------------------------------------------------------------------
   --  Subtract: R := A - B (65-limb minus 65-limb).
   --  Caller must guarantee A >= B (no borrow out).
   ---------------------------------------------------------------------

   procedure Sub65 (A, B : Limbs65; R : out Limbs65)
   with
     Pre  => LV65 (A, N_Limbs + 1) >= LV65 (B, N_Limbs + 1),
     Post =>
       LV65 (R, N_Limbs + 1) = LV65 (A, N_Limbs + 1) - LV65 (B, N_Limbs + 1)
   is
      Borrow : Unsigned_64 := 0;
      Diff   : Unsigned_64;
   begin
      R := [others => 0];
      for I in Limb_Plus_Index loop
         pragma Loop_Invariant (Borrow <= 1);
         pragma
           Loop_Invariant
             (LV65 (A, I) + GBV.Limb_Val (GB.LLI (Borrow)) * P32 (I)
                = LV65 (R, I) + LV65 (B, I));
         declare
            R_Pre : constant Limbs65 := R
            with Ghost;
            B_In  : constant Unsigned_64 := Borrow
            with Ghost;
         begin
            Diff := Unsigned_64 (A (I)) - Unsigned_64 (B (I)) - Borrow;
            R (I) := Unsigned_32 (Diff and 16#FFFFFFFF#);
            Borrow := Shift_Right (Diff, 63) and 1;
            Lemma_Sub65_Preserve (A, B, R_Pre, R, I, B_In, Diff, Borrow);
         end;
      end loop;
      --  At exit the borrow must be 0: A >= B, and LV65 (R) < P32 (N_Limbs+1),
      --  so a leftover borrow would force LV65 (R) >= P32 (N_Limbs+1).
      Lemma_LV65_Upper (R, N_Limbs + 1);
   end Sub65;

   ---------------------------------------------------------------------
   --  Schoolbook 64x64 multiply producing a 128-limb result.
   ---------------------------------------------------------------------

   procedure Mul128 (A, B : Limbs64; T : out Limbs128)
   with Post => LV128 (T, 2 * N_Limbs) = LV64 (A, N_Limbs) * LV64 (B, N_Limbs)
   is
      Acc   : Unsigned_64;
      Carry : Unsigned_64;
   begin
      T := [others => 0];
      --  Base of the outer accumulation invariant: LV128 (all-zero) = 0.
      Lemma_LV128_Zero (T, N_Limbs);
      for I in Limb_Index loop
         --  Outer accumulation frame: limbs at and above I + N_Limbs are still
         --  zero (outer iteration i writes only limbs i .. i + N_Limbs).
         pragma
           Loop_Invariant
             (for all K in Limb2_Index =>
                (if K >= I + N_Limbs then T (K) = 0));
         --  Running product: the low I limbs of A times all of B.
         pragma
           Loop_Invariant
             (LV128 (T, I + N_Limbs) = LV64 (A, I) * LV64 (B, N_Limbs));
         Carry := 0;
         declare
            T_Inner : constant Limbs128 := T
            with Ghost;
         begin
            --  Inner J-loop convolution invariant (bn_mul1 at offset I): the
            --  scalar A (I) times the low J limbs of B accumulates, weighted by
            --  P32 (I), onto the running product at value level.
            for J in Limb_Index loop
               pragma Loop_Invariant (Carry <= 16#FFFF_FFFF#);
               pragma
                 Loop_Invariant
                   (for all K in Limb2_Index =>
                      (if K < I or else K >= I + J then T (K) = T_Inner (K)));
               pragma
                 Loop_Invariant
                   (LV128 (T, I + J)
                      + GBV.Limb_Val (GB.LLI (Carry)) * P32 (I + J)
                      = LV128 (T_Inner, I + J)
                        + (P32 (I) * LV64 (B, J))
                          * GBV.Limb_Val (GB.LLI (A (I))));
               declare
                  T_Pre : constant Limbs128 := T
                  with Ghost;
                  C_Old : constant Unsigned_64 := Carry
                  with Ghost;
               begin
                  pragma
                    Assert (T (I + J) = T_Inner (I + J));  --  suffix K=I+J.
                  Acc :=
                    Unsigned_64 (T (I + J))
                    + Unsigned_64 (A (I)) * Unsigned_64 (B (J))
                    + Carry;
                  T (I + J) := Unsigned_32 (Acc and 16#FFFFFFFF#);
                  Carry := Shift_Right (Acc, 32);
                  Lemma_Mul128_Preserve
                    (T_Pre   => T_Pre,
                     T_After => T,
                     T_Inner => T_Inner,
                     A       => A,
                     B       => B,
                     I       => I,
                     J       => J,
                     C_Old   => C_Old,
                     Acc     => Acc,
                     Carry   => Carry);
               end;
            end loop;
            --  Inner exit: the convolution invariant at J = N_Limbs (from the
            --  last Lemma_Mul128_Preserve, J = N_Limbs - 1).
            pragma
              Assert
                (LV128 (T, I + N_Limbs)
                   + GBV.Limb_Val (GB.LLI (Carry)) * P32 (I + N_Limbs)
                   = LV128 (T_Inner, I + N_Limbs)
                     + (P32 (I) * LV64 (B, N_Limbs))
                       * GBV.Limb_Val (GB.LLI (A (I))));
            declare
               T_AI : constant Limbs128 := T
               with Ghost;
            begin
               --  I + 64 is in range 64 .. 127 — i.e., always inside Limbs128.
               T (I + N_Limbs) := Unsigned_32 (Carry and 16#FFFFFFFF#);
               --  The final carry write advances the running product by the
               --  full A (I) * B * 2**(32*I) term.
               Lemma_Mul128_Outer
                 (T_Inner => T_Inner,
                  T_AI    => T_AI,
                  T_Final => T,
                  A       => A,
                  B       => B,
                  I       => I,
                  Carry   => Carry);
            end;
         end;
      end loop;
      --  Outer accumulation at exit (I = N_Limbs): the full 128-limb product.
      pragma
        Assert
          (LV128 (T, 2 * N_Limbs) = LV64 (A, N_Limbs) * LV64 (B, N_Limbs));
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
      R         : Limbs65 := [others => 0];
      N65       : Limbs65 := [others => 0];
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

      --  §0e value-bridge foundation for the running remainder: anchor the
      --  65-limb valuation bounds (consumed by the in-progress Reduce
      --  functional proof; the long-division correctness builds on LV65).
      Lemma_LV65_Nonneg (R, N_Limbs + 1);
      Lemma_LV65_Upper (R, N_Limbs + 1);

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
      T := [others => 0];
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

   procedure Limb_Mod_Mul (A, B, N : Limbs64; R : out Limbs64) is
      T     : Limbs128;
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
      --  §0e value-bridge foundation: the 128-limb product valuation is
      --  bounded in [0, 2^4096) (anchors LV128 for the convolution proof).
      Lemma_LV128_Nonneg (T, 2 * N_Limbs);
      Lemma_LV128_Upper (T, 2 * N_Limbs);
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

   --  Square-divisibility helpers (Hensel-step lemmas): a value with its low m
   --  bits zero squares to one with its low 2m bits zero. Isolated so the 32-bit
   --  multiply is one focused bit-vector goal each.
   procedure Lemma_Sq_Low8 (A : Unsigned_32)
   with Ghost, Pre => (A and 255) = 0, Post => ((A * A) and 65535) = 0;

   procedure Lemma_Sq_Low8 (A : Unsigned_32) is
   begin
      null;
   end Lemma_Sq_Low8;

   procedure Lemma_Sq_Low16 (A : Unsigned_32)
   with Ghost, Pre => (A and 65535) = 0, Post => A * A = 0;

   procedure Lemma_Sq_Low16 (A : Unsigned_32) is
   begin
      null;
   end Lemma_Sq_Low16;

   --  Associativity of the modular multiply (helps gnatprove past the nonlinear
   --  rearrangement N0 * (X * c) = (N0 * X) * c in the Newton step).
   procedure Lemma_Mul3 (A, B, C : Unsigned_32)
   with Ghost, Post => A * (B * C) = (A * B) * C;

   procedure Lemma_Mul3 (A, B, C : Unsigned_32) is
   begin
      null;
   end Lemma_Mul3;

   --  Newton-step polynomial identity (mod 2^32): T*(2-T) = 1 - (T-1)^2.
   procedure Lemma_Poly_Sq (T : Unsigned_32)
   with Ghost, Post => T * (2 - T) = 1 - (T - 1) * (T - 1);

   procedure Lemma_Poly_Sq (T : Unsigned_32) is
   begin
      null;
   end Lemma_Poly_Sq;

   --  Left distributivity of the modular multiply.
   procedure Lemma_Mul_Distrib (A, X, Y : Unsigned_32)
   with Ghost, Post => A * (X + Y) = A * X + A * Y;

   procedure Lemma_Mul_Distrib (A, X, Y : Unsigned_32) is
   begin
      null;
   end Lemma_Mul_Distrib;

   --  Commutativity of the modular multiply.
   procedure Lemma_Mul_Comm (A, B : Unsigned_32)
   with Ghost, Post => A * B = B * A;

   procedure Lemma_Mul_Comm (A, B : Unsigned_32) is
   begin
      null;
   end Lemma_Mul_Comm;

   --  CIOS "kill the low limb": with m = T0 * Inv32 and N0 * Inv32 = -1 mod
   --  2^32, the low limb of T0 + m*N0 is zero, so the running accumulator can
   --  be shifted down by one limb. T0 + m*N0 = T0*(1 + Inv32*N0) = T0*0 = 0.
   procedure Lemma_Low_Limb_Killed (T0, N0, Inv32 : Unsigned_32)
   with
     Ghost,
     Pre  => N0 * Inv32 = 16#FFFFFFFF#,
     Post => T0 + (T0 * Inv32) * N0 = 0;

   procedure Lemma_Low_Limb_Killed (T0, N0, Inv32 : Unsigned_32) is
   begin
      Lemma_Mul3
        (T0, Inv32, N0);              --  (T0*Inv32)*N0 = T0*(Inv32*N0).
      Lemma_Mul_Comm (Inv32, N0);              --  Inv32*N0 = N0*Inv32.
      pragma Assert ((T0 * Inv32) * N0 = T0 * 16#FFFFFFFF#);
      Lemma_Mul_Distrib (T0, 1, 16#FFFFFFFF#);
      pragma Assert (T0 + (T0 * Inv32) * N0 = T0 * (1 + 16#FFFFFFFF#));
   end Lemma_Low_Limb_Killed;

   --  Newton-Raphson (Hensel lifting): x := x*(2 - N0*x) takes N0*x = 1 mod 2^m
   --  to N0*x = 1 mod 2^(2m), since N0*x' = 2(N0x) - (N0x)^2 = 1 - (N0x - 1)^2
   --  and (N0x - 1) = 0 mod 2^m. Five steps from m=1 (N0 odd) reach m=32.
   function Inverse_Mod_2_32 (N0 : Unsigned_32) return Unsigned_32
   with Pre => (N0 and 1) = 1, Post => N0 * Inverse_Mod_2_32'Result = 1
   is
      X : Unsigned_32 := 1;
      T : Unsigned_32;
   begin
      pragma Assert (((N0 * X) and 1) = 1);          --  m = 1 (N0 odd).
      X := X * (2 - N0 * X);
      pragma Assert (((N0 * X) and 3) = 1);          --  m = 2.
      X := X * (2 - N0 * X);
      pragma Assert (((N0 * X) and 15) = 1);         --  m = 4.
      X := X * (2 - N0 * X);
      pragma Assert (((N0 * X) and 255) = 1);        --  m = 8.

      --  Step to m = 16 via the square-divisibility helper. Prove the ring
      --  identity on the explicit square first (the nonlinear part), then bind
      --  it to an abstract Z so the final mask step carries no multiply term.
      T := N0 * X;
      declare
         X0 : constant Unsigned_32 := X
         with Ghost;
      begin
         X := X * (2 - T);
         pragma Assert (X = X0 * (2 - T));
         Lemma_Mul3 (N0, X0, 2 - T);
         pragma Assert (N0 * X = T * (2 - T));
         Lemma_Poly_Sq (T);
         pragma Assert (N0 * X = 1 - (T - 1) * (T - 1));
         pragma Assert (((T - 1) and 255) = 0);
         Lemma_Sq_Low8 (T - 1);
         declare
            Z : constant Unsigned_32 := (T - 1) * (T - 1)
            with Ghost;
         begin
            pragma Assert ((Z and 65535) = 0);
            pragma Assert (N0 * X = 1 - Z);
            pragma Assert (((N0 * X) and 65535) = 1);
         end;
      end;

      --  Step to m = 32 (full): (N0*X - 1)^2 = 0.
      T := N0 * X;
      declare
         X0 : constant Unsigned_32 := X
         with Ghost;
      begin
         X := X * (2 - T);
         pragma Assert (X = X0 * (2 - T));
         Lemma_Mul3 (N0, X0, 2 - T);
         pragma Assert (N0 * X = T * (2 - T));
         Lemma_Poly_Sq (T);
         pragma Assert (N0 * X = 1 - (T - 1) * (T - 1));
         pragma Assert (((T - 1) and 65535) = 0);
         Lemma_Sq_Low16 (T - 1);
         declare
            Z : constant Unsigned_32 := (T - 1) * (T - 1)
            with Ghost;
         begin
            pragma Assert (Z = 0);
            pragma Assert (N0 * X = 1 - Z);
            pragma Assert (N0 * X = 1);
         end;
      end;
      return X;
   end Inverse_Mod_2_32;

   --  n0_inv := -N0^-1 mod 2^32, where N0 = N (0). The Montgomery m' constant:
   --  N (0) * n0_inv = -1 (mod 2^32) = 16#FFFFFFFF#.
   function N0_Inv (N : Limbs64) return Unsigned_32
   with Pre => (N (0) and 1) = 1, Post => N (0) * N0_Inv'Result = 16#FFFFFFFF#
   is
      Inv : constant Unsigned_32 := Inverse_Mod_2_32 (N (0));
   begin
      --  N (0) * Inv = 1 (Inverse Post); -Inv + Inv = 0 (two's complement); so
      --  by distributivity N (0)*(-Inv) + 1 = 0, i.e. N (0)*(-Inv) = -1.
      pragma Assert (N (0) * Inv = 1);
      pragma Assert (((not Inv) + 1) + Inv = 0);
      Lemma_Mul_Distrib (N (0), (not Inv) + 1, Inv);
      pragma Assert (N (0) * ((not Inv) + 1) + N (0) * Inv = 0);
      pragma Assert (N (0) * ((not Inv) + 1) = 16#FFFFFFFF#);
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
      T128  : Limbs128 := [others => 0];
      R_Mod : Limbs64;
      Sq128 : Limbs128;
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

   --  Per-step mul-add value identity (bn_mul1): for the CIOS inner-loop word
   --  Acc = Tj + Aj*Bi + C with carry-in C < 2**32, the stored low word and the
   --  carry-out recombine -- at the Limb_Val level -- to exactly Tj + Aj*Bi + C.
   --  This is the local step the inner J-loop convolution invariant folds.
   procedure Lemma_MulAdd_Step (Tj, Aj, Bi : Unsigned_32; C, Acc : Unsigned_64)
   with
     Ghost,
     Pre  =>
       C <= 16#FFFF_FFFF#
       and then Acc
                = Unsigned_64 (Tj) + Unsigned_64 (Aj) * Unsigned_64 (Bi) + C,
     Post =>
       GBV.Limb_Val (GB.LLI (Unsigned_32 (Acc and 16#FFFF_FFFF#)))
       + GBV.Limb_Val (GB.LLI (Shift_Right (Acc, 32))) * Base32
       = GBV.Limb_Val (GB.LLI (Tj))
         + GBV.Limb_Val (GB.LLI (Aj)) * GBV.Limb_Val (GB.LLI (Bi))
         + GBV.Limb_Val (GB.LLI (C));

   procedure Lemma_MulAdd_Step (Tj, Aj, Bi : Unsigned_32; C, Acc : Unsigned_64)
   is
      Low : constant Unsigned_32 := Unsigned_32 (Acc and 16#FFFF_FFFF#);
      Hi  : constant Unsigned_64 := Shift_Right (Acc, 32);
   begin
      --  U64 bit-decomposition (Acc < 2**64, no wrap).
      pragma Assert (Unsigned_64 (Low) = (Acc and 16#FFFF_FFFF#));
      pragma Assert (Acc = Unsigned_64 (Low) + Hi * 2**32);
      --  Lift the decomposition to LLI (exact; 128-bit, no overflow).
      pragma Assert (GB.LLI (Acc) = GB.LLI (Low) + GB.LLI (Hi) * 2**32);
      --  Split image: Limb_Val (Acc) = Limb_Val (Low) + Limb_Val (Hi) * Base32.
      GBV.Lemma_Limb_Val_Mul32 (GB.LLI (Hi), 2**32);
      GBV.Lemma_Limb_Val_Add (GB.LLI (Low), GB.LLI (Hi) * 2**32);
      --  Operand image: Acc = Tj + Aj*Bi + C as LLI.
      pragma
        Assert
          (GB.LLI (Acc)
             = GB.LLI (Tj) + GB.LLI (Aj) * GB.LLI (Bi) + GB.LLI (C));
      GBV.Lemma_Limb_Val_Mul32 (GB.LLI (Aj), GB.LLI (Bi));
      GBV.Lemma_Limb_Val_Add (GB.LLI (Tj), GB.LLI (Aj) * GB.LLI (Bi));
      GBV.Lemma_Limb_Val_Add
        (GB.LLI (Tj) + GB.LLI (Aj) * GB.LLI (Bi), GB.LLI (C));
   end Lemma_MulAdd_Step;

   --  Frame: LV66 (T, K) reads only limbs 0 .. K-1, so two arrays agreeing
   --  there have equal valuations. Lets an update at index >= J leave the
   --  running prefix value LV66 (-, J) untouched.
   procedure Lemma_LV66_Frame (T1, T2 : Limbs66; K : Limb66_Plus_Index)
   with
     Ghost,
     Pre                =>
       (for all I in Limb66_Index => (if I < K then T1 (I) = T2 (I))),
     Post               => LV66 (T1, K) = LV66 (T2, K),
     Subprogram_Variant => (Decreases => K);

   procedure Lemma_LV66_Frame (T1, T2 : Limbs66; K : Limb66_Plus_Index) is
   begin
      if K /= 0 then
         Lemma_LV66_Frame (T1, T2, K - 1);
      end if;
   end Lemma_LV66_Frame;

   --  Pure Big_Integer ring step for the mul-add convolution preservation:
   --  given the running invariant (H1) and the per-step identity (H2), the
   --  invariant advances by one limb. A linear combination H1 + P * H2 modulo
   --  commutativity of the limb/weight products.
   procedure Lemma_Conv_Step
     (Lvtpre, Lvte, Lva, Tj, Cy, Av, Bv, Tev, Cold, P, BaseV : Big.Big_Integer)
   with
     Ghost,
     Pre  =>
       Lvtpre + Cold * P = Lvte + Lva * Bv
       and then Tj + Cy * BaseV = Tev + Av * Bv + Cold,
     Post =>
       (Lvtpre + Tj * P) + Cy * (P * BaseV)
       = (Lvte + Tev * P) + (Lva + Av * P) * Bv;

   procedure Lemma_Conv_Step
     (Lvtpre, Lvte, Lva, Tj, Cy, Av, Bv, Tev, Cold, P, BaseV : Big.Big_Integer)
   is
   begin
      --  Restate the two hypotheses (also references the data formals).
      pragma Assert (Lvtpre + Cold * P = Lvte + Lva * Bv);
      pragma Assert (Tj + Cy * BaseV = Tev + Av * Bv + Cold);
      Lemma_BI_Comm (P, BaseV);        --  P*BaseV = BaseV*P.
      Lemma_BI_Assoc (Cy, BaseV, P);   --  Cy*(BaseV*P) = (Cy*BaseV)*P.
      Lemma_BI_Assoc (Av, Bv, P);      --  (Av*Bv)*P = Av*(Bv*P).
      Lemma_BI_Comm (Bv, P);           --  Bv*P = P*Bv.
      Lemma_BI_Assoc (Av, P, Bv);      --  Av*(P*Bv) = (Av*P)*Bv.
   end Lemma_Conv_Step;

   --  Definitional one-step unfold of LV64 (forces the recursion in a clean
   --  context where the heavy convolution VC stalls on it).
   procedure Lemma_LV64_Unfold (L : Limbs64; K : Limb_Plus_Index)
   with
     Ghost,
     Pre  => K >= 1,
     Post =>
       LV64 (L, K)
       = LV64 (L, K - 1) + GBV.Limb_Val (GB.LLI (L (K - 1))) * P32 (K - 1);

   procedure Lemma_LV64_Unfold (L : Limbs64; K : Limb_Plus_Index) is
   begin
      null;
   end Lemma_LV64_Unfold;

   --  Definitional one-step unfold of LV66 (same role as Lemma_LV64_Unfold).
   procedure Lemma_LV66_Unfold (T : Limbs66; K : Limb66_Plus_Index)
   with
     Ghost,
     Pre  => K >= 1,
     Post =>
       LV66 (T, K)
       = LV66 (T, K - 1) + GBV.Limb_Val (GB.LLI (T (K - 1))) * P32 (K - 1);

   procedure Lemma_LV66_Unfold (T : Limbs66; K : Limb66_Plus_Index) is
   begin
      null;
   end Lemma_LV66_Unfold;

   --  A U64 value that fits in 32 bits has the same §0e image as its U32 cast.
   procedure Lemma_LLI_Fits32 (X : Unsigned_64)
   with
     Ghost,
     Pre  => X <= 16#FFFF_FFFF#,
     Post => GB.LLI (Unsigned_32 (X)) = GB.LLI (X);

   procedure Lemma_LLI_Fits32 (X : Unsigned_64) is
   begin
      null;
   end Lemma_LLI_Fits32;

   --  Congruence: equal factors give equal products (left multiply).
   procedure Lemma_BI_Mul_Eq (C, A, B : Big.Big_Integer)
   with Ghost, Pre => A = B, Post => C * A = C * B;

   procedure Lemma_BI_Mul_Eq (C, A, B : Big.Big_Integer) is
   begin
      null;
   end Lemma_BI_Mul_Eq;

   --  Body of Lemma_Sub65_Preserve (declared early; uses the toolkit here).
   procedure Lemma_Sub65_Preserve
     (A, B, R_Pre, R_After : Limbs65;
      I                    : Limb_Plus_Index;
      Bin, Diff, Bout      : Unsigned_64)
   is
      Av  : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (A (I)))
      with Ghost;
      Bv  : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (B (I)))
      with Ghost;
      Rv  : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (R_After (I)))
      with Ghost;
      Biv : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (Bin))
      with Ghost;
      Bov : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (Bout))
      with Ghost;
      W   : constant Big.Big_Integer := P32 (I)
      with Ghost;
   begin
      Lemma_Sub_Step (A (I), B (I), Bin, Diff, Bout, R_After (I));
      --  (S): Rv + Bv + Biv = Av + Bov * Base32.
      Lemma_LV65_Frame (R_After, R_Pre, I);
      Lemma_LV65_Unfold (A, I + 1);
      Lemma_LV65_Unfold (B, I + 1);
      Lemma_LV65_Unfold (R_After, I + 1);
      Lemma_P32_Succ (I);
      --  Multiply (S) through by W = P32 (I), then distribute both sides.
      Lemma_BI_Mul_Eq (W, Rv + Bv + Biv, Av + Bov * Base32);
      Lemma_BI_Distrib (W, Rv + Bv, Biv);
      Lemma_BI_Distrib (W, Rv, Bv);
      Lemma_BI_Distrib (W, Av, Bov * Base32);
      --  W * (Bov * Base32) = Bov * (W * Base32) = Bov * P32 (I+1).
      Lemma_BI_Comm (W, Bov * Base32);
      Lemma_BI_Assoc (Bov, Base32, W);
      Lemma_BI_Comm (Base32, W);
      Lemma_BI_Mul_Eq (Bov, Base32 * W, W * Base32);
      Lemma_BI_Mul_Eq (Bov, W * Base32, P32 (I + 1));
      --  Align limb*weight (unfold form) with weight*limb (distrib form).
      Lemma_BI_Comm (W, Rv);
      Lemma_BI_Comm (W, Bv);
      Lemma_BI_Comm (W, Av);
      Lemma_BI_Comm (W, Biv);
   end Lemma_Sub65_Preserve;

   --  Body of Lemma_Shl65_Preserve (declared early; uses the toolkit here).
   procedure Lemma_Shl65_Preserve
     (A, R_Pre, R_After : Limbs65;
      I                 : Limb_Plus_Index;
      Cin, Cout         : Unsigned_32)
   is
      Av  : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (A (I)))
      with Ghost;
      Rv  : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (R_After (I)))
      with Ghost;
      Civ : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (Cin))
      with Ghost;
      Cov : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (Cout))
      with Ghost;
      W   : constant Big.Big_Integer := P32 (I)
      with Ghost;
   begin
      Lemma_Shl_Step (A (I), Cin, R_After (I), Cout);
      --  (S): Rv + Cov*Base32 = Av + Av + Civ.
      Lemma_LV65_Frame (R_After, R_Pre, I);
      Lemma_LV65_Unfold (A, I + 1);
      Lemma_LV65_Unfold (R_After, I + 1);
      Lemma_P32_Succ (I);
      Lemma_BI_Mul_Eq (W, Rv + Cov * Base32, Av + Av + Civ);
      Lemma_BI_Distrib (W, Rv, Cov * Base32);
      Lemma_BI_Distrib (W, Av + Av, Civ);
      Lemma_BI_Distrib (W, Av, Av);
      Lemma_BI_Comm (W, Cov * Base32);
      Lemma_BI_Assoc (Cov, Base32, W);
      Lemma_BI_Comm (Base32, W);
      Lemma_BI_Mul_Eq (Cov, Base32 * W, W * Base32);
      Lemma_BI_Mul_Eq (Cov, W * Base32, P32 (I + 1));
      Lemma_BI_Comm (W, Rv);
      Lemma_BI_Comm (W, Av);
      Lemma_BI_Comm (W, Civ);
   end Lemma_Shl65_Preserve;

   --  Pure Big_Integer ring step for the Montgomery reduce (shift) loop:
   --  given H1 (Pstep = BaseV*Lvtm1 + Cold*P) and the per-step identity
   --  H2 (Low + Cy*BaseV = Trj + MN + Cold), advance by one shifted limb.
   procedure Lemma_Reduce_Step
     (Pstep, Lvtm1, Low, Cy, Cold, Trj, MN, P, BaseV : Big.Big_Integer)
   with
     Ghost,
     Pre  =>
       Pstep = BaseV * Lvtm1 + Cold * P
       and then Low + Cy * BaseV = Trj + MN + Cold,
     Post =>
       Pstep + (Trj + MN) * P = BaseV * Lvtm1 + Low * P + Cy * (P * BaseV);

   procedure Lemma_Reduce_Step
     (Pstep, Lvtm1, Low, Cy, Cold, Trj, MN, P, BaseV : Big.Big_Integer) is
   begin
      pragma Assert (Pstep = BaseV * Lvtm1 + Cold * P);
      pragma Assert (Low + Cy * BaseV = Trj + MN + Cold);
      Lemma_BI_Comm (P, BaseV);
      Lemma_BI_Assoc (Cy, BaseV, P);
   end Lemma_Reduce_Step;

   --  Montgomery reduce-loop preservation, proved in a CLEAN context (only its
   --  own Pre as hypotheses) so the heavy reduce loop only instantiates one
   --  Post.  T_After is T_Pre with limb J-1 overwritten by the low word of
   --  Acc = T_Pre (J) + M*N (J) + C_Old, and Carry the carry-out.  Given the
   --  running invariant INV(J), it yields INV(J+1).
   procedure Lemma_Reduce_Preserve
     (T_Pre, T_After, T_Red : Limbs66;
      N                     : Limbs64;
      M                     : Unsigned_32;
      C_Old, Acc, Carry     : Unsigned_64;
      J                     : Limb_Index)
   with
     Ghost,
     Pre  =>
       J >= 1
       and then C_Old <= 16#FFFF_FFFF#
       and then Acc
                = Unsigned_64 (T_Pre (J))
                  + Unsigned_64 (M) * Unsigned_64 (N (J))
                  + C_Old
       and then Carry = Shift_Right (Acc, 32)
       and then (for all K in Limb66_Index =>
                   (if K /= J - 1 then T_After (K) = T_Pre (K)))
       and then T_After (J - 1) = Unsigned_32 (Acc and 16#FFFF_FFFF#)
       and then T_Pre (J) = T_Red (J)
       and then LV66 (T_Red, J) + GBV.Limb_Val (GB.LLI (M)) * LV64 (N, J)
                = Base32
                  * LV66 (T_Pre, J - 1)
                  + GBV.Limb_Val (GB.LLI (C_Old)) * P32 (J),
     Post =>
       LV66 (T_Red, J + 1) + GBV.Limb_Val (GB.LLI (M)) * LV64 (N, J + 1)
       = Base32
         * LV66 (T_After, J)
         + GBV.Limb_Val (GB.LLI (Carry)) * P32 (J + 1);

   procedure Lemma_Reduce_Preserve
     (T_Pre, T_After, T_Red : Limbs66;
      N                     : Limbs64;
      M                     : Unsigned_32;
      C_Old, Acc, Carry     : Unsigned_64;
      J                     : Limb_Index)
   is
      M_Val  : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (M))
      with Ghost;
      N_Val  : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (N (J)))
      with Ghost;
      TR_Val : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (T_Red (J)))
      with Ghost;
      Low    : constant Big.Big_Integer :=
        GBV.Limb_Val (GB.LLI (T_After (J - 1)))
      with Ghost;
      Cy     : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (Carry))
      with Ghost;
      Cold   : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (C_Old))
      with Ghost;
   begin
      --  Per-step value identity (Lemma_MulAdd_Step image; clean context).
      Lemma_MulAdd_Step (T_Pre (J), M, N (J), C_Old, Acc);
      pragma Assert (Low + Cy * Base32 = TR_Val + M_Val * N_Val + Cold);
      --  Prefix 0 .. J-2 untouched: LV66 (T_After, J-1) = LV66 (T_Pre, J-1).
      Lemma_LV66_Frame (T_After, T_Pre, J - 1);
      Lemma_LV66_Unfold (T_After, J);
      Lemma_LV66_Unfold (T_Red, J + 1);
      Lemma_LV64_Unfold (N, J + 1);
      pragma Assert (P32 (J + 1) = P32 (J) * Base32);
      pragma Assert (P32 (J) = P32 (J - 1) * Base32);
      pragma
        Assert (LV66 (T_After, J) = LV66 (T_Pre, J - 1) + Low * P32 (J - 1));
      Lemma_BI_Mul_Eq (Low, P32 (J), P32 (J - 1) * Base32);
      Lemma_BI_Assoc (Low, P32 (J - 1), Base32);
      Lemma_BI_Comm (Low * P32 (J - 1), Base32);
      pragma Assert (Low * P32 (J) = Base32 * (Low * P32 (J - 1)));
      Lemma_Reduce_Step
        (Pstep => LV66 (T_Red, J) + M_Val * LV64 (N, J),
         Lvtm1 => LV66 (T_Pre, J - 1),
         Low   => Low,
         Cy    => Cy,
         Cold  => Cold,
         Trj   => TR_Val,
         MN    => M_Val * N_Val,
         P     => P32 (J),
         BaseV => Base32);
      --  LHS assembly: distribute m over the LV64 / LV66 unfolds.
      pragma Assert (LV66 (T_Red, J + 1) = LV66 (T_Red, J) + TR_Val * P32 (J));
      pragma Assert (LV64 (N, J + 1) = LV64 (N, J) + N_Val * P32 (J));
      Lemma_BI_Distrib (M_Val, LV64 (N, J), N_Val * P32 (J));
      Lemma_BI_Assoc (M_Val, N_Val, P32 (J));
      pragma
        Assert
          (M_Val * LV64 (N, J + 1)
             = M_Val * LV64 (N, J) + (M_Val * N_Val) * P32 (J));
      Lemma_BI_Comm (TR_Val + M_Val * N_Val, P32 (J));
      Lemma_BI_Distrib (P32 (J), TR_Val, M_Val * N_Val);
      Lemma_BI_Comm (P32 (J), TR_Val);
      Lemma_BI_Comm (P32 (J), M_Val * N_Val);
      pragma
        Assert
          ((TR_Val + M_Val * N_Val) * P32 (J)
             = TR_Val * P32 (J) + (M_Val * N_Val) * P32 (J));
      pragma
        Assert
          (LV66 (T_Red, J + 1) + M_Val * LV64 (N, J + 1)
             = (LV66 (T_Red, J) + M_Val * LV64 (N, J))
               + (TR_Val + M_Val * N_Val) * P32 (J));
      --  RHS assembly.
      pragma
        Assert
          (Base32 * LV66 (T_After, J)
             = Base32 * LV66 (T_Pre, J - 1) + Low * P32 (J));
      pragma Assert (Cy * P32 (J + 1) = Cy * (P32 (J) * Base32));
   end Lemma_Reduce_Preserve;

   --  Montgomery reduce TWO-LIMB FINALIZE, clean context. Folds the last carry
   --  (limb N_Limbs) and the top word (limb N_Limbs+1) into the shifted result,
   --  extending the loop-exit invariant to the full reduced value:
   --  Base32 * LV66 (T_After, N_Limbs+1) = LV66 (T_Red, N_Limbs+2) + m*LV64 (N).
   procedure Lemma_Reduce_Finalize
     (T_Loop, T_After, T_Red       : Limbs66;
      N                            : Limbs64;
      M                            : Unsigned_32;
      Carry_Loop, Acc, Carry_Final : Unsigned_64)
   with
     Ghost,
     Pre  =>
       Carry_Loop <= 16#FFFF_FFFF#
       and then Acc = Unsigned_64 (T_Red (N_Limbs)) + Carry_Loop
       and then Carry_Final = Shift_Right (Acc, 32)
       and then T_Red (N_Limbs + 1) <= 1
       and then T_Loop (N_Limbs) = T_Red (N_Limbs)
       and then T_Loop (N_Limbs + 1) = T_Red (N_Limbs + 1)
       and then (for all K in Limb66_Index =>
                   (if K <= N_Limbs - 2 then T_After (K) = T_Loop (K)))
       and then T_After (N_Limbs - 1) = Unsigned_32 (Acc and 16#FFFF_FFFF#)
       and then T_After (N_Limbs)
                = T_Red (N_Limbs + 1) + Unsigned_32 (Carry_Final)
       and then T_After (N_Limbs + 1) = 0
       and then LV66 (T_Red, N_Limbs)
                + GBV.Limb_Val (GB.LLI (M)) * LV64 (N, N_Limbs)
                = Base32
                  * LV66 (T_Loop, N_Limbs - 1)
                  + GBV.Limb_Val (GB.LLI (Carry_Loop)) * P32 (N_Limbs),
     Post =>
       Base32 * LV66 (T_After, N_Limbs + 1)
       = LV66 (T_Red, N_Limbs + 2)
         + GBV.Limb_Val (GB.LLI (M)) * LV64 (N, N_Limbs);

   procedure Lemma_Reduce_Finalize
     (T_Loop, T_After, T_Red       : Limbs66;
      N                            : Limbs64;
      M                            : Unsigned_32;
      Carry_Loop, Acc, Carry_Final : Unsigned_64)
   is
      Cl   : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (Carry_Loop))
      with Ghost;
      Cf   : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (Carry_Final))
      with Ghost;
      Tr64 : constant Big.Big_Integer :=
        GBV.Limb_Val (GB.LLI (T_Red (N_Limbs)))
      with Ghost;
      Tr65 : constant Big.Big_Integer :=
        GBV.Limb_Val (GB.LLI (T_Red (N_Limbs + 1)))
      with Ghost;
      Low  : constant Big.Big_Integer :=
        GBV.Limb_Val (GB.LLI (T_After (N_Limbs - 1)))
      with Ghost;
      T64  : constant Big.Big_Integer :=
        GBV.Limb_Val (GB.LLI (T_After (N_Limbs)))
      with Ghost;
      LvL  : constant Big.Big_Integer := LV66 (T_Loop, N_Limbs - 1)
      with Ghost;
   begin
      --  2-term carry split (Lemma_MulAdd_Step, Aj = Bi = 0).
      Lemma_MulAdd_Step (T_Red (N_Limbs), 0, 0, Carry_Loop, Acc);
      pragma Assert (Low + Cf * Base32 = Tr64 + Cl);
      --  Top word = T_Red(65) + Carry_Final, no wrap (both <= 1).
      pragma
        Assert
          (GB.LLI (T_After (N_Limbs))
             = GB.LLI (T_Red (N_Limbs + 1)) + GB.LLI (Carry_Final));
      GBV.Lemma_Limb_Val_Add
        (GB.LLI (T_Red (N_Limbs + 1)), GB.LLI (Carry_Final));
      pragma Assert (T64 = Tr65 + Cf);
      --  Frame + unfolds.
      Lemma_LV66_Frame (T_After, T_Loop, N_Limbs - 1);
      Lemma_LV66_Unfold (T_After, N_Limbs);
      Lemma_LV66_Unfold (T_After, N_Limbs + 1);
      Lemma_LV66_Unfold (T_Red, N_Limbs + 1);
      Lemma_LV66_Unfold (T_Red, N_Limbs + 2);
      pragma Assert (P32 (N_Limbs) = P32 (N_Limbs - 1) * Base32);
      pragma Assert (P32 (N_Limbs + 1) = P32 (N_Limbs) * Base32);
      --  LHS: LV66 (T_After, N_Limbs+1) = LvL + Low*P32(N_Limbs-1)
      --       + T64*P32(N_Limbs).
      pragma
        Assert
          (LV66 (T_After, N_Limbs + 1)
             = LvL + Low * P32 (N_Limbs - 1) + T64 * P32 (N_Limbs));
      --  Shift each term up by Base32.
      Lemma_BI_Mul_Eq (Low, P32 (N_Limbs), P32 (N_Limbs - 1) * Base32);
      Lemma_BI_Assoc (Low, P32 (N_Limbs - 1), Base32);
      Lemma_BI_Comm (Low * P32 (N_Limbs - 1), Base32);
      pragma Assert (Low * P32 (N_Limbs) = Base32 * (Low * P32 (N_Limbs - 1)));
      Lemma_BI_Mul_Eq (T64, P32 (N_Limbs + 1), P32 (N_Limbs) * Base32);
      Lemma_BI_Assoc (T64, P32 (N_Limbs), Base32);
      Lemma_BI_Comm (T64 * P32 (N_Limbs), Base32);
      pragma Assert (T64 * P32 (N_Limbs + 1) = Base32 * (T64 * P32 (N_Limbs)));
      Lemma_BI_Distrib (Base32, LvL, Low * P32 (N_Limbs - 1));
      Lemma_BI_Distrib
        (Base32, LvL + Low * P32 (N_Limbs - 1), T64 * P32 (N_Limbs));
      Lemma_BI_Mul_Eq
        (Base32,
         LV66 (T_After, N_Limbs + 1),
         LvL + Low * P32 (N_Limbs - 1) + T64 * P32 (N_Limbs));
      pragma
        Assert
          (Base32 * LV66 (T_After, N_Limbs + 1)
             = Base32 * LvL + Low * P32 (N_Limbs) + T64 * P32 (N_Limbs + 1));
      --  Expand T64 = Tr65 + Cf and fold via the per-step identity.
      Lemma_BI_Mul_Eq (Tr65 + Cf, P32 (N_Limbs + 1), P32 (N_Limbs + 1));
      Lemma_BI_Comm (Tr65 + Cf, P32 (N_Limbs + 1));
      Lemma_BI_Distrib (P32 (N_Limbs + 1), Tr65, Cf);
      Lemma_BI_Comm (P32 (N_Limbs + 1), Tr65);
      Lemma_BI_Comm (P32 (N_Limbs + 1), Cf);
      pragma
        Assert
          (T64 * P32 (N_Limbs + 1)
             = Tr65 * P32 (N_Limbs + 1) + Cf * P32 (N_Limbs + 1));
      Lemma_BI_Mul_Eq (Cf, P32 (N_Limbs + 1), P32 (N_Limbs) * Base32);
      Lemma_BI_Assoc (Cf, P32 (N_Limbs), Base32);
      Lemma_BI_Comm (Cf * P32 (N_Limbs), Base32);
      pragma Assert (Cf * P32 (N_Limbs + 1) = Base32 * Cf * P32 (N_Limbs));
      --  (Low + Cf*Base32) * P32(N_Limbs) = (Tr64 + Cl) * P32(N_Limbs).
      Lemma_BI_Mul_Eq (P32 (N_Limbs), Low + Cf * Base32, Tr64 + Cl);
      Lemma_BI_Comm (P32 (N_Limbs), Low + Cf * Base32);
      Lemma_BI_Comm (P32 (N_Limbs), Tr64 + Cl);
      Lemma_BI_Distrib (P32 (N_Limbs), Low, Cf * Base32);
      Lemma_BI_Distrib (P32 (N_Limbs), Tr64, Cl);
      Lemma_BI_Comm (P32 (N_Limbs), Low);
      Lemma_BI_Comm (P32 (N_Limbs), Cf * Base32);
      Lemma_BI_Comm (P32 (N_Limbs), Tr64);
      Lemma_BI_Comm (P32 (N_Limbs), Cl);
      pragma
        Assert
          (Low * P32 (N_Limbs) + Cf * Base32 * P32 (N_Limbs)
             = Tr64 * P32 (N_Limbs) + Cl * P32 (N_Limbs));
      --  RHS unfolds: LV66 (T_Red, N_Limbs+2) = LV66 (T_Red, N_Limbs)
      --              + Tr64*P32(N_Limbs) + Tr65*P32(N_Limbs+1).
      pragma
        Assert
          (LV66 (T_Red, N_Limbs + 2)
             = LV66 (T_Red, N_Limbs)
               + Tr64 * P32 (N_Limbs)
               + Tr65 * P32 (N_Limbs + 1));
      pragma
        Assert
          (Base32 * LV66 (T_After, N_Limbs + 1)
             = LV66 (T_Red, N_Limbs + 2)
               + GBV.Limb_Val (GB.LLI (M)) * LV64 (N, N_Limbs));
   end Lemma_Reduce_Finalize;

   --  Body of Lemma_P32_Add (declared early; uses the BI ring lemmas here).
   procedure Lemma_P32_Add (A, B : Natural) is
   begin
      if B = 0 then
         GBV.Lemma_Limb_Val_Succ (0);   --  P32 (0) = Limb_Val (1) = 1.

      else
         Lemma_P32_Add (A, B - 1);      --  P32 (A+B-1) = P32 (A) * P32 (B-1).
         --  P32 (A+B) = P32 (A+B-1)*Base32 = (P32 (A)*P32 (B-1))*Base32
         --           = P32 (A)*(P32 (B-1)*Base32) = P32 (A)*P32 (B).
         Lemma_BI_Assoc (P32 (A), P32 (B - 1), Base32);
      end if;
   end Lemma_P32_Add;

   --  Body of Lemma_Mul128_Preserve (declared early; uses the ring/convolution
   --  toolkit here). Clean context: only its own Pre as hypotheses.
   procedure Lemma_Mul128_Preserve
     (T_Pre, T_After, T_Inner : Limbs128;
      A, B                    : Limbs64;
      I, J                    : Limb_Index;
      C_Old, Acc, Carry       : Unsigned_64)
   is
      A_Val : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (A (I)))
      with Ghost;
      B_Val : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (B (J)))
      with Ghost;
   begin
      --  U64 multiplication commutes, so Acc = T_Pre(I+J) + B(J)*A(I) + C_Old.
      pragma
        Assert
          (Unsigned_64 (A (I)) * Unsigned_64 (B (J))
             = Unsigned_64 (B (J)) * Unsigned_64 (A (I)));
      --  Per-step value identity (low/hi recombine; scalar A(I) as Bi).
      Lemma_MulAdd_Step (T_Pre (I + J), B (J), A (I), C_Old, Acc);
      --  Only T (I+J) changed: prefix 0 .. I+J-1 untouched.
      Lemma_LV128_Frame (T_After, T_Pre, I + J);
      --  Definitional unfolds at I+J+1 and the B-prefix at J+1.
      Lemma_LV128_Unfold (T_After, I + J + 1);
      Lemma_LV128_Unfold (T_Inner, I + J + 1);
      Lemma_LV64_Unfold (B, J + 1);
      --  Weight steps: P32 (I+J+1) = P32 (I+J)*Base32; P32 (I+J) = P32 (I)*P32 (J).
      Lemma_P32_Succ (I + J);
      Lemma_P32_Add (I, J);
      --  Expand the B-prefix one limb at offset I:
      --  P32 (I)*LV64 (B,J+1) = P32 (I)*LV64 (B,J) + B_Val*P32 (I+J).
      Lemma_BI_Distrib (P32 (I), LV64 (B, J), B_Val * P32 (J));
      Lemma_BI_Comm (P32 (I), B_Val * P32 (J));
      Lemma_BI_Assoc (B_Val, P32 (J), P32 (I));
      Lemma_BI_Comm (P32 (J), P32 (I));
      pragma
        Assert
          (P32 (I) * LV64 (B, J + 1)
             = P32 (I) * LV64 (B, J) + B_Val * P32 (I + J));
      --  Congruence: multiply the expanded B-prefix by the fixed scalar A(I).
      Lemma_BI_Mul_Eq
        (A_Val,
         P32 (I) * LV64 (B, J + 1),
         P32 (I) * LV64 (B, J) + B_Val * P32 (I + J));
      Lemma_BI_Comm (A_Val, P32 (I) * LV64 (B, J + 1));
      Lemma_BI_Comm (A_Val, P32 (I) * LV64 (B, J) + B_Val * P32 (I + J));
      --  Ring step: H1 (inv J) + per-step H2, fixed scalar A(I) factored out.
      Lemma_Conv_Step
        (Lvtpre => LV128 (T_Pre, I + J),
         Lvte   => LV128 (T_Inner, I + J),
         Lva    => P32 (I) * LV64 (B, J),
         Tj     => GBV.Limb_Val (GB.LLI (T_After (I + J))),
         Cy     => GBV.Limb_Val (GB.LLI (Carry)),
         Av     => B_Val,
         Bv     => A_Val,
         Tev    => GBV.Limb_Val (GB.LLI (T_Inner (I + J))),
         Cold   => GBV.Limb_Val (GB.LLI (C_Old)),
         P      => P32 (I + J),
         BaseV  => Base32);
      --  Assemble the Post from Conv_Step's result: unfold/frame on the LHS,
      --  unfold on the Inner side, and the carry weight via P32_Succ.
      pragma
        Assert
          (LV128 (T_After, I + J + 1)
             = LV128 (T_Pre, I + J)
               + GBV.Limb_Val (GB.LLI (T_After (I + J))) * P32 (I + J));
      pragma
        Assert
          (LV128 (T_Inner, I + J + 1)
             = LV128 (T_Inner, I + J)
               + GBV.Limb_Val (GB.LLI (T_Inner (I + J))) * P32 (I + J));
      Lemma_BI_Mul_Eq
        (GBV.Limb_Val (GB.LLI (Carry)), P32 (I + J + 1), P32 (I + J) * Base32);
   end Lemma_Mul128_Preserve;

   --  Body of Lemma_Mul128_Outer (declared early; uses the toolkit here).
   procedure Lemma_Mul128_Outer
     (T_Inner, T_AI, T_Final : Limbs128;
      A, B                   : Limbs64;
      I                      : Limb_Index;
      Carry                  : Unsigned_64)
   is
      A_Val : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (A (I)))
      with Ghost;
      LB    : constant Big.Big_Integer := LV64 (B, N_Limbs)
      with Ghost;
   begin
      --  The carry fits 32 bits, so the written limb's value is Limb_Val (Carry).
      pragma Assert ((Carry and 16#FFFF_FFFF#) = Carry);
      Lemma_LLI_Fits32 (Carry);
      --  Carry-write extension: only limb I+N_Limbs changed (= Carry).
      Lemma_LV128_Frame (T_Final, T_AI, I + N_Limbs);
      Lemma_LV128_Unfold (T_Final, I + N_Limbs + 1);
      pragma
        Assert
          (LV128 (T_Final, I + N_Limbs + 1)
             = LV128 (T_AI, I + N_Limbs)
               + GBV.Limb_Val (GB.LLI (Carry)) * P32 (I + N_Limbs));
      --  Substitute the inner-exit identity (the carry term cancels).
      pragma
        Assert
          (LV128 (T_Final, I + N_Limbs + 1)
             = LV128 (T_Inner, I + N_Limbs) + (P32 (I) * LB) * A_Val);
      --  Apply the running accumulation invariant on T_Inner.
      pragma
        Assert
          (LV128 (T_Final, I + N_Limbs + 1)
             = LV64 (A, I) * LB + (P32 (I) * LB) * A_Val);
      --  Expand LV64 (A, I+1) and rearrange to the product form.
      Lemma_LV64_Unfold (A, I + 1);
      Lemma_BI_Comm (LV64 (A, I) + A_Val * P32 (I), LB);
      Lemma_BI_Distrib (LB, LV64 (A, I), A_Val * P32 (I));
      Lemma_BI_Comm (LB, LV64 (A, I));
      Lemma_BI_Comm (LB, A_Val * P32 (I));
      Lemma_BI_Assoc (A_Val, P32 (I), LB);
      Lemma_BI_Comm (A_Val, P32 (I) * LB);
      pragma
        Assert
          (LV64 (A, I + 1) * LB = LV64 (A, I) * LB + (P32 (I) * LB) * A_Val);
   end Lemma_Mul128_Outer;

   --  Pure ring step for the OUTER Montgomery loop (EXACT, no mod). From the
   --  running invariant H1 (Lvt_Old * P_I = Av*LvB_I + Q_Old*Nv), the net
   --  per-iteration identity H2 (Lvt_New * Base32 = Lvt_Old + Av*Bi + Mv*Nv),
   --  and the B-limb unfold H3 (LvB_I1 = LvB_I + Bi*P_I), advance one B-limb:
   --  Lvt_New * (P_I*Base32) = Av*LvB_I1 + (Q_Old + Mv*P_I)*Nv.
   procedure Lemma_Mont_Step
     (Lvt_Old, Lvt_New, Av, Bi, Nv, Mv, LvB_I, LvB_I1, Q_Old, P_I :
        Big.Big_Integer)
   with
     Ghost,
     Pre  =>
       Lvt_New * Base32 = Lvt_Old + Av * Bi + Mv * Nv
       and then Lvt_Old * P_I = Av * LvB_I + Q_Old * Nv
       and then LvB_I1 = LvB_I + Bi * P_I,
     Post => Lvt_New * (P_I * Base32) = Av * LvB_I1 + (Q_Old + Mv * P_I) * Nv;

   procedure Lemma_Mont_Step
     (Lvt_Old, Lvt_New, Av, Bi, Nv, Mv, LvB_I, LvB_I1, Q_Old, P_I :
        Big.Big_Integer) is
   begin
      pragma Assert (Lvt_New * Base32 = Lvt_Old + Av * Bi + Mv * Nv);
      pragma Assert (Lvt_Old * P_I = Av * LvB_I + Q_Old * Nv);
      pragma Assert (LvB_I1 = LvB_I + Bi * P_I);
      --  LHS = (Lvt_New*Base32) * P_I.
      Lemma_BI_Comm (P_I, Base32);
      Lemma_BI_Assoc (Lvt_New, Base32, P_I);
      pragma Assert (Lvt_New * (P_I * Base32) = (Lvt_New * Base32) * P_I);
      Lemma_BI_Mul_Eq (P_I, Lvt_New * Base32, Lvt_Old + Av * Bi + Mv * Nv);
      Lemma_BI_Comm (P_I, Lvt_New * Base32);
      Lemma_BI_Comm (P_I, Lvt_Old + Av * Bi + Mv * Nv);
      Lemma_BI_Distrib (P_I, Lvt_Old + Av * Bi, Mv * Nv);
      Lemma_BI_Distrib (P_I, Lvt_Old, Av * Bi);
      Lemma_BI_Comm (P_I, Lvt_Old);
      Lemma_BI_Comm (P_I, Av * Bi);
      Lemma_BI_Comm (P_I, Mv * Nv);
      pragma
        Assert
          (Lvt_New * (P_I * Base32)
             = Lvt_Old * P_I + Av * Bi * P_I + Mv * Nv * P_I);
      --  RHS: Av*LvB_I1 + (Q_Old + Mv*P_I)*Nv.
      Lemma_BI_Distrib (Av, LvB_I, Bi * P_I);
      Lemma_BI_Assoc (Av, Bi, P_I);
      Lemma_BI_Comm (Q_Old + Mv * P_I, Nv);
      Lemma_BI_Distrib (Nv, Q_Old, Mv * P_I);
      Lemma_BI_Comm (Nv, Q_Old);
      Lemma_BI_Assoc (Mv, P_I, Nv);
      Lemma_BI_Comm (Nv, Mv * P_I);
      Lemma_BI_Assoc (Mv, Nv, P_I);
      Lemma_BI_Comm (Nv, P_I);
      pragma
        Assert
          (Av * LvB_I1 + (Q_Old + Mv * P_I) * Nv
             = Av * LvB_I + Av * Bi * P_I + Q_Old * Nv + Mv * Nv * P_I);
   end Lemma_Mont_Step;

   procedure Mont_Mul
     (A, B, N : Limbs64; Inv32 : Unsigned_32; Out_R : out Limbs64)
   with Pre => N (0) * Inv32 = 16#FFFFFFFF#
   is
      T       : Limbs66 := [others => 0];
      Acc     : Unsigned_64;
      Carry   : Unsigned_64;
      M       : Unsigned_32;
      T_Entry : Limbs66 := [others => 0]
      with Ghost;
      T_Red   : Limbs66 := [others => 0]
      with Ghost;
      Q       : Big.Big_Integer := 0
      with Ghost;
      Q_Old   : Big.Big_Integer := 0
      with Ghost;
   begin
      --  §0e value-bridge foundation: the 66-limb CIOS accumulator valuation
      --  is bounded in [0, 2^(32*66)) (anchors LV66 for the Mont_Mul proof).
      Lemma_LV66_Nonneg (T, N_Limbs + 2);
      Lemma_LV66_Upper (T, N_Limbs + 2);
      --  Base of the outer Montgomery invariant: T all-zero => LV66 = 0, so at
      --  I = 0 the invariant reads 0 * P32 (0) = A * 0 + 0 * N.
      Lemma_LV66_Zero (T, N_Limbs + 1);
      for I in Limb_Index loop
         --  Outer invariant: the top accumulator word is cleared at the end of
         --  every reduce step (and initially), so a fresh mul-add starts from
         --  T (N_Limbs + 1) = 0.  Needed by the carry-finalize value identity.
         pragma Loop_Invariant (T (N_Limbs + 1) = 0);
         --  Exact Montgomery running invariant: after I limbs of B processed,
         --  value(T) * 2^(32*I) = A * value (low I limbs of B) + Q * N, with Q
         --  the accumulated Montgomery quotient (no mod -- exact).
         pragma
           Loop_Invariant
             (LV66 (T, N_Limbs + 1) * P32 (I)
                = LV64 (A, N_Limbs) * LV64 (B, I) + Q * LV64 (N, N_Limbs));
         Q_Old := Q;
         --  T := T + A * B (I).  Inner J-loop convolution invariant (bn_mul1):
         --  the updated low J limbs plus the carry equal the original low J
         --  limbs plus A's low J limbs times the scalar B (I), at the value
         --  level (LV66/LV64 over the §0e Limb_Val bridge).
         Carry := 0;
         T_Entry := T;
         for J in Limb_Index loop
            pragma Loop_Invariant (Carry <= 16#FFFF_FFFF#);
            pragma
              Loop_Invariant
                (for all K in Limb66_Index =>
                   (if K >= J then T (K) = T_Entry (K)));
            pragma
              Loop_Invariant
                (LV66 (T, J) + GBV.Limb_Val (GB.LLI (Carry)) * P32 (J)
                   = LV66 (T_Entry, J)
                     + LV64 (A, J) * GBV.Limb_Val (GB.LLI (B (I))));
            declare
               T_Pre  : constant Limbs66 := T
               with Ghost;
               C_Old  : constant Unsigned_64 := Carry
               with Ghost;
               B_Val  : constant Big.Big_Integer :=
                 GBV.Limb_Val (GB.LLI (B (I)))
               with Ghost;
               A_Val  : constant Big.Big_Integer :=
                 GBV.Limb_Val (GB.LLI (A (J)))
               with Ghost;
               TE_Val : constant Big.Big_Integer :=
                 GBV.Limb_Val (GB.LLI (T_Entry (J)))
               with Ghost;
            begin
               pragma
                 Assert (T (J) = T_Entry (J));   --  suffix invariant, K=J.
               Acc :=
                 Unsigned_64 (T (J))
                 + Unsigned_64 (A (J)) * Unsigned_64 (B (I))
                 + Carry;
               Lemma_MulAdd_Step (T (J), A (J), B (I), Carry, Acc);
               T (J) := Unsigned_32 (Acc and 16#FFFFFFFF#);
               Carry := Shift_Right (Acc, 32);

               --  Prefix 0 .. J-1 untouched (only T (J) changed): frame LV66.
               Lemma_LV66_Frame (T, T_Pre, J);
               --  Per-step identity (Lemma_MulAdd_Step, via T (J) = low,
               --  Carry = hi, and the pre-update T (J) = T_Entry (J)).
               pragma
                 Assert
                   (GBV.Limb_Val (GB.LLI (T (J)))
                      + GBV.Limb_Val (GB.LLI (Carry)) * Base32
                      = TE_Val
                        + A_Val * B_Val
                        + GBV.Limb_Val (GB.LLI (C_Old)));
               --  Definitional unfolds at J+1.
               pragma
                 Assert
                   (LV66 (T, J + 1)
                      = LV66 (T_Pre, J)
                        + GBV.Limb_Val (GB.LLI (T (J))) * P32 (J));
               pragma
                 Assert
                   (LV66 (T_Entry, J + 1)
                      = LV66 (T_Entry, J) + TE_Val * P32 (J));
               Lemma_LV64_Unfold (A, J + 1);
               pragma Assert (P32 (J + 1) = P32 (J) * Base32);
               --  Ring step: H1 (running invariant) + P32 (J) * H2 (per-step).
               Lemma_Conv_Step
                 (Lvtpre => LV66 (T_Pre, J),
                  Lvte   => LV66 (T_Entry, J),
                  Lva    => LV64 (A, J),
                  Tj     => GBV.Limb_Val (GB.LLI (T (J))),
                  Cy     => GBV.Limb_Val (GB.LLI (Carry)),
                  Av     => A_Val,
                  Bv     => B_Val,
                  Tev    => TE_Val,
                  Cold   => GBV.Limb_Val (GB.LLI (C_Old)),
                  P      => P32 (J),
                  BaseV  => Base32);
               pragma
                 Assert
                   (LV66 (T, J + 1)
                      + GBV.Limb_Val (GB.LLI (Carry)) * P32 (J + 1)
                      = LV66 (T_Entry, J + 1) + LV64 (A, J + 1) * B_Val);
            end;
         end loop;

         --  Carry-finalize: fold the final mul-add carry into limbs 64/65,
         --  extending the convolution to the whole accumulator:
         --  LV66 (T, N_Limbs+2) = LV66 (T_Entry, N_Limbs+2) + LV64 (A) * B (I).
         declare
            T_Pre : constant Limbs66 := T
            with Ghost;
            B_Val : constant Big.Big_Integer := GBV.Limb_Val (GB.LLI (B (I)))
            with Ghost;
         begin
            --  Inner-loop exit facts (J = N_Limbs).
            pragma Assert (T (N_Limbs) = T_Entry (N_Limbs));
            pragma Assert (T (N_Limbs + 1) = T_Entry (N_Limbs + 1));
            pragma Assert (T (N_Limbs + 1) = 0);   --  outer invariant.
            pragma
              Assert
                (LV66 (T, N_Limbs)
                   + GBV.Limb_Val (GB.LLI (Carry)) * P32 (N_Limbs)
                   = LV66 (T_Entry, N_Limbs) + LV64 (A, N_Limbs) * B_Val);

            Acc := Unsigned_64 (T (N_Limbs)) + Carry;
            --  2-term carry split (Lemma_MulAdd_Step with Aj = Bi = 0).
            Lemma_MulAdd_Step (T (N_Limbs), 0, 0, Carry, Acc);
            T (N_Limbs) := Unsigned_32 (Acc and 16#FFFFFFFF#);
            T (N_Limbs + 1) :=
              T (N_Limbs + 1) + Unsigned_32 (Shift_Right (Acc, 32));

            --  Low limbs 0 .. N_Limbs-1 untouched by the finalize.
            Lemma_LV66_Frame (T, T_Pre, N_Limbs);
            pragma Assert (T_Entry (N_Limbs + 1) = 0);   --  outer invariant.
            --  Top word is just the carry-out (started at 0), so <= 1: the
            --  reduce-step shift later folds it without overflow.
            pragma Assert (T (N_Limbs + 1) <= 1);
            --  U64-level: the stored words equal Acc's low / high halves
            --  (T (N_Limbs+1) started at 0, so the add is 0 + carry-out).
            pragma
              Assert (Unsigned_64 (T (N_Limbs)) = (Acc and 16#FFFF_FFFF#));
            pragma
              Assert (Unsigned_64 (T (N_Limbs + 1)) = Shift_Right (Acc, 32));
            --  Hence the Limb_Val images match the per-step split exactly.
            pragma
              Assert
                (GBV.Limb_Val (GB.LLI (T (N_Limbs)))
                   = GBV.Limb_Val
                       (GB.LLI (Unsigned_32 (Acc and 16#FFFF_FFFF#))));
            pragma
              Assert (T (N_Limbs + 1) = Unsigned_32 (Shift_Right (Acc, 32)));
            Lemma_LLI_Fits32 (Shift_Right (Acc, 32));
            pragma
              Assert
                (GBV.Limb_Val (GB.LLI (T (N_Limbs + 1)))
                   = GBV.Limb_Val (GB.LLI (Shift_Right (Acc, 32))));
            --  LV66 unfolds at N_Limbs+1, N_Limbs+2 (both T and T_Entry).
            Lemma_LV66_Unfold (T, N_Limbs + 1);
            Lemma_LV66_Unfold (T, N_Limbs + 2);
            Lemma_LV66_Unfold (T_Entry, N_Limbs + 1);
            Lemma_LV66_Unfold (T_Entry, N_Limbs + 2);
            pragma Assert (P32 (N_Limbs + 1) = P32 (N_Limbs) * Base32);
            --  Ring step (reuse Lemma_Conv_Step with the A-coefficient = 0).
            Lemma_Conv_Step
              (Lvtpre => LV66 (T_Pre, N_Limbs),
               Lvte   => LV66 (T_Entry, N_Limbs),
               Lva    => LV64 (A, N_Limbs),
               Tj     => GBV.Limb_Val (GB.LLI (T (N_Limbs))),
               Cy     => GBV.Limb_Val (GB.LLI (T (N_Limbs + 1))),
               Av     => GBV.Limb_Val (0),
               Bv     => B_Val,
               Tev    => GBV.Limb_Val (GB.LLI (T_Entry (N_Limbs))),
               Cold   => GBV.Limb_Val (GB.LLI (Carry)),
               P      => P32 (N_Limbs),
               BaseV  => Base32);
            --  Assemble: unfold both sides and drop the (zero) top T_Entry word.
            pragma Assert (GBV.Limb_Val (GB.LLI (T_Entry (N_Limbs + 1))) = 0);
            --  LHS unfold, step by step (frame + two LV66 unfolds + P32 step).
            pragma Assert (LV66 (T, N_Limbs) = LV66 (T_Pre, N_Limbs));
            pragma
              Assert
                (LV66 (T, N_Limbs + 1)
                   = LV66 (T_Pre, N_Limbs)
                     + GBV.Limb_Val (GB.LLI (T (N_Limbs))) * P32 (N_Limbs));
            pragma
              Assert
                (LV66 (T, N_Limbs + 2)
                   = LV66 (T, N_Limbs + 1)
                     + GBV.Limb_Val (GB.LLI (T (N_Limbs + 1)))
                       * P32 (N_Limbs + 1));
            pragma
              Assert
                (GBV.Limb_Val (GB.LLI (T (N_Limbs + 1))) * P32 (N_Limbs + 1)
                   = GBV.Limb_Val (GB.LLI (T (N_Limbs + 1)))
                     * (P32 (N_Limbs) * Base32));
            pragma
              Assert
                (LV66 (T, N_Limbs + 2)
                   = LV66 (T_Pre, N_Limbs)
                     + GBV.Limb_Val (GB.LLI (T (N_Limbs))) * P32 (N_Limbs)
                     + GBV.Limb_Val (GB.LLI (T (N_Limbs + 1)))
                       * (P32 (N_Limbs) * Base32));
            pragma
              Assert
                (LV66 (T_Entry, N_Limbs + 2)
                   = LV66 (T_Entry, N_Limbs)
                     + GBV.Limb_Val (GB.LLI (T_Entry (N_Limbs)))
                       * P32 (N_Limbs));
            --  The A-coefficient term vanishes (Limb_Val (0) = 0).
            pragma Assert (GBV.Limb_Val (0) = 0);
            pragma
              Assert
                ((LV64 (A, N_Limbs) + GBV.Limb_Val (0) * P32 (N_Limbs)) * B_Val
                   = LV64 (A, N_Limbs) * B_Val);
            --  Conv_Step RHS (right side of its Post) equals the goal RHS.
            pragma
              Assert
                ((LV66 (T_Entry, N_Limbs)
                  + GBV.Limb_Val (GB.LLI (T_Entry (N_Limbs))) * P32 (N_Limbs))
                   + (LV64 (A, N_Limbs) + GBV.Limb_Val (0) * P32 (N_Limbs))
                     * B_Val
                   = LV66 (T_Entry, N_Limbs + 2) + LV64 (A, N_Limbs) * B_Val);
            --  Conv_Step LHS equals LV66 (T, N_Limbs+2) (unfold + frame).
            pragma
              Assert
                ((LV66 (T_Pre, N_Limbs)
                  + GBV.Limb_Val (GB.LLI (T (N_Limbs))) * P32 (N_Limbs))
                   + GBV.Limb_Val (GB.LLI (T (N_Limbs + 1)))
                     * (P32 (N_Limbs) * Base32)
                   = LV66 (T, N_Limbs + 2));
            pragma
              Assert
                (LV66 (T, N_Limbs + 2)
                   = LV66 (T_Entry, N_Limbs + 2) + LV64 (A, N_Limbs) * B_Val);
         end;

         --  m := T (0) * Inv32 mod 2^32. This is the multiplier that
         --  makes T + m*N divisible by 2^32, so T (0) becomes zero
         --  and we can shift right by one limb.
         M := T (0) * Inv32;
         --  CIOS invariant foundation: the low limb of T + M*N vanishes.
         Lemma_Low_Limb_Killed (T (0), N (0), Inv32);
         pragma Assert (T (0) + M * N (0) = 0);
         --  Accumulate the Montgomery quotient (exact running invariant).
         Q := Q_Old + GBV.Limb_Val (GB.LLI (M)) * P32 (I);

         --  T := (T + M * N) / 2^32 (the division is the limb shift). T_Red
         --  snapshots the pre-reduce accumulator; the shift loop writes T (J-1)
         --  and leaves limbs >= J-1 equal to T_Red until they are consumed.
         T_Red := T;
         pragma Assert (T_Red (N_Limbs + 1) <= 1);   --  carry-out bound.
         --  Carry the mul-add identity (A) onto the reduce snapshot T_Red.
         pragma
           Assert
             (LV66 (T_Red, N_Limbs + 2)
                = LV66 (T_Entry, N_Limbs + 2)
                  + LV64 (A, N_Limbs) * GBV.Limb_Val (GB.LLI (B (I))));
         Carry := 0;
         --  J = 0: low half of T (0) + M * N (0) + carry. Result's low
         --  half is discarded (it is zero by construction); only the
         --  carry into the next limb matters.
         Acc :=
           Unsigned_64 (T (0)) + Unsigned_64 (M) * Unsigned_64 (N (0)) + Carry;
         Lemma_MulAdd_Step (T (0), M, N (0), Carry, Acc);
         pragma
           Assert (Unsigned_32 (Acc and 16#FFFF_FFFF#) = T (0) + M * N (0));
         pragma Assert (Unsigned_32 (Acc and 16#FFFF_FFFF#) = 0);   --  kill.
         Carry := Shift_Right (Acc, 32);
         --  INV (1): the J=0 low limb vanished; the carry holds the value.
         Lemma_LV66_Unfold (T_Red, 1);
         Lemma_LV64_Unfold (N, 1);
         GBV.Lemma_Limb_Val_Succ (0);            --  Limb_Val (1) = 1.
         pragma Assert (P32 (0) = 1);
         pragma Assert (P32 (1) = Base32);
         pragma Assert (T_Red (0) = T (0));
         pragma
           Assert
             (GBV.Limb_Val (GB.LLI (Unsigned_32 (Acc and 16#FFFF_FFFF#))) = 0);
         --  MulAdd image with the low word zero and carry-in zero.
         pragma
           Assert
             (GBV.Limb_Val (GB.LLI (Carry)) * Base32
                = GBV.Limb_Val (GB.LLI (T (0)))
                  + GBV.Limb_Val (GB.LLI (M)) * GBV.Limb_Val (GB.LLI (N (0))));
         pragma Assert (LV66 (T_Red, 1) = GBV.Limb_Val (GB.LLI (T_Red (0))));
         pragma Assert (LV64 (N, 1) = GBV.Limb_Val (GB.LLI (N (0))));
         pragma Assert (Base32 * LV66 (T, 0) = 0);
         pragma
           Assert
             (LV66 (T_Red, 1) + GBV.Limb_Val (GB.LLI (M)) * LV64 (N, 1)
                = Base32
                  * LV66 (T, 0)
                  + GBV.Limb_Val (GB.LLI (Carry)) * P32 (1));
         for J in 1 .. N_Limbs - 1 loop
            pragma Loop_Invariant (Carry <= 16#FFFF_FFFF#);
            pragma
              Loop_Invariant
                (for all K in Limb66_Index =>
                   (if K >= J - 1 then T (K) = T_Red (K)));
            pragma
              Loop_Invariant
                (LV66 (T_Red, J) + GBV.Limb_Val (GB.LLI (M)) * LV64 (N, J)
                   = Base32
                     * LV66 (T, J - 1)
                     + GBV.Limb_Val (GB.LLI (Carry)) * P32 (J));
            declare
               T_Pre : constant Limbs66 := T
               with Ghost;
               C_Old : constant Unsigned_64 := Carry
               with Ghost;
            begin
               Acc :=
                 Unsigned_64 (T (J))
                 + Unsigned_64 (M) * Unsigned_64 (N (J))
                 + Carry;
               T (J - 1) := Unsigned_32 (Acc and 16#FFFFFFFF#);
               Carry := Shift_Right (Acc, 32);
               --  Preservation: discharged by the clean-context lemma.
               Lemma_Reduce_Preserve
                 (T_Pre, T, T_Red, N, M, C_Old, Acc, Carry, J);
            end;
         end loop;
         --  Convolution invariant at loop exit (J = N_Limbs): the low N_Limbs
         --  limbs of T_Red + M*N have been folded and shifted into T (0..62).
         pragma
           Assert
             (LV66 (T_Red, N_Limbs)
                + GBV.Limb_Val (GB.LLI (M)) * LV64 (N, N_Limbs)
                = Base32
                  * LV66 (T, N_Limbs - 1)
                  + GBV.Limb_Val (GB.LLI (Carry)) * P32 (N_Limbs));
         declare
            T_Loop     : constant Limbs66 := T
            with Ghost;
            Carry_Loop : constant Unsigned_64 := Carry
            with Ghost;
         begin
            --  Loop-exit suffix facts (J = N_Limbs).
            pragma Assert (T (N_Limbs) = T_Red (N_Limbs));
            pragma Assert (T (N_Limbs + 1) = T_Red (N_Limbs + 1));
            Acc := Unsigned_64 (T (N_Limbs)) + Carry;
            T (N_Limbs - 1) := Unsigned_32 (Acc and 16#FFFFFFFF#);
            Carry := Shift_Right (Acc, 32);
            T (N_Limbs) := T (N_Limbs + 1) + Unsigned_32 (Carry);
            T (N_Limbs + 1) := 0;
            --  Full reduce identity: Base32 * value (T) = T_Red + M*N.
            Lemma_Reduce_Finalize
              (T_Loop, T, T_Red, N, M, Carry_Loop, Acc, Carry);
            pragma
              Assert
                (Base32 * LV66 (T, N_Limbs + 1)
                   = LV66 (T_Red, N_Limbs + 2)
                     + GBV.Limb_Val (GB.LLI (M)) * LV64 (N, N_Limbs));
            --  Net per-iteration identity (compose mul-add A + reduce B):
            --  the new T, times R-step Base32, is the old T (T_Entry) plus
            --  A*B(I) plus M*N -- the exact CIOS step before reduction mod N.
            pragma
              Assert
                (Base32 * LV66 (T, N_Limbs + 1)
                   = LV66 (T_Entry, N_Limbs + 2)
                     + LV64 (A, N_Limbs) * GBV.Limb_Val (GB.LLI (B (I)))
                     + GBV.Limb_Val (GB.LLI (M)) * LV64 (N, N_Limbs));
            --  Outer Montgomery invariant preservation (exact, via the
            --  accumulated quotient Q).  T_Entry top word is 0, so its
            --  N_Limbs+2 and N_Limbs+1 valuations agree.
            Lemma_LV66_Unfold (T_Entry, N_Limbs + 2);
            pragma
              Assert
                (LV66 (T_Entry, N_Limbs + 2) = LV66 (T_Entry, N_Limbs + 1));
            --  inv (I) on the outer snapshot (T_Entry = T at loop top).
            pragma
              Assert
                (LV66 (T_Entry, N_Limbs + 1) * P32 (I)
                   = LV64 (A, N_Limbs)
                     * LV64 (B, I)
                     + Q_Old * LV64 (N, N_Limbs));
            --  Net identity in Lvt_New*Base32 form.
            Lemma_BI_Comm (Base32, LV66 (T, N_Limbs + 1));
            pragma
              Assert
                (LV66 (T, N_Limbs + 1) * Base32
                   = LV66 (T_Entry, N_Limbs + 1)
                     + LV64 (A, N_Limbs) * GBV.Limb_Val (GB.LLI (B (I)))
                     + GBV.Limb_Val (GB.LLI (M)) * LV64 (N, N_Limbs));
            Lemma_LV64_Unfold (B, I + 1);
            Lemma_Mont_Step
              (Lvt_Old => LV66 (T_Entry, N_Limbs + 1),
               Lvt_New => LV66 (T, N_Limbs + 1),
               Av      => LV64 (A, N_Limbs),
               Bi      => GBV.Limb_Val (GB.LLI (B (I))),
               Nv      => LV64 (N, N_Limbs),
               Mv      => GBV.Limb_Val (GB.LLI (M)),
               LvB_I   => LV64 (B, I),
               LvB_I1  => LV64 (B, I + 1),
               Q_Old   => Q_Old,
               P_I     => P32 (I));
            pragma Assert (P32 (I + 1) = P32 (I) * Base32);
            --  LHS: rewrite LV66 * P32 (I+1) into the LV66 * (P32 (I)*Base32)
            --  shape Lemma_Mont_Step produced (gnatprove won't push the
            --  P32 (I+1) = P32 (I)*Base32 equality through the product inline).
            Lemma_BI_Mul_Eq
              (LV66 (T, N_Limbs + 1), P32 (I + 1), P32 (I) * Base32);
            --  RHS: Q = Q_Old + Limb_Val (M) * P32 (I), so the accumulated
            --  quotient term matches Lemma_Mont_Step's (Q_Old + Mv*P_I)*Nv.
            Lemma_BI_Mul_Eq
              (LV64 (N, N_Limbs),
               Q,
               Q_Old + GBV.Limb_Val (GB.LLI (M)) * P32 (I));
            Lemma_BI_Comm (LV64 (N, N_Limbs), Q);
            Lemma_BI_Comm
              (LV64 (N, N_Limbs), Q_Old + GBV.Limb_Val (GB.LLI (M)) * P32 (I));
            pragma
              Assert
                (LV66 (T, N_Limbs + 1) * P32 (I + 1)
                   = LV64 (A, N_Limbs)
                     * LV64 (B, I + 1)
                     + Q * LV64 (N, N_Limbs));
         end;
      end loop;

      --  T now holds A*B*R^-1 mod N, possibly with one extra N. The
      --  value lives in T (0 .. N_Limbs); the top word (T (N_Limbs))
      --  is at most 1.
      declare
         T64      : Limbs64;
         Top      : constant Unsigned_32 := T (N_Limbs);
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
                  Diff := Unsigned_64 (T64 (J)) - Unsigned_64 (N (J)) - Borrow;
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
         RL := [others => 0];
      else
         Limb_Mod_Mul (AL, BL, NL, RL);
      end if;
      --  §0e value-bridge foundation (consumed by the in-progress Mod_Mul
      --  functional proof; for now anchors the limb valuation bounds).
      Lemma_LV64_Nonneg (RL, N_Limbs);
      Lemma_LV64_Upper (RL, N_Limbs);
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
      Result     : Limbs64 := [others => 0];
      Tmp        : Limbs64;
      Bit        : Unsigned_32;
      Limb_Word  : Unsigned_32;
   begin
      From_Bytes (Base, BL);
      From_Bytes (Exp, EL);
      From_Bytes (N, NL);

      --  Edge cases: N = 0 (illegal — return zero per the ads), or
      --  N = 1 (everything is 0 mod 1), or N even (Montgomery needs
      --  gcd(N, R)=1; RSA moduli are odd, but be defensive). For an
      --  even N we have no fast path; return zero rather than risk
      --  a divergent computation. (Callers verify the modulus shape
      --  earlier in the RSA pipeline.)
      if Is_Zero64 (NL) or else (NL (0) and 1) = 0 then
         Result := [others => 0];
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
            Result := [others => 0];
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
         Inv32    : constant Unsigned_32 := N0_Inv (NL);
         R2       : Limbs64;
         One_L    : Limbs64 := [others => 0];
         Base_M   : Limbs64;
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
         pragma
           Loop_Invariant
             (Diff = 0
                xor (for some K in Bigint'First .. I => A (K) /= B (K)));
      end loop;
      return Diff = 0;
   end Equal_CT;

end Tls_Core.Bignum_2048;
