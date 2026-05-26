with Ada.Unchecked_Conversion;

package body Tls_Core.Field25519
  with SPARK_Mode
is

   use Interfaces;

   package GB renames Tls_Core.Ghost_Bignum;
   package GBV renames Tls_Core.Ghost_Bignum.Value;

   ---------------------------------------------------------------------
   --  Ghost spec layer — bodies for Spec functions declared in the
   --  spec file. Computable, no stub returns. §0e-clean: the limb /
   --  power ingress is Ghost_Bignum.Value.Limb_Val (unit recursion),
   --  never the SPARK_Mode-Off To_Big_Integer, so the limb-array
   --  valuation never bounces off the opaque ingress.
   ---------------------------------------------------------------------

   function Limb_Big (X : Integer_64) return Big.Big_Integer
   is (GBV.Limb_Val (GB.LLI (X)));

   function Pow_2_16 (N : Natural) return Big.Big_Integer is
   begin
      if N = 0 then
         GBV.Lemma_Limb_Val_Succ (0);             --  Limb_Val (1) = 1 > 0.
         return GBV.Limb_Val (1);
      else
         GBV.Lemma_Limb_Val_Succ (0);             --  Limb_Val (1) = 1.
         GBV.Lemma_Limb_Val_Mono
           (1, 65536);      --  Limb_Val (65536) >= 1 > 0.
         return Pow_2_16 (N - 1) * GBV.Limb_Val (65536);
      end if;
   end Pow_2_16;

   function Prime_P_Spec return Big.Big_Integer
   is (Big.To_Big_Integer (2)**255 - Big.To_Big_Integer (19));

   function Mod_P_Spec (X : Big.Big_Integer) return Big.Big_Integer
   is (X mod Prime_P_Spec);

   subtype Big_Index is Natural range 0 .. 30;
   type Big_Buf is array (Big_Index) of Integer_64;

   --  Bitwise reinterpret between the signed and unsigned 64-bit
   --  views. Two's-complement is the wire-level convention; this
   --  is just a pun, not a value conversion.
   function To_U64 is new Ada.Unchecked_Conversion (Integer_64, Unsigned_64);
   function To_I64 is new Ada.Unchecked_Conversion (Unsigned_64, Integer_64);

   --  Arithmetic right shift on Integer_64 — Ada's `/` truncates
   --  toward zero, not toward -inf. Reinterpret-cast through
   --  Unsigned_64 to invoke Interfaces.Shift_Right_Arithmetic.
   function Asr (X : Integer_64; N : Natural) return Integer_64
   is (To_I64 (Shift_Right_Arithmetic (To_U64 (X), N)));

   function And_64 (X, Y : Integer_64) return Integer_64
   is (To_I64 (To_U64 (X) and To_U64 (Y)));

   ---------------------------------------------------------------------
   --  Bit-level bound lemmas (proved via SPARK's modular bit-vector model
   --  of the Unchecked_Conversion puns; mirror HACL\* carry-bound reasoning).
   ---------------------------------------------------------------------

   --  For a non-negative B-bounded limb, the arithmetic shift-right is the
   --  non-negative floor quotient, in 0 .. B / 2**16.
   procedure Lemma_Asr16_Nonneg (X : Integer_64; B : Integer_64)
   with
     Ghost,
     Global => null,
     Pre    => B in 0 .. 2**62 and then X in 0 .. B,
     Post   => Asr (X, 16) in 0 .. B / 2**16;

   procedure Lemma_Asr16_Nonneg (X : Integer_64; B : Integer_64) is
      U : constant Unsigned_64 := To_U64 (X);
   begin
      --  X >= 0 so the unsigned view equals X numerically and has bit 63 clear;
      --  for such a value the arithmetic shift right is the logical shift,
      --  which the bit-vector theory equates to division by 2**16.
      pragma Assert (U = Unsigned_64 (X));
      pragma Assert (U <= Unsigned_64 (B));
      pragma Assert (U < 2**63);
      pragma Assert (Shift_Right_Arithmetic (U, 16) = Shift_Right (U, 16));
      pragma Assert (Shift_Right (U, 16) = U / 2**16);
      pragma Assert (To_I64 (Shift_Right_Arithmetic (U, 16)) = Asr (X, 16));
      pragma Assert (Asr (X, 16) = Integer_64 (U / 2**16));
      pragma
        Assert
          (Integer_64 (U / 2**16) <= Integer_64 (Unsigned_64 (B) / 2**16));
      pragma Assert (Integer_64 (Unsigned_64 (B) / 2**16) = B / 2**16);
   end Lemma_Asr16_Nonneg;

   --  Arithmetic shift-right-by-16 of a B-bounded signed limb is bounded by
   --  B / 2**16 + 1.
   procedure Lemma_Asr16_Bound (X : Integer_64; B : Integer_64)
   with
     Ghost,
     Global => null,
     Pre    => B in 0 .. 2**62 and then X in -B .. B,
     Post   => Asr (X, 16) in -(B / 2**16 + 1) .. B / 2**16 + 1;

   procedure Lemma_Asr16_Bound (X : Integer_64; B : Integer_64) is
      U : constant Unsigned_64 := To_U64 (X);
   begin
      if X >= 0 then
         Lemma_Asr16_Nonneg (X, B);
         pragma Assert (Asr (X, 16) >= -(B / 2**16 + 1));
      else
         --  X < 0: two's-complement U = 2**64 + X >= 2**63, and the arithmetic
         --  shift sign-extends, so S = U / 2**16 + 16#FFFF# * 2**48 and the
         --  signed view To_I64 (S) = U / 2**16 - 2**48 (>= -(B/2**16 + 1)).
         pragma Assert (U >= 2**63);
         --  U = 2**64 + X >= 2**64 - B, written without the out-of-range 2**64.
         pragma Assert (U >= Unsigned_64'Last - Unsigned_64 (B - 1));
         pragma
           Assert
             (Shift_Right_Arithmetic (U, 16)
                = Shift_Right (U, 16) + 16#FFFF# * 2**48);
         pragma Assert (Shift_Right (U, 16) = U / 2**16);
         pragma
           Assert
             (To_I64 (Shift_Right_Arithmetic (U, 16))
                = Integer_64 (U / 2**16) - 2**48);
         pragma Assert (To_I64 (Shift_Right_Arithmetic (U, 16)) = Asr (X, 16));
         pragma Assert (Asr (X, 16) <= -1);
         pragma Assert (Integer_64 (U / 2**16) >= 2**48 - (B / 2**16 + 1));
         pragma Assert (Asr (X, 16) >= -(B / 2**16 + 1));
      end if;
   end Lemma_Asr16_Bound;

   --  The carry split: X - (Asr (X,16) << 16) is X's low 16 bits, the
   --  non-negative remainder in 0 .. 2**16-1, and equals And_64 (X, 0xFFFF).
   --  Proved entirely on the Unsigned_64 bit-vector view (the residue of an
   --  arithmetic shift-right then left is the masked low bits), then the
   --  signed difference is recovered from the unsigned identity.
   procedure Lemma_Carry_Reduce (X : Integer_64)
   with
     Ghost,
     Global => null,
     Post   =>
       X - To_I64 (Shift_Left (To_U64 (Asr (X, 16)), 16))
       = And_64 (X, 16#FFFF#)
       and then And_64 (X, 16#FFFF#) in 0 .. 2**16 - 1;

   procedure Lemma_Carry_Reduce (X : Integer_64) is
      U  : constant Unsigned_64 := To_U64 (X);
      Hi : constant Unsigned_64 :=
        Shift_Left (Shift_Right_Arithmetic (U, 16), 16);
      Lo : constant Unsigned_64 := U and 16#FFFF#;
   begin
      --  Bit-vector identities (decidable in the U64 model):
      pragma
        Assert (U = Hi + Lo);          --  shift-out + masked-low reassemble
      pragma Assert (Lo <= 16#FFFF#);       --  the mask bounds the low part
      --  Hi is exactly the punned (Asr (X,16) << 16); Lo = And_64 (X, 0xFFFF).
      pragma Assert (To_U64 (Asr (X, 16)) = Shift_Right_Arithmetic (U, 16));
      pragma Assert (To_I64 (Lo) = And_64 (X, 16#FFFF#));
      pragma Assert (To_I64 (U) = X);
      --  2's-complement add-homomorphism: To_I64 (Hi) + To_I64 (Lo)
      --  = To_I64 (Hi + Lo) = To_I64 (U) = X, so X - To_I64 (Hi) = To_I64 (Lo).
      pragma Assert (To_I64 (Hi) + To_I64 (Lo) = To_I64 (U));
   end Lemma_Carry_Reduce;

   --  And_64 with a concrete low-bit mask lands in 0 .. mask (a bit-vector
   --  fact on the pun model).  Concrete masks (no symbolic 2**N) keep the
   --  exponentiation out of the VCs.  Used for the borrow bit (1), the 16-bit
   --  limb mask (16#FFFF#) and the byte mask (16#FF#).
   procedure Lemma_And_1 (X : Integer_64)
   with Ghost, Global => null, Post => And_64 (X, 1) in 0 .. 1;

   procedure Lemma_And_1 (X : Integer_64) is
      U : constant Unsigned_64 := To_U64 (X);
   begin
      pragma Assert ((U and 1) <= 1);
      pragma Assert (To_I64 (U and 1) = And_64 (X, 1));
   end Lemma_And_1;

   procedure Lemma_And_FFFF (X : Integer_64)
   with Ghost, Global => null, Post => And_64 (X, 16#FFFF#) in 0 .. 16#FFFF#;

   procedure Lemma_And_FFFF (X : Integer_64) is
      U : constant Unsigned_64 := To_U64 (X);
   begin
      pragma Assert ((U and 16#FFFF#) <= 16#FFFF#);
      pragma Assert (To_I64 (U and 16#FFFF#) = And_64 (X, 16#FFFF#));
   end Lemma_And_FFFF;

   procedure Lemma_And_FF (X : Integer_64)
   with Ghost, Global => null, Post => And_64 (X, 16#FF#) in 0 .. 16#FF#;

   procedure Lemma_And_FF (X : Integer_64) is
      U : constant Unsigned_64 := To_U64 (X);
   begin
      pragma Assert ((U and 16#FF#) <= 16#FF#);
      pragma Assert (To_I64 (U and 16#FF#) = And_64 (X, 16#FF#));
   end Lemma_And_FF;

   ---------------------------------------------------------------------
   --  Carry
   --
   --  AoRTE / felem_fits half (the Equiv_Spec mod-p conjunct is left
   --  honest-unproven — that is the 2^255-19 value-layer reduce algebra).
   --
   --  The loop threads three families of limb bounds:
   --    * limbs already processed (K < I) are reduced to 0 .. 2**16-1;
   --    * limb I is the current working limb (its incoming carry added);
   --    * limbs not yet reached (K > I) keep their (signed) input bound.
   --  Two passes are modelled: a wide input (In_Felem .. Carry_In_Cap) gives
   --  a Carried (.,Carry_Out_Cap) output; a once-carried input
   --  (Carried .. Carry_Out_Cap) gives the tight Carried (.,Reduced_Cap),
   --  because in that pass the propagating carry collapses to <= 1 past
   --  limb 2, so the 38× top-fold into limb 0 is < 2**17.
   ---------------------------------------------------------------------

   procedure Carry (O : in out Felt) is
      C        : Integer_64;
      --  The current limb may carry one inbound carry (< 2**40) on top of its
      --  original (<= Carry_In_Cap) magnitude; < 2**56, so every sum fits.
      Work_Cap : constant Integer_64 := Carry_In_Cap + 2**40;
      --  Whether the input is already once-carried (Carried, Carry_Out_Cap):
      --  the tight second pass collapses the carry to <= 1 past limb 2.
      Narrow   : constant Boolean := Carried (O, Carry_Out_Cap)
      with Ghost;
      --  Position-aware working bound on limb I in the narrow pass: only limb 0
      --  is large; the carry it spills shrinks to <= 1 from limb 3 on, so the
      --  38× top-fold back into limb 0 is <= 38 and the output is tight.
      function Narrow_Work (I : Felt_Index) return Integer_64
      is (if I = 0
          then Carry_Out_Cap
          elsif I = 1
          then 2**16 - 1 + 2**29
          elsif I = 2
          then 2**16 - 1 + 2**14
          else 2**16)
      with Ghost;

      --  Refine the carry magnitude on the narrow pass: limb I is
      --  Narrow_Work (I)-bounded and non-negative, so Cr = Asr (O(I),16) is in
      --  0 .. Narrow_Work (I) / 2**16 — the position-shrinking carry chain.
      procedure Lemma_Narrow_Carry (F : Felt; Cr : Integer_64; I : Felt_Index)
      with
        Ghost,
        Global => (Input => Narrow),
        Pre    =>
          Cr = Asr (F (I), 16)
          and then (if Narrow then F (I) in 0 .. Narrow_Work (I)),
        Post   => (if Narrow then Cr in 0 .. Narrow_Work (I) / 2**16);

      procedure Lemma_Narrow_Carry (F : Felt; Cr : Integer_64; I : Felt_Index)
      is
      begin
         if Narrow then
            Lemma_Asr16_Nonneg (F (I), Narrow_Work (I));
            --  Cr = Asr (F(I),16) (Pre), now bounded by the floor quotient.
            pragma Assert (Cr in 0 .. Narrow_Work (I) / 2**16);
         end if;
      end Lemma_Narrow_Carry;
   begin
      for I in Felt_Index loop
         --  Strictly-above limbs are untouched (original bound).
         pragma
           Loop_Invariant
             (for all K in Felt_Index =>
                (if K > I then O (K) in -Carry_In_Cap .. Carry_In_Cap));
         --  The current limb may already carry one inbound carry.
         pragma Loop_Invariant (O (I) in -Work_Cap .. Work_Cap);
         --  Limbs already processed are reduced to the low 16 bits.
         pragma
           Loop_Invariant
             (for all K in Felt_Index =>
                (if K < I then O (K) in 0 .. 2**16 - 1));
         --  Narrow pass: the unreached limbs (>= 1) keep their 16-bit Carried
         --  shape, and the current working limb is position-bounded.
         pragma
           Loop_Invariant
             (if Narrow
                then
                  O (I) in 0 .. Narrow_Work (I)
                  and then (for all K in Felt_Index =>
                              (if K > I and then K >= 1
                               then O (K) in 0 .. 2**16 - 1)));

         Lemma_Asr16_Bound
           (O (I), Work_Cap);   --  |C| <= Work_Cap/2**16 < 2**40.
         C := Asr (O (I), 16);
         Lemma_Carry_Reduce
           (O (I));            --  low-16 residue, in 0..2**16-1.

         --  Narrow pass: the carry out of limb I is the non-negative floor
         --  quotient of a Narrow_Work (I)-bounded value, so it is small enough
         --  that the next limb stays within Narrow_Work (I+1).
         Lemma_Narrow_Carry (O, C, I);

         O (I) := O (I) - To_I64 (Shift_Left (To_U64 (C), 16));
         if I < 15 then
            O (I + 1) := O (I + 1) + C;
         else
            --  Narrow pass: C = C_15 <= Narrow_Work (15) / 2**16 = 1, so the
            --  38× fold back into the (already 16-bit) limb 0 is <= 38, hence
            --  the output limb 0 is < 2**17 = Reduced_Cap.
            O (0) :=
              O (0) + 38 * C;            --  38 * (top fold) into limb 0.
         end if;
      end loop;
   end Carry;

   ---------------------------------------------------------------------
   --  F_Add / F_Sub
   --
   --  Per-limb additivity / subtractivity of the §0e-clean ingress, lifted
   --  from Ghost_Bignum.Value.Limb_Val's additivity pillar. Bounds keep the
   --  Integer_64 sum/difference inside Val_Int = -2**110 .. 2**110.
   ---------------------------------------------------------------------

   procedure Lemma_Limb_Big_Add (X, Y : Integer_64)
   with
     Ghost,
     Global => null,
     Pre    =>
       X in -F_Add_Cap .. F_Add_Cap and then Y in -F_Add_Cap .. F_Add_Cap,
     Post   => Limb_Big (X + Y) = Limb_Big (X) + Limb_Big (Y);

   procedure Lemma_Limb_Big_Add (X, Y : Integer_64) is
   begin
      --  Integer_64 -> LLI is a homomorphism (no overflow under the Pre):
      --  LLI (X + Y) = LLI (X) + LLI (Y), then Limb_Val additivity.
      pragma Assert (GB.LLI (X + Y) = GB.LLI (X) + GB.LLI (Y));
      GBV.Lemma_Limb_Val_Add (GB.LLI (X), GB.LLI (Y));
   end Lemma_Limb_Big_Add;

   procedure Lemma_Limb_Big_Sub (X, Y : Integer_64)
   with
     Ghost,
     Global => null,
     Pre    =>
       X in -F_Add_Cap .. F_Add_Cap and then Y in -F_Add_Cap .. F_Add_Cap,
     Post   => Limb_Big (X - Y) = Limb_Big (X) - Limb_Big (Y);

   procedure Lemma_Limb_Big_Sub (X, Y : Integer_64) is
   begin
      pragma Assert (GB.LLI (X - Y) = GB.LLI (X) - GB.LLI (Y));
      GBV.Lemma_Limb_Val_Add (GB.LLI (X - Y), GB.LLI (Y));
      --  Limb_Val (LLI (X-Y) + LLI (Y))
      --     = Limb_Val (LLI (X-Y)) + Limb_Val (LLI (Y)),
      --  and LLI (X-Y) + LLI (Y) = LLI (X), so rearrange.
      pragma Assert (GB.LLI (X - Y) + GB.LLI (Y) = GB.LLI (X));
   end Lemma_Limb_Big_Sub;

   --  Linearity of To_Big_Up_To: a felt whose low-N limbs are the limbwise
   --  sum (difference) of A and B has prefix value the sum (difference) of
   --  the prefix values. Recursion on N; each step is one Limb_Big additivity
   --  lemma. (HACL\* Field51: as_nat is linear under fadd5 / fsub5.)
   procedure Lemma_To_Big_Add (O, A, B : Felt; N : Natural)
   with
     Ghost,
     Global             => null,
     Pre                =>
       N <= 16
       and then In_Felem (A, F_Add_Cap)
       and then In_Felem (B, F_Add_Cap)
       and then (for all K in Felt_Index =>
                   (if K < N then O (K) = A (K) + B (K))),
     Post               =>
       To_Big_Up_To (O, N) = To_Big_Up_To (A, N) + To_Big_Up_To (B, N),
     Subprogram_Variant => (Decreases => N);

   procedure Lemma_To_Big_Add (O, A, B : Felt; N : Natural) is
   begin
      if N = 0 then
         null;
      else
         Lemma_To_Big_Add (O, A, B, N - 1);   --  IH on the N-1 prefix.
         Lemma_Limb_Big_Add (A (N - 1), B (N - 1));
         --  To_Big_Up_To (O,N) = To_Big_Up_To (O,N-1) + Limb_Big (O(N-1))*W,
         --  O(N-1) = A(N-1)+B(N-1), and Limb_Big distributes over the sum.
      end if;
   end Lemma_To_Big_Add;

   procedure Lemma_To_Big_Sub (O, A, B : Felt; N : Natural)
   with
     Ghost,
     Global             => null,
     Pre                =>
       N <= 16
       and then In_Felem (A, F_Add_Cap)
       and then In_Felem (B, F_Add_Cap)
       and then (for all K in Felt_Index =>
                   (if K < N then O (K) = A (K) - B (K))),
     Post               =>
       To_Big_Up_To (O, N) = To_Big_Up_To (A, N) - To_Big_Up_To (B, N),
     Subprogram_Variant => (Decreases => N);

   procedure Lemma_To_Big_Sub (O, A, B : Felt; N : Natural) is
   begin
      if N = 0 then
         null;
      else
         Lemma_To_Big_Sub (O, A, B, N - 1);
         Lemma_Limb_Big_Sub (A (N - 1), B (N - 1));
      end if;
   end Lemma_To_Big_Sub;

   procedure F_Add (O : out Felt; A, B : Felt) is
   begin
      O := A;
      for I in Felt_Index loop
         O (I) := A (I) + B (I);
         pragma
           Loop_Invariant
             (for all K in Felt_Index =>
                (if K <= I then O (K) = A (K) + B (K)));
         pragma
           Loop_Invariant
             (for all K in Felt_Index =>
                (if K <= I then O (K) in -(2 * F_Add_Cap) .. 2 * F_Add_Cap));
      end loop;
      Lemma_To_Big_Add (O, A, B, 16);
   end F_Add;

   procedure F_Sub (O : out Felt; A, B : Felt) is
   begin
      O := A;
      for I in Felt_Index loop
         O (I) := A (I) - B (I);
         pragma
           Loop_Invariant
             (for all K in Felt_Index =>
                (if K <= I then O (K) = A (K) - B (K)));
         pragma
           Loop_Invariant
             (for all K in Felt_Index =>
                (if K <= I then O (K) in -(2 * F_Add_Cap) .. 2 * F_Add_Cap));
      end loop;
      Lemma_To_Big_Sub (O, A, B, 16);
   end F_Sub;

   ---------------------------------------------------------------------
   --  F_Mul / F_Sqr
   --
   --  16-term convolution into a 31-wide buffer, then the 2^256 = 38 mod p
   --  fold of the top half down, then two carry passes.  AoRTE half proven;
   --  the Equiv_Spec mod-p conjunct stays honest-unproven (value-layer port).
   ---------------------------------------------------------------------

   procedure F_Mul (O : out Felt; A, B : Felt) is
      T        : Big_Buf := [others => 0];
      --  One product magnitude bound.
      Prod_Cap : constant Integer_64 :=
        F_Mul_In_Cap * F_Mul_In_Cap;  --  2**40.
      --  Each of the 31 convolution columns receives at most one product per
      --  outer limb I (j = K - I is unique), so after all 16 rounds every
      --  column is <= 16 * Prod_Cap; the 38× fold then gives <= 39 * 16 *
      --  Prod_Cap < 2**50 < Carry_In_Cap.
      Col_Cap  : constant Integer_64 := 16 * Prod_Cap;
   begin
      O := [others => 0];
      --  Schoolbook convolution: T(I+J) += A(I)*B(J).  Each column K is hit by
      --  at most one (I,J) per outer round (J = K - I is unique), so after I
      --  rounds every column holds at most I products of magnitude <= Prod_Cap.
      for I in Felt_Index loop
         pragma
           Loop_Invariant
             (for all K in Big_Index =>
                T (K)
                in -(Integer_64 (I) * Prod_Cap) .. Integer_64 (I) * Prod_Cap);
         for J in Felt_Index loop
            --  Columns already hit this round (I .. I+J-1) hold one extra
            --  product; the rest still hold at most I.
            pragma
              Loop_Invariant
                (for all K in Big_Index =>
                   (if K >= I and then K <= I + J - 1
                    then
                      T (K)
                      in -(Integer_64 (I + 1) * Prod_Cap)
                       .. Integer_64 (I + 1) * Prod_Cap
                    else
                      T (K)
                      in -(Integer_64 (I) * Prod_Cap)
                       .. Integer_64 (I) * Prod_Cap));
            pragma Assert (abs (A (I) * B (J)) <= Prod_Cap);
            T (I + J) := T (I + J) + A (I) * B (J);
         end loop;
      end loop;
      --  Now every column is <= 16 * Prod_Cap = Col_Cap.
      pragma Assert (for all K in Big_Index => T (K) in -Col_Cap .. Col_Cap);
      --  2^256 = 38 mod p: fold the top 15 columns down by 38.  The folded
      --  low columns (< I) hold <= (1 + 38) * Col_Cap; columns >= I (incl. the
      --  unfolded top half) still hold <= Col_Cap.
      for I in 0 .. 14 loop
         pragma
           Loop_Invariant
             (for all K in Big_Index =>
                (if K < I
                 then T (K) in -(39 * Col_Cap) .. 39 * Col_Cap
                 else T (K) in -Col_Cap .. Col_Cap));
         T (I) := T (I) + 38 * T (I + 16);
      end loop;
      --  Every low column (0 .. 15) is now <= 39 * Col_Cap < Carry_In_Cap.
      pragma
        Assert
          (for all K in Big_Index =>
             (if K <= 15 then T (K) in -(39 * Col_Cap) .. 39 * Col_Cap));
      for I in Felt_Index loop
         pragma
           Loop_Invariant
             (for all K in Felt_Index =>
                (if K < I then O (K) in -Carry_In_Cap .. Carry_In_Cap));
         pragma Assert (T (I) in -(39 * Col_Cap) .. 39 * Col_Cap);
         O (I) := T (I);
      end loop;
      pragma Assert (In_Felem (O, Carry_In_Cap));
      Carry (O);
      Carry (O);
   end F_Mul;

   procedure F_Sqr (O : out Felt; A : Felt) is
   begin
      F_Mul (O, A, A);
   end F_Sqr;

   ---------------------------------------------------------------------
   --  F_Inv via Fermat: a^(-1) = a^(p-2) mod p, where p = 2^255 - 19.
   --  (p-2) has bits 1..254 set except bits 2 and 4.
   --  AoRTE: every F_Sqr/F_Mul output is In_Felem (.,Reduced_Cap), which is
   --  comfortably within F_Mul_In_Cap, so the loop self-sustains.
   ---------------------------------------------------------------------

   procedure F_Inv (O : out Felt; I_Val : Felt) is
      C, T : Felt;
   begin
      C := I_Val;
      for K in reverse 0 .. 253 loop
         pragma Loop_Invariant (In_Felem (C, F_Mul_In_Cap));
         F_Sqr (T, C);
         C := T;
         if K /= 2 and then K /= 4 then
            F_Mul (T, C, I_Val);
            C := T;
         end if;
      end loop;
      O := C;
   end F_Inv;

   ---------------------------------------------------------------------
   --  Pow_2523 — z^((p-5)/8). TweetNaCl-shape exponent walk.
   ---------------------------------------------------------------------

   procedure Pow_2523 (O : out Felt; Z : Felt) is
      C, T : Felt;
   begin
      C := Z;
      for A in reverse 0 .. 250 loop
         pragma Loop_Invariant (In_Felem (C, F_Mul_In_Cap));
         F_Sqr (T, C);
         C := T;
         if A /= 1 then
            F_Mul (T, C, Z);
            C := T;
         end if;
      end loop;
      O := C;
   end Pow_2523;

   ---------------------------------------------------------------------
   --  C_Swap — constant-time conditional swap via XOR masking.
   --  Swap_Bit in {0,1}; the output is exactly the (conditionally) swapped
   --  pair, so each output limb equals one of the input limbs and the
   --  In_Felem bound is preserved.  Proved on the bit-vector pun model.
   ---------------------------------------------------------------------

   procedure C_Swap (P, Q : in out Felt; Swap_Bit : Integer_64) is
      Mask : constant Integer_64 := -Swap_Bit;
      T    : Integer_64;
      --  Mask is all-0 bits (Swap_Bit = 0) or all-1 bits (Swap_Bit = 1), so
      --  the per-limb decision is uniform: either no limb swaps or all do.
      Swap : constant Boolean := Swap_Bit = 1
      with Ghost;
   begin
      pragma
        Assert (To_U64 (Mask) = 0 or else To_U64 (Mask) = Unsigned_64'Last);
      for I in Felt_Index loop
         --  Unreached limbs hold their entry values.
         pragma
           Loop_Invariant
             (for all K in Felt_Index =>
                (if K >= I
                 then
                   P (K) = P'Loop_Entry (K)
                   and then Q (K) = Q'Loop_Entry (K)));
         --  Processed limbs are uniformly swapped or uniformly kept.
         pragma
           Loop_Invariant
             (for all K in Felt_Index =>
                (if K < I
                 then
                   (if Swap
                    then
                      P (K) = Q'Loop_Entry (K)
                      and then Q (K) = P'Loop_Entry (K)
                    else
                      P (K) = P'Loop_Entry (K)
                      and then Q (K) = Q'Loop_Entry (K))));

         declare
            Pi : constant Integer_64 := P (I);
            Qi : constant Integer_64 := Q (I);
            Up : constant Unsigned_64 := To_U64 (Pi);
            Uq : constant Unsigned_64 := To_U64 (Qi);
            Um : constant Unsigned_64 := To_U64 (Mask);
            Ut : constant Unsigned_64 := Um and (Up xor Uq);
         begin
            T := To_I64 (Ut);
            --  Ut is 0 (keep) when Mask = 0, else Up xor Uq (swap).
            pragma Assert (if Swap then Ut = (Up xor Uq) else Ut = 0);
            P (I) := To_I64 (Up xor To_U64 (T));
            Q (I) := To_I64 (Uq xor To_U64 (T));
            pragma Assert (To_U64 (T) = Ut);
            --  To_U64 (To_I64 (u)) = u; then XOR-cancellation a xor (a xor b)=b.
            pragma Assert (To_U64 (P (I)) = (Up xor Ut));
            pragma Assert (To_U64 (Q (I)) = (Uq xor Ut));
            pragma
              Assert
                (if Swap
                   then To_U64 (P (I)) = Uq and then To_U64 (Q (I)) = Up
                   else To_U64 (P (I)) = Up and then To_U64 (Q (I)) = Uq);
            --  Round-trip puns: To_I64 (To_U64 (x)) = x.
            pragma Assert (To_I64 (Up) = Pi);
            pragma Assert (To_I64 (Uq) = Qi);
            pragma Assert (To_I64 (To_U64 (P (I))) = P (I));
            pragma Assert (To_I64 (To_U64 (Q (I))) = Q (I));
            pragma
              Assert
                (if Swap
                   then P (I) = Qi and then Q (I) = Pi
                   else P (I) = Pi and then Q (I) = Qi);
         end;
      end loop;
   end C_Swap;

   ---------------------------------------------------------------------
   --  Pack — final reduction mod p, then serialize 32 LE bytes.
   ---------------------------------------------------------------------

   --  One conditional-subtract-and-swap reduction pass (TweetNaCl Pack inner).
   --  Cap bounds the incoming T limbs; the subtracted M working values and the
   --  permutation-swapped result stay within Cap + 2**17 (one 16-bit constant +
   --  borrow per limb).  AoRTE only — the canonical reduction value is the
   --  honest-unproven functional half elsewhere.
   procedure Reduce_Pass (T : in out Felt; Cap : Integer_64)
   with
     Global => null,
     Pre    => Cap in 2**17 .. 2**18 and then In_Felem (T, Cap),
     Post   => In_Felem (T, Cap + 2**17);

   procedure Reduce_Pass (T : in out Felt; Cap : Integer_64) is
      M   : Felt;
      B   : Integer_64;
      Win : constant Integer_64 := Cap + 2**17;
   begin
      M := T;   --  full init; overwritten limb-by-limb below.
      M (0) := T (0) - 16#FFED#;
      pragma Assert (M (0) in -Win .. Win);
      for I in 1 .. 14 loop
         --  Limbs up to the previous index are settled within Win; T unchanged.
         pragma Loop_Invariant (In_Felem (T, Cap));
         pragma
           Loop_Invariant
             (for all K in Felt_Index =>
                (if K <= I - 1 then M (K) in -Win .. Win));
         Lemma_And_1 (Asr (M (I - 1), 16));   --  borrow bit in {0,1}.
         M (I) := T (I) - 16#FFFF# - And_64 (Asr (M (I - 1), 16), 1);
         pragma Assert (M (I) in -Win .. Win);
         Lemma_And_FFFF (M (I - 1));
         M (I - 1) := And_64 (M (I - 1), 16#FFFF#);
         pragma Assert (M (I - 1) in -Win .. Win);
      end loop;
      --  After the loop M(0..14) are all within Win: M(0..13) by the invariant
      --  (settled to <= I-1 = 13), M(14) by the last iteration's assignment.
      pragma Assert (M (14) in -Win .. Win);
      pragma
        Assert
          (for all K in Felt_Index => (if K <= 14 then M (K) in -Win .. Win));
      Lemma_And_1 (Asr (M (14), 16));
      M (15) := T (15) - 16#7FFF# - And_64 (Asr (M (14), 16), 1);
      pragma Assert (M (15) in -Win .. Win);
      Lemma_And_1 (Asr (M (15), 16));
      B := And_64 (Asr (M (15), 16), 1);
      Lemma_And_FFFF (M (14));
      M (14) := And_64 (M (14), 16#FFFF#);
      pragma Assert (M (14) in -Win .. Win);
      pragma
        Assert
          (for all K in Felt_Index => (if K <= 14 then M (K) in -Win .. Win));
      --  T and M both within Win; the relational C_Swap Post (the result is a
      --  permutation of the inputs) carries the bound across.
      pragma Assert (In_Felem (T, Win) and then In_Felem (M, Win));
      C_Swap (T, M, 1 - B);
      --  M holds the unselected branch (a permutation member); reading it keeps
      --  the post-swap M live so flow analysis does not flag a dead update.
      pragma Assert (In_Felem (M, Win));
   end Reduce_Pass;

   procedure Pack (O : out Bytes_32; N : Felt) is
      T : Felt;
   begin
      O := [others => 0];
      T := N;
      Carry (T);
      Carry (T);
      Carry (T);
      --  After three carries T is Carried (.,Reduced_Cap) <= In_Felem (.,2**17).
      pragma Assert (In_Felem (T, 2**17));
      Reduce_Pass (T, 2**17);   --  -> In_Felem (T, 2**18).
      Reduce_Pass (T, 2**18);   --  -> In_Felem (T, 2**19).
      --  Serialise: each limb's low byte and next byte, both masked to 8 bits.
      for I in Felt_Index loop
         pragma Loop_Invariant (In_Felem (T, 2**19));
         Lemma_And_FF (T (I));
         Lemma_And_FF (Asr (T (I), 8));
         O (1 + 2 * I) := Octet (And_64 (T (I), 16#FF#));
         O (2 + 2 * I) := Octet (And_64 (Asr (T (I), 8), 16#FF#));
      end loop;
   end Pack;

   ---------------------------------------------------------------------
   --  Unpack — read 32 LE bytes; mask off bit 255 of the high byte.
   --  Each limb is a 16-bit byte pair, well within F_Mul_In_Cap.
   ---------------------------------------------------------------------

   procedure Unpack (O : out Felt; B : Bytes_32) is
   begin
      O := [others => 0];
      for I in Felt_Index loop
         pragma
           Loop_Invariant
             (for all K in Felt_Index =>
                (if K < I then O (K) in 0 .. 2**16 - 1));
         O (I) :=
           Integer_64 (B (1 + 2 * I)) + Integer_64 (B (2 + 2 * I)) * 256;
      end loop;
      O (15) := And_64 (O (15), 16#7FFF#);
   end Unpack;

   ---------------------------------------------------------------------
   --  Parity — low bit of the canonical packing.
   ---------------------------------------------------------------------

   function Parity (N : Felt) return Integer_64 is
      Buf    : Bytes_32;
      Result : Integer_64;
   begin
      Pack (Buf, N);
      Result := Integer_64 (Buf (1) and 1);
      return Result;
   end Parity;

end Tls_Core.Field25519;
