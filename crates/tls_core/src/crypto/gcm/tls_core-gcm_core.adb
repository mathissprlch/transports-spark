package body Tls_Core.Gcm_Core
  with SPARK_Mode
is


   use Interfaces;

   ---------------------------------------------------------------------
   --  Forward declaration: Lemma_GF128_Mul_From_Eq is needed by
   --  Spec_GF128_Mul's body. See its full body further down.
   ---------------------------------------------------------------------

   procedure Lemma_GF128_Mul_From_Eq
     (V1, V2, Z1, Z2, Y_Arg : Block_16; K : Natural)
   with
     Ghost,
     Pre                => K <= 128 and then V1 = V2 and then Z1 = Z2,
     Post               =>
       Spec_GF128_Mul_From (V1, Z1, Y_Arg, K)
       = Spec_GF128_Mul_From (V2, Z2, Y_Arg, K),
     Subprogram_Variant => (Decreases => 128 - K);

   ---------------------------------------------------------------------
   --  Spec_GF128_Mul body — non-recursive wrapper. The Post in the
   --  spec ties the result to Spec_GF128_Mul_From at K=0; the body
   --  computes that exact value, using the Eq congruence lemma to
   --  bridge the local named Zero to the spec's literal aggregate.
   ---------------------------------------------------------------------

   function Spec_GF128_Mul (X, Y : Block_16) return Block_16 is
   begin
      return Spec_GF128_Mul_From (X, Zero_Block, Y, 0);
   end Spec_GF128_Mul;

   ---------------------------------------------------------------------
   --  Spec_Build_Mac_Data — only spec function not expression-defined.
   --  Constructed pointwise to match Spec_Build_Mac_Data_Byte_At so
   --  the imperative Build_Mac_Data Post discharges by structural
   --  equality to a single byte-equality quantifier.
   ---------------------------------------------------------------------

   function Spec_Build_Mac_Data
     (AAD : Octet_Array; Ciphertext : Octet_Array) return Octet_Array
   is
      Total  : constant Natural :=
        Spec_Mac_Length (AAD'Length, Ciphertext'Length);
      Result : Octet_Array (1 .. Total) := [others => 0];
   begin
      for I in 1 .. Total loop
         Result (I) := Spec_Build_Mac_Data_Byte_At (AAD, Ciphertext, I);
         pragma Loop_Invariant (Result'First = 1);
         pragma Loop_Invariant (Result'Last = Total);
         pragma
           Loop_Invariant
             (for all K in 1 .. I =>
                Result (K) = Spec_Build_Mac_Data_Byte_At (AAD, Ciphertext, K));
      end loop;
      return Result;
   end Spec_Build_Mac_Data;

   ---------------------------------------------------------------------
   --  INC32
   ---------------------------------------------------------------------

   procedure Increment_Counter (Counter : in out Block_16) is
      Carry : Unsigned_8 := 1;
      Idx   : Integer := 16;
      C0    : constant Block_16 := Counter
      with Ghost;
   begin
      --  Functional proof: maintain the inductive invariant
      --      Spec_Inc32_Step (Counter, Idx, Carry)
      --        = Spec_Inc32_Step (C0, 16, 1)
      --        = Spec_Inc32 (Counter'Old)
      --  At the start of each iteration the LHS unfolds one step into
      --      Spec_Inc32_Step (Counter', Idx-1, Carry')
      --  which is the new invariant after the body executes — gnatprove
      --  unfolds the recursive expression function by exactly one
      --  recursive call between iterations, which is well within the
      --  SMT solver's reach without `Inline_For_Proof`.
      pragma Assert (Spec_Inc32 (C0) = Spec_Inc32_Step (Counter, 16, 1));
      while Idx >= 13 and then Carry > 0 loop
         pragma Loop_Invariant (Idx in 13 .. 16);
         pragma Loop_Invariant (Carry in 0 .. 1);
         pragma
           Loop_Invariant
             (Spec_Inc32_Step (Counter, Idx, Carry) = Spec_Inc32 (C0));
         pragma Loop_Variant (Decreases => Idx);
         declare
            Sum         : constant Unsigned_16 :=
              Unsigned_16 (Counter (Idx)) + Unsigned_16 (Carry);
            New_Byte    : constant Octet := Octet (Sum and 16#FF#);
            New_Counter : constant Block_16 :=
              (Counter with delta Idx => New_Byte);
            New_Carry   : constant Unsigned_8 := (if Sum >= 256 then 1 else 0);
         begin
            --  The expression-function body of Spec_Inc32_Step,
            --  unfolded once: when Idx in 13..16 and Carry > 0, the
            --  recursive case fires.
            pragma
              Assert
                (Spec_Inc32_Step (Counter, Idx, Carry)
                   = Spec_Inc32_Step (New_Counter, Idx - 1, New_Carry));
            Counter (Idx) := New_Byte;
            if Sum >= 256 then
               Carry := 1;
            else
               Carry := 0;
            end if;
            pragma Assert (Counter = New_Counter);
            pragma Assert (Carry = New_Carry);
         end;
         Idx := Idx - 1;
      end loop;
      --  Loop exit: either Idx < 13 or Carry = 0; in both cases the
      --  base case of Spec_Inc32_Step fires, returning Counter.
      pragma Assert (Idx < 13 or else Carry = 0);
      pragma Assert (Spec_Inc32_Step (Counter, Idx, Carry) = Counter);
      pragma Assert (Spec_Inc32 (C0) = Counter);
   end Increment_Counter;

   ---------------------------------------------------------------------
   --  Build_J0
   ---------------------------------------------------------------------

   procedure Build_J0 (Nonce : Octet_Array; Out_J0 : out Block_16) is
   begin
      Out_J0 := [others => 0];
      Out_J0 (1 .. 12) := Nonce;
      Out_J0 (16) := 1;
      --  Out_J0 = Spec_Build_J0 (Nonce) follows from extensional
      --  equality of the 16 bytes after the three assignments above.
      pragma
        Assert
          (for all I in 1 .. 12 => Out_J0 (I) = Nonce (Nonce'First + (I - 1)));
      pragma Assert (for all I in 13 .. 15 => Out_J0 (I) = 0);
      pragma Assert (Out_J0 (16) = 1);
   end Build_J0;

   ---------------------------------------------------------------------
   --  Build_Mac_Data
   ---------------------------------------------------------------------

   procedure Build_Mac_Data
     (AAD        : Octet_Array;
      Ciphertext : Octet_Array;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural)
   is
      Aad_Len : constant Natural := AAD'Length;
      Ct_Len  : constant Natural := Ciphertext'Length;
      Pad_A   : constant Natural := Pad_Len (Aad_Len);
      Pad_C   : constant Natural := Pad_Len (Ct_Len);
      Total   : constant Natural := Spec_Mac_Length (Aad_Len, Ct_Len);

      --  Single-loop pointwise build — each iteration writes one
      --  byte at index I and dispatches to the correct source
      --  region. Maintains the invariant
      --      forall K in 1 .. I => Out_Buf (K) =
      --        Spec_Build_Mac_Data_Byte_At (AAD, Ciphertext, K)
      --  by mirroring exactly the if-elsif chain of
      --  Spec_Build_Mac_Data_Byte_At.
   begin
      Out_Buf := [others => 0];
      for I in 1 .. Total loop
         if I <= Aad_Len then
            Out_Buf (I) := AAD (AAD'First + (I - 1));
         elsif I <= Aad_Len + Pad_A then
            Out_Buf (I) := 0;
         elsif I <= Aad_Len + Pad_A + Ct_Len then
            Out_Buf (I) :=
              Ciphertext (Ciphertext'First + (I - Aad_Len - Pad_A - 1));
         elsif I <= Aad_Len + Pad_A + Ct_Len + Pad_C then
            Out_Buf (I) := 0;
         elsif I <= Aad_Len + Pad_A + Ct_Len + Pad_C + 8 then
            Out_Buf (I) :=
              Spec_U64_BE (Unsigned_64 (Aad_Len) * 8)
                (I - (Aad_Len + Pad_A + Ct_Len + Pad_C));
         else
            Out_Buf (I) :=
              Spec_U64_BE (Unsigned_64 (Ct_Len) * 8)
                (I - (Aad_Len + Pad_A + Ct_Len + Pad_C + 8));
         end if;
         pragma
           Loop_Invariant
             (for all K in 1 .. I =>
                Out_Buf (K)
                = Spec_Build_Mac_Data_Byte_At (AAD, Ciphertext, K));
         pragma
           Loop_Invariant
             (for all K in I + 1 .. Out_Buf'Last => Out_Buf (K) = 0);
      end loop;
      Out_Last := Total;
   end Build_Mac_Data;

   ---------------------------------------------------------------------
   --  Lemma_GF128_Mul_From_Unfold — one-step unfolding of
   --  Spec_GF128_Mul_From's expression-function definition. The lemma
   --  body simply restates the recursive case of the spec; gnatprove
   --  proves the Post by direct evaluation of the expression function,
   --  WITHOUT needing `Inline_For_Proof` because the lemma's body is
   --  evaluated at the call site rather than the definition site of
   --  the recursive function.
   --
   --  Mirror of HACL\* `Vale.AES.GHash_BE.lemma_ghash_unrolled` —
   --  same role: turns `Spec_GF128_Mul_From (V, Z, Y, K)` for K < 128
   --  into the concrete recursive expansion the loop's per-iteration
   --  state advances.
   ---------------------------------------------------------------------

   procedure Lemma_GF128_Mul_From_Unfold (V, Z, Y : Block_16; K : Natural)
   with
     Ghost,
     Pre  => K < 128,
     Post =>
       Spec_GF128_Mul_From (V, Z, Y, K)
       = Spec_GF128_Mul_From
           (Spec_Mul_By_X (V),
            (if ((Shift_Right (Unsigned_8 (Y (1 + K / 8)), 7 - (K mod 8)))
                 and Unsigned_8'(1))
               = 1
             then Spec_Xor_Block (Z, V)
             else Z),
            Y,
            K + 1);

   procedure Lemma_GF128_Mul_From_Unfold (V, Z, Y : Block_16; K : Natural) is
   begin
      null;
   end Lemma_GF128_Mul_From_Unfold;

   ---------------------------------------------------------------------
   --  Lemma_GF128_Mul_From_Eq — function congruence for
   --  Spec_GF128_Mul_From: equal arguments yield equal results. SMT
   --  treats recursive calls opaquely; this lemma forces the
   --  congruence axiom to fire. Forward-declared at the top of this
   --  body to make it usable from Spec_GF128_Mul.
   ---------------------------------------------------------------------

   procedure Lemma_GF128_Mul_From_Eq
     (V1, V2, Z1, Z2, Y_Arg : Block_16; K : Natural)
   is
      --  Inductive proof of function congruence over the
      --  Spec_GF128_Mul_From recursion: SMT does not auto-derive
      --  Leibniz substitution on the recursive call, so we step
      --  through it explicitly. Variant: 128 - K decreases at each
      --  recursive call; base case K = 128 returns Z trivially.
   begin
      if K < 128 then
         declare
            Bit_Set : constant Boolean :=
              ((Shift_Right (Unsigned_8 (Y_Arg (1 + K / 8)), 7 - (K mod 8)))
               and Unsigned_8'(1))
              = 1;
            New_V1  : constant Block_16 := Spec_Mul_By_X (V1);
            New_V2  : constant Block_16 := Spec_Mul_By_X (V2);
            New_Z1  : constant Block_16 :=
              (if Bit_Set then Spec_Xor_Block (Z1, V1) else Z1);
            New_Z2  : constant Block_16 :=
              (if Bit_Set then Spec_Xor_Block (Z2, V2) else Z2);
         begin
            pragma Assert (New_V1 = New_V2);
            pragma Assert (New_Z1 = New_Z2);
            Lemma_GF128_Mul_From_Eq
              (V1    => New_V1,
               V2    => New_V2,
               Z1    => New_Z1,
               Z2    => New_Z2,
               Y_Arg => Y_Arg,
               K     => K + 1);
         end;
      end if;
   end Lemma_GF128_Mul_From_Eq;

   ---------------------------------------------------------------------
   --  Lemma_Spec_GF128_Mul_Equals_Target — bridge from
   --  Spec_GF128_Mul (X, Y) to Spec_GF128_Mul_From (X, Zero, Y, 0)
   --  using the Eq congruence lemma to handle the aggregate-equality
   --  step Block_16'(others => 0) = Zero.
   ---------------------------------------------------------------------

   procedure Lemma_Spec_GF128_Mul_Equals_Target (X, Y, Zero : Block_16)
   with
     Ghost,
     Pre  => Zero = Zero_Block,
     Post => Spec_GF128_Mul (X, Y) = Spec_GF128_Mul_From (X, Zero, Y, 0);

   procedure Lemma_Spec_GF128_Mul_Equals_Target (X, Y, Zero : Block_16) is
   begin
      --  Spec_GF128_Mul's Post gives us
      --      Spec_GF128_Mul (X, Y) = Spec_GF128_Mul_From (X, Zero_Block, Y, 0)
      --  Then by congruence with Zero = Zero_Block, the RHS equals
      --  Spec_GF128_Mul_From (X, Zero, Y, 0).
      Lemma_GF128_Mul_From_Eq
        (V1 => X, V2 => X, Z1 => Zero_Block, Z2 => Zero, Y_Arg => Y, K => 0);
   end Lemma_Spec_GF128_Mul_Equals_Target;

   ---------------------------------------------------------------------
   --  Lemma_GF128_Mul_From_Base — restate the base case of
   --  Spec_GF128_Mul_From at K = 128.
   ---------------------------------------------------------------------

   procedure Lemma_GF128_Mul_From_Base (V, Z, Y : Block_16)
   with Ghost, Post => Spec_GF128_Mul_From (V, Z, Y, 128) = Z;

   procedure Lemma_GF128_Mul_From_Base (V, Z, Y : Block_16) is
   begin
      null;
   end Lemma_GF128_Mul_From_Base;

   ---------------------------------------------------------------------
   --  Mul_By_X_Inplace — imperative shift-by-1-and-reduce that
   --  matches Spec_Mul_By_X byte-for-byte. Pulled out of Ghash_Mul as
   --  its own subprogram so its functional Post can be proved
   --  locally (15-iteration reverse shift loop with a tight per-byte
   --  invariant); Ghash_Mul then calls it as a one-line bridge.
   ---------------------------------------------------------------------

   procedure Mul_By_X_Inplace (V : in out Block_16)
   with Post => V = Spec_Mul_By_X (V'Old);

   procedure Mul_By_X_Inplace (V : in out Block_16) is
      V0  : constant Block_16 := V
      with Ghost;
      Msb : constant Octet := V (16) and 16#01#;
   begin
      for L in reverse 2 .. 16 loop
         V (L) :=
           Octet (Shift_Right (Unsigned_8 (V (L)), 1))
           or (Octet
                 (Shift_Left (Unsigned_8 (V (L - 1)) and Unsigned_8'(1), 7)));
         --  Post-body invariant at this cut point: V(K) for K in
         --  L..16 holds the shifted-byte value; V(K) for K in 1..L-1
         --  is still V0. The reverse-loop preservation step folds
         --  L → L-1: bytes already shifted (L..16) extend down by
         --  one; the byte to be processed next iteration is L-1,
         --  whose source V(L-2) is still original (in V(1..L-1)).
         pragma Loop_Invariant (for all K in 1 .. L - 1 => V (K) = V0 (K));
         pragma
           Loop_Invariant
             (for all K in L .. 16 => V (K) = Spec_Shifted_Byte (V0, K));
      end loop;
      --  After the reverse loop: L exited at 2, post-body invariant
      --  with L=2 says V(1) = V0(1) and V(2..16) all shifted.
      pragma Assert (V (1) = V0 (1));
      pragma
        Assert (for all K in 2 .. 16 => V (K) = Spec_Shifted_Byte (V0, K));
      V (1) := Octet (Shift_Right (Unsigned_8 (V (1)), 1));
      pragma Assert (V (1) = Spec_Shifted_Byte (V0, 1));
      if Msb = 1 then
         V (1) := V (1) xor 16#E1#;
      end if;
      --  Pointwise byte-equality with Spec_Mul_By_X (V0):
      pragma
        Assert
          (V (1)
             = (if (V0 (16) and 16#01#) = 1
                then Spec_Shifted_Byte (V0, 1) xor 16#E1#
                else Spec_Shifted_Byte (V0, 1)));
      pragma Assert (V = Spec_Mul_By_X (V0));
   end Mul_By_X_Inplace;

   ---------------------------------------------------------------------
   --  Ghash_Mul — GF(2^128) bit-by-bit multiply.
   ---------------------------------------------------------------------

   procedure Ghash_Mul (X : in out Block_16; Y : Block_16) is
      X0     : constant Block_16 := X
      with Ghost;
      Target : constant Block_16 := Spec_GF128_Mul_From (X0, Zero_Block, Y, 0)
      with Ghost;
      V      : Block_16 := X;
      Z      : Block_16 := Zero_Block;
   begin
      --  Functional proof: maintain
      --      Spec_GF128_Mul_From (V, Z, Y, K) = Target
      --  where Target is the K=0 starting point of the recursion. At
      --  loop exit (K=128), Spec_GF128_Mul_From's base case returns
      --  Z, so Z = Target. Spec_GF128_Mul (X0, Y) unfolds to Target
      --  by its own expression-function definition.
      --
      --  Per-iteration unfold: at K < 128, the recursive case of
      --  Spec_GF128_Mul_From has
      --      Spec_GF128_Mul_From (V, Z, Y, K) =
      --        Spec_GF128_Mul_From
      --          (Spec_Mul_By_X (V),
      --           (if bit-K-of-Y = 1 then Spec_Xor_Block (Z, V) else Z),
      --           Y, K + 1)
      --  which the body's `Mul_By_X_Inplace (V)` (already PLATINUM)
      --  plus the Z := Z xor V conditional XOR exactly mirror.
      pragma Assert (V = X0);
      pragma Assert (Z = Zero_Block);
      pragma Assert (Spec_GF128_Mul_From (V, Z, Y, 0) = Target);
      for K in 0 .. 127 loop
         pragma Loop_Invariant (Spec_GF128_Mul_From (V, Z, Y, K) = Target);
         declare
            Byte_I : constant Positive := 1 + K / 8;
            Bit_J  : constant Natural := 7 - (K mod 8);
            Bit    : constant Unsigned_8 :=
              (Shift_Right (Unsigned_8 (Y (Byte_I)), Bit_J))
              and Unsigned_8'(1);
            V_Old  : constant Block_16 := V
            with Ghost;
            Z_Old  : constant Block_16 := Z
            with Ghost;
            --  Z_New is the spec's expected post-XOR value.
            Z_New  : constant Block_16 :=
              (if Bit = 1 then Spec_Xor_Block (Z, V) else Z)
            with Ghost;
         begin
            --  Z update: bit-conditional XOR of Z with V. After the
            --  inner loop, Z = Z_New byte-for-byte.
            if Bit = 1 then
               for L in 1 .. 16 loop
                  Z (L) := Z (L) xor V (L);
                  pragma
                    Loop_Invariant
                      (for all M in 1 .. L =>
                         Z (M) = (Z_Old (M) xor V_Old (M)));
                  pragma
                    Loop_Invariant
                      (for all M in L + 1 .. 16 => Z (M) = Z_Old (M));
                  pragma Loop_Invariant (V = V_Old);
               end loop;
               pragma Assert (Z = Spec_Xor_Block (Z_Old, V_Old));
               pragma Assert (Z = Z_New);
            else
               pragma Assert (Z = Z_Old);
               pragma Assert (Z = Z_New);
            end if;
            pragma Assert (V = V_Old);

            --  V update: in-place mul-by-X (already PLATINUM).
            Mul_By_X_Inplace (V);
            pragma Assert (V = Spec_Mul_By_X (V_Old));

            --  Unfold one step of Spec_GF128_Mul_From at K via the
            --  ghost lemma. After this, the spec's recursive
            --  expansion is in scope and substitution gives the
            --  state-advance equality the loop invariant needs.
            Lemma_GF128_Mul_From_Unfold (V_Old, Z_Old, Y, K);
            pragma Assert (V = Spec_Mul_By_X (V_Old));
            pragma Assert (Z = Z_New);
            --  Bridge: the lemma's Post gives
            --     Spec_GF128_Mul_From (V_Old, Z_Old, Y, K) =
            --       Spec_GF128_Mul_From (Spec_Mul_By_X (V_Old), Z_New, Y, K+1)
            --  Substituting V = Spec_Mul_By_X (V_Old) and Z = Z_New
            --  gives the desired form. Sometimes SMT does not apply
            --  this substitution when the function is recursive; the
            --  Eq lemma applies it explicitly.
            Lemma_GF128_Mul_From_Eq
              (V1    => Spec_Mul_By_X (V_Old),
               V2    => V,
               Z1    => Z_New,
               Z2    => Z,
               Y_Arg => Y,
               K     => K + 1);
            pragma
              Assert
                (Spec_GF128_Mul_From (Spec_Mul_By_X (V_Old), Z_New, Y, K + 1)
                   = Spec_GF128_Mul_From (V, Z, Y, K + 1));
            pragma
              Assert
                (Spec_GF128_Mul_From (V_Old, Z_Old, Y, K)
                   = Spec_GF128_Mul_From (V, Z, Y, K + 1));
         end;
      end loop;
      --  After loop: K = 128. Base case of Spec_GF128_Mul_From
      --  returns Z, so Z = Target. Then Target IS Spec_GF128_Mul
      --  (X0, Y) by Spec_GF128_Mul's Post tying it to the same
      --  Spec_GF128_Mul_From recursion at K = 0 with Zero_Block.
      Lemma_GF128_Mul_From_Base (V, Z, Y);
      pragma Assert (Spec_GF128_Mul_From (V, Z, Y, 128) = Z);
      pragma Assert (Z = Target);
      pragma Assert (Target = Spec_GF128_Mul (X0, Y));
      pragma Assert (Z = Spec_GF128_Mul (X0, Y));
      X := Z;
   end Ghash_Mul;

   ---------------------------------------------------------------------
   --  Lemma_GF128_Mul_Eq — function congruence for Spec_GF128_Mul:
   --  equal X yields equal results. Proved via Spec_GF128_Mul's
   --  explicit Post + the GF128_Mul_From_Eq congruence lemma at K=0.
   ---------------------------------------------------------------------

   procedure Lemma_GF128_Mul_Eq (X1, X2, Y : Block_16)
   with
     Ghost,
     Pre  => X1 = X2,
     Post => Spec_GF128_Mul (X1, Y) = Spec_GF128_Mul (X2, Y);

   procedure Lemma_GF128_Mul_Eq (X1, X2, Y : Block_16) is
   begin
      Lemma_GF128_Mul_From_Eq
        (V1    => X1,
         V2    => X2,
         Z1    => Zero_Block,
         Z2    => Zero_Block,
         Y_Arg => Y,
         K     => 0);
   end Lemma_GF128_Mul_Eq;

   ---------------------------------------------------------------------
   --  Lemma_GHash_Fold_Step / Lemma_GHash_Fold_Final — restate the
   --  recursive case (Length > 16) and base case (Length <= 16) of
   --  Spec_GHash_Fold. Both are direct expansions of the spec's
   --  expression-function body; gnatprove proves the Posts by
   --  evaluating the body at the lemma's arguments.
   ---------------------------------------------------------------------

   procedure Lemma_GHash_Fold_Step
     (H : Block_16; Data : Octet_Array; Y : Block_16)
   with
     Ghost,
     Pre  => Data'Length > 16 and then Data'Last < Integer'Last - 16,
     Post =>
       Spec_GHash_Fold (H, Data, Y)
       = Spec_GHash_Fold
           (H,
            Data (Data'First + 16 .. Data'Last),
            Spec_GF128_Mul
              (Spec_Xor_Block (Y, Spec_GHash_Block_From_First (Data)), H));

   procedure Lemma_GHash_Fold_Step
     (H : Block_16; Data : Octet_Array; Y : Block_16) is
   begin
      null;
   end Lemma_GHash_Fold_Step;

   procedure Lemma_GHash_Fold_Final
     (H : Block_16; Data : Octet_Array; Y : Block_16)
   with
     Ghost,
     Pre  => Data'Length in 1 .. 16 and then Data'Last < Integer'Last - 16,
     Post =>
       Spec_GHash_Fold (H, Data, Y)
       = Spec_GF128_Mul
           (Spec_Xor_Block (Y, Spec_GHash_Block_From_First (Data)), H);

   procedure Lemma_GHash_Fold_Final
     (H : Block_16; Data : Octet_Array; Y : Block_16) is
   begin
      null;
   end Lemma_GHash_Fold_Final;

   ---------------------------------------------------------------------
   --  Ghash — full-message accumulator.
   --
   --  Body uses the bit-by-bit Ghash_Mul (not the 4-bit table)
   --  because the table-multiply equivalence to `Spec_GF128_Mul`
   --  requires a separate equivalence proof not yet ported (the
   --  HACL\* `Vale.AES.GHash_BE` table-correctness proof is over
   --  polynomial reasoning; porting it into SPARK is a separate
   --  session). Performance impact on the worst-case TLS record
   --  (~33326 bytes input) is bounded: bit-by-bit is ~16x slower per
   --  block but still completes in microseconds. The 4-bit table
   --  primitive remains in `Tls_Core.Ghash_Table` and may be
   --  re-routed once the equivalence proof closes (open functional
   --  correctness gap per docs/conventions.md §0b).
   ---------------------------------------------------------------------

   procedure Ghash (H : Block_16; Data : Octet_Array; Out_X : in out Block_16)
   is
      Cursor : Natural := 0;
      Block  : Block_16 := [others => 0];
      Out_X0 : constant Block_16 := Out_X
      with Ghost;
      --  Folded_Tail (C) is Spec_GHash_Fold over the suffix
      --  Data[Data'First + C .. Data'Last] starting from Out_X.
      --  Captures the loop's "remaining work" at each iteration.
      function Folded_Tail (C : Natural; Acc : Block_16) return Block_16
      is (if C >= Data'Length
          then Acc
          else Spec_GHash_Fold (H, Data (Data'First + C .. Data'Last), Acc))
      with
        Ghost,
        Pre => C <= Data'Length and then Data'Last < Integer'Last - 16640;
   begin
      pragma
        Assert (Folded_Tail (0, Out_X) = Spec_GHash_Fold (H, Data, Out_X0));
      --  Main loop: process 16-byte blocks while there are STRICTLY
      --  MORE than 16 bytes left, so Spec_GHash_Fold's recursive
      --  case fires. The last 1..16 bytes always go to the tail
      --  block, which uses Spec_GHash_Fold's small-Length branch.
      while Cursor + 16 < Data'Length loop
         pragma Loop_Invariant (Cursor in 0 .. Data'Length);
         pragma Loop_Invariant (Cursor mod 16 = 0);
         pragma Loop_Invariant (Cursor + 16 < Data'Length);
         pragma
           Loop_Invariant
             (Folded_Tail (Cursor, Out_X) = Spec_GHash_Fold (H, Data, Out_X0));
         pragma Loop_Variant (Decreases => Data'Length - Cursor);
         declare
            Out_X_Pre : constant Block_16 := Out_X
            with Ghost;
            Suffix    : constant Octet_Array :=
              Data (Data'First + Cursor .. Data'Last)
            with Ghost;
         begin
            pragma Assert (Suffix'Length >= 16);
            for I in 1 .. 16 loop
               pragma Loop_Invariant (Cursor + 16 <= Data'Length);
               pragma
                 Loop_Invariant
                   (for all M in 1 .. I - 1 =>
                      Block (M) = Data (Data'First + Cursor + M - 1));
               Block (I) := Data (Data'First + Cursor + I - 1);
            end loop;
            --  Block is now the first 16 bytes of Suffix; that
            --  matches Spec_GHash_Block_From_First (Suffix).
            pragma
              Assert
                (for all I in 1 .. 16 =>
                   Block (I) = Suffix (Suffix'First + I - 1));
            pragma Assert (Block = Spec_GHash_Block_From_First (Suffix));

            --  Out_X := Out_X xor Block.
            declare
               Out_X_Mid : constant Block_16 := Out_X
               with Ghost;
            begin
               for I in 1 .. 16 loop
                  Out_X (I) := Out_X (I) xor Block (I);
                  pragma
                    Loop_Invariant
                      (for all M in 1 .. I =>
                         Out_X (M) = (Out_X_Mid (M) xor Block (M)));
                  pragma
                    Loop_Invariant
                      (for all M in I + 1 .. 16 => Out_X (M) = Out_X_Mid (M));
               end loop;
               pragma Assert (Out_X = Spec_Xor_Block (Out_X_Mid, Block));
               pragma Assert (Out_X_Mid = Out_X_Pre);
               pragma Assert (Out_X = Spec_Xor_Block (Out_X_Pre, Block));
            end;

            --  Out_X := Spec_GF128_Mul (Out_X, H).
            declare
               Out_X_Before_Mul : constant Block_16 := Out_X
               with Ghost;
            begin
               pragma
                 Assert (Out_X_Before_Mul = Spec_Xor_Block (Out_X_Pre, Block));
               Ghash_Mul (Out_X, H);
               pragma Assert (Out_X = Spec_GF128_Mul (Out_X_Before_Mul, H));
               Lemma_GF128_Mul_Eq
                 (X1 => Out_X_Before_Mul,
                  X2 => Spec_Xor_Block (Out_X_Pre, Block),
                  Y  => H);
               pragma
                 Assert
                   (Out_X
                      = Spec_GF128_Mul (Spec_Xor_Block (Out_X_Pre, Block), H));
               pragma Assert (Block = Spec_GHash_Block_From_First (Suffix));
               Lemma_GF128_Mul_Eq
                 (X1 => Spec_Xor_Block (Out_X_Pre, Block),
                  X2 =>
                    Spec_Xor_Block
                      (Out_X_Pre, Spec_GHash_Block_From_First (Suffix)),
                  Y  => H);
               pragma
                 Assert
                   (Out_X
                      = Spec_GF128_Mul
                          (Spec_Xor_Block
                             (Out_X_Pre, Spec_GHash_Block_From_First (Suffix)),
                           H));
            end;

            --  Spec_GHash_Fold's recursive case for Suffix'Length > 16:
            --    Spec_GHash_Fold (H, Suffix, Out_X_Pre) =
            --      Spec_GHash_Fold
            --        (H,
            --         Suffix [Suffix'First + 16 .. Suffix'Last],
            --         Spec_GF128_Mul
            --           (Spec_Xor_Block
            --              (Out_X_Pre, Spec_GHash_Block_From_First (Suffix)),
            --            H))
            --  i.e. = Spec_GHash_Fold (H, <next-suffix>, Out_X).
            Lemma_GHash_Fold_Step (H, Suffix, Out_X_Pre);
            --  Lemma's Post:
            --    Spec_GHash_Fold (H, Suffix, Out_X_Pre) =
            --      Spec_GHash_Fold
            --        (H, Suffix [Suffix'First+16 .. Suffix'Last], <new-Y>)
            --  where <new-Y> = Spec_GF128_Mul (Spec_Xor_Block
            --   (Out_X_Pre, Spec_GHash_Block_From_First (Suffix)), H)
            --   = Out_X (just established).
            pragma
              Assert
                (Suffix (Suffix'First + 16 .. Suffix'Last)
                   = Data (Data'First + Cursor + 16 .. Data'Last));
            pragma
              Assert
                (Spec_GHash_Fold (H, Suffix, Out_X_Pre)
                   = Spec_GHash_Fold
                       (H,
                        Data (Data'First + Cursor + 16 .. Data'Last),
                        Out_X));
            pragma
              Assert
                (Folded_Tail (Cursor + 16, Out_X)
                   = Spec_GHash_Fold
                       (H,
                        Data (Data'First + Cursor + 16 .. Data'Last),
                        Out_X));
            pragma
              Assert
                (Spec_GHash_Fold (H, Suffix, Out_X_Pre)
                   = Folded_Tail (Cursor + 16, Out_X));
         end;

         Cursor := Cursor + 16;
         pragma
           Assert
             (Folded_Tail (Cursor, Out_X) = Spec_GHash_Fold (H, Data, Out_X0));
      end loop;

      --  Loop exit: Cursor + 16 >= Data'Length, i.e. Cursor in
      --  Data'Length - 16 .. Data'Length. Two sub-cases:
      --    (a) Cursor = Data'Length — no tail; Out_X is already
      --        the answer.
      --    (b) Cursor < Data'Length — short tail Data[Cursor..]
      --        of length Tail in 1..16. Spec_GHash_Fold's
      --        small-Length branch fires and returns
      --        Spec_GF128_Mul (Spec_Xor_Block (Out_X,
      --                          Spec_GHash_Block_From_First (
      --                            Data[Cursor..])), H)
      --        which is exactly what the tail-handling code below
      --        computes byte-for-byte.
      if Cursor < Data'Length then
         declare
            Out_X_Pre : constant Block_16 := Out_X
            with Ghost;
            Tail      : constant Natural := Data'Length - Cursor;
            Suffix    : constant Octet_Array :=
              Data (Data'First + Cursor .. Data'Last)
            with Ghost;
         begin
            pragma Assert (Tail in 1 .. 16);
            pragma Assert (Suffix'Length = Tail);
            Block := [others => 0];
            for I in 1 .. Tail loop
               pragma Loop_Invariant (Cursor + Tail <= Data'Length);
               pragma Loop_Invariant (Cursor < Data'Length);
               pragma
                 Loop_Invariant
                   (for all M in 1 .. I - 1 =>
                      Block (M) = Data (Data'First + Cursor + M - 1));
               pragma Loop_Invariant (for all M in I .. 16 => Block (M) = 0);
               Block (I) := Data (Data'First + Cursor + I - 1);
            end loop;
            --  Block is the zero-padded first 16 bytes of Suffix —
            --  i.e. byte_or_zero (Suffix, 0, I) for I in 1..16.
            pragma
              Assert
                (for all I in 1 .. 16 =>
                   Block (I) = Spec_GHash_Byte_Or_Zero (Suffix, 0, I));
            pragma Assert (Block = Spec_GHash_Block_From_First (Suffix));

            declare
               Out_X_Mid : constant Block_16 := Out_X
               with Ghost;
            begin
               for I in 1 .. 16 loop
                  Out_X (I) := Out_X (I) xor Block (I);
                  pragma
                    Loop_Invariant
                      (for all M in 1 .. I =>
                         Out_X (M) = (Out_X_Mid (M) xor Block (M)));
                  pragma
                    Loop_Invariant
                      (for all M in I + 1 .. 16 => Out_X (M) = Out_X_Mid (M));
               end loop;
               pragma Assert (Out_X = Spec_Xor_Block (Out_X_Pre, Block));
            end;

            declare
               Out_X_Before_Mul : constant Block_16 := Out_X
               with Ghost;
            begin
               pragma
                 Assert (Out_X_Before_Mul = Spec_Xor_Block (Out_X_Pre, Block));
               Ghash_Mul (Out_X, H);
               pragma Assert (Out_X = Spec_GF128_Mul (Out_X_Before_Mul, H));
               Lemma_GF128_Mul_Eq
                 (X1 => Out_X_Before_Mul,
                  X2 => Spec_Xor_Block (Out_X_Pre, Block),
                  Y  => H);
               pragma
                 Assert
                   (Out_X
                      = Spec_GF128_Mul (Spec_Xor_Block (Out_X_Pre, Block), H));
               pragma Assert (Block = Spec_GHash_Block_From_First (Suffix));
               Lemma_GF128_Mul_Eq
                 (X1 => Spec_Xor_Block (Out_X_Pre, Block),
                  X2 =>
                    Spec_Xor_Block
                      (Out_X_Pre, Spec_GHash_Block_From_First (Suffix)),
                  Y  => H);
               pragma
                 Assert
                   (Out_X
                      = Spec_GF128_Mul
                          (Spec_Xor_Block
                             (Out_X_Pre, Spec_GHash_Block_From_First (Suffix)),
                           H));
            end;

            --  Spec_GHash_Fold's small-Length branch:
            --    Spec_GHash_Fold (H, Suffix, Out_X_Pre) =
            --      Spec_GF128_Mul (Spec_Xor_Block (Out_X_Pre,
            --                       Spec_GHash_Block_From_First (Suffix)), H)
            Lemma_GHash_Fold_Final (H, Suffix, Out_X_Pre);
            pragma Assert (Out_X = Spec_GHash_Fold (H, Suffix, Out_X_Pre));
            pragma Assert (Out_X = Folded_Tail (Cursor, Out_X_Pre));
            pragma
              Assert
                (Folded_Tail (Cursor, Out_X_Pre)
                   = Spec_GHash_Fold (H, Data, Out_X0));
         end;
      else
         --  Cursor = Data'Length: Folded_Tail (Cursor, Out_X) = Out_X.
         pragma Assert (Cursor = Data'Length);
         pragma Assert (Folded_Tail (Cursor, Out_X) = Out_X);
         pragma Assert (Out_X = Spec_GHash_Fold (H, Data, Out_X0));
      end if;
   end Ghash;

   ---------------------------------------------------------------------
   --  Aes_Ctr_Pkg — generic counter-mode encrypt.
   ---------------------------------------------------------------------

   package body Aes_Ctr_Pkg is

      function Spec_Aes_Ctr
        (RK : Round_Keys; J : Block_16; Input : Octet_Array) return Octet_Array
      is
         Take   : Natural;
         Stream : constant Block_16 := Spec_Encrypt_Block (RK, J);
         Result : Octet_Array (1 .. Input'Length) := [others => 0];
      begin
         if Input'Length = 0 then
            return Result;
         end if;
         Take := (if Input'Length >= 16 then 16 else Input'Length);
         for I in 1 .. Take loop
            Result (I) := Input (Input'First + (I - 1)) xor Stream (I);
            pragma Loop_Invariant (Take in 1 .. 16);
            pragma Loop_Invariant (Result'Length = Input'Length);
            pragma Loop_Invariant (Result'First = 1);
         end loop;
         if Input'Length <= 16 then
            return Result;
         end if;
         declare
            Tail : constant Octet_Array :=
              Spec_Aes_Ctr
                (RK, Spec_Inc32 (J), Input (Input'First + 16 .. Input'Last));
         begin
            for I in 1 .. Tail'Length loop
               Result (16 + I) := Tail (I);
               pragma Loop_Invariant (Tail'Length = Input'Length - 16);
            end loop;
         end;
         return Result;
      end Spec_Aes_Ctr;

      procedure Aes_Ctr
        (RK        : Round_Keys;
         Initial_J : Block_16;
         Input     : Octet_Array;
         Output    : out Octet_Array)
      is
         Counter : Block_16 := Initial_J;
         Stream  : Block_16;
         Cursor  : Natural := 0;
      begin
         Output := [others => 0];
         while Cursor < Input'Length loop
            pragma Loop_Variant (Decreases => Input'Length - Cursor);
            pragma Loop_Invariant (Cursor in 0 .. Input'Length);
            Encrypt_Block (RK, Counter, Stream);
            declare
               Take : constant Natural :=
                 Natural'Min (16, Input'Length - Cursor);
            begin
               for I in 1 .. Take loop
                  Output (Output'First + Cursor + I - 1) :=
                    Input (Input'First + Cursor + I - 1) xor Stream (I);
               end loop;
               Cursor := Cursor + Take;
            end;
            Increment_Counter (Counter);
         end loop;
         --  AoRTE-only on the functional Post: discharging
         --  Output = Spec_Aes_Ctr (RK, Initial_J, Input) requires a
         --  per-block invariant tying (Counter, Cursor) to the
         --  recursive structure of Spec_Aes_Ctr (specifically that
         --  Counter = Spec_Inc32^k (Initial_J) at iteration k). The
         --  invariant is straightforward but its discharge depends
         --  on the formal generic Post (Encrypt_Block matches
         --  Spec_Encrypt_Block) — see docs/conventions.md §0b for the AES
         --  spec gap. Honest-unproven §0b gap.
         null;
      end Aes_Ctr;

   end Aes_Ctr_Pkg;

end Tls_Core.Gcm_Core;
