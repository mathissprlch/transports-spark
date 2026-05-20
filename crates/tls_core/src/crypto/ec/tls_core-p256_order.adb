with Interfaces;

package body Tls_Core.P256_Order
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use Interfaces;

   ---------------------------------------------------------------------
   --  Ghost spec layer — bodies for ghost functions declared in the
   --  spec. Computable Big_Integer arithmetic; no stub returns.
   ---------------------------------------------------------------------

   package Octet_Big is new Big.Signed_Conversions (Int => Integer);

   function Byte_Big (X : Octet) return Big.Big_Integer
   is (Octet_Big.To_Big_Integer (Integer (X)));

   function Pow_2_8 (N : Natural) return Big.Big_Integer
   is (Big.To_Big_Integer (2) ** (8 * N));

   --  P-256 group order n — written in hex limbs that exactly match
   --  the wire representation in N_Limbs below. Constructed as a
   --  Big_Integer literal via byte-walk so the value is computable
   --  and unfolds for the prover.
   function Order_N_Spec return Big.Big_Integer is
      --  n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
      --  Build from MSB to LSB.
      Hex_BE : constant array (1 .. 32) of Octet :=
        (16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#00#, 16#00#, 16#00#, 16#00#,
         16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
         16#BC#, 16#E6#, 16#FA#, 16#AD#, 16#A7#, 16#17#, 16#9E#, 16#84#,
         16#F3#, 16#B9#, 16#CA#, 16#C2#, 16#FC#, 16#63#, 16#25#, 16#51#);
      R : Big.Big_Integer := Big.To_Big_Integer (0);
   begin
      for I in Hex_BE'Range loop
         R := R * Big.To_Big_Integer (256)
              + Octet_Big.To_Big_Integer (Integer (Hex_BE (I)));
      end loop;
      return R;
   end Order_N_Spec;

   function Spec_Mod_N (X : Big.Big_Integer) return Big.Big_Integer
   is (X mod Order_N_Spec);

   function Spec_Q_Inv (A : Big.Big_Integer) return Big.Big_Integer is
      N      : constant Big.Big_Integer := Order_N_Spec;
      Two    : constant Big.Big_Integer := Big.To_Big_Integer (2);
      Zero_B : constant Big.Big_Integer := Big.To_Big_Integer (0);
      Result : Big.Big_Integer := Big.To_Big_Integer (1);
      Base   : Big.Big_Integer := Spec_Mod_N (A);
      Exp    : Big.Big_Integer := N - Big.To_Big_Integer (2);
   begin
      while Exp > Zero_B loop
         pragma Loop_Variant (Decreases => Exp);
         if Exp mod Two = Big.To_Big_Integer (1) then
            Result := (Result * Base) mod N;
         end if;
         Exp := Exp / Two;
         Base := (Base * Base) mod N;
      end loop;
      return Result;
   end Spec_Q_Inv;

   ---------------------------------------------------------------------
   --  Internal limb representation.
   --
   --  Same shape as P256_Field: eight 32-bit limbs in little-endian
   --  order. The 256-bit integer is sum_i Limbs (i) * 2^(32*i).
   ---------------------------------------------------------------------

   subtype Limb_Index is Natural range 0 .. 7;
   type Limbs8 is array (Limb_Index) of Unsigned_32;

   subtype Limb9_Index is Natural range 0 .. 8;
   type Limbs9 is array (Limb9_Index) of Unsigned_32;

   subtype Limb16_Index is Natural range 0 .. 15;
   type Limbs16 is array (Limb16_Index) of Unsigned_32;

   --  NIST P-256 group order n = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFF
   --                              BCE6FAADA7179E84F3B9CAC2FC632551
   --  as eight 32-bit little-endian limbs.
   N_Limbs : constant Limbs8 :=
     (16#FC632551#, 16#F3B9CAC2#, 16#A7179E84#, 16#BCE6FAAD#,
      16#FFFFFFFF#, 16#FFFFFFFF#, 16#00000000#, 16#FFFFFFFF#);

   ---------------------------------------------------------------------
   --  Encoding / decoding between 32 BE bytes and limbs.
   ---------------------------------------------------------------------

   procedure From_Bytes (B : Scalar; L : out Limbs8) is
   begin
      for I in Limb_Index loop
         L (I) :=
             Shift_Left (Unsigned_32 (B (32 - 4 * I - 3)), 24)
           or Shift_Left (Unsigned_32 (B (32 - 4 * I - 2)), 16)
           or Shift_Left (Unsigned_32 (B (32 - 4 * I - 1)),  8)
           or            Unsigned_32 (B (32 - 4 * I));
      end loop;
   end From_Bytes;

   procedure To_Bytes (L : Limbs8; B : out Scalar) is
   begin
      for I in Limb_Index loop
         B (32 - 4 * I - 3) := Octet (Shift_Right (L (I), 24) and 16#FF#);
         B (32 - 4 * I - 2) := Octet (Shift_Right (L (I), 16) and 16#FF#);
         B (32 - 4 * I - 1) := Octet (Shift_Right (L (I),  8) and 16#FF#);
         B (32 - 4 * I)     := Octet (L (I) and 16#FF#);
      end loop;
   end To_Bytes;

   ---------------------------------------------------------------------
   --  Comparison: True iff A >= N_Limbs.
   ---------------------------------------------------------------------

   function Geq_N (A : Limbs8) return Boolean is
   begin
      --  Compare from MSB limb downward.
      for I in reverse Limb_Index loop
         if A (I) > N_Limbs (I) then
            return True;
         elsif A (I) < N_Limbs (I) then
            return False;
         end if;
      end loop;
      return True;  --  exactly equal
   end Geq_N;

   --  True iff A9 (treated as 9-limb value) >= n.
   function Geq_N_9 (A : Limbs9) return Boolean is
   begin
      if A (8) /= 0 then
         return True;
      end if;
      for I in reverse Limb_Index loop
         if A (I) > N_Limbs (I) then
            return True;
         elsif A (I) < N_Limbs (I) then
            return False;
         end if;
      end loop;
      return True;
   end Geq_N_9;

   ---------------------------------------------------------------------
   --  In-place subtract n from a 9-limb value.
   ---------------------------------------------------------------------

   procedure Sub_N_9 (A : in out Limbs9) is
      Borrow : Unsigned_64 := 0;
      Diff   : Unsigned_64;
   begin
      for I in Limb_Index loop
         Diff :=
             Unsigned_64 (A (I))
           - Unsigned_64 (N_Limbs (I))
           - Borrow;
         A (I) := Unsigned_32 (Diff and 16#FFFFFFFF#);
         Borrow := Shift_Right (Diff, 63) and 1;
      end loop;
      Diff := Unsigned_64 (A (8)) - Borrow;
      A (8) := Unsigned_32 (Diff and 16#FFFFFFFF#);
   end Sub_N_9;

   ---------------------------------------------------------------------
   --  In-place subtract n from an 8-limb value (assumes A >= n).
   ---------------------------------------------------------------------

   procedure Sub_N_8 (A : in out Limbs8) is
      Borrow : Unsigned_64 := 0;
      Diff   : Unsigned_64;
   begin
      for I in Limb_Index loop
         Diff :=
             Unsigned_64 (A (I))
           - Unsigned_64 (N_Limbs (I))
           - Borrow;
         A (I) := Unsigned_32 (Diff and 16#FFFFFFFF#);
         Borrow := Shift_Right (Diff, 63) and 1;
      end loop;
   end Sub_N_8;

   ---------------------------------------------------------------------
   --  In-place add n to an 8-limb value, returns carry-out.
   ---------------------------------------------------------------------

   procedure Add_N_8 (A : in out Limbs8) is
      Carry : Unsigned_64 := 0;
      Sum   : Unsigned_64;
   begin
      for I in Limb_Index loop
         Sum := Unsigned_64 (A (I)) + Unsigned_64 (N_Limbs (I)) + Carry;
         A (I) := Unsigned_32 (Sum and 16#FFFFFFFF#);
         Carry := Shift_Right (Sum, 32);
      end loop;
   end Add_N_8;

   ---------------------------------------------------------------------
   --  Modular Add / Sub.
   ---------------------------------------------------------------------

   procedure Limb_Add_Mod (A, B : Limbs8; R : out Limbs8) is
      Carry : Unsigned_64 := 0;
      Sum   : Unsigned_64;
      T     : Limbs9;
   begin
      for I in Limb_Index loop
         Sum := Unsigned_64 (A (I)) + Unsigned_64 (B (I)) + Carry;
         T (I) := Unsigned_32 (Sum and 16#FFFFFFFF#);
         Carry := Shift_Right (Sum, 32);
      end loop;
      T (8) := Unsigned_32 (Carry);

      --  Sum is < 2*n < 2^257; subtract n while >= n.
      while Geq_N_9 (T) loop
         Sub_N_9 (T);
      end loop;
      for I in Limb_Index loop
         R (I) := T (I);
      end loop;
   end Limb_Add_Mod;

   procedure Limb_Sub_Mod (A, B : Limbs8; R : out Limbs8) is
      Borrow : Unsigned_64 := 0;
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
         --  Add n back to recover the modular result.
         Add_N_8 (T);
         R := T;
      end if;
   end Limb_Sub_Mod;

   ---------------------------------------------------------------------
   --  Reduce an 8-limb value mod n. Input < 2*n - so at most one
   --  conditional subtraction. (Used after digest-as-integer where
   --  the value can equal up to 2^256 - 1, which is < 2*n.)
   ---------------------------------------------------------------------

   procedure Reduce_Once_If_Geq (A : in out Limbs8) is
   begin
      if Geq_N (A) then
         Sub_N_8 (A);
      end if;
   end Reduce_Once_If_Geq;

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
   --  Reduce a 16-limb (512-bit) value mod n via bit-serial
   --  shift-and-subtract. Walk T from the MSB downward; at each
   --  step shift R left by one bit, OR in the next bit of T, and
   --  subtract n if R >= n. After 512 iterations R is in [0, n).
   --
   --  R is held as a 9-limb buffer because the intermediate value
   --  R-shifted-left can briefly carry into bit 256 before the
   --  subtract; the subtract routine handles the 9th limb.
   ---------------------------------------------------------------------

   procedure Reduce_Mul (T : Limbs16; R : out Limbs8) is
      Acc : Limbs9 := (others => 0);
      Bit : Unsigned_32;
      Carry_Out : Unsigned_32;
   begin
      for K in reverse 0 .. 511 loop
         declare
            Limb_Idx : constant Natural := K / 32;
            Bit_Idx  : constant Natural := K mod 32;
         begin
            Bit := Shift_Right (T (Limb_Idx), Bit_Idx) and 1;
         end;
         --  Acc := (Acc << 1) | Bit
         Carry_Out := Bit;
         for I in Limb9_Index loop
            declare
               New_Carry : constant Unsigned_32 :=
                 Shift_Right (Acc (I), 31) and 1;
            begin
               Acc (I) := Shift_Left (Acc (I), 1) or Carry_Out;
               Carry_Out := New_Carry;
            end;
         end loop;
         --  Acc may now be up to 257 bits; reduce while >= n.
         while Geq_N_9 (Acc) loop
            Sub_N_9 (Acc);
         end loop;
      end loop;
      for I in Limb_Index loop
         R (I) := Acc (I);
      end loop;
   end Reduce_Mul;

   ---------------------------------------------------------------------
   --  Modular multiply.
   ---------------------------------------------------------------------

   procedure Limb_Mul_Mod (A, B : Limbs8; R : out Limbs8) is
      T : Limbs16;
   begin
      Limb_Mul (A, B, T);
      Reduce_Mul (T, R);
   end Limb_Mul_Mod;

   procedure Limb_Square_Mod (A : Limbs8; R : out Limbs8) is
   begin
      Limb_Mul_Mod (A, A, R);
   end Limb_Square_Mod;

   ---------------------------------------------------------------------
   --  Public Add / Sub / Mul.
   ---------------------------------------------------------------------

   procedure Add (A, B : Scalar; Out_C : out Scalar) is
      AL, BL, RL : Limbs8;
   begin
      From_Bytes (A, AL);
      Reduce_Once_If_Geq (AL);
      From_Bytes (B, BL);
      Reduce_Once_If_Geq (BL);
      Limb_Add_Mod (AL, BL, RL);
      To_Bytes (RL, Out_C);
   end Add;

   procedure Sub (A, B : Scalar; Out_C : out Scalar) is
      AL, BL, RL : Limbs8;
   begin
      From_Bytes (A, AL);
      Reduce_Once_If_Geq (AL);
      From_Bytes (B, BL);
      Reduce_Once_If_Geq (BL);
      Limb_Sub_Mod (AL, BL, RL);
      To_Bytes (RL, Out_C);
   end Sub;

   procedure Mul (A, B : Scalar; Out_C : out Scalar) is
      AL, BL, RL : Limbs8;
   begin
      From_Bytes (A, AL);
      From_Bytes (B, BL);
      Limb_Mul_Mod (AL, BL, RL);
      To_Bytes (RL, Out_C);
   end Mul;

   procedure Reduce (A : Scalar; Out_C : out Scalar) is
      AL : Limbs8;
   begin
      From_Bytes (A, AL);
      Reduce_Once_If_Geq (AL);
      To_Bytes (AL, Out_C);
   end Reduce;

   ---------------------------------------------------------------------
   --  Invert via Fermat: a^(n-2) mod n.
   --
   --  n   = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFF
   --        BCE6FAADA7179E84F3B9CAC2FC632551
   --  n-2 = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFF
   --        BCE6FAADA7179E84F3B9CAC2FC63254F
   ---------------------------------------------------------------------

   N_Minus_2 : constant Scalar :=
     (16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#00#, 16#00#, 16#00#, 16#00#,
      16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#, 16#FF#,
      16#BC#, 16#E6#, 16#FA#, 16#AD#, 16#A7#, 16#17#, 16#9E#, 16#84#,
      16#F3#, 16#B9#, 16#CA#, 16#C2#, 16#FC#, 16#63#, 16#25#, 16#4F#);

   procedure Invert (A : Scalar; Out_C : out Scalar) is
      Result  : Limbs8 := (others => 0);
      Base    : Limbs8;
      Tmp     : Limbs8;
      Bit     : Unsigned_8;
      Started : Boolean := False;
   begin
      Result (0) := 1;
      From_Bytes (A, Base);
      Reduce_Once_If_Geq (Base);

      for Byte_Idx in 1 .. 32 loop
         Bit := Unsigned_8 (N_Minus_2 (Byte_Idx));
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
   --  Predicates.
   ---------------------------------------------------------------------

   function Is_Zero (X : Scalar) return Boolean is
      Diff : Octet := 0;
   begin
      for I in X'Range loop
         Diff := Diff or X (I);
      end loop;
      return Diff = 0;
   end Is_Zero;

   function In_Range (X : Scalar) return Boolean is
      L : Limbs8;
   begin
      if Is_Zero (X) then
         return False;
      end if;
      From_Bytes (X, L);
      return not Geq_N (L);
   end In_Range;

end Tls_Core.P256_Order;
