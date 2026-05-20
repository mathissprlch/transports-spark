with Interfaces;

package body Tls_Core.P256
  with SPARK_Mode
is


   use Interfaces;
   use Tls_Core.P256_Field;

   ---------------------------------------------------------------------
   --  Ghost spec layer — bodies for the HACL\* Spec.P256 port.
   --  Computable Big_Integer arithmetic; no stub returns.
   ---------------------------------------------------------------------

   --  Curve parameter b as a Big_Integer (mod p). Mirrors the wire
   --  bytes used in B_Param below.
   function B_Coeff_Spec return Big.Big_Integer
   with Ghost, Global => null;

   function B_Coeff_Spec return Big.Big_Integer is
      Hex_BE : constant array (1 .. 32) of Octet :=
        [16#5A#,
         16#C6#,
         16#35#,
         16#D8#,
         16#AA#,
         16#3A#,
         16#93#,
         16#E7#,
         16#B3#,
         16#EB#,
         16#BD#,
         16#55#,
         16#76#,
         16#98#,
         16#86#,
         16#BC#,
         16#65#,
         16#1D#,
         16#06#,
         16#B0#,
         16#CC#,
         16#53#,
         16#B0#,
         16#F6#,
         16#3B#,
         16#CE#,
         16#3C#,
         16#3E#,
         16#27#,
         16#D2#,
         16#60#,
         16#4B#];
      package Octet_Big is new Big.Signed_Conversions (Int => Integer);
      R      : Big.Big_Integer := Big.To_Big_Integer (0);
   begin
      for I in Hex_BE'Range loop
         R :=
           R
           * Big.To_Big_Integer (256)
           + Octet_Big.To_Big_Integer (Integer (Hex_BE (I)));
      end loop;
      return R;
   end B_Coeff_Spec;

   --  Convert a Field bytes (BE 32) to its represented Big_Integer
   --  (already mod 2^256; we then reduce mod p).
   function Field_To_Big (F : P256_Field.Field) return Big.Big_Integer
   with Ghost, Global => null;

   function Field_To_Big (F : P256_Field.Field) return Big.Big_Integer
   is (P256_Field.Mod_P_Spec (P256_Field.To_Big_Spec (F)));

   function Spec_Of (P : Point) return Spec_Point
   is ((X => Field_To_Big (P.X),
        Y => Field_To_Big (P.Y),
        Z => Field_To_Big (P.Z)));

   function Spec_Infinity return Spec_Point
   is ((X => Big.To_Big_Integer (1),
        Y => Big.To_Big_Integer (1),
        Z => Big.To_Big_Integer (0)));

   --  Module-level mod-p arithmetic helpers used by the spec point
   --  operations. The F\* `*%` / `+%` / `-%` reduce mod p after
   --  each step; these mirror that.
   function FAdd_Spec (X, Y : Big.Big_Integer) return Big.Big_Integer
   with Ghost, Global => null;
   function FSub_Spec (X, Y : Big.Big_Integer) return Big.Big_Integer
   with Ghost, Global => null;
   function FMul_Spec (X, Y : Big.Big_Integer) return Big.Big_Integer
   with Ghost, Global => null;

   function FAdd_Spec (X, Y : Big.Big_Integer) return Big.Big_Integer
   is (P256_Field.Mod_P_Spec (X + Y));

   function FSub_Spec (X, Y : Big.Big_Integer) return Big.Big_Integer
   is (P256_Field.Mod_P_Spec (X - Y));

   function FMul_Spec (X, Y : Big.Big_Integer) return Big.Big_Integer
   is (P256_Field.Mod_P_Spec (X * Y));

   --  HACL\* point_double (Spec.P256.PointOps.fst), translated
   --  from the projective formulas of Algorithm 6, eprint
   --  2015/1060. b_coeff is the curve parameter b mod p.
   function Spec_Point_Double (P : Spec_Point) return Spec_Point is

      X : constant Big.Big_Integer := P.X;
      Y : constant Big.Big_Integer := P.Y;
      Z : constant Big.Big_Integer := P.Z;

      T0 : Big.Big_Integer := FMul_Spec (X, X);
      T1 : constant Big.Big_Integer := FMul_Spec (Y, Y);
      T2 : Big.Big_Integer := FMul_Spec (Z, Z);
      T3 : Big.Big_Integer := FMul_Spec (X, Y);
      T4 : Big.Big_Integer;
      Z3 : Big.Big_Integer;
      Y3 : Big.Big_Integer;
      X3 : Big.Big_Integer;
      B  : constant Big.Big_Integer := B_Coeff_Spec;
   begin
      T3 := FAdd_Spec (T3, T3);
      T4 := FMul_Spec (Y, Z);
      Z3 := FMul_Spec (X, Z);
      Z3 := FAdd_Spec (Z3, Z3);
      Y3 := FMul_Spec (B, T2);
      Y3 := FSub_Spec (Y3, Z3);
      X3 := FAdd_Spec (Y3, Y3);
      Y3 := FAdd_Spec (X3, Y3);
      X3 := FSub_Spec (T1, Y3);
      Y3 := FAdd_Spec (T1, Y3);
      Y3 := FMul_Spec (X3, Y3);
      X3 := FMul_Spec (X3, T3);
      T3 := FAdd_Spec (T2, T2);
      T2 := FAdd_Spec (T2, T3);
      Z3 := FMul_Spec (B, Z3);
      Z3 := FSub_Spec (Z3, T2);
      Z3 := FSub_Spec (Z3, T0);
      T3 := FAdd_Spec (Z3, Z3);
      Z3 := FAdd_Spec (Z3, T3);
      T3 := FAdd_Spec (T0, T0);
      T0 := FAdd_Spec (T3, T0);
      T0 := FSub_Spec (T0, T2);
      T0 := FMul_Spec (T0, Z3);
      Y3 := FAdd_Spec (Y3, T0);
      T0 := FAdd_Spec (T4, T4);
      Z3 := FMul_Spec (T0, Z3);
      X3 := FSub_Spec (X3, Z3);
      Z3 := FMul_Spec (T0, T1);
      Z3 := FAdd_Spec (Z3, Z3);
      Z3 := FAdd_Spec (Z3, Z3);
      return (X => X3, Y => Y3, Z => Z3);
   end Spec_Point_Double;

   --  HACL\* point_add (Spec.P256.PointOps.fst), Algorithm 4 of
   --  eprint 2015/1060.
   function Spec_Point_Add (P, Q : Spec_Point) return Spec_Point is

      X1 : constant Big.Big_Integer := P.X;
      Y1 : constant Big.Big_Integer := P.Y;
      Z1 : constant Big.Big_Integer := P.Z;
      X2 : constant Big.Big_Integer := Q.X;
      Y2 : constant Big.Big_Integer := Q.Y;
      Z2 : constant Big.Big_Integer := Q.Z;

      T0, T1, T2, T3, T4, T5, X3, Y3, Z3 : Big.Big_Integer;
      B                                  : constant Big.Big_Integer :=
        B_Coeff_Spec;
   begin
      T0 := FMul_Spec (X1, X2);
      T1 := FMul_Spec (Y1, Y2);
      T2 := FMul_Spec (Z1, Z2);
      T3 := FAdd_Spec (X1, Y1);
      T4 := FAdd_Spec (X2, Y2);
      T3 := FMul_Spec (T3, T4);
      T4 := FAdd_Spec (T0, T1);
      T3 := FSub_Spec (T3, T4);
      T4 := FAdd_Spec (Y1, Z1);
      T5 := FAdd_Spec (Y2, Z2);
      T4 := FMul_Spec (T4, T5);
      T5 := FAdd_Spec (T1, T2);
      T4 := FSub_Spec (T4, T5);
      X3 := FAdd_Spec (X1, Z1);
      Y3 := FAdd_Spec (X2, Z2);
      X3 := FMul_Spec (X3, Y3);
      Y3 := FAdd_Spec (T0, T2);
      Y3 := FSub_Spec (X3, Y3);
      Z3 := FMul_Spec (B, T2);
      X3 := FSub_Spec (Y3, Z3);
      Z3 := FAdd_Spec (X3, X3);
      X3 := FAdd_Spec (X3, Z3);
      Z3 := FSub_Spec (T1, X3);
      X3 := FAdd_Spec (T1, X3);
      Y3 := FMul_Spec (B, Y3);
      T1 := FAdd_Spec (T2, T2);
      T2 := FAdd_Spec (T1, T2);
      Y3 := FSub_Spec (Y3, T2);
      Y3 := FSub_Spec (Y3, T0);
      T1 := FAdd_Spec (Y3, Y3);
      Y3 := FAdd_Spec (T1, Y3);
      T1 := FAdd_Spec (T0, T0);
      T0 := FAdd_Spec (T1, T0);
      T0 := FSub_Spec (T0, T2);
      T1 := FMul_Spec (T4, Y3);
      T2 := FMul_Spec (T0, Y3);
      Y3 := FMul_Spec (X3, Z3);
      Y3 := FAdd_Spec (Y3, T2);
      X3 := FMul_Spec (T3, X3);
      X3 := FSub_Spec (X3, T1);
      Z3 := FMul_Spec (T4, Z3);
      T1 := FMul_Spec (T3, T0);
      Z3 := FAdd_Spec (Z3, T1);
      return (X => X3, Y => Y3, Z => Z3);
   end Spec_Point_Add;

   --  Two projective points are equivalent iff they map to the
   --  same affine point. Both-at-infinity is the Z = 0 case;
   --  otherwise compare cross-multiplied affine coords mod p.
   function Spec_Equiv_Point (P, Q : Spec_Point) return Boolean is
      P_Mod              : constant Big.Big_Integer := P256_Field.Prime_P_Spec;
      Pz_Zero            : constant Boolean :=
        (P.Z mod P_Mod) = Big.To_Big_Integer (0);
      Qz_Zero            : constant Boolean :=
        (Q.Z mod P_Mod) = Big.To_Big_Integer (0);
      Pz2, Pz3, Qz2, Qz3 : Big.Big_Integer;
   begin
      if Pz_Zero or Qz_Zero then
         return Pz_Zero = Qz_Zero;
      end if;
      Pz2 := (P.Z * P.Z) mod P_Mod;
      Pz3 := (Pz2 * P.Z) mod P_Mod;
      Qz2 := (Q.Z * Q.Z) mod P_Mod;
      Qz3 := (Qz2 * Q.Z) mod P_Mod;
      return
        ((P.X * Qz2) mod P_Mod) = ((Q.X * Pz2) mod P_Mod)
        and then ((P.Y * Qz3) mod P_Mod) = ((Q.Y * Pz3) mod P_Mod);
   end Spec_Equiv_Point;

   --  HACL\* Spec.P256.fst :  point_mul  — port. Walks the 32-byte
   --  scalar MSB-first; one Spec_Point_Double per bit and one
   --  Spec_Point_Add when the bit is 1, exactly matching the
   --  Montgomery-ladder semantics of Scalar_Mul below.
   function Spec_Scalar_Mult
     (Scalar : Octet_Array; P : Spec_Point) return Spec_Point
   is
      Acc : Spec_Point := Spec_Infinity;
      Bit : Natural;
   begin
      for I in 0 .. 31 loop
         declare
            Byte_V : constant Natural := Natural (Scalar (Scalar'First + I));
         begin
            for B in reverse 0 .. 7 loop
               declare
                  Pow_2_B : constant Natural :=
                    (case B is
                       when 0      => 1,
                       when 1      => 2,
                       when 2      => 4,
                       when 3      => 8,
                       when 4      => 16,
                       when 5      => 32,
                       when 6      => 64,
                       when 7      => 128);
               begin
                  Bit := (Byte_V / Pow_2_B) mod 2;
               end;
               Acc := Spec_Point_Double (Acc);
               if Bit = 1 then
                  Acc := Spec_Point_Add (Acc, P);
               end if;
            end loop;
         end;
      end loop;
      return Acc;
   end Spec_Scalar_Mult;

   ---------------------------------------------------------------------
   --  Curve parameter b (NIST P-256, FIPS 186-4 §D.1.2.3).
   --
   --      b = 0x5AC635D8 AA3A93E7 B3EBBD55 769886BC
   --          651D06B0 CC53B0F6 3BCE3C3E 27D2604B
   ---------------------------------------------------------------------

   B_Param : constant Field :=
     [16#5A#,
      16#C6#,
      16#35#,
      16#D8#,
      16#AA#,
      16#3A#,
      16#93#,
      16#E7#,
      16#B3#,
      16#EB#,
      16#BD#,
      16#55#,
      16#76#,
      16#98#,
      16#86#,
      16#BC#,
      16#65#,
      16#1D#,
      16#06#,
      16#B0#,
      16#CC#,
      16#53#,
      16#B0#,
      16#F6#,
      16#3B#,
      16#CE#,
      16#3C#,
      16#3E#,
      16#27#,
      16#D2#,
      16#60#,
      16#4B#];

   ---------------------------------------------------------------------
   --  Helpers.
   ---------------------------------------------------------------------

   function Is_Infinity (P : Point) return Boolean is
   begin
      return Tls_Core.P256_Field.Equal_CT (P.Z, Tls_Core.P256_Field.Zero);
   end Is_Infinity;

   --  Compute t = a + a (mod p) without going through the slower
   --  Mul-by-2 path. Just calls Add (a, a, t).
   procedure F_Double (A : Field; R : out Field) is
   begin
      Tls_Core.P256_Field.Add (A, A, R);
   end F_Double;

   ---------------------------------------------------------------------
   --  Point doubling — Bernstein–Lange "dbl-2001-b" specialised for
   --  curves with a = -3 (which P-256 is).
   --
   --     delta = Z^2
   --     gamma = Y^2
   --     beta  = X * gamma
   --     alpha = 3 (X - delta)(X + delta)
   --     X3    = alpha^2 - 8 * beta
   --     Z3    = (Y + Z)^2 - gamma - delta
   --     Y3    = alpha (4 beta - X3) - 8 gamma^2
   --
   --  Source: explicit-formulas database / SEC 1 §2.2.1.
   ---------------------------------------------------------------------

   procedure Double_Point (P : Point; R : out Point) is
      Delta_F, Gamma_F, Beta_F, Alpha_F : Field;
      T1, T2, T3, T4                    : Field;
      Eight_Beta                        : Field;
      Eight_Gamma_Sq                    : Field;
      Four_Beta                         : Field;
   begin
      if Is_Infinity (P) then
         R := Infinity;
         return;
      end if;

      --  delta = Z^2
      Square (P.Z, Delta_F);
      --  gamma = Y^2
      Square (P.Y, Gamma_F);
      --  beta = X * gamma
      Mul (P.X, Gamma_F, Beta_F);

      --  alpha = 3*(X - delta)*(X + delta)
      Sub (P.X, Delta_F, T1);          --  X - delta
      Add (P.X, Delta_F, T2);          --  X + delta
      Mul (T1, T2, T3);                --  (X-delta)(X+delta)
      Add (T3, T3, T4);                --  2 * t3
      Add (T4, T3, Alpha_F);           --  3 * t3

      --  X3 = alpha^2 - 8*beta
      Square (Alpha_F, T1);
      F_Double (Beta_F, T2);           --  2 beta
      F_Double (T2, T3);               --  4 beta
      F_Double (T3, Eight_Beta);       --  8 beta
      Sub (T1, Eight_Beta, R.X);

      --  Z3 = (Y + Z)^2 - gamma - delta
      Add (P.Y, P.Z, T1);
      Square (T1, T2);
      Sub (T2, Gamma_F, T3);
      Sub (T3, Delta_F, R.Z);

      --  Y3 = alpha * (4*beta - X3) - 8 * gamma^2
      F_Double (Beta_F, T1);           --  2 beta
      F_Double (T1, Four_Beta);        --  4 beta
      Sub (Four_Beta, R.X, T2);
      Mul (Alpha_F, T2, T3);
      Square (Gamma_F, T1);            --  gamma^2
      F_Double (T1, T2);               --  2 gamma^2
      F_Double (T2, T1);               --  4 gamma^2
      F_Double (T1, Eight_Gamma_Sq);   --  8 gamma^2
      Sub (T3, Eight_Gamma_Sq, R.Y);
   end Double_Point;

   ---------------------------------------------------------------------
   --  Generic point addition — Bernstein–Lange "add-2007-bl"
   --  (Jacobian + Jacobian, both finite, P1 != +/-P2).
   --
   --     Z1Z1 = Z1^2
   --     Z2Z2 = Z2^2
   --     U1 = X1 * Z2Z2
   --     U2 = X2 * Z1Z1
   --     S1 = Y1 * Z2 * Z2Z2
   --     S2 = Y2 * Z1 * Z1Z1
   --     H  = U2 - U1
   --     I  = (2H)^2
   --     J  = H * I
   --     r  = 2 (S2 - S1)
   --     V  = U1 * I
   --     X3 = r^2 - J - 2 V
   --     Y3 = r (V - X3) - 2 S1 J
   --     Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2) * H
   --
   --  Source: explicit-formulas database; SEC 1 §2.2.1.
   ---------------------------------------------------------------------

   procedure Add_Distinct (P1, P2 : Point; R : out Point) is
      Z1Z1, Z2Z2, U1, U2, S1, S2, H, I_F, J, R_F, V : Field;
      T1, T2, T3, T4                                : Field;
      Two_H                                         : Field;
   begin
      --  Z1Z1 = Z1^2; Z2Z2 = Z2^2
      Square (P1.Z, Z1Z1);
      Square (P2.Z, Z2Z2);
      --  U1 = X1 * Z2Z2; U2 = X2 * Z1Z1
      Mul (P1.X, Z2Z2, U1);
      Mul (P2.X, Z1Z1, U2);
      --  S1 = Y1 * Z2 * Z2Z2
      Mul (P1.Y, P2.Z, T1);
      Mul (T1, Z2Z2, S1);
      --  S2 = Y2 * Z1 * Z1Z1
      Mul (P2.Y, P1.Z, T1);
      Mul (T1, Z1Z1, S2);
      --  H = U2 - U1
      Sub (U2, U1, H);
      --  I = (2H)^2
      F_Double (H, Two_H);
      Square (Two_H, I_F);
      --  J = H * I
      Mul (H, I_F, J);
      --  r = 2*(S2 - S1)
      Sub (S2, S1, T2);
      F_Double (T2, R_F);
      --  V = U1 * I
      Mul (U1, I_F, V);
      --  X3 = r^2 - J - 2V
      Square (R_F, T1);
      Sub (T1, J, T2);
      F_Double (V, T3);
      Sub (T2, T3, R.X);
      --  Y3 = r*(V - X3) - 2*S1*J
      Sub (V, R.X, T1);
      Mul (R_F, T1, T2);
      Mul (S1, J, T3);
      F_Double (T3, T4);
      Sub (T2, T4, R.Y);
      --  Z3 = ((Z1+Z2)^2 - Z1Z1 - Z2Z2) * H
      Add (P1.Z, P2.Z, T1);
      Square (T1, T2);
      Sub (T2, Z1Z1, T3);
      Sub (T3, Z2Z2, T4);
      Mul (T4, H, R.Z);
   end Add_Distinct;

   ---------------------------------------------------------------------
   --  Full add — handles identity / equal / negation cases.
   ---------------------------------------------------------------------

   procedure Add_Point (P1, P2 : Point; R : out Point) is
      Z1Z1, Z2Z2, U1, U2, S1, S2 : Field;
      T1                         : Field;
      U_Eq, S_Eq                 : Boolean;
   begin
      if Is_Infinity (P1) then
         R := P2;
         return;
      end if;
      if Is_Infinity (P2) then
         R := P1;
         return;
      end if;

      --  Detect equal/inverse points (U1 = U2 means same affine X).
      Square (P1.Z, Z1Z1);
      Square (P2.Z, Z2Z2);
      Mul (P1.X, Z2Z2, U1);
      Mul (P2.X, Z1Z1, U2);
      Mul (P1.Y, P2.Z, T1);
      Mul (T1, Z2Z2, S1);
      Mul (P2.Y, P1.Z, T1);
      Mul (T1, Z1Z1, S2);

      U_Eq := Equal_CT (U1, U2);
      S_Eq := Equal_CT (S1, S2);

      if U_Eq then
         if S_Eq then
            Double_Point (P1, R);
         else
            R := Infinity;
         end if;
         return;
      end if;

      Add_Distinct (P1, P2, R);
   end Add_Point;

   ---------------------------------------------------------------------
   --  Decode_Uncompressed (SEC 1 §2.3.4) and curve membership check.
   ---------------------------------------------------------------------

   procedure Decode_Uncompressed
     (Bytes : Octet_Array; Out_P : out Point; OK : out Boolean)
   is
      X, Y                 : Field;
      Lhs, Rhs             : Field;
      X_Cubed, Three_X, T1 : Field;
      Three                : Field := [others => 0];
   begin
      Out_P := Infinity;
      OK := False;

      --  Header byte must be 0x04 (uncompressed).
      if Bytes (Bytes'First) /= 16#04# then
         return;
      end if;

      --  Slice X (next 32 bytes) and Y (last 32 bytes).
      for I in 0 .. 31 loop
         X (1 + I) := Bytes (Bytes'First + 1 + I);
         Y (1 + I) := Bytes (Bytes'First + 33 + I);
      end loop;

      --  Curve equation: Y^2 = X^3 - 3*X + b (mod p).
      Square (Y, Lhs);
      Square (X, T1);
      Mul (T1, X, X_Cubed);
      Three (32) := 3;
      Mul (Three, X, Three_X);
      Sub (X_Cubed, Three_X, T1);
      Add (T1, B_Param, Rhs);

      if not Equal_CT (Lhs, Rhs) then
         return;
      end if;

      Out_P := (X => X, Y => Y, Z => One);
      OK := True;
   end Decode_Uncompressed;

   ---------------------------------------------------------------------
   --  Encode_Uncompressed (SEC 1 §2.3.3).
   ---------------------------------------------------------------------

   procedure Encode_Uncompressed (P : Point; Out_Bytes : out Octet_Array) is
      AX, AY : Field;
   begin
      if Is_Infinity (P) then
         for I in Out_Bytes'Range loop
            Out_Bytes (I) := 0;
         end loop;
         return;
      end if;

      --  Affine x = X / Z^2, affine y = Y / Z^3.
      declare
         Z_Inv, Z_Inv2, Z_Inv3 : Field;
      begin
         Invert (P.Z, Z_Inv);
         Square (Z_Inv, Z_Inv2);
         Mul (Z_Inv2, Z_Inv, Z_Inv3);
         Mul (P.X, Z_Inv2, AX);
         Mul (P.Y, Z_Inv3, AY);
      end;

      Out_Bytes (Out_Bytes'First) := 16#04#;
      for I in 0 .. 31 loop
         Out_Bytes (Out_Bytes'First + 1 + I) := AX (1 + I);
         Out_Bytes (Out_Bytes'First + 33 + I) := AY (1 + I);
      end loop;
   end Encode_Uncompressed;

   ---------------------------------------------------------------------
   --  To_Affine_X — recover x = X / Z^2.
   ---------------------------------------------------------------------

   procedure To_Affine_X (P : Point; Out_X : out Field) is
      Z_Inv, Z_Inv2 : Field;
   begin
      if Is_Infinity (P) then
         Out_X := Tls_Core.P256_Field.Zero;
         return;
      end if;
      Invert (P.Z, Z_Inv);
      Square (Z_Inv, Z_Inv2);
      Mul (P.X, Z_Inv2, Out_X);
   end To_Affine_X;

   ---------------------------------------------------------------------
   --  Public Add_Points wrapper — exposes Add_Point for ECDSA.
   ---------------------------------------------------------------------

   procedure Add_Points (P1, P2 : Point; Out_R : out Point) is
   begin
      Add_Point (P1, P2, Out_R);
   end Add_Points;

   ---------------------------------------------------------------------
   --  Constant-time conditional swap of two points. Mask = -Bit so
   --  that a 1 bit selects the swap and a 0 bit leaves the points
   --  alone, with no branching on Bit beyond the mask itself.
   ---------------------------------------------------------------------

   procedure C_Swap_Field (A, B : in out Field; Bit : Octet) is
      Mask : constant Octet := (if Bit = 1 then 16#FF# else 16#00#);
      T    : Octet;
   begin
      for I in Field'Range loop
         T := (A (I) xor B (I)) and Mask;
         A (I) := A (I) xor T;
         B (I) := B (I) xor T;
      end loop;
   end C_Swap_Field;

   procedure C_Swap_Point (P1, P2 : in out Point; Bit : Octet) is
   begin
      C_Swap_Field (P1.X, P2.X, Bit);
      C_Swap_Field (P1.Y, P2.Y, Bit);
      C_Swap_Field (P1.Z, P2.Z, Bit);
   end C_Swap_Point;

   ---------------------------------------------------------------------
   --  Scalar_Mul — Montgomery ladder over Jacobian coordinates.
   --
   --  Maintain (R0, R1) with invariant R1 - R0 = P. For each
   --  scalar bit b (MSB-first):
   --      cswap(R0, R1, b)
   --      R1 = R0 + R1
   --      R0 = 2 R0
   --      cswap(R0, R1, b)
   --
   --  After 256 iterations starting from (R0, R1) = (O, P), we have
   --  R0 = scalar * P. The first iteration swallows the leading
   --  zeros uniformly (R0 stays at O until the first 1 bit flips
   --  it to P, then doubling-and-adding takes over).
   --
   --  Each iteration performs one full add (Add_Distinct) and one
   --  double (Double_Point). The general add formula degenerates
   --  when one operand is the point at infinity; we handle that
   --  via the wrapper Add_Point. R0 remains O for as many leading-
   --  zero bits as the scalar has, after which all subsequent
   --  iterations operate on two finite points whose difference is
   --  always P, never the identity.
   ---------------------------------------------------------------------

   procedure Scalar_Mul (Scalar : Octet_Array; P : Point; Out_R : out Point) is
      R0     : Point := Infinity;
      R1     : Point := P;
      T0, T1 : Point;
      Bit    : Octet;
      Byte_V : Unsigned_8;
   begin
      for I in 0 .. 31 loop
         Byte_V := Unsigned_8 (Scalar (Scalar'First + I));
         for B in reverse 0 .. 7 loop
            Bit := Octet ((Shift_Right (Byte_V, B)) and 1);
            C_Swap_Point (R0, R1, Bit);
            Add_Point (R0, R1, T1);
            Double_Point (R0, T0);
            R0 := T0;
            R1 := T1;
            C_Swap_Point (R0, R1, Bit);
         end loop;
      end loop;
      Out_R := R0;
   end Scalar_Mul;

end Tls_Core.P256;
