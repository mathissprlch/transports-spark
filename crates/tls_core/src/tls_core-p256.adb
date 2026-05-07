with Interfaces;

package body Tls_Core.P256
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use Interfaces;
   use Tls_Core.P256_Field;

   ---------------------------------------------------------------------
   --  Curve parameter b (NIST P-256, FIPS 186-4 §D.1.2.3).
   --
   --      b = 0x5AC635D8 AA3A93E7 B3EBBD55 769886BC
   --          651D06B0 CC53B0F6 3BCE3C3E 27D2604B
   ---------------------------------------------------------------------

   B_Param : constant Field :=
     (16#5A#, 16#C6#, 16#35#, 16#D8#, 16#AA#, 16#3A#, 16#93#, 16#E7#,
      16#B3#, 16#EB#, 16#BD#, 16#55#, 16#76#, 16#98#, 16#86#, 16#BC#,
      16#65#, 16#1D#, 16#06#, 16#B0#, 16#CC#, 16#53#, 16#B0#, 16#F6#,
      16#3B#, 16#CE#, 16#3C#, 16#3E#, 16#27#, 16#D2#, 16#60#, 16#4B#);

   ---------------------------------------------------------------------
   --  Helpers.
   ---------------------------------------------------------------------

   function Is_Infinity (P : Point) return Boolean is
   begin
      return Tls_Core.P256_Field.Equal_CT
        (P.Z, Tls_Core.P256_Field.Zero);
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
      T1, T2, T3, T4 : Field;
      Eight_Beta : Field;
      Eight_Gamma_Sq : Field;
      Four_Beta : Field;
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
      T1, T2, T3, T4 : Field;
      Two_H : Field;
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
      T1 : Field;
      U_Eq, S_Eq : Boolean;
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
     (Bytes : Octet_Array;
      Out_P : out Point;
      OK    : out Boolean)
   is
      X, Y : Field;
      Lhs, Rhs : Field;
      X_Cubed, Three_X, T1 : Field;
      Three : Field := (others => 0);
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

   procedure Encode_Uncompressed
     (P         : Point;
      Out_Bytes : out Octet_Array)
   is
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
      T : Octet;
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

   procedure Scalar_Mul
     (Scalar : Octet_Array;
      P      : Point;
      Out_R  : out Point)
   is
      R0 : Point := Infinity;
      R1 : Point := P;
      T0, T1 : Point;
      Bit : Octet;
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
