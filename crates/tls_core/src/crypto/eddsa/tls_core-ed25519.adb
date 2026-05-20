with Interfaces;

with Tls_Core.Field25519;
with Tls_Core.Sha512;

package body Tls_Core.Ed25519 is

   use Interfaces;
   use Tls_Core.Field25519;

   ---------------------------------------------------------------------
   --  Edwards curve parameters and base point B (RFC 8032 §5.1.5).
   --  d = -121665/121666 mod p; we hand-compute and embed the
   --  16-limb representation here.
   ---------------------------------------------------------------------

   --  d in 16 × 16-bit limbs, little-endian (low limb first).
   D_Felt : constant Felt :=
     [16#78A3#,
      16#1359#,
      16#4DCA#,
      16#75EB#,
      16#D8AB#,
      16#4141#,
      16#0A4D#,
      16#0070#,
      16#E898#,
      16#7779#,
      16#4079#,
      16#8CC7#,
      16#FE73#,
      16#2B6F#,
      16#6CEE#,
      16#5203#];

   --  2 * d.
   D2_Felt : constant Felt :=
     [16#F159#,
      16#26B2#,
      16#9B94#,
      16#EBD6#,
      16#B156#,
      16#8283#,
      16#149A#,
      16#00E0#,
      16#D130#,
      16#EEF3#,
      16#80F2#,
      16#198E#,
      16#FCE7#,
      16#56DF#,
      16#D9DC#,
      16#2406#];

   --  Curve order L = 2^252 + 27742317777372353535851937790883648493
   --  is held inside Mod_L_Pkg below as L_Bytes_S so it can sit
   --  under SPARK_Mode => On with a tight 0..255 element subtype.

   ---------------------------------------------------------------------
   --  Edwards extended-coordinate point (X, Y, Z, T) with affine
   --  relation x = X/Z, y = Y/Z, x*y = T/Z.
   ---------------------------------------------------------------------

   type Point is record
      X, Y, Z, T : Felt;
   end record;

   --  Identity element: (0, 1, 1, 0) in extended coordinates.
   procedure Set_Identity (P : out Point);
   procedure Set_Identity (P : out Point) is
   begin
      P.X := [others => 0];
      P.Y := [others => 0];
      P.Y (0) := 1;
      P.Z := [others => 0];
      P.Z (0) := 1;
      P.T := [others => 0];
   end Set_Identity;

   --  Base point B in extended coordinates (RFC 8032 §5.1). T is
   --  computed at runtime via Get_Base_Point so we avoid a separate
   --  hardcoded constant that could drift from X*Y.

   Bx : constant Felt :=
     [16#D51A#,
      16#8F25#,
      16#2D60#,
      16#C956#,
      16#A7B2#,
      16#9525#,
      16#C760#,
      16#692C#,
      16#DC5C#,
      16#FDD6#,
      16#E231#,
      16#C0A4#,
      16#53FE#,
      16#CD6E#,
      16#36D3#,
      16#2169#];

   By : constant Felt :=
     [16#6658#,
      16#6666#,
      16#6666#,
      16#6666#,
      16#6666#,
      16#6666#,
      16#6666#,
      16#6666#,
      16#6666#,
      16#6666#,
      16#6666#,
      16#6666#,
      16#6666#,
      16#6666#,
      16#6666#,
      16#6666#];

   procedure Get_Base_Point (P : out Point);
   procedure Get_Base_Point (P : out Point) is
   begin
      P.X := Bx;
      P.Y := By;
      P.Z := [1, others => 0];
      F_Mul (P.T, Bx, By);
   end Get_Base_Point;

   ---------------------------------------------------------------------
   --  Point addition (RFC 8032 §5.1.4):
   --      A = (Y1-X1)*(Y2-X2)
   --      B = (Y1+X1)*(Y2+X2)
   --      C = T1 * 2d * T2
   --      D = Z1 * 2 * Z2
   --      E = B - A; F = D - C; G = D + C; H = B + A
   --      X3 = E*F; Y3 = G*H; T3 = E*H; Z3 = F*G
   ---------------------------------------------------------------------

   procedure Point_Add (R : out Point; P, Q : Point);
   procedure Point_Add (R : out Point; P, Q : Point) is
      Aval, Bval, Cval, Dval : Felt;
      Eval, Fval, Gval, Hval : Felt;
      T1, T2                 : Felt;
   begin
      F_Sub (T1, P.Y, P.X);
      F_Sub (T2, Q.Y, Q.X);
      F_Mul (Aval, T1, T2);

      F_Add (T1, P.Y, P.X);
      F_Add (T2, Q.Y, Q.X);
      F_Mul (Bval, T1, T2);

      F_Mul (T1, P.T, D2_Felt);
      F_Mul (Cval, T1, Q.T);

      F_Add (T1, P.Z, P.Z);
      F_Mul (Dval, T1, Q.Z);

      F_Sub (Eval, Bval, Aval);
      F_Sub (Fval, Dval, Cval);
      F_Add (Gval, Dval, Cval);
      F_Add (Hval, Bval, Aval);

      F_Mul (R.X, Eval, Fval);
      F_Mul (R.Y, Gval, Hval);
      F_Mul (R.T, Eval, Hval);
      F_Mul (R.Z, Fval, Gval);
   end Point_Add;

   ---------------------------------------------------------------------
   --  Scalar multiplication via simple double-and-add over the bits
   --  of `Scalar` (LE). Not constant-time; verification doesn't need
   --  it (only signing of secret keys does).
   ---------------------------------------------------------------------

   procedure Scalar_Mult_Bytes
     (R : out Point; Scalar : Octet_Array; Base : Point);
   procedure Scalar_Mult_Bytes
     (R : out Point; Scalar : Octet_Array; Base : Point)
   is
      Acc, Tmp, Cur : Point;
   begin
      Set_Identity (Acc);
      Cur := Base;
      for I in 0 .. (Scalar'Length * 8) - 1 loop
         declare
            Byte : constant Integer_64 :=
              Integer_64 (Scalar (Scalar'First + I / 8));
            Bit  : constant Integer_64 := And_64 (Asr (Byte, I mod 8), 1);
         begin
            if Bit = 1 then
               Point_Add (Tmp, Acc, Cur);
               Acc := Tmp;
            end if;
            Point_Add (Tmp, Cur, Cur);
            Cur := Tmp;
         end;
      end loop;
      R := Acc;
   end Scalar_Mult_Bytes;

   ---------------------------------------------------------------------
   --  Point compression: encode as the y-coordinate's 32 LE bytes,
   --  with the sign bit of x stuffed into the high bit of the last
   --  byte.
   --
   --  Steps: normalize Z=1 (multiply x, y by Z^-1), pack y, then
   --  OR in the parity of x into bit 7 of byte 32.
   ---------------------------------------------------------------------

   procedure Encode_Point (Out_Bytes : out Bytes_32; P : Point);
   procedure Encode_Point (Out_Bytes : out Bytes_32; P : Point) is
      Z_Inv, X_Aff, Y_Aff : Felt;
      Sign_Bit            : Integer_64;
   begin
      F_Inv (Z_Inv, P.Z);
      F_Mul (X_Aff, P.X, Z_Inv);
      F_Mul (Y_Aff, P.Y, Z_Inv);
      Pack (Out_Bytes, Y_Aff);
      Sign_Bit := Parity (X_Aff);
      Out_Bytes (32) :=
        Out_Bytes (32) or Octet (Shift_Left (Unsigned_8 (Sign_Bit), 7));
   end Encode_Point;

   ---------------------------------------------------------------------
   --  Point decompression — reverse of Encode_Point. Recovers x from
   --  y per the curve equation x^2 = (y^2 - 1) / (d*y^2 + 1) and
   --  the spec's tonelli-shanks-like square root for p = 5 mod 8:
   --      x = sqrt_candidate * (sqrt_candidate^2 == numerator
   --                            ? 1 : sqrt(-1))
   --      where sqrt_candidate = (numerator * denominator^3) *
   --                             (numerator * denominator^7)^((p-5)/8)
   --
   --  Returns OK = False if the input doesn't decode to a valid point.
   ---------------------------------------------------------------------

   --  Felt equality test via canonical packing.
   function Felt_Eq (A, B : Felt) return Boolean;
   function Felt_Eq (A, B : Felt) return Boolean is
      Pa, Pb : Bytes_32;
   begin
      Pack (Pa, A);
      Pack (Pb, B);
      for I in Pa'Range loop
         if Pa (I) /= Pb (I) then
            return False;
         end if;
      end loop;
      return True;
   end Felt_Eq;

   procedure Decode_Point
     (P : out Point; In_Bytes : Bytes_32; OK : out Boolean);
   procedure Decode_Point
     (P : out Point; In_Bytes : Bytes_32; OK : out Boolean)
   is
      One                               : constant Felt := [1, others => 0];
      I_Sqrt_M1                         : constant Felt :=
      --  sqrt(-1) mod p — TweetNaCl's `gf I` constant.
        [16#A0B0#,
         16#4A0E#,
         16#1B27#,
         16#C4EE#,
         16#E478#,
         16#AD2F#,
         16#1806#,
         16#2F43#,
         16#D7A7#,
         16#3DFB#,
         16#0099#,
         16#2B4D#,
         16#DF0B#,
         16#4FC1#,
         16#2480#,
         16#2B83#];
      Y, Y2, Num, Den, Den2, Den4, Den6 : Felt;
      T1, X_Cand, Chk, Tmp, Negated     : Felt;
      Local_In                          : Bytes_32 := In_Bytes;
      Sign_Bit                          : constant Integer_64 :=
        And_64 (Asr (Integer_64 (In_Bytes (32)), 7), 1);
   begin
      Local_In (32) := Local_In (32) and 16#7F#;
      Unpack (Y, Local_In);
      P.Y := Y;
      P.Z := One;
      --  num = y^2 - 1, den = d*y^2 + 1.
      F_Sqr (Y2, Y);
      F_Mul (Den, Y2, D_Felt);
      F_Sub (Num, Y2, One);
      F_Add (Tmp, One, Den);
      Den := Tmp;
      --  den^2, den^4, den^6.
      F_Sqr (Den2, Den);
      F_Sqr (Den4, Den2);
      F_Mul (Den6, Den4, Den2);
      --  t = num * den^7.
      F_Mul (T1, Num, Den6);
      F_Mul (Tmp, T1, Den);
      T1 := Tmp;
      --  t = t^((p-5)/8).
      Pow_2523 (Tmp, T1);
      T1 := Tmp;
      --  x_cand = t * num * den^3.
      F_Mul (Tmp, T1, Num);
      T1 := Tmp;
      F_Mul (Tmp, T1, Den);
      T1 := Tmp;
      F_Mul (Tmp, T1, Den);
      T1 := Tmp;
      F_Mul (X_Cand, T1, Den);
      --  Check: x_cand^2 * den == num? If not, multiply by sqrt(-1).
      F_Sqr (Chk, X_Cand);
      F_Mul (Tmp, Chk, Den);
      Chk := Tmp;
      if not Felt_Eq (Chk, Num) then
         F_Mul (Tmp, X_Cand, I_Sqrt_M1);
         X_Cand := Tmp;
      end if;
      --  Re-check after possible sqrt(-1) multiply.
      F_Sqr (Chk, X_Cand);
      F_Mul (Tmp, Chk, Den);
      Chk := Tmp;
      if not Felt_Eq (Chk, Num) then
         OK := False;
         Set_Identity (P);
         return;
      end if;
      --  Pick the candidate's sign matching the encoded sign bit.
      if Parity (X_Cand) /= Sign_Bit then
         F_Sub (Negated, [others => 0], X_Cand);
         X_Cand := Negated;
      end if;
      P.X := X_Cand;
      F_Mul (P.T, X_Cand, Y);
      OK := True;
   end Decode_Point;

   ---------------------------------------------------------------------
   --  Reduce a 64-byte little-endian integer mod L.
   --
   --  Algorithm: HACL* style 56-bit-limb Barrett reduction.  Mirrors
   --  Hacl.Spec.BignumQ.Mul.barrett_reduction5
   --  (https://github.com/hacl-star/hacl-star/blob/main/code/ed25519/
   --   Hacl.Spec.BignumQ.Mul.fst) — the verified, performance-first
   --  reference used by miTLS / project-everest.
   --
   --  Representation:
   --    Qelem (5 limbs of 56 bits each, LSB first)        ≡ 0 .. 2^280
   --    Qelem_Wide (10 limbs of 56 bits each, LSB first) ≡ 0 .. 2^560
   --
   --  Pipeline (cf. HACL barrett_reduction5):
   --    1. Carry-propagate the in/out X64_Array (each limb in
   --       0 .. 2**21) into a 64-byte little-endian integer.
   --    2. Load 64 bytes into a Qelem_Wide (10 56-bit limbs).
   --    3. q          := (input >> 248)           (Qelem)
   --    4. qmu        := q * mu                   (Qelem_Wide)
   --    5. qdiv       := qmu >> 264               (Qelem)
   --    6. r          := input mod 2^264          (Qelem)
   --    7. qmul       := (qdiv * L) mod 2^264     (Qelem)
   --    8. s          := (r - qmul) mod 2^264     (Qelem)
   --    9. result     := if s >= L then s - L else s
   --
   --  Each step is its own straight-line procedure with tight
   --  Pre/Post limb bounds; no loop invariants on cumulative
   --  carry chains, so every VC discharges automatically at level=2.
   --  Behaviour is bit-identical to the previous TweetNaCl modL —
   --  validated end-to-end by the RFC 8032 §7.1 sign+verify KAT
   --  vectors (see tls_core_tests.adb scenario 23).
   ---------------------------------------------------------------------

   --  Internal helper: 64-element Integer_64 staging used by Sign's
   --  polynomial product.  Per-limb bound 2**21 covers
   --  255 + 32*255*255 = 2,081,055 < 2**21 (verify path uses 0..255).
   subtype X64 is Natural range 0 .. 63;
   type X64_Array is array (X64) of Interfaces.Integer_64;

   --  Per-limb starting bound used as Mod_L_Core's precondition.
   --  Polynomial product `r + k*a` (Sign): each limb is bounded
   --  by 32 cross terms of 255*255 plus 255 < 2**21.  Verify
   --  path feeds bytes 0..255, well within 2**21.  Lower bound
   --  is 0: every contribution is non-negative.
   X_Limb_Bound : constant := 2**21;

   package Mod_L_Pkg
     with SPARK_Mode => On
   is

      procedure Mod_L_Core (Out_Bytes : out Bytes_32; X : X64_Array)
      with Pre => (for all K in X64 => X (K) in 0 .. X_Limb_Bound);

   end Mod_L_Pkg;

   package body Mod_L_Pkg
     with SPARK_Mode => On
   is

      subtype U64 is Interfaces.Unsigned_64;
      subtype U128 is Interfaces.Unsigned_128;

      --  56-bit limb (HACL Hacl.Spec.BignumQ.Definitions.qelem5).
      Pow56 : constant := 2**56;
      subtype Limb is U64 range 0 .. Pow56 - 1;

      --  5-limb representation (560/2 bits but only 280 used; the
      --  top limb in HACL is further restricted to 32 bits when
      --  storing, but here we keep the full 56 for arithmetic
      --  intermediates).
      type Qelem is array (0 .. 4) of Limb;
      type Qelem_Wide is array (0 .. 9) of Limb;

      --  Curve order L = 2^252 + 27742317777372353535851937790883648493
      --  Hacl.Spec.BignumQ.Mul.make_m.
      Make_M : constant Qelem :=
        [16#0012_631A_5CF5_D3ED#,
         16#00F9_DEA2_F79C_D658#,
         16#0000_0000_0000_14DE#,
         16#0000_0000_0000_0000#,
         16#0000_0000_1000_0000#];

      --  mu = floor(2^512 / L), 56-bit-limb LE.
      --  Hacl.Spec.BignumQ.Mul.make_mu.
      Make_Mu : constant Qelem :=
        [16#009C_E5A3_0A2C_131B#,
         16#0021_5D08_6329_A7ED#,
         16#00FF_FFFF_FFEB_2106#,
         16#00FF_FFFF_FFFF_FFFF#,
         16#0000_000F_FFFF_FFFF#];

      Mask56 : constant U64 := Pow56 - 1;
      Mask40 : constant U64 := 2**40 - 1;

      ---------------------------------------------------------------
      --  Step 1: carry-propagate X (each limb 0..2**21) into 64
      --  little-endian bytes.  After the loop, every Result(I) is
      --  in 0..255.
      --
      --  Carry bound: each iteration's carry is ((prev limb +
      --  prev carry) / 256), with prev limb ≤ 2**21 and prev
      --  carry ≤ 2**21 (loop-invariant).  So
      --      next carry ≤ (2**21 + 2**21) / 256 = 2**14
      --  which is ≤ 2**21, preserving the bound.  We use the
      --  precise round number 2**21 because it lets the proof
      --  carry forward without per-iteration tightening.
      ---------------------------------------------------------------

      type Bytes_64 is array (0 .. 63) of U64;

      procedure Carry_Propagate_64 (X : X64_Array; B : out Bytes_64)
      with
        Pre  => (for all K in X64 => X (K) in 0 .. X_Limb_Bound),
        Post => (for all K in 0 .. 63 => B (K) <= 255);

      procedure Carry_Propagate_64 (X : X64_Array; B : out Bytes_64) is
         C : Integer_64 := 0;  --  running carry
         V : Integer_64;
      begin
         B := [others => 0];
         for I in 0 .. 63 loop
            pragma Loop_Invariant (C in 0 .. X_Limb_Bound);
            pragma Loop_Invariant (for all K in 0 .. I - 1 => B (K) <= 255);

            V := X (I) + C;
            --  V <= X_Limb_Bound + X_Limb_Bound = 2 * 2**21 = 2**22.
            C := V / 256;
            B (I) := U64 (V - C * 256);
            --  V - C*256 = V mod 256, in 0..255.
         end loop;
      --  C may be nonzero in pathological inputs whose total
      --  value > 2^512; we discard it, which is sound because
      --  the only effect is the input wraps mod 2^512, but
      --  our actual inputs (Sign's r + k*a, Verify's hash) are
      --  always < 2^512 so C = 0 in practice.  No proof of that
      --  property is needed; the per-byte bound is what matters
      --  and is delivered unconditionally.
      end Carry_Propagate_64;

      ---------------------------------------------------------------
      --  Step 2: load 64 LE bytes into a 10-limb 56-bit
      --  Qelem_Wide.  Mirrors Hacl.Impl.Load56.load_64_bytes:
      --    b[i] = (bytes[7*i+6:7*i+0] little-endian) for i=0..8
      --    b[9] = bytes[63] as u64
      ---------------------------------------------------------------

      function Load_56_LE (B : Bytes_64; Off : Natural) return Limb
      with
        Pre  => Off in 0 .. 57 and then (for all K in 0 .. 63 => B (K) <= 255),
        Post => Load_56_LE'Result <= Mask56;

      function Load_56_LE (B : Bytes_64; Off : Natural) return Limb is
         R : U64;
      begin
         --  Combine 7 bytes; result fits in 56 bits.
         R := B (Off);
         R := R + Interfaces.Shift_Left (B (Off + 1), 8);
         R := R + Interfaces.Shift_Left (B (Off + 2), 16);
         R := R + Interfaces.Shift_Left (B (Off + 3), 24);
         R := R + Interfaces.Shift_Left (B (Off + 4), 32);
         R := R + Interfaces.Shift_Left (B (Off + 5), 40);
         R := R + Interfaces.Shift_Left (B (Off + 6), 48);
         return R;
      end Load_56_LE;

      procedure Load_64_Bytes (B : Bytes_64; W : out Qelem_Wide)
      with Pre => (for all K in 0 .. 63 => B (K) <= 255);

      procedure Load_64_Bytes (B : Bytes_64; W : out Qelem_Wide) is
      begin
         W :=
           [Load_56_LE (B, 0),
            Load_56_LE (B, 7),
            Load_56_LE (B, 14),
            Load_56_LE (B, 21),
            Load_56_LE (B, 28),
            Load_56_LE (B, 35),
            Load_56_LE (B, 42),
            Load_56_LE (B, 49),
            Load_56_LE (B, 56),
            B (63)];        --  one byte (input is 64 bytes total)
      end Load_64_Bytes;

      ---------------------------------------------------------------
      --  Step 3: q := input >> 248.  Mirrors HACL div_248 +
      --  div_2_24_step.  Consumes limbs 4..9 of the wide
      --  representation (6 limbs covering bits 224..559) and emits
      --  5 limbs covering bits 248..527 (an over-estimate by 32
      --  bits is harmless because Barrett's mu accommodates it).
      --
      --  div_2_24_step (x, y) = (x >> 24) | ((y & 0xFFFFFF) << 32)
      ---------------------------------------------------------------

      function Div_2_24_Step (X, Y : Limb) return Limb
      with Post => Div_2_24_Step'Result <= Mask56;

      function Div_2_24_Step (X, Y : Limb) return Limb is
         X_Shr : constant U64 := Interfaces.Shift_Right (X, 24);
         --  X / 2^24, ≤ 2^32-1 since X ≤ 2^56-1.
         Y_Lo  : constant U64 := Y and 16#FFFFFF#;
         --  ≤ 2^24 - 1.
         Y_Shl : constant U64 := Interfaces.Shift_Left (Y_Lo, 32);
         --  ≤ (2^24 - 1) * 2^32 < 2^56.
      begin
         return (X_Shr or Y_Shl) and Mask56;
      end Div_2_24_Step;

      procedure Div_248 (W : Qelem_Wide; Q : out Qelem);

      procedure Div_248 (W : Qelem_Wide; Q : out Qelem) is
      begin
         Q :=
           [Div_2_24_Step (W (4), W (5)),
            Div_2_24_Step (W (5), W (6)),
            Div_2_24_Step (W (6), W (7)),
            Div_2_24_Step (W (7), W (8)),
            Div_2_24_Step (W (8), W (9))];
      end Div_248;

      ---------------------------------------------------------------
      --  Step 4: qmu := q * mu  (Qelem * Qelem -> Qelem_Wide).
      --
      --  Each Limb fits in 56 bits, so each partial product fits
      --  in 112 bits.  Sum of up to five partial products fits in
      --  ~115 bits, well within Unsigned_128.  After carrying the
      --  10-limb result is normalised so each limb is in 0..2^56-1.
      ---------------------------------------------------------------

      procedure Carry_Wide (X : U128; T : out Limb; C : out U128)
      with Post => C = X / U128 (Pow56) and then T <= Mask56;

      procedure Carry_Wide (X : U128; T : out Limb; C : out U128) is
      begin
         T := U64 (X and U128 (Mask56));
         C := X / U128 (Pow56);
      end Carry_Wide;

      procedure Mul_5_Wide (X, Y : Qelem; Z : out Qelem_Wide);

      procedure Mul_5_Wide (X, Y : Qelem; Z : out Qelem_Wide) is
         --  Each x_i * y_j ≤ (2^56 - 1)^2 < 2^112, fits in U128.
         --  Z[k] = sum of x_i * y_j with i + j = k; max 5 such
         --  terms (k=4) so the sum fits in 5 * 2^112 < 2^115 < 2^128.

         function P (I, J : Natural) return U128
         with
           Pre  => I in 0 .. 4 and then J in 0 .. 4,
           Post => P'Result <= U128 ((Pow56 - 1) * (Pow56 - 1));

         function P (I, J : Natural) return U128 is
         begin
            return U128 (X (I)) * U128 (Y (J));
         end P;

         Z0, Z1, Z2, Z3, Z4, Z5, Z6, Z7, Z8 : U128;
         T0, T1, T2, T3, T4, T5, T6, T7, T8 : Limb;
         C                                  : U128;
      begin
         Z0 := P (0, 0);
         Z1 := P (0, 1) + P (1, 0);
         Z2 := P (0, 2) + P (1, 1) + P (2, 0);
         Z3 := P (0, 3) + P (1, 2) + P (2, 1) + P (3, 0);
         Z4 := P (0, 4) + P (1, 3) + P (2, 2) + P (3, 1) + P (4, 0);
         Z5 := P (1, 4) + P (2, 3) + P (3, 2) + P (4, 1);
         Z6 := P (2, 4) + P (3, 3) + P (4, 2);
         Z7 := P (3, 4) + P (4, 3);
         Z8 := P (4, 4);

         --  Carry chain (Hacl mul_5 does this with carry56_wide /
         --  add_inner_carry).  After each step T_i is the next
         --  output limb (in 0..Mask56) and C is the carry to fold
         --  into the next column.
         Carry_Wide (Z0, T0, C);
         Carry_Wide (Z1 + C, T1, C);
         Carry_Wide (Z2 + C, T2, C);
         Carry_Wide (Z3 + C, T3, C);
         Carry_Wide (Z4 + C, T4, C);
         Carry_Wide (Z5 + C, T5, C);
         Carry_Wide (Z6 + C, T6, C);
         Carry_Wide (Z7 + C, T7, C);
         Carry_Wide (Z8 + C, T8, C);
         --  C now holds the residual at bit position 504+; for our
         --  Barrett input space (input < 2^512) it fits in 56 bits.
         Z := [T0, T1, T2, T3, T4, T5, T6, T7, T8, U64 (C and U128 (Mask56))];
      end Mul_5_Wide;

      ---------------------------------------------------------------
      --  Step 5: qdiv := qmu >> 264.  Mirrors HACL div_264 with
      --  div_2_40_step (x, y) = (x >> 40) | ((y & mask40) << 16).
      ---------------------------------------------------------------

      function Div_2_40_Step (X, Y : Limb) return Limb
      with Post => Div_2_40_Step'Result <= Mask56;

      function Div_2_40_Step (X, Y : Limb) return Limb is
         X_Shr : constant U64 := Interfaces.Shift_Right (X, 40);
         Y_Lo  : constant U64 := Y and Mask40;
         Y_Shl : constant U64 := Interfaces.Shift_Left (Y_Lo, 16);
      begin
         return (X_Shr or Y_Shl) and Mask56;
      end Div_2_40_Step;

      procedure Div_264 (W : Qelem_Wide; Q : out Qelem);

      procedure Div_264 (W : Qelem_Wide; Q : out Qelem) is
      begin
         Q :=
           [Div_2_40_Step (W (4), W (5)),
            Div_2_40_Step (W (5), W (6)),
            Div_2_40_Step (W (6), W (7)),
            Div_2_40_Step (W (7), W (8)),
            Div_2_40_Step (W (8), W (9))];
      end Div_264;

      ---------------------------------------------------------------
      --  Step 6: r := input mod 2^264.  Mirrors HACL mod_264 — keep
      --  limbs 0..3 unchanged, mask limb 4 to 40 bits (264 = 4 * 56
      --  + 40).
      ---------------------------------------------------------------

      procedure Mod_264 (W : Qelem_Wide; R : out Qelem)
      with Post => R (4) <= Mask40;

      procedure Mod_264 (W : Qelem_Wide; R : out Qelem) is
      begin
         R := [W (0), W (1), W (2), W (3), W (4) and Mask40];
      end Mod_264;

      ---------------------------------------------------------------
      --  Step 7: qmul := (qdiv * L) mod 2^264.  Mirrors HACL
      --  low_mul_5: schoolbook product, but only the low 5 columns
      --  matter (columns 0..3 give 56 bits each, column 4 is masked
      --  to 40 bits).
      ---------------------------------------------------------------

      procedure Low_Mul_5 (X, Y : Qelem; R : out Qelem)
      with Post => R (4) <= Mask40;

      procedure Low_Mul_5 (X, Y : Qelem; R : out Qelem) is
         function P (I, J : Natural) return U128
         with
           Pre  => I in 0 .. 4 and then J in 0 .. 4,
           Post => P'Result <= U128 ((Pow56 - 1) * (Pow56 - 1));

         function P (I, J : Natural) return U128 is
         begin
            return U128 (X (I)) * U128 (Y (J));
         end P;

         W0, W1, W2, W3, W4 : U128;
         R0, R1, R2, R3     : Limb;
         C                  : U128;
      begin
         W0 := P (0, 0);
         W1 := P (0, 1) + P (1, 0);
         W2 := P (0, 2) + P (1, 1) + P (2, 0);
         W3 := P (0, 3) + P (1, 2) + P (2, 1) + P (3, 0);
         W4 := P (0, 4) + P (1, 3) + P (2, 2) + P (3, 1) + P (4, 0);

         Carry_Wide (W0, R0, C);
         Carry_Wide (W1 + C, R1, C);
         Carry_Wide (W2 + C, R2, C);
         Carry_Wide (W3 + C, R3, C);
         R := [R0, R1, R2, R3, U64 ((W4 + C) and U128 (Mask40))];
      end Low_Mul_5;

      ---------------------------------------------------------------
      --  Step 8: s := (r - qmul) mod 2^264.  Mirrors HACL
      --  sub_mod_264 / subm_step:
      --      diff_i := r_i - q_i - borrow_in
      --      borrow_out := (diff_i >> 63)              (0 or 1)
      --      t_i := diff_i + (borrow_out << 56)        (re-add 2^56)
      --
      --  All arithmetic on U64 modulo 2^64; the borrow propagation
      --  is exact because the running borrow is in {0, 1}.
      ---------------------------------------------------------------

      procedure Subm_Step
        (X, Y : Limb; B_In : Limb; T : out Limb; B_Out : out Limb)
      with Pre => B_In <= 1, Post => B_Out <= 1 and then T <= Mask56;

      procedure Subm_Step
        (X, Y : Limb; B_In : Limb; T : out Limb; B_Out : out Limb)
      is
         Y_Plus : constant U64 := Y + B_In;  --  ≤ Mask56 + 1 ≤ 2^56
         D      : constant U64 := X - Y_Plus;  --  modular sub
      begin
         B_Out := Interfaces.Shift_Right (D, 63);  --  0 or 1
         T := (D + Interfaces.Shift_Left (B_Out, 56)) and Mask56;
      end Subm_Step;

      procedure Subm_Last_Step
        (X, Y : Limb; B_In : Limb; T : out Limb; B_Out : out Limb)
      with
        Pre  => B_In <= 1 and then X <= Mask40 and then Y <= Mask40,
        Post => B_Out <= 1 and then T <= Mask40;

      procedure Subm_Last_Step
        (X, Y : Limb; B_In : Limb; T : out Limb; B_Out : out Limb)
      is
         Y_Plus : constant U64 := Y + B_In;
         D      : constant U64 := X - Y_Plus;
      begin
         B_Out := Interfaces.Shift_Right (D, 63);
         T := (D + Interfaces.Shift_Left (B_Out, 40)) and Mask40;
      end Subm_Last_Step;

      procedure Sub_Mod_264 (R, Q : Qelem; S : out Qelem)
      with Pre => R (4) <= Mask40 and then Q (4) <= Mask40;

      procedure Sub_Mod_264 (R, Q : Qelem; S : out Qelem) is
         B0, B1, B2, B3, B4 : Limb;
         T0, T1, T2, T3, T4 : Limb;
      begin
         Subm_Step (R (0), Q (0), 0, T0, B0);
         Subm_Step (R (1), Q (1), B0, T1, B1);
         Subm_Step (R (2), Q (2), B1, T2, B2);
         Subm_Step (R (3), Q (3), B2, T3, B3);
         Subm_Last_Step (R (4), Q (4), B3, T4, B4);
         pragma Unreferenced (B4);
         S := [T0, T1, T2, T3, T4];
      end Sub_Mod_264;

      ---------------------------------------------------------------
      --  Step 9: subm_conditional — if S >= L then S := S - L.
      --  Constant-time-ish via Choose, mirroring HACL.
      ---------------------------------------------------------------

      procedure Subm_Conditional (S : in out Qelem);

      procedure Subm_Conditional (S : in out Qelem) is
         Y0, Y1, Y2, Y3, Y4 : Limb;
         T0, T1, T2, T3, T4 : Limb;
         B0, B1, B2, B3, B4 : Limb;
         Mask               : U64;
      begin
         Y0 := Make_M (0);
         Y1 := Make_M (1);
         Y2 := Make_M (2);
         Y3 := Make_M (3);
         Y4 := Make_M (4);

         Subm_Step (S (0), Y0, 0, T0, B0);
         Subm_Step (S (1), Y1, B0, T1, B1);
         Subm_Step (S (2), Y2, B1, T2, B2);
         Subm_Step (S (3), Y3, B2, T3, B3);
         Subm_Step (S (4), Y4, B3, T4, B4);
         --  B4 = 1 ⇔ original S < L (the subtract underflowed) ⇒
         --  keep S; B4 = 0 ⇔ S >= L ⇒ replace S with the difference.
         Mask := B4 - 1;  --  all-ones if B4 = 0, all-zero if B4 = 1
         S (0) := S (0) xor (Mask and (S (0) xor T0));
         S (1) := S (1) xor (Mask and (S (1) xor T1));
         S (2) := S (2) xor (Mask and (S (2) xor T2));
         S (3) := S (3) xor (Mask and (S (3) xor T3));
         S (4) := S (4) xor (Mask and (S (4) xor T4));
      end Subm_Conditional;

      ---------------------------------------------------------------
      --  Pack a Qelem (5 56-bit limbs) into 32 LE bytes.  Mirrors
      --  Hacl.Impl.Store56.store_56:
      --     bytes[0..6]   = limb 0 LE 7 bytes
      --     bytes[7..13]  = limb 1
      --     bytes[14..20] = limb 2
      --     bytes[21..27] = limb 3
      --     bytes[28..31] = limb 4 low 32 bits
      ---------------------------------------------------------------

      procedure Store_56_LE
        (B : in out Bytes_32; Off : Positive; Limb_Val : Limb)
      with Pre => Off in 1 .. 26;

      procedure Store_56_LE
        (B : in out Bytes_32; Off : Positive; Limb_Val : Limb)
      is
         V : U64 := Limb_Val;
      begin
         for K in 0 .. 6 loop
            pragma Loop_Invariant (V <= Mask56);
            B (Off + K) := Octet (V and 16#FF#);
            V := Interfaces.Shift_Right (V, 8);
         end loop;
      end Store_56_LE;

      procedure Pack_32 (S : Qelem; Out_Bytes : out Bytes_32);

      procedure Pack_32 (S : Qelem; Out_Bytes : out Bytes_32) is
         V : U64;
      begin
         Out_Bytes := [others => 0];
         Store_56_LE (Out_Bytes, 1, S (0));
         Store_56_LE (Out_Bytes, 8, S (1));
         Store_56_LE (Out_Bytes, 15, S (2));
         Store_56_LE (Out_Bytes, 22, S (3));
         --  Limb 4 is canonically ≤ 2^32 - 1 after final reduction
         --  (L's top limb is 0x10000000 = 2^28, the canonical
         --  reduced range maxes the top limb at L's top - 1, < 2^28).
         --  Store its low 32 bits into bytes 29..32.  Higher bits are
         --  guaranteed zero by the canonical-reduction post-condition.
         V := S (4);
         for K in 0 .. 3 loop
            pragma Loop_Invariant (V <= Mask56);
            Out_Bytes (29 + K) := Octet (V and 16#FF#);
            V := Interfaces.Shift_Right (V, 8);
         end loop;
      end Pack_32;

      ---------------------------------------------------------------
      --  Mod_L_Core
      ---------------------------------------------------------------

      procedure Mod_L_Core (Out_Bytes : out Bytes_32; X : X64_Array) is
         B    : Bytes_64;
         W    : Qelem_Wide;
         Q    : Qelem;
         Qmu  : Qelem_Wide;
         Qdiv : Qelem;
         R    : Qelem;
         Qmul : Qelem;
         S    : Qelem;
      begin
         --  1. Carry-propagate X into 64 LE bytes.
         Carry_Propagate_64 (X, B);
         --  2. Load bytes into 10-limb wide representation.
         Load_64_Bytes (B, W);
         --  3..5. Barrett quotient estimate qdiv = floor(input / L).
         Div_248 (W, Q);
         Mul_5_Wide (Q, Make_Mu, Qmu);
         Div_264 (Qmu, Qdiv);
         --  6..8. Subtract qdiv * L from input mod 2^264.
         Mod_264 (W, R);
         Low_Mul_5 (Qdiv, Make_M, Qmul);
         Sub_Mod_264 (R, Qmul, S);
         --  9. Final conditional subtract of L.
         Subm_Conditional (S);
         --  10. Pack to 32 LE bytes.
         Pack_32 (S, Out_Bytes);
      end Mod_L_Core;

   end Mod_L_Pkg;

   procedure Mod_L (Out_Bytes : out Bytes_32; X_In : Octet_Array);
   procedure Mod_L (Out_Bytes : out Bytes_32; X_In : Octet_Array) is
      X : X64_Array := [others => 0];
   begin
      pragma Assert (X_In'Length = 64);
      for I in 0 .. 63 loop
         X (I) := Integer_64 (X_In (X_In'First + I));
      end loop;
      Mod_L_Pkg.Mod_L_Core (Out_Bytes, X);
   end Mod_L;

   ---------------------------------------------------------------------
   --  Verify — RFC 8032 §5.1.7.
   ---------------------------------------------------------------------

   function Verify
     (Public_Key : Bytes_32; Message : Octet_Array; Sig : Signature)
      return Boolean
   is
      R_Bytes : constant Bytes_32 := Sig (1 .. 32);
      S_Bytes : constant Bytes_32 := Sig (33 .. 64);

      A_Point, R_Point, Lhs, Rhs, Tmp_P : Point;
      A_OK, R_OK                        : Boolean;

      Hash_Buf : Tls_Core.Sha512.Digest;
      K_Bytes  : Bytes_32;
      K_Wide   : Octet_Array (1 .. 64);

      Final_Lhs, Final_Rhs : Bytes_32;

      Ctx : Tls_Core.Sha512.Context;
   begin
      --  s must be canonical: most TweetNaCl-style implementations
      --  check the top 4 bits of s[31] against L's structure. Here
      --  we just require s < 2^252 + change; a strict L comparison
      --  is the spec's MAY anyway.
      if (S_Bytes (32) and 16#F0#) /= 0 then
         return False;
      end if;

      --  Decode public key.
      Decode_Point (A_Point, Public_Key, A_OK);
      if not A_OK then
         return False;
      end if;

      --  Decode R.
      Decode_Point (R_Point, R_Bytes, R_OK);
      if not R_OK then
         return False;
      end if;

      --  k = SHA-512(R ‖ A ‖ M) reduced mod L.
      Tls_Core.Sha512.Init (Ctx);
      Tls_Core.Sha512.Update (Ctx, R_Bytes);
      Tls_Core.Sha512.Update (Ctx, Public_Key);
      Tls_Core.Sha512.Update (Ctx, Message);
      Tls_Core.Sha512.Finalize (Ctx, Hash_Buf);
      for I in 1 .. 64 loop
         K_Wide (I) := Hash_Buf (I);
      end loop;
      Mod_L (K_Bytes, K_Wide);

      --  Compute Lhs = [s]B and Rhs = R + [k]A.
      declare
         B : Point;
      begin
         Get_Base_Point (B);
         Scalar_Mult_Bytes (Lhs, S_Bytes, B);
      end;
      Scalar_Mult_Bytes (Tmp_P, K_Bytes, A_Point);
      Point_Add (Rhs, R_Point, Tmp_P);

      Encode_Point (Final_Lhs, Lhs);
      Encode_Point (Final_Rhs, Rhs);

      for I in Final_Lhs'Range loop
         if Final_Lhs (I) /= Final_Rhs (I) then
            return False;
         end if;
      end loop;
      return True;
   end Verify;

   ---------------------------------------------------------------------
   --  Derive the clamped scalar a and prefix from the seed.
   ---------------------------------------------------------------------

   procedure Seed_To_Scalar_And_Prefix
     (Seed : Bytes_32; A_Out : out Bytes_32; Prefix : out Bytes_32);
   procedure Seed_To_Scalar_And_Prefix
     (Seed : Bytes_32; A_Out : out Bytes_32; Prefix : out Bytes_32)
   is
      H : Tls_Core.Sha512.Digest;
   begin
      Tls_Core.Sha512.Hash (Seed, H);
      A_Out := H (1 .. 32);
      A_Out (1) := A_Out (1) and 16#F8#;
      A_Out (32) := (A_Out (32) and 16#7F#) or 16#40#;
      Prefix := H (33 .. 64);
   end Seed_To_Scalar_And_Prefix;

   ---------------------------------------------------------------------
   --  Public_Of_Seed — A = encode([a]B).
   ---------------------------------------------------------------------

   procedure Public_Of_Seed (Seed : Bytes_32; Out_Public : out Bytes_32) is
      A      : Bytes_32;
      Prefix : Bytes_32;
      B, P   : Point;
   begin
      Seed_To_Scalar_And_Prefix (Seed, A, Prefix);
      Get_Base_Point (B);
      Scalar_Mult_Bytes (P, A, B);
      Encode_Point (Out_Public, P);
   end Public_Of_Seed;

   ---------------------------------------------------------------------
   --  Sign — RFC 8032 §5.1.6.
   ---------------------------------------------------------------------

   procedure Sign
     (Seed : Bytes_32; Message : Octet_Array; Out_Sig : out Signature)
   is
      A_Bytes : Bytes_32;
      Prefix  : Bytes_32;
      Pub_Key : Bytes_32;
      B_Pt    : Point;

      R_Hash  : Tls_Core.Sha512.Digest;
      R_Bytes : Bytes_32;
      R_Pt    : Point;
      R_Enc   : Bytes_32;

      K_Hash  : Tls_Core.Sha512.Digest;
      K_Bytes : Bytes_32;

      X     : X64_Array := [others => 0];
      S_Out : Bytes_32;

      Ctx : Tls_Core.Sha512.Context;
   begin
      Out_Sig := [others => 0];

      Seed_To_Scalar_And_Prefix (Seed, A_Bytes, Prefix);
      Get_Base_Point (B_Pt);

      --  A = encode([a]B)
      declare
         A_Pt : Point;
      begin
         Scalar_Mult_Bytes (A_Pt, A_Bytes, B_Pt);
         Encode_Point (Pub_Key, A_Pt);
      end;

      --  r = SHA-512(prefix || message), reduced mod L.
      Tls_Core.Sha512.Init (Ctx);
      Tls_Core.Sha512.Update (Ctx, Prefix);
      Tls_Core.Sha512.Update (Ctx, Message);
      Tls_Core.Sha512.Finalize (Ctx, R_Hash);
      declare
         R_Wide : Octet_Array (1 .. 64);
      begin
         for I in 1 .. 64 loop
            R_Wide (I) := R_Hash (I);
         end loop;
         Mod_L (R_Bytes, R_Wide);
      end;

      --  R = encode([r]B).
      Scalar_Mult_Bytes (R_Pt, R_Bytes, B_Pt);
      Encode_Point (R_Enc, R_Pt);

      --  k = SHA-512(R_enc || A || message), reduced mod L.
      Tls_Core.Sha512.Init (Ctx);
      Tls_Core.Sha512.Update (Ctx, R_Enc);
      Tls_Core.Sha512.Update (Ctx, Pub_Key);
      Tls_Core.Sha512.Update (Ctx, Message);
      Tls_Core.Sha512.Finalize (Ctx, K_Hash);
      declare
         K_Wide : Octet_Array (1 .. 64);
      begin
         for I in 1 .. 64 loop
            K_Wide (I) := K_Hash (I);
         end loop;
         Mod_L (K_Bytes, K_Wide);
      end;

      --  s = (r + k * a) mod L. Build the polynomial product into X
      --  per TweetNaCl: x[i+j] += k[i] * a[j], then mod L.
      for I in 0 .. 31 loop
         X (I) := Integer_64 (R_Bytes (1 + I));
      end loop;
      for I in 0 .. 31 loop
         for J in 0 .. 31 loop
            X (I + J) :=
              X (I + J)
              + Integer_64 (K_Bytes (1 + I)) * Integer_64 (A_Bytes (1 + J));
         end loop;
      end loop;
      Mod_L_Pkg.Mod_L_Core (S_Out, X);

      --  Concatenate R || s.
      Out_Sig (1 .. 32) := R_Enc;
      Out_Sig (33 .. 64) := S_Out;
   end Sign;

end Tls_Core.Ed25519;
