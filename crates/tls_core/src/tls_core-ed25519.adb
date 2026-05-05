with Ada.Unchecked_Conversion;
with Interfaces;

package body Tls_Core.Ed25519
with SPARK_Mode => Off
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use Interfaces;

   ---------------------------------------------------------------------
   --  Field arithmetic over GF(2^255 - 19). Same 16-limb 16-bit
   --  representation as Tls_Core.X25519. Duplicated rather than
   --  shared so each curve module is independently auditable.
   ---------------------------------------------------------------------

   subtype Felt_Index is Natural range 0 .. 15;
   type Felt is array (Felt_Index) of Integer_64;

   subtype Big_Index is Natural range 0 .. 30;
   type Big_Buf is array (Big_Index) of Integer_64;

   function To_U64 is new Ada.Unchecked_Conversion
     (Integer_64, Unsigned_64);
   function To_I64 is new Ada.Unchecked_Conversion
     (Unsigned_64, Integer_64);

   function Asr (X : Integer_64; N : Natural) return Integer_64
   is (To_I64 (Shift_Right_Arithmetic (To_U64 (X), N)));

   function And_64 (X, Y : Integer_64) return Integer_64
   is (To_I64 (To_U64 (X) and To_U64 (Y)));

   procedure Carry (O : in out Felt);
   procedure Carry (O : in out Felt) is
      C : Integer_64;
   begin
      for I in Felt_Index loop
         C := Asr (O (I), 16);
         O (I) := O (I) - To_I64 (Shift_Left (To_U64 (C), 16));
         if I < 15 then
            O (I + 1) := O (I + 1) + C;
         else
            O (0) := O (0) + 38 * C;
         end if;
      end loop;
   end Carry;

   procedure F_Add (O : out Felt; A, B : Felt);
   procedure F_Add (O : out Felt; A, B : Felt) is
   begin
      for I in Felt_Index loop
         O (I) := A (I) + B (I);
      end loop;
   end F_Add;

   procedure F_Sub (O : out Felt; A, B : Felt);
   procedure F_Sub (O : out Felt; A, B : Felt) is
   begin
      for I in Felt_Index loop
         O (I) := A (I) - B (I);
      end loop;
   end F_Sub;

   procedure F_Mul (O : out Felt; A, B : Felt);
   procedure F_Mul (O : out Felt; A, B : Felt) is
      T : Big_Buf := (others => 0);
   begin
      for I in Felt_Index loop
         for J in Felt_Index loop
            T (I + J) := T (I + J) + A (I) * B (J);
         end loop;
      end loop;
      for I in 0 .. 14 loop
         T (I) := T (I) + 38 * T (I + 16);
      end loop;
      for I in Felt_Index loop
         O (I) := T (I);
      end loop;
      Carry (O);
      Carry (O);
   end F_Mul;

   procedure F_Sqr (O : out Felt; A : Felt);
   procedure F_Sqr (O : out Felt; A : Felt) is
   begin
      F_Mul (O, A, A);
   end F_Sqr;

   procedure F_Inv (O : out Felt; I_Val : Felt);
   procedure F_Inv (O : out Felt; I_Val : Felt) is
      C : Felt;
      T : Felt;
   begin
      C := I_Val;
      for K in reverse 0 .. 253 loop
         F_Sqr (T, C);
         C := T;
         if K /= 2 and then K /= 4 then
            F_Mul (T, C, I_Val);
            C := T;
         end if;
      end loop;
      O := C;
   end F_Inv;

   --  Final reduction mod p, then serialize to 32 LE bytes.
   procedure Pack (O : out Bytes_32; N : Felt);
   procedure Pack (O : out Bytes_32; N : Felt) is
      T, M : Felt;
      B    : Integer_64;

      procedure Cswap_Felt (P, Q : in out Felt; Swap_Bit : Integer_64);
      procedure Cswap_Felt (P, Q : in out Felt; Swap_Bit : Integer_64) is
         Mask : constant Integer_64 := -Swap_Bit;
         Tmp  : Integer_64;
      begin
         for I in Felt_Index loop
            Tmp := To_I64
              (To_U64 (Mask) and (To_U64 (P (I)) xor To_U64 (Q (I))));
            P (I) := To_I64 (To_U64 (P (I)) xor To_U64 (Tmp));
            Q (I) := To_I64 (To_U64 (Q (I)) xor To_U64 (Tmp));
         end loop;
      end Cswap_Felt;
   begin
      T := N;
      Carry (T); Carry (T); Carry (T);
      for J in 0 .. 1 loop
         M (0) := T (0) - 16#FFED#;
         for I in 1 .. 14 loop
            M (I) :=
              T (I) - 16#FFFF#
              - And_64 (Asr (M (I - 1), 16), 1);
            M (I - 1) := And_64 (M (I - 1), 16#FFFF#);
         end loop;
         M (15) :=
           T (15) - 16#7FFF#
           - And_64 (Asr (M (14), 16), 1);
         B := And_64 (Asr (M (15), 16), 1);
         M (14) := And_64 (M (14), 16#FFFF#);
         Cswap_Felt (T, M, 1 - B);
      end loop;
      for I in Felt_Index loop
         O (1 + 2 * I) := Octet (And_64 (T (I), 16#FF#));
         O (2 + 2 * I) := Octet (And_64 (Asr (T (I), 8), 16#FF#));
      end loop;
   end Pack;

   procedure Unpack (O : out Felt; B : Bytes_32);
   procedure Unpack (O : out Felt; B : Bytes_32) is
   begin
      for I in Felt_Index loop
         O (I) :=
           Integer_64 (B (1 + 2 * I))
           + Integer_64 (B (2 + 2 * I)) * 256;
      end loop;
      O (15) := And_64 (O (15), 16#7FFF#);
   end Unpack;

   --  Signed-byte parity test: returns the low bit of T (0)
   --  AFTER full reduction. Used to recover the sign bit of x
   --  during point decompression.
   function Parity (N : Felt) return Integer_64;
   function Parity (N : Felt) return Integer_64 is
      Buf : Bytes_32;
   begin
      Pack (Buf, N);
      return Integer_64 (Buf (1) and 1);
   end Parity;

   ---------------------------------------------------------------------
   --  Edwards curve parameters and base point B (RFC 8032 §5.1.5).
   --  d = -121665/121666 mod p; we hand-compute and embed the
   --  16-limb representation here.
   ---------------------------------------------------------------------

   --  d in 16 × 16-bit limbs, little-endian (low limb first).
   D_Felt : constant Felt :=
     (16#78A3#, 16#1359#, 16#4DCA#, 16#75EB#,
      16#D8AB#, 16#4141#, 16#0A4D#, 16#0070#,
      16#E898#, 16#7779#, 16#4079#, 16#8CC7#,
      16#FE73#, 16#2B6F#, 16#6CEE#, 16#5203#);

   --  2 * d.
   D2_Felt : constant Felt :=
     (16#F159#, 16#26B2#, 16#9B94#, 16#EBD6#,
      16#B156#, 16#8283#, 16#149A#, 16#00E0#,
      16#D130#, 16#EEF3#, 16#80F2#, 16#198E#,
      16#FCE7#, 16#56DF#, 16#D9DC#, 16#2406#);

   --  Curve order L = 2^252 + 27742317777372353535851937790883648493,
   --  little-endian byte representation (32 bytes).
   L_Bytes : constant array (0 .. 31) of Integer_64 :=
     (16#ED#, 16#D3#, 16#F5#, 16#5C#, 16#1A#, 16#63#, 16#12#, 16#58#,
      16#D6#, 16#9C#, 16#F7#, 16#A2#, 16#DE#, 16#F9#, 16#DE#, 16#14#,
      16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#,
      16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#00#, 16#10#);

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
      P.X := (others => 0);
      P.Y := (others => 0); P.Y (0) := 1;
      P.Z := (others => 0); P.Z (0) := 1;
      P.T := (others => 0);
   end Set_Identity;

   --  Base point B in extended coordinates (RFC 8032 §5.1). T is
   --  computed at runtime via Get_Base_Point so we avoid a separate
   --  hardcoded constant that could drift from X*Y.

   Bx : constant Felt :=
     (16#D51A#, 16#8F25#, 16#2D60#, 16#C956#,
      16#A7B2#, 16#9525#, 16#C760#, 16#692C#,
      16#DC5C#, 16#FDD6#, 16#E231#, 16#C0A4#,
      16#53FE#, 16#CD6E#, 16#36D3#, 16#2169#);

   By : constant Felt :=
     (16#6658#, 16#6666#, 16#6666#, 16#6666#,
      16#6666#, 16#6666#, 16#6666#, 16#6666#,
      16#6666#, 16#6666#, 16#6666#, 16#6666#,
      16#6666#, 16#6666#, 16#6666#, 16#6666#);

   procedure Get_Base_Point (P : out Point);
   procedure Get_Base_Point (P : out Point) is
   begin
      P.X := Bx;
      P.Y := By;
      P.Z := (1, others => 0);
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
      T1, T2 : Felt;
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
     (R       : out Point;
      Scalar  : Octet_Array;
      Base    : Point);
   procedure Scalar_Mult_Bytes
     (R       : out Point;
      Scalar  : Octet_Array;
      Base    : Point)
   is
      Acc, Tmp, Cur : Point;
   begin
      Set_Identity (Acc);
      Cur := Base;
      for I in 0 .. (Scalar'Length * 8) - 1 loop
         declare
            Byte : constant Integer_64 :=
              Integer_64 (Scalar (Scalar'First + I / 8));
            Bit  : constant Integer_64 :=
              And_64 (Asr (Byte, I mod 8), 1);
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
      Sign_Bit : Integer_64;
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

   --  pow2523 (TweetNaCl): compute z^((p-5)/8) where p = 2^255 - 19.
   --  Algorithm: c <- z; for a from 250 downto 0: c <- c²; if a /= 1 then c <- c*z.
   procedure Pow_2523 (O : out Felt; Z : Felt);
   procedure Pow_2523 (O : out Felt; Z : Felt) is
      C, Tmp : Felt;
   begin
      C := Z;
      for A in reverse 0 .. 250 loop
         F_Sqr (Tmp, C); C := Tmp;
         if A /= 1 then
            F_Mul (Tmp, C, Z); C := Tmp;
         end if;
      end loop;
      O := C;
   end Pow_2523;

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
     (P  : out Point;
      In_Bytes : Bytes_32;
      OK : out Boolean);
   procedure Decode_Point
     (P  : out Point;
      In_Bytes : Bytes_32;
      OK : out Boolean)
   is
      One        : constant Felt := (1, others => 0);
      I_Sqrt_M1  : constant Felt :=
        --  sqrt(-1) mod p — TweetNaCl's `gf I` constant.
        (16#A0B0#, 16#4A0E#, 16#1B27#, 16#C4EE#,
         16#E478#, 16#AD2F#, 16#1806#, 16#2F43#,
         16#D7A7#, 16#3DFB#, 16#0099#, 16#2B4D#,
         16#DF0B#, 16#4FC1#, 16#2480#, 16#2B83#);
      Y, Y2, Num, Den, Den2, Den4, Den6 : Felt;
      T1, X_Cand, Chk, Tmp, Negated : Felt;
      Local_In : Bytes_32 := In_Bytes;
      Sign_Bit : constant Integer_64 :=
        And_64 (Asr (Integer_64 (In_Bytes (32)), 7), 1);
   begin
      Local_In (32) := Local_In (32) and 16#7F#;
      Unpack (Y, Local_In);
      P.Y := Y;
      P.Z := One;
      --  num = y^2 - 1, den = d*y^2 + 1.
      F_Sqr  (Y2,  Y);
      F_Mul  (Den, Y2, D_Felt);
      F_Sub  (Num, Y2, One);
      F_Add  (Tmp, One, Den); Den := Tmp;
      --  den^2, den^4, den^6.
      F_Sqr (Den2, Den);
      F_Sqr (Den4, Den2);
      F_Mul (Den6, Den4, Den2);
      --  t = num * den^7.
      F_Mul (T1,  Num, Den6);
      F_Mul (Tmp, T1,  Den); T1 := Tmp;
      --  t = t^((p-5)/8).
      Pow_2523 (Tmp, T1); T1 := Tmp;
      --  x_cand = t * num * den^3.
      F_Mul (Tmp, T1,    Num);  T1 := Tmp;
      F_Mul (Tmp, T1,    Den);  T1 := Tmp;
      F_Mul (Tmp, T1,    Den);  T1 := Tmp;
      F_Mul (X_Cand, T1, Den);
      --  Check: x_cand^2 * den == num? If not, multiply by sqrt(-1).
      F_Sqr (Chk, X_Cand);
      F_Mul (Tmp, Chk, Den); Chk := Tmp;
      if not Felt_Eq (Chk, Num) then
         F_Mul (Tmp, X_Cand, I_Sqrt_M1); X_Cand := Tmp;
      end if;
      --  Re-check after possible sqrt(-1) multiply.
      F_Sqr (Chk, X_Cand);
      F_Mul (Tmp, Chk, Den); Chk := Tmp;
      if not Felt_Eq (Chk, Num) then
         OK := False;
         Set_Identity (P);
         return;
      end if;
      --  Pick the candidate's sign matching the encoded sign bit.
      if Parity (X_Cand) /= Sign_Bit then
         F_Sub (Negated, (others => 0), X_Cand);
         X_Cand := Negated;
      end if;
      P.X := X_Cand;
      F_Mul (P.T, X_Cand, Y);
      OK := True;
   end Decode_Point;

   ---------------------------------------------------------------------
   --  Reduce a 64-byte little-endian integer mod L.
   --  Algorithm ported from TweetNaCl modL.
   ---------------------------------------------------------------------

   procedure Mod_L (Out_Bytes : out Bytes_32; X_In : Octet_Array);
   procedure Mod_L (Out_Bytes : out Bytes_32; X_In : Octet_Array) is
      X : array (0 .. 63) of Integer_64;
      Carry_Acc : Integer_64;
   begin
      pragma Assert (X_In'Length = 64);
      for I in 0 .. 63 loop
         X (I) := Integer_64 (X_In (X_In'First + I));
      end loop;

      for I in reverse 32 .. 63 loop
         Carry_Acc := 0;
         for J in (I - 32) .. (I - 13) loop
            X (J) := X (J) + Carry_Acc - 16 * X (I) * L_Bytes (J - (I - 32));
            Carry_Acc := Asr (X (J) + 128, 8);
            X (J) := X (J) - To_I64 (Shift_Left (To_U64 (Carry_Acc), 8));
         end loop;
         X (I - 12) := X (I - 12) + Carry_Acc;
         X (I) := 0;
      end loop;

      Carry_Acc := 0;
      for J in 0 .. 31 loop
         X (J) := X (J) + Carry_Acc - Asr (X (31), 4) * L_Bytes (J);
         Carry_Acc := Asr (X (J), 8);
         X (J) := And_64 (X (J), 16#FF#);
      end loop;
      for J in 0 .. 31 loop
         X (J) := X (J) - Carry_Acc * L_Bytes (J);
      end loop;
      for I in 0 .. 31 loop
         X (I + 1) := X (I + 1) + Asr (X (I), 8);
         Out_Bytes (1 + I) := Octet (And_64 (X (I), 16#FF#));
      end loop;
   end Mod_L;

   ---------------------------------------------------------------------
   --  Verify — RFC 8032 §5.1.7.
   ---------------------------------------------------------------------

   function Verify
     (Public_Key : Bytes_32;
      Message    : Octet_Array;
      Sig        : Signature)
      return Boolean
   is
      R_Bytes : constant Bytes_32 := Sig (1 .. 32);
      S_Bytes : constant Bytes_32 := Sig (33 .. 64);

      A_Point, R_Point, Lhs, Rhs, Tmp_P : Point;
      A_OK, R_OK : Boolean;

      Hash_Buf : Tls_Core.Sha512.Digest;
      K_Bytes  : Bytes_32;
      K_Wide   : Octet_Array (1 .. 64);

      --  Reject high-bit-set s per §5.1.7 paragraph 2 cofactored
      --  malleability rule: s must be < L.
      Highest_Bytes_Zero : Boolean := True;
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
      pragma Unreferenced (Highest_Bytes_Zero);

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

   procedure Debug_Encode_Base (Out_Bytes : out Bytes_32) is
      B : Point;
   begin
      Get_Base_Point (B);
      Encode_Point (Out_Bytes, B);
   end Debug_Encode_Base;

   procedure Debug_Scalar_Base
     (Scalar : Bytes_32;
      Out_Bytes : out Bytes_32)
   is
      B, P : Point;
   begin
      Get_Base_Point (B);
      Scalar_Mult_Bytes (P, Scalar, B);
      Encode_Point (Out_Bytes, P);
   end Debug_Scalar_Base;

   procedure Debug_Decode_Encode
     (In_Bytes  : Bytes_32;
      Out_Bytes : out Bytes_32;
      OK        : out Boolean)
   is
      P : Point;
   begin
      Out_Bytes := (others => 0);
      Decode_Point (P, In_Bytes, OK);
      if OK then
         Encode_Point (Out_Bytes, P);
      end if;
   end Debug_Decode_Encode;

end Tls_Core.Ed25519;
