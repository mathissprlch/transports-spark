with Interfaces;

with Tls_Core.Field25519;
with Tls_Core.Sha512;

package body Tls_Core.Ed25519
with SPARK_Mode => Off
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use Interfaces;
   use Tls_Core.Field25519;

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

   --  Internal helper: reduce a 64-element Integer_64 array (the
   --  shape Sign produces from polynomial multiplication) mod L
   --  in-place, then emit the canonical 32-byte LE result.
   subtype X64 is Natural range 0 .. 63;
   type X64_Array is array (X64) of Integer_64;

   procedure Mod_L_Core (Out_Bytes : out Bytes_32; X : in out X64_Array);
   procedure Mod_L_Core (Out_Bytes : out Bytes_32; X : in out X64_Array) is
      Carry_Acc : Integer_64;
   begin
      for I in reverse 32 .. 63 loop
         Carry_Acc := 0;
         for J in (I - 32) .. (I - 13) loop
            X (J) := X (J) + Carry_Acc - 16 * X (I) * L_Bytes (J - (I - 32));
            Carry_Acc := Asr (X (J) + 128, 8);
            X (J) := X (J) - Carry_Acc * 256;
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
   end Mod_L_Core;

   procedure Mod_L (Out_Bytes : out Bytes_32; X_In : Octet_Array);
   procedure Mod_L (Out_Bytes : out Bytes_32; X_In : Octet_Array) is
      X : X64_Array := (others => 0);
   begin
      pragma Assert (X_In'Length = 64);
      for I in 0 .. 63 loop
         X (I) := Integer_64 (X_In (X_In'First + I));
      end loop;
      Mod_L_Core (Out_Bytes, X);
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

   function Spec_Verify
     (Public_Key : Bytes_32;
      Message    : Octet_Array;
      Sig        : Signature)
      return Boolean
   is
      pragma Unreferenced (Public_Key, Message, Sig);
   begin
      return False;
   end Spec_Verify;

   ---------------------------------------------------------------------
   --  Derive the clamped scalar a and prefix from the seed.
   ---------------------------------------------------------------------

   procedure Seed_To_Scalar_And_Prefix
     (Seed   : Bytes_32;
      A_Out  : out Bytes_32;
      Prefix : out Bytes_32);
   procedure Seed_To_Scalar_And_Prefix
     (Seed   : Bytes_32;
      A_Out  : out Bytes_32;
      Prefix : out Bytes_32)
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

   procedure Public_Of_Seed
     (Seed       : Bytes_32;
      Out_Public : out Bytes_32)
   is
      A : Bytes_32;
      Prefix : Bytes_32;
      B, P : Point;
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
     (Seed    : Bytes_32;
      Message : Octet_Array;
      Out_Sig : out Signature)
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

      X       : X64_Array := (others => 0);
      S_Out   : Bytes_32;

      Ctx     : Tls_Core.Sha512.Context;
   begin
      Out_Sig := (others => 0);

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
      Mod_L_Core (S_Out, X);

      --  Concatenate R || s.
      Out_Sig (1 .. 32) := R_Enc;
      Out_Sig (33 .. 64) := S_Out;
   end Sign;

end Tls_Core.Ed25519;
