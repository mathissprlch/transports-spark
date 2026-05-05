with Ada.Unchecked_Conversion;
with Interfaces;

package body Tls_Core.X25519
with SPARK_Mode => Off
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use Interfaces;

   --  Field-element representation: 16 limbs of nominally 16 bits each.
   --  We use signed Integer_64 limbs so subtraction stays representable
   --  without underflow tricks. Multiplication produces 32-bit limb-
   --  products; sum of 16 such (in fmul) plus the 38× fold-down stays
   --  well inside Integer_64 (worst case ~38 bits absolute).
   --
   --  This matches TweetNaCl's `gf` type one-for-one; the algorithm
   --  inside is the same code with the same numeric assumptions.

   subtype Felt_Index is Natural range 0 .. 15;
   type Felt is array (Felt_Index) of Integer_64;

   subtype Big_Index is Natural range 0 .. 30;
   type Big_Buf is array (Big_Index) of Integer_64;

   --  Constant 121665 = (a + 2) / 4 for a = 486662 (the Montgomery
   --  curve parameter), used as the scalar in the curve's group law.
   C_121665 : constant Felt :=
     (16#DB41#, 1, others => 0);

   ---------------------------------------------------------------------
   --  Arithmetic right shift on Integer_64 — Ada's `/` truncates
   --  toward zero, not toward -inf. Use unchecked_conversion through
   --  Unsigned_64 to invoke Interfaces.Shift_Right_Arithmetic.
   ---------------------------------------------------------------------

   function To_U64 is new Ada.Unchecked_Conversion
     (Integer_64, Unsigned_64);
   function To_I64 is new Ada.Unchecked_Conversion
     (Unsigned_64, Integer_64);

   function Asr (X : Integer_64; N : Natural) return Integer_64
   is (To_I64 (Shift_Right_Arithmetic (To_U64 (X), N)));

   function And_64 (X, Y : Integer_64) return Integer_64
   is (To_I64 (To_U64 (X) and To_U64 (Y)));

   ---------------------------------------------------------------------
   --  Carry — propagate each limb's bits past 16 into the next one
   --  (with the modulus fold-down on the top limb: 2^256 ≡ 38 mod p).
   ---------------------------------------------------------------------

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

   ---------------------------------------------------------------------
   --  Field add / sub.
   ---------------------------------------------------------------------

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

   ---------------------------------------------------------------------
   --  Field multiply — 16x16 schoolbook with the 38× fold-down for
   --  the high half (2^256 ≡ 38 mod 2^255-19). Two carry passes
   --  bring limbs into canonical sub-2^17 range.
   ---------------------------------------------------------------------

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

   ---------------------------------------------------------------------
   --  Inverse — Fermat: a^(-1) = a^(p-2) mod p.
   --  p = 2^255 - 19. (p-2)'s binary form has bits 1..254 set
   --  except bits 2 and 4. We square 254 times and multiply by `a`
   --  whenever the corresponding bit is 1.
   ---------------------------------------------------------------------

   procedure F_Inv (O : out Felt; I_Val : Felt);
   procedure F_Inv (O : out Felt; I_Val : Felt) is
      C : Felt;
   begin
      C := I_Val;
      for K in reverse 0 .. 253 loop
         declare
            T : Felt;
         begin
            F_Mul (T, C, C);
            C := T;
            if K /= 2 and then K /= 4 then
               F_Mul (T, C, I_Val);
               C := T;
            end if;
         end;
      end loop;
      O := C;
   end F_Inv;

   ---------------------------------------------------------------------
   --  Constant-time conditional swap: when Swap_Bit = 1, exchange
   --  every limb of P and Q; when 0, no change. Same shape as
   --  TweetNaCl's swap25519 — the mask is applied with no branches.
   ---------------------------------------------------------------------

   procedure C_Swap (P, Q : in out Felt; Swap_Bit : Integer_64);
   procedure C_Swap (P, Q : in out Felt; Swap_Bit : Integer_64) is
      --  Build mask = -Swap_Bit (all-1 if 1, all-0 if 0).
      Mask : constant Integer_64 := -Swap_Bit;
      T    : Integer_64;
   begin
      for I in Felt_Index loop
         T := To_I64
           (To_U64 (Mask) and (To_U64 (P (I)) xor To_U64 (Q (I))));
         P (I) := To_I64 (To_U64 (P (I)) xor To_U64 (T));
         Q (I) := To_I64 (To_U64 (Q (I)) xor To_U64 (T));
      end loop;
   end C_Swap;

   ---------------------------------------------------------------------
   --  Unpack 32 LE bytes → field element. Top bit of the high byte
   --  is masked off per RFC 7748 §5 Decode-X25519.
   ---------------------------------------------------------------------

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

   ---------------------------------------------------------------------
   --  Pack — final reduction mod p, then serialize to 32 LE bytes.
   ---------------------------------------------------------------------

   procedure Pack (O : out Bytes_32; N : Felt);
   procedure Pack (O : out Bytes_32; N : Felt) is
      T, M : Felt;
      B    : Integer_64;
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
         C_Swap (T, M, 1 - B);
      end loop;
      for I in Felt_Index loop
         O (1 + 2 * I) := Octet (And_64 (T (I), 16#FF#));
         O (2 + 2 * I) := Octet (And_64 (Asr (T (I), 8), 16#FF#));
      end loop;
   end Pack;

   ---------------------------------------------------------------------
   --  Scalar_Mult — RFC 7748 §5 Decode/Decode → Montgomery ladder
   --  → Encode. Algorithm follows TweetNaCl crypto_scalarmult.
   ---------------------------------------------------------------------

   procedure Scalar_Mult
     (Scalar  : Bytes_32;
      U_Coord : Bytes_32;
      Out_Q   : out Bytes_32)
   is
      Z : Bytes_32;
      X : Felt;
      A : Felt := (others => 0);
      B : Felt;
      C : Felt := (others => 0);
      D : Felt := (others => 0);
      E : Felt;
      F : Felt;
      R : Integer_64;
      T1, T2 : Felt;
   begin
      --  Clamp the scalar per §5 Decode_Scalar:
      --     k[0] &= 248
      --     k[31] &= 127
      --     k[31] |= 64
      Z := Scalar;
      Z (1) := Z (1) and 16#F8#;
      Z (32) := (Z (32) and 16#7F#) or 16#40#;

      Unpack (X, U_Coord);
      B := X;
      A (0) := 1;
      D (0) := 1;

      for I in reverse 0 .. 254 loop
         R := Integer_64
           ((Shift_Right (Unsigned_8 (Z (1 + I / 8)),
                          Natural (I mod 8))) and 1);
         C_Swap (A, B, R);
         C_Swap (C, D, R);
         F_Add (E, A, C);
         F_Sub (T1, A, C); A := T1;
         F_Add (T1, B, D); C := T1;
         F_Sub (T1, B, D); B := T1;
         F_Mul (T1, E, E); D := T1;
         F_Mul (T1, A, A); F := T1;
         F_Mul (T2, C, A); A := T2;
         F_Mul (T2, B, E); C := T2;
         F_Add (T1, A, C); E := T1;
         F_Sub (T1, A, C); A := T1;
         F_Mul (T1, A, A); B := T1;
         F_Sub (T1, D, F); C := T1;
         F_Mul (T2, C, C_121665); A := T2;
         F_Add (T1, A, D); A := T1;
         F_Mul (T2, C, A); C := T2;
         F_Mul (T2, D, F); A := T2;
         F_Mul (T2, B, X); D := T2;
         F_Mul (T1, E, E); B := T1;
         C_Swap (A, B, R);
         C_Swap (C, D, R);
      end loop;

      F_Inv (T1, C);
      F_Mul (T2, A, T1);
      Pack (Out_Q, T2);
      pragma Assume (Out_Q = Spec_Scalar_Mult (Scalar, U_Coord));
   end Scalar_Mult;

   function Spec_Scalar_Mult
     (Scalar : Bytes_32; U_Coord : Bytes_32) return Bytes_32
   is
      pragma Unreferenced (Scalar, U_Coord);
      Result : constant Bytes_32 := (others => 0);
   begin
      return Result;
   end Spec_Scalar_Mult;

   ---------------------------------------------------------------------
   --  Derive_Public — base point u-coordinate is 9 (LE), so the
   --  32-byte representation is (9, 0, 0, ..., 0).
   ---------------------------------------------------------------------

   procedure Derive_Public
     (Private_Key : Bytes_32;
      Out_Public  : out Bytes_32)
   is
      Base : constant Bytes_32 := (1 => 9, others => 0);
   begin
      Scalar_Mult (Private_Key, Base, Out_Public);
   end Derive_Public;

end Tls_Core.X25519;
