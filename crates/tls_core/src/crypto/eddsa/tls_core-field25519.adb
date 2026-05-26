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
   --  Carry
   ---------------------------------------------------------------------

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
   --  F_Add / F_Sub
   ---------------------------------------------------------------------

   procedure F_Add (O : out Felt; A, B : Felt) is
   begin
      O := [others => 0];
      for I in Felt_Index loop
         O (I) := A (I) + B (I);
      end loop;
   end F_Add;

   procedure F_Sub (O : out Felt; A, B : Felt) is
   begin
      O := [others => 0];
      for I in Felt_Index loop
         O (I) := A (I) - B (I);
      end loop;
   end F_Sub;

   ---------------------------------------------------------------------
   --  F_Mul / F_Sqr
   ---------------------------------------------------------------------

   procedure F_Mul (O : out Felt; A, B : Felt) is
      T : Big_Buf := [others => 0];
   begin
      O := [others => 0];
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

   procedure F_Sqr (O : out Felt; A : Felt) is
   begin
      F_Mul (O, A, A);
   end F_Sqr;

   ---------------------------------------------------------------------
   --  F_Inv via Fermat: a^(-1) = a^(p-2) mod p, where p = 2^255 - 19.
   --  (p-2) has bits 1..254 set except bits 2 and 4.
   ---------------------------------------------------------------------

   procedure F_Inv (O : out Felt; I_Val : Felt) is
      C, T : Felt;
   begin
      O := [others => 0];
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

   ---------------------------------------------------------------------
   --  Pow_2523 — z^((p-5)/8). TweetNaCl-shape exponent walk.
   ---------------------------------------------------------------------

   procedure Pow_2523 (O : out Felt; Z : Felt) is
      C, T : Felt;
   begin
      O := [others => 0];
      C := Z;
      for A in reverse 0 .. 250 loop
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
   --  C_Swap
   ---------------------------------------------------------------------

   procedure C_Swap (P, Q : in out Felt; Swap_Bit : Integer_64) is
      Mask : constant Integer_64 := -Swap_Bit;
      T    : Integer_64;
   begin
      for I in Felt_Index loop
         T := To_I64 (To_U64 (Mask) and (To_U64 (P (I)) xor To_U64 (Q (I))));
         P (I) := To_I64 (To_U64 (P (I)) xor To_U64 (T));
         Q (I) := To_I64 (To_U64 (Q (I)) xor To_U64 (T));
      end loop;
   end C_Swap;

   ---------------------------------------------------------------------
   --  Pack — final reduction mod p, then serialize 32 LE bytes.
   ---------------------------------------------------------------------

   procedure Pack (O : out Bytes_32; N : Felt) is
      T, M : Felt;
      B    : Integer_64;
   begin
      O := [others => 0];
      T := N;
      Carry (T);
      Carry (T);
      Carry (T);
      for J in 0 .. 1 loop
         M (0) := T (0) - 16#FFED#;
         for I in 1 .. 14 loop
            M (I) := T (I) - 16#FFFF# - And_64 (Asr (M (I - 1), 16), 1);
            M (I - 1) := And_64 (M (I - 1), 16#FFFF#);
         end loop;
         M (15) := T (15) - 16#7FFF# - And_64 (Asr (M (14), 16), 1);
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
   --  Unpack — read 32 LE bytes; mask off bit 255 of the high byte.
   ---------------------------------------------------------------------

   procedure Unpack (O : out Felt; B : Bytes_32) is
   begin
      O := [others => 0];
      for I in Felt_Index loop
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
