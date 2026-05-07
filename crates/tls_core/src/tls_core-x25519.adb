with Interfaces;

with Tls_Core.Field25519;

package body Tls_Core.X25519
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use Interfaces;
   use Tls_Core.Field25519;

   --  Constant 121665 = (a + 2) / 4 for a = 486662 (the Montgomery
   --  curve parameter), used as the scalar in the curve's group law.
   C_121665 : constant Felt := (16#DB41#, 1, others => 0);

   ---------------------------------------------------------------------
   --  Scalar_Mult — RFC 7748 §5 Decode → Montgomery ladder → Encode.
   --  Algorithm follows TweetNaCl crypto_scalarmult exactly.
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
      --  Clamp the scalar per §5 Decode_Scalar.
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
   end Scalar_Mult;

   ---------------------------------------------------------------------
   --  Derive_Public — base point u-coordinate is 9 (LE).
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
