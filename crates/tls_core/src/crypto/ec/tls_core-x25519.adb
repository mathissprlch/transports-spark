with Interfaces;

package body Tls_Core.X25519
  with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use Interfaces;
   use Tls_Core.Field25519;

   ---------------------------------------------------------------------
   --  Spec ghost bodies — the HACL\* Spec.Curve25519 reference,
   --  re-expressed as Big_Integer arithmetic. Computable; gnatprove
   --  unfolds these for proof. None is a stub.
   ---------------------------------------------------------------------

   ---------------------------------------------------------------------
   --  Spec_Decode_Scalar — RFC 7748 §5 Decode_Scalar / Spec.Curve25519
   --      let decodeScalar k =
   --        let k = k.[0]  <- (k.[0] &. 248)
   --        let k = k.[31] <- (k.[31] &. 127)
   --        let k = k.[31] <- (k.[31] |. 64)
   --        k
   ---------------------------------------------------------------------

   function Spec_Decode_Scalar (Scalar : Bytes_32) return Bytes_32 is
      Z : Bytes_32 := Scalar;
   begin
      Z (1) := Z (1) and 16#F8#;
      Z (32) := (Z (32) and 16#7F#) or 16#40#;
      return Z;
   end Spec_Decode_Scalar;

   ---------------------------------------------------------------------
   --  Spec_Decode_Point —
   --      let decodePoint u = (nat_from_bytes_le u % pow2 255) % prime
   ---------------------------------------------------------------------

   function Spec_Decode_Point (U_Coord : Bytes_32) return Big.Big_Integer is
      Sum   : Big.Big_Integer := Big.To_Big_Integer (0);
      Two_8 : constant Big.Big_Integer := Big.To_Big_Integer (256);
      Pow   : Big.Big_Integer := Big.To_Big_Integer (1);
   begin
      for I in U_Coord'Range loop
         Sum := Sum + Big.To_Big_Integer (Integer (U_Coord (I))) * Pow;
         Pow := Pow * Two_8;
      end loop;
      --  Mask high bit (mod 2^255) and then mod prime.
      Sum := Sum mod (Big.To_Big_Integer (2)**255);
      Sum := Sum mod Field25519.Prime_P_Spec;
      return Sum;
   end Spec_Decode_Point;

   ---------------------------------------------------------------------
   --  Spec_Encode_Point —
   --      let encodePoint (x, z) = nat_to_bytes_le 32 (x /% z)
   --  Here we take an already-reduced elem rather than (x, z),
   --  since the Post on the ladder produces the affine x.
   ---------------------------------------------------------------------

   function Spec_Encode_Point (P : Big.Big_Integer) return Bytes_32 is
      Out_B : Bytes_32 := (others => 0);
      Q     : Big.Big_Integer := P;
      Two_8 : constant Big.Big_Integer := Big.To_Big_Integer (256);
   begin
      for I in Out_B'Range loop
         declare
            Byte_Big : constant Big.Big_Integer := Q mod Two_8;
            package Int_Big is new Big.Signed_Conversions (Int => Integer);
         begin
            Out_B (I) := Octet (Int_Big.From_Big_Integer (Byte_Big));
            Q := Q / Two_8;
         end;
      end loop;
      return Out_B;
   end Spec_Encode_Point;

   ---------------------------------------------------------------------
   --  Spec_Montgomery_Ladder — port of Spec.Curve25519 montgomery_ladder.
   --
   --  F\* source:
   --      let q     = (init, one)
   --      let nq    = (one, zero)
   --      let nqp1  = (init, one)
   --      let nq, nqp1 = cswap2 1 nq nqp1
   --      let nq, nqp1 = add_and_double q nq nqp1
   --      let swap = 1 in
   --      let nq, nqp1, swap = repeat 251 (ladder_step k q) (nq, nqp1, swap)
   --      let nq, nqp1 = cswap2 swap nq nqp1
   --      let nq = double nq; let nq = double nq; let nq = double nq
   --      nq
   --
   --  We expand to 255 iterations of the cswap-add_and_double pattern
   --  exactly as the imperative impl does (TweetNaCl shape), so the
   --  spec and impl walk the same scalar bits in the same order.
   --  Both forms compute the same elem; F\* proves equivalence in
   --  Spec.Curve25519.Lemmas (out of scope here — the spec we trust
   --  is the unrolled 255-step form, which exactly mirrors the
   --  TweetNaCl algorithm in the impl).
   ---------------------------------------------------------------------

   function Spec_Montgomery_Ladder
     (Init : Big.Big_Integer; Scalar : Bytes_32) return Big.Big_Integer
   is
      P : constant Big.Big_Integer := Field25519.Prime_P_Spec;

      --  (X2, Z2) = nq, (X3, Z3) = nqp1
      X2 : Big.Big_Integer := Big.To_Big_Integer (1);
      Z2 : Big.Big_Integer := Big.To_Big_Integer (0);
      X3 : Big.Big_Integer := Init;
      Z3 : Big.Big_Integer := Big.To_Big_Integer (1);
      X1 : constant Big.Big_Integer := Init;

      Swap_Bit                                               : Natural := 0;
      Bit                                                    : Natural;
      A, B, C, D, DA, CB, AA, BB, E, E121665, X2_New, Z2_New : Big.Big_Integer;
      C_121665                                               :
        constant Big.Big_Integer := Big.To_Big_Integer (121665);

      procedure CSwap (S : Natural) with Post => True is
         T : Big.Big_Integer;
      begin
         if S = 1 then
            T := X2;
            X2 := X3;
            X3 := T;
            T := Z2;
            Z2 := Z3;
            Z3 := T;
         end if;
      end CSwap;

   begin
      for I in reverse 0 .. 254 loop
         declare
            Pow_Tab  : constant array (Natural range 0 .. 7) of Natural :=
              (1, 2, 4, 8, 16, 32, 64, 128);
            Byte_Idx : constant Positive := 1 + I / 8;
            Bit_Pos  : constant Natural range 0 .. 7 := I mod 8;
            Byte_Val : constant Natural := Natural (Scalar (Byte_Idx));
            Pow      : constant Positive := Pow_Tab (Bit_Pos);
         begin
            Bit := (Byte_Val / Pow) mod 2;
         end;

         CSwap ((if Bit /= Swap_Bit then 1 else 0));
         Swap_Bit := Bit;

         --  add_and_double, all reductions mod p:
         A := (X2 + Z2) mod P;
         B := ((X2 - Z2) mod P + P) mod P;
         C := (X3 + Z3) mod P;
         D := ((X3 - Z3) mod P + P) mod P;
         DA := (D * A) mod P;
         CB := (C * B) mod P;
         AA := (A * A) mod P;
         BB := (B * B) mod P;
         E := ((AA - BB) mod P + P) mod P;
         E121665 := (E * C_121665) mod P;

         X2_New := (AA * BB) mod P;
         Z2_New := (E * ((E121665 + AA) mod P)) mod P;
         X2 := X2_New;
         Z2 := Z2_New;

         declare
            X3_Sum : constant Big.Big_Integer := (DA + CB) mod P;
            X3_Sub : constant Big.Big_Integer := ((DA - CB) mod P + P) mod P;
         begin
            X3 := (X3_Sum * X3_Sum) mod P;
            Z3 := (((X3_Sub * X3_Sub) mod P) * X1) mod P;
         end;
      end loop;

      CSwap (Swap_Bit);

      --  Result = X2 / Z2 = X2 * Z2^(p-2) mod p.
      --  We use the defining equation rather than a closed-form
      --  Pow_Mod here; this is the same content as
      --  encodePoint (X2, Z2) = X2 /% Z2.
      declare
         Z_Inv : Big.Big_Integer := Big.To_Big_Integer (1);
         Base  : Big.Big_Integer := Z2;
         Exp   : Big.Big_Integer := P - Big.To_Big_Integer (2);
         Two   : constant Big.Big_Integer := Big.To_Big_Integer (2);
         Zero  : constant Big.Big_Integer := Big.To_Big_Integer (0);
      begin
         while Exp > Zero loop
            pragma Loop_Variant (Decreases => Exp);
            if Exp mod Two = Big.To_Big_Integer (1) then
               Z_Inv := (Z_Inv * Base) mod P;
            end if;
            Exp := Exp / Two;
            Base := (Base * Base) mod P;
         end loop;
         return (X2 * Z_Inv) mod P;
      end;
   end Spec_Montgomery_Ladder;

   ---------------------------------------------------------------------

   --  Constant 121665 = (a + 2) / 4 for a = 486662 (the Montgomery
   --  curve parameter), used as the scalar in the curve's group law.
   C_121665 : constant Felt := (16#DB41#, 1, others => 0);

   ---------------------------------------------------------------------
   --  Scalar_Mult — RFC 7748 §5 Decode → Montgomery ladder → Encode.
   --  Algorithm follows TweetNaCl crypto_scalarmult exactly.
   ---------------------------------------------------------------------

   procedure Scalar_Mult
     (Scalar : Bytes_32; U_Coord : Bytes_32; Out_Q : out Bytes_32)
   is
      Z      : Bytes_32;
      X      : Felt;
      A      : Felt := (others => 0);
      B      : Felt;
      C      : Felt := (others => 0);
      D      : Felt := (others => 0);
      E      : Felt;
      F      : Felt;
      R      : Integer_64;
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
         R :=
           Integer_64
             ((Shift_Right (Unsigned_8 (Z (1 + I / 8)), Natural (I mod 8)))
              and 1);
         C_Swap (A, B, R);
         C_Swap (C, D, R);
         F_Add (E, A, C);
         F_Sub (T1, A, C);
         A := T1;
         F_Add (T1, B, D);
         C := T1;
         F_Sub (T1, B, D);
         B := T1;
         F_Mul (T1, E, E);
         D := T1;
         F_Mul (T1, A, A);
         F := T1;
         F_Mul (T2, C, A);
         A := T2;
         F_Mul (T2, B, E);
         C := T2;
         F_Add (T1, A, C);
         E := T1;
         F_Sub (T1, A, C);
         A := T1;
         F_Mul (T1, A, A);
         B := T1;
         F_Sub (T1, D, F);
         C := T1;
         F_Mul (T2, C, C_121665);
         A := T2;
         F_Add (T1, A, D);
         A := T1;
         F_Mul (T2, C, A);
         C := T2;
         F_Mul (T2, D, F);
         A := T2;
         F_Mul (T2, B, X);
         D := T2;
         F_Mul (T1, E, E);
         B := T1;
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

   procedure Derive_Public (Private_Key : Bytes_32; Out_Public : out Bytes_32)
   is
      Base : constant Bytes_32 := (1 => 9, others => 0);
   begin
      Scalar_Mult (Private_Key, Base, Out_Public);
   end Derive_Public;

end Tls_Core.X25519;
