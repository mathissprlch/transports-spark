pragma Ada_2022;
with Tls_Core.Ghost_Bignum.Value;

package body Tls_Core.Ghost_Bignum.Montgomery
  with SPARK_Mode
is

   ---------------------------------------------------------------------
   --  Ring / modular helper lemmas (discharged from the SMT Big_Integer
   --  theory; isolated so each instance is seen on three operands).
   ---------------------------------------------------------------------

   procedure Lemma_Comm (X, Y : BI.Big_Integer)
   with Post => X * Y = Y * X;
   procedure Lemma_Comm (X, Y : BI.Big_Integer) is
   begin
      null;
   end Lemma_Comm;

   procedure Lemma_Assoc (X, Y, Z : BI.Big_Integer)
   with Post => X * (Y * Z) = (X * Y) * Z;
   procedure Lemma_Assoc (X, Y, Z : BI.Big_Integer) is
   begin
      null;
   end Lemma_Assoc;

   procedure Lemma_Distrib (X, Y, Z : BI.Big_Integer)
   with Post => X * (Y + Z) = X * Y + X * Z;
   procedure Lemma_Distrib (X, Y, Z : BI.Big_Integer) is
   begin
      null;
   end Lemma_Distrib;

   --  Four-factor rearrange: (a*b)*(c*d) = (a*c)*(b*d), from comm/assoc.
   procedure Lemma_Swap4 (A, B, C, D : BI.Big_Integer)
   with Post => (A * B) * (C * D) = (A * C) * (B * D);
   procedure Lemma_Swap4 (A, B, C, D : BI.Big_Integer) is
   begin
      Lemma_Assoc (A, B, C * D);          --  A*(B*(C*D)) = (A*B)*(C*D)
      Lemma_Assoc (B, C, D);              --  B*(C*D) = (B*C)*D
      Lemma_Comm (B, C);                  --  B*C = C*B
      Lemma_Assoc (C, B, D);              --  C*(B*D) = (C*B)*D
      Lemma_Assoc (A, C, B * D);          --  A*(C*(B*D)) = (A*C)*(B*D)
      pragma Assert ((A * B) * (C * D) = A * (B * (C * D)));
      pragma Assert (A * (B * (C * D)) = A * ((B * C) * D));
      pragma Assert (A * ((B * C) * D) = A * ((C * B) * D));
      pragma Assert (A * ((C * B) * D) = A * (C * (B * D)));
      pragma Assert (A * (C * (B * D)) = (A * C) * (B * D));
   end Lemma_Swap4;

   --  Euclidean uniqueness of the remainder (port of bignum_2048's
   --  Lemma_Mod_Unique): X >= 0, D > 0, X = Q*D + R, 0 <= R < D ⇒ X mod D = R.
   procedure Lemma_Mod_Unique (X, Q, R, D : BI.Big_Integer)
   with
     Pre  =>
       D > 0
       and then X >= 0
       and then X = Q * D + R
       and then R >= 0
       and then R < D,
     Post => X mod D = R;
   procedure Lemma_Mod_Unique (X, Q, R, D : BI.Big_Integer) is
      K : constant BI.Big_Integer := X / D - Q;
   begin
      pragma Assert (X = (X / D) * D + (X mod D));
      Lemma_Distrib (D, X / D, -Q);
      Lemma_Comm (D, K);
      Lemma_Comm (D, X / D);
      Lemma_Comm (D, Q);
      pragma Assert (K * D = R - (X mod D));
      pragma Assert (K * D < D);
      pragma Assert (K * D > -D);
      if K >= 1 then
         Value.Lemma_BI_Mul_Mono (D, 1, K);
         Lemma_Comm (D, K);
      elsif K <= -1 then
         Value.Lemma_BI_Mul_Mono (D, K, -1);
         Lemma_Comm (D, K);
      end if;
      pragma Assert (K = 0);
   end Lemma_Mod_Unique;

   --  Full modular product (port of Lemma_Mod_Mul_Cong):
   --  (A*B) mod N = ((A mod N)*(B mod N)) mod N for non-negative A, B.
   procedure Lemma_Mod_Mul (A, B, N : BI.Big_Integer)
   with
     Pre  => N > 0 and then A >= 0 and then B >= 0,
     Post => (A * B) mod N = ((A mod N) * (B mod N)) mod N;
   procedure Lemma_Mod_Mul (A, B, N : BI.Big_Integer) is
      Qa : constant BI.Big_Integer := A / N;
      Qb : constant BI.Big_Integer := B / N;
      Ra : constant BI.Big_Integer := A mod N;
      Rb : constant BI.Big_Integer := B mod N;
      M  : constant BI.Big_Integer := Qa * Qb * N + Qa * Rb + Ra * Qb;
      Qr : constant BI.Big_Integer := (Ra * Rb) / N;
      Rr : constant BI.Big_Integer := (Ra * Rb) mod N;
   begin
      pragma Assert (A = Qa * N + Ra);
      pragma Assert (B = Qb * N + Rb);
      pragma Assert (Ra >= 0 and then Ra < N);
      pragma Assert (Rb >= 0 and then Rb < N);
      pragma Assert (Ra * Rb >= 0);
      pragma Assert (Ra * Rb = Qr * N + Rr);
      pragma Assert (Rr >= 0 and then Rr < N);
      pragma Assert (A * B = M * N + Ra * Rb);
      pragma Assert (A * B = (M + Qr) * N + Rr);
      pragma Assert (A * B >= 0);
      Lemma_Mod_Unique (A * B, M + Qr, Rr, N);
   end Lemma_Mod_Mul;

   --  Idempotence: (X mod N) mod N = X mod N for non-negative X.
   procedure Lemma_Mod_Idem (X, N : BI.Big_Integer)
   with Pre => N > 0 and then X >= 0, Post => (X mod N) mod N = X mod N;
   procedure Lemma_Mod_Idem (X, N : BI.Big_Integer) is
   begin
      Lemma_Mod_Unique (X mod N, 0, X mod N, N);
   end Lemma_Mod_Idem;

   --  Modular product reduces on the right: (a * (b mod N)) mod N = (a*b) mod N.
   procedure Lemma_Mod_Mul_R (A, B, N : BI.Big_Integer)
   with
     Pre  => N > 0 and then A >= 0 and then B >= 0,
     Post => (A * (B mod N)) mod N = (A * B) mod N;
   procedure Lemma_Mod_Mul_R (A, B, N : BI.Big_Integer) is
   begin
      Lemma_Mod_Mul (A, B, N);                  --  (A*B) mod N = (Ra*Rb) mod N
      Lemma_Mod_Mul
        (A,
         B mod N,
         N);            --  (A*(B mod N)) mod N = (Ra*(B mod N mod N)) mod N
      Lemma_Mod_Idem (B, N);
   end Lemma_Mod_Mul_R;

   --  Modular product reduces on the left: ((p mod N) * q) mod N = (p*q) mod N.
   procedure Lemma_Mod_Mul_L (P, Q, N : BI.Big_Integer)
   with
     Pre  => N > 0 and then P >= 0 and then Q >= 0,
     Post => ((P mod N) * Q) mod N = (P * Q) mod N;
   procedure Lemma_Mod_Mul_L (P, Q, N : BI.Big_Integer) is
   begin
      Lemma_Comm (P mod N, Q);
      Lemma_Mod_Mul_R (Q, P, N);
      Lemma_Comm (Q, P);
   end Lemma_Mod_Mul_L;

   ---------------------------------------------------------------------
   --  Pow2 / Pow algebra.
   ---------------------------------------------------------------------

   procedure Lemma_Pow2_Pos (A : Natural) is
   begin
      if A /= 0 then
         Lemma_Pow2_Pos (A - 1);
      end if;
   end Lemma_Pow2_Pos;

   procedure Lemma_Pow2_Succ (A : Positive) is
   begin
      Lemma_Comm (Pow2 (A - 1), 2);
   end Lemma_Pow2_Succ;

   procedure Lemma_Pow2_Is_Pow (A : Natural) is
   begin
      if A /= 0 then
         Lemma_Pow2_Is_Pow (A - 1);
      end if;
   end Lemma_Pow2_Is_Pow;

   procedure Lemma_Pow2_Add (A1, B1 : Natural) is
   begin
      if B1 /= 0 then
         Lemma_Pow2_Add (A1, B1 - 1);   --  Pow2(A1+B1-1) = Pow2(A1)*Pow2(B1-1)
         Lemma_Pow2_Succ (A1 + B1);     --  Pow2(A1+B1) = 2*Pow2(A1+B1-1)
         Lemma_Pow2_Succ (B1);          --  Pow2(B1) = 2*Pow2(B1-1)
         --  Pow2(A1+B1) = 2*(Pow2(A1)*Pow2(B1-1)) = Pow2(A1)*(2*Pow2(B1-1)).
         Lemma_Assoc (2, Pow2 (A1), Pow2 (B1 - 1));
         Lemma_Comm (2, Pow2 (A1));
         Lemma_Assoc (Pow2 (A1), 2, Pow2 (B1 - 1));
      end if;
   end Lemma_Pow2_Add;

   procedure Lemma_Pow2_Pow_Mul (M, K : Natural) is
   begin
      if K /= 0 then
         pragma Assert (M * K <= Natural'Last);
         pragma Assert (M * (K - 1) <= Natural'Last - M);
         Lemma_Pow2_Pow_Mul (M, K - 1);   --  Pow(Pow2(M),K-1) = Pow2(M*(K-1))
         Lemma_Pow2_Add
           (M * (K - 1), M); --  Pow2(M*(K-1)+M) = Pow2(M*(K-1))*Pow2(M)
         pragma Assert (M * (K - 1) + M = M * K);
      end if;
   end Lemma_Pow2_Pow_Mul;

   procedure Lemma_Pow_One (E : Natural) is
   begin
      if E /= 0 then
         Lemma_Pow_One (E - 1);
      end if;
   end Lemma_Pow_One;

   procedure Lemma_Pow_Mul_Base (X, Y : BI.Big_Integer; E : Natural) is
   begin
      if E /= 0 then
         Lemma_Pow_Mul_Base (X, Y, E - 1);
         --  Pow (X*Y, E) = Pow (X*Y, E-1) * (X*Y)
         --              = (Pow (X,E-1) * Pow (Y,E-1)) * (X*Y)
         --              = (Pow (X,E-1) * X) * (Pow (Y,E-1) * Y)
         --              = Pow (X,E) * Pow (Y,E)
         Lemma_Swap4 (Pow (X, E - 1), Pow (Y, E - 1), X, Y);
      end if;
   end Lemma_Pow_Mul_Base;

   procedure Lemma_Pow_Nonneg (B : BI.Big_Integer; E : Natural) is
   begin
      if E /= 0 then
         Lemma_Pow_Nonneg (B, E - 1);
      end if;
   end Lemma_Pow_Nonneg;

   procedure Lemma_Pow_Cong
     (X, Y : BI.Big_Integer; E : Natural; N : BI.Big_Integer) is
   begin
      if E /= 0 then
         Lemma_Pow_Cong
           (X, Y, E - 1, N);   --  Pow(X,E-1) mod N = Pow(Y,E-1) mod N
         Lemma_Pow_Nonneg (X, E - 1);
         Lemma_Pow_Nonneg (Y, E - 1);
         --  Pow(X,E) mod N = (Pow(X,E-1) * X) mod N
         --                 = ((Pow(X,E-1) mod N) * (X mod N)) mod N
         --                 = ((Pow(Y,E-1) mod N) * (Y mod N)) mod N
         --                 = (Pow(Y,E-1) * Y) mod N = Pow(Y,E) mod N
         Lemma_Mod_Mul (Pow (X, E - 1), X, N);
         Lemma_Mod_Mul (Pow (Y, E - 1), Y, N);
      end if;
   end Lemma_Pow_Cong;

   ---------------------------------------------------------------------
   --  Modular inverse of 2**A and the Montgomery cancellation.
   ---------------------------------------------------------------------

   function Mont_Inv (A : Positive; N : BI.Big_Integer) return BI.Big_Integer
   is
      Inv2 : constant BI.Big_Integer := (N + 1) / 2;
      D    : constant BI.Big_Integer := Pow (Inv2, A) mod N;
   begin
      --  2 * Inv2 = N + 1 (N odd ⇒ N+1 even ⇒ exact halving); Inv2 >= 1.
      pragma Assert ((N + 1) mod 2 = 0);
      pragma Assert (2 * Inv2 = N + 1);
      pragma Assert (Inv2 >= 1);
      Lemma_Pow2_Pos (A);                --  Pow2 (A) > 0.
      Lemma_Pow_Nonneg (Inv2, A);        --  Pow (Inv2, A) >= 0.

      --  Pow2 (A) = Pow (2, A), and Pow (2,A) * Pow (Inv2,A) = Pow (N+1, A).
      Lemma_Pow2_Is_Pow (A);
      Lemma_Pow_Mul_Base (2, Inv2, A);
      pragma Assert (Pow (2, A) * Pow (Inv2, A) = Pow (N + 1, A));

      --  Pow (N+1, A) ≡ Pow (1, A) = 1 (mod N).
      pragma Assert ((N + 1) mod N = 1 mod N);
      Lemma_Pow_Cong (N + 1, 1, A, N);
      Lemma_Pow_One (A);
      pragma Assert (Pow (N + 1, A) mod N = 1);

      --  Assemble: (Pow2(A) * D) mod N = (Pow2(A) * Pow(Inv2,A)) mod N
      --          = Pow (N+1, A) mod N = 1.
      Lemma_Mod_Mul_R (Pow2 (A), Pow (Inv2, A), N);
      pragma Assert ((Pow2 (A) * D) mod N = (Pow2 (A) * Pow (Inv2, A)) mod N);
      pragma Assert ((Pow2 (A) * D) mod N = 1);
      return D;
   end Mont_Inv;

   procedure Lemma_Mont_Id (N, R, D, A : BI.Big_Integer) is
   begin
      --  (A*R mod N) * D mod N = (A*R*D) mod N      [left reduce]
      --                        = (A*(R*D)) mod N    [assoc]
      --                        = (A*(R*D mod N)) mod N  [right reduce, backward]
      --                        = (A*1) mod N = A mod N
      Lemma_Mod_Mul_L (A * R, D, N);
      Lemma_Assoc (A, R, D);
      Lemma_Mod_Mul_R (A, R * D, N);
   end Lemma_Mont_Id;

end Tls_Core.Ghost_Bignum.Montgomery;
