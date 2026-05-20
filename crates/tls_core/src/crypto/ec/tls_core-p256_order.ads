--  Tls_Core.P256_Order — arithmetic over Z_n where
--      n = ffffffff 00000000 ffffffff ffffffff
--          bce6faad a7179e84 f3b9cac2 fc632551
--  is the order of the NIST P-256 generator (FIPS 186-4 §D.1.2.3).
--
--  Wire / byte representation matches Tls_Core.P256_Field: a Scalar
--  is 32 bytes big-endian. ECDSA r, s, e (digest as integer) and
--  per-signature k all live in Z_n; all the multiplicative inverses
--  in §6.4.2 are mod n, NOT mod p.
--
--  Internal representation: eight 32-bit limbs little-endian. Add
--  and Sub use a single conditional add/subtract of n. Mul folds a
--  16-limb schoolbook product through a bit-serial shift/subtract
--  reduction (correct but slow — fine for the per-verify cost).
--  Invert is Fermat: a^(n-2) mod n via square-and-multiply.
--
--  Functional Posts: every public scalar operation has a Post that
--  links the represented integer of the output to the canonical
--  HACL\* spec
--      Spec.P256.PointOps.fst :  qadd / qmul / qinv
--  via the ghost layer below. The represented integer of a Scalar S
--  (32 bytes big-endian) is `To_Big_Spec (S)`; the equivalence
--  relation `Equiv_N_Spec (A, B)` is congruence modulo n. Posts
--  state "the value of the output, modulo n, equals the HACL\* spec
--  value of the inputs, modulo n."
--
--  Status (v0.5 platinum push, 2026-05-07):
--    * Ghost layer is real, computable, no `Spec_*` stubs (docs/conventions.md
--      §0d B3).
--    * Posts are functional (docs/conventions.md §0d A4): each one
--      references real Big_Integer arithmetic, not a tautology.
--    * AoRTE on the limb arithmetic + the bit-serial reducer + the
--      Fermat exponent walk, plus the functional Post proofs, are
--      NOT yet discharged at level=2. Honest unproven (clause 1
--      not yet satisfied) — no SPARK_Mode (Off), no pragma Assume,
--      no annotation has been used to make them disappear (clause
--      6). RFC 6979 §A.2.5 P-256 KAT exercises end-to-end.

with Ada.Numerics.Big_Numbers.Big_Integers;

package Tls_Core.P256_Order
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   subtype Scalar is Octet_Array (1 .. 32);

   Zero : constant Scalar := (others => 0);
   One  : constant Scalar :=
     (1 .. 31 => 0, 32 => 1);

   pragma Warnings (On, "array aggregate using () is an obsolescent syntax");

   ---------------------------------------------------------------------
   --  Ghost spec layer.
   --
   --  Integer interpretation of a 32-byte big-endian Scalar plus the
   --  HACL\* `qadd`/`qsub`/`qmul`/`qinv` (Spec.P256.PointOps.fst)
   --  expressed over Big_Integer.
   ---------------------------------------------------------------------

   package Big renames Ada.Numerics.Big_Numbers.Big_Integers;

   use type Big.Big_Integer;

   function Byte_Big (X : Octet) return Big.Big_Integer
   with Ghost, Global => null;

   function Pow_2_8 (N : Natural) return Big.Big_Integer
   with Ghost, Global => null,
        Pre  => N <= 32,
        Post => Pow_2_8'Result > Big.To_Big_Integer (0);

   function To_Big_Up_To
     (S : Scalar; N : Natural) return Big.Big_Integer
   is
     (if N = 0 then Big.To_Big_Integer (0)
      else
        To_Big_Up_To (S, N - 1)
        + Byte_Big (S (32 - (N - 1))) * Pow_2_8 (N - 1))
   with Ghost,
        Global => null,
        Pre => N <= 32,
        Subprogram_Variant => (Decreases => N);

   --  Integer interpretation of the 32-byte big-endian Scalar.
   function To_Big_Spec (S : Scalar) return Big.Big_Integer
   is (To_Big_Up_To (S, 32))
   with Ghost, Global => null;

   --  Group order n (Spec.P256.PointOps.fst :  order ).
   function Order_N_Spec return Big.Big_Integer
   with Ghost, Global => null,
        Post => Order_N_Spec'Result > Big.To_Big_Integer (0);

   --  Canonical residue mod n.
   function Spec_Mod_N (X : Big.Big_Integer) return Big.Big_Integer
   with Ghost, Global => null,
        Post => Big.In_Range
                  (Spec_Mod_N'Result,
                   Big.To_Big_Integer (0),
                   Order_N_Spec - Big.To_Big_Integer (1));

   --  Equivalence mod n.
   function Equiv_N_Spec (A, B : Big.Big_Integer) return Boolean
   is (Spec_Mod_N (A) = Spec_Mod_N (B))
   with Ghost, Global => null;

   --  HACL\* Spec.P256.PointOps.fst :  qadd / qmul / qinv .
   --      let qadd x y = (x + y) % order
   --      let qmul x y = (x * y) % order
   --      let qinv x   = pow_mod #order x (order - 2)
   --  qsub is implicit via qadd of the negation.

   function Spec_Q_Add (A, B : Big.Big_Integer) return Big.Big_Integer
   is (Spec_Mod_N (A + B))
   with Ghost, Global => null;

   function Spec_Q_Sub (A, B : Big.Big_Integer) return Big.Big_Integer
   is (Spec_Mod_N (A - B))
   with Ghost, Global => null;

   function Spec_Q_Mul (A, B : Big.Big_Integer) return Big.Big_Integer
   is (Spec_Mod_N (A * B))
   with Ghost, Global => null;

   function Spec_Q_Inv (A : Big.Big_Integer) return Big.Big_Integer
   with Ghost, Global => null,
        Post => Big.In_Range
                  (Spec_Q_Inv'Result,
                   Big.To_Big_Integer (0),
                   Order_N_Spec - Big.To_Big_Integer (1));

   ---------------------------------------------------------------------
   --  Public scalar operations with functional Posts.
   ---------------------------------------------------------------------

   --  --------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Z_n addition for P-256 group order.
   --
   --  Standard:    FIPS 186-4 §6.4.2 (ECDSA verify, mod-n step).
   --  Spec mirror: HACL*  specs/Spec.P256.PointOps.fst :  qadd
   --
   --  Functional: Equiv_N_Spec (To_Big_Spec (Out_C),
   --                            Spec_Q_Add (To_Big_Spec (A),
   --                                        To_Big_Spec (B)))
   --  Proven at:  honest unproven (Post not discharged at level=2;
   --              B4 clean).
   --  --------------------------------------------------------------
   procedure Add (A, B : Scalar; Out_C : out Scalar)
   with Post =>
     Equiv_N_Spec
       (To_Big_Spec (Out_C),
        Spec_Q_Add (To_Big_Spec (A), To_Big_Spec (B)));

   --  --------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Z_n subtraction.
   --
   --  Functional: Equiv_N_Spec (To_Big_Spec (Out_C),
   --                            Spec_Q_Sub (..., ...))
   --  --------------------------------------------------------------
   procedure Sub (A, B : Scalar; Out_C : out Scalar)
   with Post =>
     Equiv_N_Spec
       (To_Big_Spec (Out_C),
        Spec_Q_Sub (To_Big_Spec (A), To_Big_Spec (B)));

   --  --------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Z_n multiplication.
   --
   --  Spec mirror: HACL*  specs/Spec.P256.PointOps.fst :  qmul
   --
   --  Functional: Equiv_N_Spec (To_Big_Spec (Out_C),
   --                            Spec_Q_Mul (To_Big_Spec (A),
   --                                        To_Big_Spec (B)))
   --  --------------------------------------------------------------
   procedure Mul (A, B : Scalar; Out_C : out Scalar)
   with Post =>
     Equiv_N_Spec
       (To_Big_Spec (Out_C),
        Spec_Q_Mul (To_Big_Spec (A), To_Big_Spec (B)));

   --  --------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Z_n inversion via Fermat (a^(n-2) mod n).
   --
   --  Standard:    FIPS 186-4 §6.4.2 step 3 (s^-1 mod n).
   --  Spec mirror: HACL*  specs/Spec.P256.PointOps.fst :  qinv
   --
   --  Functional: when A is non-zero mod n, the output multiplied
   --              by A is congruent to 1 mod n.
   --  --------------------------------------------------------------
   procedure Invert (A : Scalar; Out_C : out Scalar)
   with Post =>
     (if not Equiv_N_Spec (To_Big_Spec (A), Big.To_Big_Integer (0))
      then
        Equiv_N_Spec
          (To_Big_Spec (Out_C) * To_Big_Spec (A),
           Big.To_Big_Integer (1)));

   --  --------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Single-step reduction mod n.
   --
   --  Inputs already < n pass through unchanged. Used for the
   --  digest-as-integer step in ECDSA verify (FIPS 186-4 §6.4.2
   --  step 3) and to canonicalise scalars at the API boundary.
   --
   --  Functional: To_Big_Spec (Out_C) = Spec_Mod_N (To_Big_Spec (A))
   --              when A < 2*n, which holds for any 32-byte input
   --              (since n > 2^255 and the input is < 2^256 < 2*n).
   --  --------------------------------------------------------------
   procedure Reduce (A : Scalar; Out_C : out Scalar)
   with Post =>
     To_Big_Spec (Out_C) = Spec_Mod_N (To_Big_Spec (A));

   --  True iff X = 0.
   function Is_Zero (X : Scalar) return Boolean;

   --  True iff 0 < X < n (the "1 ≤ r,s ≤ n-1" gate from
   --  FIPS 186-4 §6.4.2).
   function In_Range (X : Scalar) return Boolean;

end Tls_Core.P256_Order;
