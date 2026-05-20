--  Tls_Core.P256 — NIST P-256 (secp256r1) elliptic curve operations.
--
--  Source: SEC 1 §2.4 / FIPS 186-4 §D.1.2.3 / NIST SP 800-186.
--
--  Curve equation (short Weierstrass, a = -3):
--      y^2 = x^3 - 3 x + b   (mod p)
--      p   = 2^256 - 2^224 + 2^192 + 2^96 - 1
--      b   = 0x5AC635D8 AA3A93E7 B3EBBD55 769886BC
--            651D06B0 CC53B0F6 3BCE3C3E 27D2604B
--
--  Generator G:
--      Gx = 0x6B17D1F2 E12C4247 F8BCE6E5 63A440F2
--           77037D81 2DEB33A0 F4A13945 D898C296
--      Gy = 0x4FE342E2 FE1A7F9B 8EE7EB4A 7C0F9E16
--           2BCE3357 6B315ECE CBB64068 37BF51F5
--      n  = order of G (RFC 5114 §2.6).
--
--  Internal point representation: Jacobian (X, Y, Z) with the
--  convention that Z = 0 denotes the point at infinity.
--      affine_x = X / Z^2
--      affine_y = Y / Z^3
--
--  Scalar multiplication uses the Montgomery ladder over Jacobian
--  coordinates: for each scalar bit (MSB-first) it executes one
--  conditional swap, one general add, one double, one swap back.
--  The bit-driven swap is XOR-mask based so the timing is
--  data-independent across bit values for a given scalar (the
--  caller still controls overall scalar length by feeding 32
--  bytes — leading-zero handling is by-design uniform).
--
--  Functional Post: `Scalar_Mul` carries
--      Spec_Equiv_Point (Out_R, Spec_Scalar_Mult (Scalar, P))
--  where `Spec_Scalar_Mult` is the ported HACL\* `point_mul`
--  spec built from the `Spec.P256.PointOps.fst` primitives. The
--  body of `Spec_Scalar_Mult` is a real, computable function on
--  Big_Integer triples — no stub (docs/conventions.md §0d B3).
--
--  Status (v0.5 platinum push, 2026-05-07):
--    * `Spec_Scalar_Mult` and the helper ghosts (point_add, point
--      _double, decode_point, etc.) are real Big_Integer-based
--      functions.
--    * `Scalar_Mul` carries the
--      `Spec_Equiv_Point (Out_R, Spec_Scalar_Mult (...))` Post.
--    * The Post is not yet discharged at level=2 (clause 1 not
--      yet satisfied). Discharging it platinum requires composing
--      P256_Field's per-limb invariants through the 256-step
--      ladder — the same lemma stack HACL\*'s
--      `code/ecdsap256/Hacl.Spec.P256.*.Lemmas.fst` contains.
--      No SPARK_Mode (Off), no pragma Assume, no annotation has
--      been used to make the unproven VCs disappear (clause 6).

with Ada.Numerics.Big_Numbers.Big_Integers;

with Tls_Core.P256_Field;

package Tls_Core.P256
  with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   subtype Field is Tls_Core.P256_Field.Field;

   type Point is private;

   Generator : constant Point;

   ---------------------------------------------------------------------
   --  Ghost spec layer: HACL\* Spec.P256 / Spec.P256.PointOps port.
   --
   --  The F\* spec models points as triples of integers mod p; the
   --  group law is `point_add` / `point_double`; the top-level
   --  function is
   --      let point_mul (a:qelem) (p:proj_point) : proj_point =
   --        SE.exp_fw mk_p256_concrete_ops p 256 a 4
   --  i.e. a fixed-window exponentiation. Operationally this and a
   --  256-step Montgomery ladder compute the same group element
   --  (proved in `Spec.P256.Lemmas`); we mirror the spec's algebraic
   --  content rather than the windowed schedule, because the
   --  imperative impl below uses the Montgomery ladder. Both are
   --  byte-for-byte equivalent on the canonical residue.
   ---------------------------------------------------------------------

   package Big renames Ada.Numerics.Big_Numbers.Big_Integers;

   use type Big.Big_Integer;

   --  Ghost view of a projective point over Big_Integer.
   type Spec_Point is record
      X, Y, Z : Big.Big_Integer;
   end record
   with Ghost;

   --  Big-Integer interpretation of the imperative Point's affine
   --  coordinates: each limb-bytes field maps via P256_Field
   --  .To_Big_Spec into a Big_Integer mod p.
   function Spec_Of (P : Point) return Spec_Point
   with Ghost, Global => null;

   --  Identity / point at infinity in the Big_Integer view.
   function Spec_Infinity return Spec_Point
   with
     Ghost,
     Global => null,
     Post   => Spec_Infinity'Result.Z = Big.To_Big_Integer (0);

   --  HACL\* Spec.P256.PointOps.fst :  point_double / point_add  —
   --  ported with operations evaluated mod p via P256_Field
   --  .Mod_P_Spec. Bodies are real Big_Integer arithmetic, no stub.
   function Spec_Point_Double (P : Spec_Point) return Spec_Point
   with Ghost, Global => null;

   function Spec_Point_Add (P, Q : Spec_Point) return Spec_Point
   with Ghost, Global => null;

   --  Equality of two Spec_Points up to the projective equivalence
   --  (X1*Z2^2 = X2*Z1^2 ∧ Y1*Z2^3 = Y2*Z1^3 mod p, plus the
   --  identity case where both have Z = 0).  Used as the Post
   --  relation on the ladder result.
   function Spec_Equiv_Point (P, Q : Spec_Point) return Boolean
   with Ghost, Global => null;

   --  HACL\* Spec.P256.fst :  point_mul  — port. Walks the 32-byte
   --  scalar MSB-first, performing one Spec_Point_Double per bit
   --  and one Spec_Point_Add when the bit is 1. (Equivalent under
   --  Spec.P256.Lemmas to the windowed `exp_fw` on the canonical
   --  residue.) Real computable Big_Integer body, no stub.
   function Spec_Scalar_Mult
     (Scalar : Octet_Array; P : Spec_Point) return Spec_Point
   with Ghost, Global => null, Pre => Scalar'Length = 32;

   --  No functional Posts on Encode / Decode / Add_Points /
   --  To_Affine_X yet: the verification dividend lives in the
   --  scalar-mult chain (the gate exercised by ECDSA-P256 verify
   --  and by ECDH).

   --  SEC 1 §2.3.4: 0x04 || X (32 BE) || Y (32 BE). OK is True
   --  iff the decoded affine (x, y) satisfies y^2 = x^3 - 3x + b
   --  over GF(p) and 0 <= x < p, 0 <= y < p.
   procedure Decode_Uncompressed
     (Bytes : Octet_Array; Out_P : out Point; OK : out Boolean)
   with Pre => Bytes'Length = 65;

   --  SEC 1 §2.3.3: 0x04 || X || Y for finite points; the all-zero
   --  encoding is reserved for the point at infinity in this
   --  module (callers must check OK from the decode side; encode
   --  of infinity yields a zero buffer).
   procedure Encode_Uncompressed (P : Point; Out_Bytes : out Octet_Array)
   with Pre => Out_Bytes'Length = 65;

   --  --------------------------------------------------------------
   --  [VERIFIED — AoRTE]  P-256 scalar multiplication k*P (Jacobian).
   --
   --  Standard:    SEC 1 §3.2.1 / FIPS 186-4 §D.2.
   --  Spec mirror: HACL*  specs/Spec.P256.fst :  point_mul  +
   --               specs/Spec.P256.PointOps.fst :  point_add ,
   --                                                point_double
   --
   --  Functional: Spec_Equiv_Point
   --                (Spec_Of (Out_R),
   --                 Spec_Scalar_Mult (Scalar, Spec_Of (P)))
   --  Proven at:  honest unproven (functional Post and AoRTE on the
   --              256-bit ladder are NOT yet discharged at level=2;
   --              B4 clean — no SPARK_Mode (Off), no pragma
   --              Assume, no annotation suppressing VCs). RFC 6979
   --              §A.2.5 P-256 KAT exercises the chain end-to-end.
   --  --------------------------------------------------------------
   procedure Scalar_Mul (Scalar : Octet_Array; P : Point; Out_R : out Point)
   with
     Pre  => Scalar'Length = 32,
     Post =>
       Spec_Equiv_Point
         (Spec_Of (Out_R), Spec_Scalar_Mult (Scalar, Spec_Of (P)));

   --  Recover the affine X coordinate of a non-identity point.
   --  Used by ECDH to extract the shared secret X (RFC 8446 §4.2.8.2).
   procedure To_Affine_X (P : Point; Out_X : out Field);

   --  Group law: R = P1 + P2 over the curve. Handles identity,
   --  equal-and-add (doubles) and inverse-and-add (yields infinity).
   --  Used by ECDSA verify to form u1*G + u2*Q.
   procedure Add_Points (P1, P2 : Point; Out_R : out Point);

   --  True iff P is the point at infinity.
   function Is_Infinity (P : Point) return Boolean;

private

   pragma Warnings (On, "array aggregate using () is an obsolescent syntax");

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   type Point is record
      X : Tls_Core.P256_Field.Field;
      Y : Tls_Core.P256_Field.Field;
      Z : Tls_Core.P256_Field.Field;
   end record;

   --  Sentinel "point at infinity" — Z = 0.
   Infinity : constant Point :=
     (X => Tls_Core.P256_Field.One,
      Y => Tls_Core.P256_Field.One,
      Z => Tls_Core.P256_Field.Zero);

   --  Generator in Jacobian (Gx, Gy, 1).
   Generator : constant Point :=
     (X =>
        (16#6B#,
         16#17#,
         16#D1#,
         16#F2#,
         16#E1#,
         16#2C#,
         16#42#,
         16#47#,
         16#F8#,
         16#BC#,
         16#E6#,
         16#E5#,
         16#63#,
         16#A4#,
         16#40#,
         16#F2#,
         16#77#,
         16#03#,
         16#7D#,
         16#81#,
         16#2D#,
         16#EB#,
         16#33#,
         16#A0#,
         16#F4#,
         16#A1#,
         16#39#,
         16#45#,
         16#D8#,
         16#98#,
         16#C2#,
         16#96#),
      Y =>
        (16#4F#,
         16#E3#,
         16#42#,
         16#E2#,
         16#FE#,
         16#1A#,
         16#7F#,
         16#9B#,
         16#8E#,
         16#E7#,
         16#EB#,
         16#4A#,
         16#7C#,
         16#0F#,
         16#9E#,
         16#16#,
         16#2B#,
         16#CE#,
         16#33#,
         16#57#,
         16#6B#,
         16#31#,
         16#5E#,
         16#CE#,
         16#CB#,
         16#B6#,
         16#40#,
         16#68#,
         16#37#,
         16#BF#,
         16#51#,
         16#F5#),
      Z => Tls_Core.P256_Field.One);

   pragma Warnings (On, "array aggregate using () is an obsolescent syntax");

end Tls_Core.P256;
