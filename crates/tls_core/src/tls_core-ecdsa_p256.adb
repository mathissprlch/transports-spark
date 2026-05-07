with Tls_Core.Sha256;
with Tls_Core.P256;
with Tls_Core.P256_Field;
with Tls_Core.P256_Order;

package body Tls_Core.Ecdsa_P256
with SPARK_Mode
is

   use type Tls_Core.Octet;

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   ---------------------------------------------------------------------
   --  Verify — FIPS 186-4 §6.4.2.
   ---------------------------------------------------------------------

   procedure Verify
     (Public_Key : Public_Key_Bytes;
      Message    : Octet_Array;
      R, S       : Component;
      OK         : out Boolean)
   is
      E_Digest : Tls_Core.Sha256.Digest;
      E_Bytes  : Component := (others => 0);
      E_Mod    : Component;
      W        : Component;
      U1       : Component;
      U2       : Component;

      Q        : Tls_Core.P256.Point;
      U1_G     : Tls_Core.P256.Point;
      U2_Q     : Tls_Core.P256.Point;
      Sum      : Tls_Core.P256.Point;
      Decoded  : Boolean;

      X_Field  : Tls_Core.P256_Field.Field;
      X_Bytes  : Component := (others => 0);
      X_Mod_N  : Component;
   begin
      OK := False;

      --  (1) Range checks: 1 <= r,s <= n-1.
      if not Tls_Core.P256_Order.In_Range (R)
        or else not Tls_Core.P256_Order.In_Range (S)
      then
         return;
      end if;

      --  Decode and validate the public key Q (membership check
      --  inside Decode_Uncompressed). Q must not be infinity (the
      --  decoder yields OK=False for a malformed point, but a valid
      --  affine pair is never infinity by construction).
      Tls_Core.P256.Decode_Uncompressed (Public_Key, Q, Decoded);
      if not Decoded then
         return;
      end if;

      --  (2) e = SHA-256 (M); take the 32 digest bytes as a
      --      big-endian 256-bit integer (no truncation needed —
      --      SHA-256 already gives 256 bits, matching n's bit length).
      Tls_Core.Sha256.Hash (Message, E_Digest);
      for I in 0 .. 31 loop
         E_Bytes (1 + I) := E_Digest (1 + I);
      end loop;
      Tls_Core.P256_Order.Reduce (E_Bytes, E_Mod);

      --  (3) w = s^-1 mod n
      Tls_Core.P256_Order.Invert (S, W);

      --  (4) u1 = e * w mod n
      Tls_Core.P256_Order.Mul (E_Mod, W, U1);

      --  (5) u2 = r * w mod n
      Tls_Core.P256_Order.Mul (R, W, U2);

      --  (6) Sum = u1 * G + u2 * Q. Reject if infinity.
      Tls_Core.P256.Scalar_Mul (U1, Tls_Core.P256.Generator, U1_G);
      Tls_Core.P256.Scalar_Mul (U2, Q, U2_Q);
      Tls_Core.P256.Add_Points (U1_G, U2_Q, Sum);
      if Tls_Core.P256.Is_Infinity (Sum) then
         return;
      end if;

      --  (7) x1 = affine X (Sum); valid iff (x1 mod n) == r.
      Tls_Core.P256.To_Affine_X (Sum, X_Field);
      for I in 0 .. 31 loop
         X_Bytes (1 + I) := X_Field (1 + I);
      end loop;
      Tls_Core.P256_Order.Reduce (X_Bytes, X_Mod_N);

      OK := True;
      for I in 1 .. 32 loop
         if X_Mod_N (I) /= R (I) then
            OK := False;
            exit;
         end if;
      end loop;

   end Verify;

   ---------------------------------------------------------------------
   --  Sign — FIPS 186-4 §6.4.1, with caller-supplied per-signature K.
   ---------------------------------------------------------------------

   procedure Sign
     (Private_Key : Component;
      Message     : Octet_Array;
      K           : Component;
      Out_R       : out Component;
      Out_S       : out Component;
      OK          : out Boolean)
   is
      E_Digest : Tls_Core.Sha256.Digest;
      E_Bytes  : Component := (others => 0);
      E_Mod    : Component;

      KG       : Tls_Core.P256.Point;
      X_Field  : Tls_Core.P256_Field.Field;
      X_Bytes  : Component := (others => 0);
      R_Mod    : Component;

      K_Inv    : Component;
      D_R      : Component;
      E_Plus   : Component;
      S_Mod    : Component;
   begin
      Out_R := (others => 0);
      Out_S := (others => 0);
      OK    := False;

      if not Tls_Core.P256_Order.In_Range (K) then
         return;
      end if;
      if not Tls_Core.P256_Order.In_Range (Private_Key) then
         return;
      end if;

      --  e = SHA-256 (M) reduced mod n.
      Tls_Core.Sha256.Hash (Message, E_Digest);
      for I in 0 .. 31 loop
         E_Bytes (1 + I) := E_Digest (1 + I);
      end loop;
      Tls_Core.P256_Order.Reduce (E_Bytes, E_Mod);

      --  R = (k*G).x mod n. Reject r = 0.
      Tls_Core.P256.Scalar_Mul (K, Tls_Core.P256.Generator, KG);
      if Tls_Core.P256.Is_Infinity (KG) then
         return;
      end if;
      Tls_Core.P256.To_Affine_X (KG, X_Field);
      for I in 0 .. 31 loop
         X_Bytes (1 + I) := X_Field (1 + I);
      end loop;
      Tls_Core.P256_Order.Reduce (X_Bytes, R_Mod);
      if Tls_Core.P256_Order.Is_Zero (R_Mod) then
         return;
      end if;

      --  S = k^-1 (e + d*r) mod n. Reject s = 0.
      Tls_Core.P256_Order.Invert (K, K_Inv);
      Tls_Core.P256_Order.Mul (Private_Key, R_Mod, D_R);
      Tls_Core.P256_Order.Add (E_Mod, D_R, E_Plus);
      Tls_Core.P256_Order.Mul (K_Inv, E_Plus, S_Mod);
      if Tls_Core.P256_Order.Is_Zero (S_Mod) then
         return;
      end if;

      Out_R := R_Mod;
      Out_S := S_Mod;
      OK    := True;

   end Sign;

end Tls_Core.Ecdsa_P256;
