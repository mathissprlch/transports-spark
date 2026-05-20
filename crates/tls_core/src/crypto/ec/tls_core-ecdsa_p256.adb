with Tls_Core.Hmac_Sha256;
with Tls_Core.Sha256;
with Tls_Core.P256;
with Tls_Core.P256_Field;
with Tls_Core.P256_Order;

package body Tls_Core.Ecdsa_P256
  with SPARK_Mode
is

   use type Tls_Core.Octet;


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
      E_Bytes  : Component := [others => 0];
      E_Mod    : Component;
      W        : Component;
      U1       : Component;
      U2       : Component;

      Q       : Tls_Core.P256.Point;
      U1_G    : Tls_Core.P256.Point;
      U2_Q    : Tls_Core.P256.Point;
      Sum     : Tls_Core.P256.Point;
      Decoded : Boolean;

      X_Field : Tls_Core.P256_Field.Field;
      X_Bytes : Component := [others => 0];
      X_Mod_N : Component;
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
      E_Bytes  : Component := [others => 0];
      E_Mod    : Component;

      KG      : Tls_Core.P256.Point;
      X_Field : Tls_Core.P256_Field.Field;
      X_Bytes : Component := [others => 0];
      R_Mod   : Component;

      K_Inv  : Component;
      D_R    : Component;
      E_Plus : Component;
      S_Mod  : Component;
   begin
      Out_R := [others => 0];
      Out_S := [others => 0];
      OK := False;

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
      OK := True;

   end Sign;

   ---------------------------------------------------------------------
   --  Derive_K_Rfc6979 — RFC 6979 §3.2 deterministic K for P-256/SHA-256.
   ---------------------------------------------------------------------

   procedure Derive_K_Rfc6979
     (Private_Key : Component;
      Message     : Octet_Array;
      Out_K       : out Component;
      OK          : out Boolean)
   is
      --  P-256 group order n in big-endian (FIPS 186-4 §D.1.2.3).
      N_BE : constant Component :=
        [16#FF#,
         16#FF#,
         16#FF#,
         16#FF#,
         16#00#,
         16#00#,
         16#00#,
         16#00#,
         16#FF#,
         16#FF#,
         16#FF#,
         16#FF#,
         16#FF#,
         16#FF#,
         16#FF#,
         16#FF#,
         16#BC#,
         16#E6#,
         16#FA#,
         16#AD#,
         16#A7#,
         16#17#,
         16#9E#,
         16#84#,
         16#F3#,
         16#B9#,
         16#CA#,
         16#C2#,
         16#FC#,
         16#63#,
         16#25#,
         16#51#];

      function Less_Than (A, B : Component) return Boolean is
      begin
         for I in 1 .. 32 loop
            if A (I) < B (I) then
               return True;
            elsif A (I) > B (I) then
               return False;
            end if;
         end loop;
         return False;
      end Less_Than;

      function Is_Zero (A : Component) return Boolean is
      begin
         for I in 1 .. 32 loop
            if A (I) /= 0 then
               return False;
            end if;
         end loop;
         return True;
      end Is_Zero;

      --  In-place reduction A := A mod n. Used for bits2octets(h1):
      --  since |h1| = 256 bits and n > 2^255, at most one subtraction
      --  is required.
      procedure Reduce_Mod_N (A : in out Component) is
         Borrow : Integer := 0;
         Diff   : Integer;
      begin
         if not Less_Than (A, N_BE) then
            for I in reverse 1 .. 32 loop
               pragma Loop_Invariant (Borrow in 0 .. 1);
               Diff := Integer (A (I)) - Integer (N_BE (I)) - Borrow;
               if Diff < 0 then
                  Diff := Diff + 256;
                  Borrow := 1;
               else
                  Borrow := 0;
               end if;
               A (I) := Octet (Diff);
            end loop;
         end if;
      end Reduce_Mod_N;

      H1      : Tls_Core.Sha256.Digest;
      H1_Modq : Component;
      X_Bytes : constant Component := Private_Key;

      V       : Component := [others => 16#01#];
      K       : Component := [others => 16#00#];
      Big_Buf : Octet_Array (1 .. 1 + 32 + 32 + 32) := [others => 0];
      New_V   : Tls_Core.Hmac_Sha256.Tag;
      New_K   : Tls_Core.Hmac_Sha256.Tag;

      Iter : Natural := 0;
   begin
      Out_K := [others => 0];
      OK := False;

      --  Step 1: h1 = SHA-256 (m); reduce mod n.
      Tls_Core.Sha256.Hash (Message, H1);
      H1_Modq := H1;
      Reduce_Mod_N (H1_Modq);

      --  Steps 4–7: initial K/V update.
      Big_Buf (1 .. 32) := V;
      Big_Buf (33) := 16#00#;
      Big_Buf (34 .. 65) := X_Bytes;
      Big_Buf (66 .. 97) := H1_Modq;
      Tls_Core.Hmac_Sha256.Compute (K, Big_Buf, New_K);
      K := New_K;
      Tls_Core.Hmac_Sha256.Compute (K, V, New_V);
      V := New_V;
      Big_Buf (1 .. 32) := V;
      Big_Buf (33) := 16#01#;
      Big_Buf (34 .. 65) := X_Bytes;
      Big_Buf (66 .. 97) := H1_Modq;
      Tls_Core.Hmac_Sha256.Compute (K, Big_Buf, New_K);
      K := New_K;
      Tls_Core.Hmac_Sha256.Compute (K, V, New_V);
      V := New_V;

      --  Step 8: rejection-sample loop. For SHA-256/P-256 the inner
      --  T-build loop runs once because holen = 32 and qlen/8 = 32.
      while Iter < 256 loop
         pragma Loop_Invariant (Iter in 0 .. 255);
         Tls_Core.Hmac_Sha256.Compute (K, V, New_V);
         V := New_V;
         if not Is_Zero (V) and then Less_Than (V, N_BE) then
            Out_K := V;
            OK := True;
            return;
         end if;
         --  Reject: K := HMAC_K (V || 0x00); V := HMAC_K (V).
         Big_Buf (1 .. 32) := V;
         Big_Buf (33) := 16#00#;
         Tls_Core.Hmac_Sha256.Compute (K, Big_Buf (1 .. 33), New_K);
         K := New_K;
         Tls_Core.Hmac_Sha256.Compute (K, V, New_V);
         V := New_V;
         Iter := Iter + 1;
      end loop;
   end Derive_K_Rfc6979;

end Tls_Core.Ecdsa_P256;
