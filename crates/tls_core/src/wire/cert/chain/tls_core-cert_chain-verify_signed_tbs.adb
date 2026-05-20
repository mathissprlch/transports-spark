separate (Tls_Core.Cert_Chain)
procedure Verify_Signed_TBS
  (TBS_Bytes : Octet_Array;
   Sig_Bytes : Octet_Array;
   Sig_Alg   : Tls_Core.Cert.Signature_Alg;
   Spki_Buf  : Octet_Array;
   OK        : out Boolean)
is
   use Tls_Core.Cert;
   Spki_OK : Boolean;
   Kind    : Tls_Core.X509_Spki.Key_Kind;
   Key_F   : Natural;
   Key_L   : Natural;
begin
   OK := False;

   Tls_Core.X509_Spki.Decode (Spki_Buf, Spki_OK, Kind, Key_F, Key_L);
   if not Spki_OK then
      return;
   end if;

   case Sig_Alg is
      when Ecdsa_With_Sha256 =>
         if Kind /= Tls_Core.X509_Spki.Ecdsa_P256 then
            return;
         end if;
         --  Issuer's SPKI yields a 65-byte 04||X||Y SEC1 point.
         if Key_L - Key_F + 1 /= 65 then
            return;
         end if;
         if Spki_Buf (Key_F) /= 16#04# then
            return;
         end if;
         declare
            Pub    : Tls_Core.Ecdsa_P256.Public_Key_Bytes := [others => 0];
            R, S   : Tls_Core.Ecdsa_P256.Component;
            Sig_OK : Boolean;
            Vrf_OK : Boolean;
         begin
            for I in 0 .. 64 loop
               Pub (1 + I) := Spki_Buf (Key_F + I);
            end loop;
            if Sig_Bytes'Length not in 8 .. 80 then
               return;
            end if;
            Parse_Ecdsa_Sig_Der (Sig_Bytes, R, S, Sig_OK);
            if not Sig_OK then
               return;
            end if;
            Tls_Core.Ecdsa_P256.Verify
              (Public_Key => Pub,
               Message    => TBS_Bytes,
               R          => R,
               S          => S,
               OK         => Vrf_OK);
            OK := Vrf_OK;
         end;

      when Rsa_Pss_Sha256    =>
         if Kind /= Tls_Core.X509_Spki.Rsa then
            return;
         end if;
         --  Stage the SPKI body into a 1024-byte fixed buffer
         --  (largest plausible: 4096-bit RSA SPKI). SPARK rejects
         --  variable-bound subtype constraints, so we can't form
         --  an Octet_Array (1 .. Key_L - Key_F + 1) directly.
         declare
            Inner_Len                  : constant Natural := Key_L - Key_F + 1;
            Inner_Buf                  : Octet_Array (1 .. 1024) :=
              [others => 0];
            Rsa_OK                     : Boolean;
            Mod_F, Mod_L, Exp_F, Exp_L : Natural;
            N                          : Tls_Core.Bignum_2048.Bigint :=
              [others => 0];
            E                          : Tls_Core.Bignum_2048.Bigint :=
              [others => 0];
            Sig_BE                     : Tls_Core.Bignum_2048.Bigint :=
              [others => 0];
         begin
            if Inner_Len < 2 or else Inner_Len > 1024 then
               return;
            end if;
            for I in 0 .. Inner_Len - 1 loop
               Inner_Buf (1 + I) := Spki_Buf (Key_F + I);
            end loop;
            Tls_Core.X509_Spki.Decode_Rsa_Key
              (Inner_Buf (1 .. Inner_Len), Rsa_OK, Mod_F, Mod_L, Exp_F, Exp_L);
            if not Rsa_OK then
               return;
            end if;
            --  Strip leading 0x00 sign byte from modulus / exponent
            --  if present; right-align into 256-byte BE buffer.
            declare
               ML : Natural := Mod_L - Mod_F + 1;
               MP : Natural := Mod_F;
               EL : Natural := Exp_L - Exp_F + 1;
               EP : Natural := Exp_F;
            begin
               if ML > 1 and then Inner_Buf (MP) = 16#00# then
                  MP := MP + 1;
                  ML := ML - 1;
               end if;
               if EL > 1 and then Inner_Buf (EP) = 16#00# then
                  EP := EP + 1;
                  EL := EL - 1;
               end if;
               if ML > 256 or else EL > 256 or else ML = 0 or else EL = 0 then
                  return;
               end if;
               for I in 0 .. ML - 1 loop
                  N (256 - ML + 1 + I) := Inner_Buf (MP + I);
               end loop;
               for I in 0 .. EL - 1 loop
                  E (256 - EL + 1 + I) := Inner_Buf (EP + I);
               end loop;
            end;
            --  Signature must be exactly 256 bytes for RSA-2048.
            if Sig_Bytes'Length /= 256 then
               return;
            end if;
            for I in 0 .. 255 loop
               Sig_BE (1 + I) := Sig_Bytes (Sig_Bytes'First + I);
            end loop;
            declare
               Vrf_OK : Boolean;
            begin
               Tls_Core.Rsa_Pss.Verify_Sha256
                 (N         => N,
                  E         => E,
                  Message   => TBS_Bytes,
                  Signature => Sig_BE,
                  OK        => Vrf_OK);
               OK := Vrf_OK;
            end;
         end;

      when Unknown           =>
         return;
   end case;
end Verify_Signed_TBS;
