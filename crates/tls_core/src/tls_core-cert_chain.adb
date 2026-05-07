--  Tls_Core.Cert_Chain — body. Hand-written cert-chain walker.
--
--  Decomposes into:
--    Verify_Signed_TBS    — verify one cert's signature with parent's pub key
--    Parse_Ecdsa_Sig_Der  — pull (r, s) out of an ECDSA-Sig-Value SEQUENCE
--    Public_Key_From_Spki — wraps Tls_Core.X509_Spki.Decode +
--                           Decode_Rsa_Key as one shot
--
--  Termination: chain length is bounded by Max_Chain_Depth, trust
--  store by Max_Trust_Roots. Walker uses a counted FOR loop.

with Tls_Core.Bignum_2048;
with Tls_Core.Cert_Verify;
with Tls_Core.Ecdsa_P256;
with Tls_Core.Rsa_Pss;
with Tls_Core.X509_Spki;

package body Tls_Core.Cert_Chain
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use type Tls_Core.Octet;
   use type Tls_Core.X509_Spki.Key_Kind;
   use type Tls_Core.Cert.Signature_Alg;

   ---------------------------------------------------------------------
   --  Decode a DER ECDSA signature SEQUENCE { r INTEGER, s INTEGER }
   --  into two 32-byte big-endian P-256 scalars (left-pad with zeros
   --  if the INTEGER body is shorter, strip a leading 0x00 sign byte
   --  if the body is 33 bytes).
   --
   --  Sets OK := False if the SEQUENCE / INTEGERs are malformed or
   --  one of the components doesn't fit in 32 bytes.
   ---------------------------------------------------------------------
   procedure Parse_Ecdsa_Sig_Der
     (Sig : Octet_Array;
      R   : out Tls_Core.Ecdsa_P256.Component;
      S   : out Tls_Core.Ecdsa_P256.Component;
      OK  : out Boolean)
   with
     Pre  => Sig'First = 1
             and then Sig'Length in 8 .. 80
             and then Sig'Last < Integer'Last - 16,
     Post => True;

   procedure Parse_Ecdsa_Sig_Der
     (Sig : Octet_Array;
      R   : out Tls_Core.Ecdsa_P256.Component;
      S   : out Tls_Core.Ecdsa_P256.Component;
      OK  : out Boolean)
   is
      --  Inline a tiny DER walker — same shape as Tls_Core.Cert.Read_Tlv
      --  but bounded to <= 80 bytes so we don't need a long-form length
      --  parser path.
      procedure Read_Tlv_Small
        (Buf : Octet_Array;
         Pos : Natural;
         Tag : out Octet;
         VP  : out Natural;
         VL  : out Natural;
         Nx  : out Natural;
         Ok  : out Boolean)
      with
        Pre  => Buf'First = 1 and then Buf'Last < Integer'Last - 16,
        Post => (if Ok then VP in Buf'First .. Buf'Last + 1
                          and then VL <= Buf'Length
                          and then (if VL > 0 then VP in Buf'Range
                                              and then VP + VL - 1 in Buf'Range)
                          and then Nx = VP + VL);

      procedure Read_Tlv_Small
        (Buf : Octet_Array;
         Pos : Natural;
         Tag : out Octet;
         VP  : out Natural;
         VL  : out Natural;
         Nx  : out Natural;
         Ok  : out Boolean)
      is
         L0 : Octet;
         Hdr_End : Natural;
         Len : Natural := 0;
         N_Octets : Natural;
      begin
         Tag := 0; VP := Buf'First; VL := 0; Nx := Buf'First; Ok := False;
         if Pos < Buf'First or else Pos >= Buf'Last then
            return;
         end if;
         Tag := Buf (Pos);
         L0 := Buf (Pos + 1);
         if L0 < 16#80# then
            Len := Natural (L0);
            Hdr_End := Pos + 1;
         elsif L0 = 16#80# then
            return;
         else
            N_Octets := Natural (L0 and 16#7F#);
            if N_Octets = 0 or else N_Octets > 2 then
               return;
            end if;
            if Pos + 1 + N_Octets > Buf'Last then
               return;
            end if;
            Len := 0;
            for I in 1 .. N_Octets loop
               --  Before iter I, Len < 256**(I-1). Each step at most
               --  multiplies by 256 and adds < 256, so Len stays
               --  < 256**I. With N_Octets <= 2, Len < 65536 at exit.
               pragma Loop_Invariant (I in 1 .. 2);
               pragma Loop_Invariant
                 (if I = 1 then Len = 0 else Len < 256);
               Len := Len * 256 + Natural (Buf (Pos + 1 + I));
            end loop;
            Hdr_End := Pos + 1 + N_Octets;
         end if;
         if Len > Buf'Last - Hdr_End then
            return;
         end if;
         VP := Hdr_End + 1;
         VL := Len;
         Nx := Hdr_End + 1 + Len;
         Ok := True;
      end Read_Tlv_Small;

      Outer_Tag : Octet; Outer_VP, Outer_VL, Outer_Nx : Natural;
      Outer_OK : Boolean;
      R_Tag : Octet; R_VP, R_VL, R_Nx : Natural; R_OK : Boolean;
      S_Tag : Octet; S_VP, S_VL, S_Nx : Natural; S_OK : Boolean;
   begin
      R := (others => 0);
      S := (others => 0);
      OK := False;

      Read_Tlv_Small (Sig, Sig'First,
                      Outer_Tag, Outer_VP, Outer_VL, Outer_Nx, Outer_OK);
      if not Outer_OK or else Outer_Tag /= 16#30# then
         return;
      end if;
      if Outer_Nx /= Sig'Last + 1 then
         return;
      end if;

      Read_Tlv_Small (Sig, Outer_VP, R_Tag, R_VP, R_VL, R_Nx, R_OK);
      if not R_OK or else R_Tag /= 16#02# then
         return;
      end if;
      if R_Nx > Outer_VP + Outer_VL then
         return;
      end if;

      Read_Tlv_Small (Sig, R_Nx, S_Tag, S_VP, S_VL, S_Nx, S_OK);
      if not S_OK or else S_Tag /= 16#02# then
         return;
      end if;
      if S_Nx /= Outer_VP + Outer_VL then
         return;
      end if;

      --  Strip a leading 0x00 sign byte if present, then left-pad to 32 BE.
      declare
         RL : Natural := R_VL;
         RP : Natural := R_VP;
         SL : Natural := S_VL;
         SP : Natural := S_VP;
      begin
         if RL > 0 and then RP <= Sig'Last and then Sig (RP) = 16#00#
           and then RL > 1
         then
            RP := RP + 1;
            RL := RL - 1;
         end if;
         if SL > 0 and then SP <= Sig'Last and then Sig (SP) = 16#00#
           and then SL > 1
         then
            SP := SP + 1;
            SL := SL - 1;
         end if;
         if RL > 32 or else SL > 32 or else RL = 0 or else SL = 0 then
            return;
         end if;
         --  Right-aligned (BE) into 32-byte component.
         if RP + RL - 1 > Sig'Last or else SP + SL - 1 > Sig'Last then
            return;
         end if;
         for I in 0 .. RL - 1 loop
            R (32 - RL + 1 + I) := Sig (RP + I);
         end loop;
         for I in 0 .. SL - 1 loop
            S (32 - SL + 1 + I) := Sig (SP + I);
         end loop;
         OK := True;
      end;
   end Parse_Ecdsa_Sig_Der;

   ---------------------------------------------------------------------
   --  Verify_Signed_TBS — given a child cert's TBS bytes + its outer
   --  signature value + the signature algorithm enum, plus the parent
   --  cert's SPKI region, decide whether the child's signature is a
   --  valid signature by the parent's public key over the TBS.
   ---------------------------------------------------------------------
   procedure Verify_Signed_TBS
     (TBS_Bytes  : Octet_Array;
      Sig_Bytes  : Octet_Array;
      Sig_Alg    : Tls_Core.Cert.Signature_Alg;
      Spki_Buf   : Octet_Array;
      OK         : out Boolean)
   with
     Pre  => TBS_Bytes'First = 1
             and then TBS_Bytes'Length in 1 .. 16384
             and then TBS_Bytes'Last < Integer'Last - 256
             and then Sig_Bytes'First = 1
             and then Sig_Bytes'Length in 1 .. 512
             and then Sig_Bytes'Last < Integer'Last - 256
             and then Spki_Buf'First = 1
             and then Spki_Buf'Length >= 16
             and then Spki_Buf'Last < Integer'Last - 16,
     Post => True;

   procedure Verify_Signed_TBS
     (TBS_Bytes  : Octet_Array;
      Sig_Bytes  : Octet_Array;
      Sig_Alg    : Tls_Core.Cert.Signature_Alg;
      Spki_Buf   : Octet_Array;
      OK         : out Boolean)
   is
      use Tls_Core.Cert;
      Spki_OK   : Boolean;
      Kind      : Tls_Core.X509_Spki.Key_Kind;
      Key_F     : Natural;
      Key_L     : Natural;
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
               Pub : Tls_Core.Ecdsa_P256.Public_Key_Bytes := (others => 0);
               R, S : Tls_Core.Ecdsa_P256.Component;
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

         when Rsa_Pss_Sha256 =>
            if Kind /= Tls_Core.X509_Spki.Rsa then
               return;
            end if;
            --  Stage the SPKI body into a 1024-byte fixed buffer
            --  (largest plausible: 4096-bit RSA SPKI). SPARK rejects
            --  variable-bound subtype constraints, so we can't form
            --  an Octet_Array (1 .. Key_L - Key_F + 1) directly.
            declare
               Inner_Len : constant Natural := Key_L - Key_F + 1;
               Inner_Buf : Octet_Array (1 .. 1024) := (others => 0);
               Rsa_OK : Boolean;
               Mod_F, Mod_L, Exp_F, Exp_L : Natural;
               N : Tls_Core.Bignum_2048.Bigint := (others => 0);
               E : Tls_Core.Bignum_2048.Bigint := (others => 0);
               Sig_BE : Tls_Core.Bignum_2048.Bigint := (others => 0);
            begin
               if Inner_Len < 2 or else Inner_Len > 1024 then
                  return;
               end if;
               for I in 0 .. Inner_Len - 1 loop
                  Inner_Buf (1 + I) := Spki_Buf (Key_F + I);
               end loop;
               Tls_Core.X509_Spki.Decode_Rsa_Key
                 (Inner_Buf (1 .. Inner_Len),
                  Rsa_OK, Mod_F, Mod_L, Exp_F, Exp_L);
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
                     MP := MP + 1; ML := ML - 1;
                  end if;
                  if EL > 1 and then Inner_Buf (EP) = 16#00# then
                     EP := EP + 1; EL := EL - 1;
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
                    (N => N, E => E,
                     Message => TBS_Bytes,
                     Signature => Sig_BE,
                     OK => Vrf_OK);
                  OK := Vrf_OK;
               end;
            end;

         when Unknown =>
            return;
      end case;
   end Verify_Signed_TBS;

   ---------------------------------------------------------------------
   --  Validate_Chain
   ---------------------------------------------------------------------
   procedure Validate_Chain
     (All_Certs   : Octet_Array;
      Chain_In    : Chain;
      Trust       : Trust_Store;
      Result      : out Validation_Result;
      Leaf_Parsed : out Tls_Core.Cert.Parsed_Cert)
   is
      Parsed_Chain : array (1 .. Max_Chain_Depth) of Tls_Core.Cert.Parsed_Cert;
   begin
      Result := Bad_Cert_Format;
      Leaf_Parsed :=
        (Tbs_First    => 0, Tbs_Last     => 0,
         Spki_First   => 0, Spki_Last    => 0,
         Sig_Alg      => Tls_Core.Cert.Unknown,
         Sig_First    => 0, Sig_Last     => 0,
         Issuer_First => 0, Issuer_Last  => 0,
         Subject_First => 0, Subject_Last => 0,
         San_Present  => False,
         San_First    => 0, San_Last     => 0);

      if Chain_In.Count = 0 then
         return;
      end if;

      --  Step 1: parse every entry. Any malformed cert => Bad_Cert_Format.
      for I in 1 .. Chain_In.Count loop
         pragma Loop_Invariant
           (Chain_In.Count in 1 .. Max_Chain_Depth);
         pragma Loop_Invariant
           (for all J in 1 .. I - 1 =>
              Parsed_Chain (J).Tbs_First
                in Chain_In.Entries (J).First .. Chain_In.Entries (J).Last
              and then Parsed_Chain (J).Tbs_Last
                in Chain_In.Entries (J).First .. Chain_In.Entries (J).Last
              and then Parsed_Chain (J).Tbs_First
                <= Parsed_Chain (J).Tbs_Last
              and then Parsed_Chain (J).Sig_First
                in Chain_In.Entries (J).First .. Chain_In.Entries (J).Last
              and then Parsed_Chain (J).Sig_Last
                in Chain_In.Entries (J).First .. Chain_In.Entries (J).Last
              and then Parsed_Chain (J).Sig_First
                <= Parsed_Chain (J).Sig_Last
              and then Parsed_Chain (J).Spki_First
                in Chain_In.Entries (J).First .. Chain_In.Entries (J).Last
              and then Parsed_Chain (J).Spki_Last
                in Chain_In.Entries (J).First .. Chain_In.Entries (J).Last
              and then Parsed_Chain (J).Spki_First
                <= Parsed_Chain (J).Spki_Last);
         declare
            Ent : constant Chain_Entry := Chain_In.Entries (I);
            Slice_Len : constant Natural := Ent.Last - Ent.First + 1;
            Slice_Buf : Octet_Array (1 .. 16384) := (others => 0);
            P : Tls_Core.Cert.Parsed_Cert;
            P_OK : Boolean;
         begin
            if Slice_Len < 16 or else Slice_Len > 16384 then
               Result := Bad_Cert_Format;
               return;
            end if;
            for K in 0 .. Slice_Len - 1 loop
               Slice_Buf (1 + K) := All_Certs (Ent.First + K);
            end loop;
            Tls_Core.Cert.Parse (Slice_Buf (1 .. Slice_Len), P, P_OK);
            if not P_OK then
               Result := Bad_Cert_Format;
               return;
            end if;
            --  Translate the parsed indices from Slice's local frame
            --  (Slice'First = 1) back to All_Certs absolute frame.
            --  Cert.Parse Post says every index lies in 1 .. Slice_Len
            --  when OK; after the offset translation each index lies
            --  in Ent.First .. Ent.Last ⊆ All_Certs'Range.
            declare
               Off : constant Integer := Ent.First - 1;
            begin
               P.Tbs_First := P.Tbs_First + Off;
               P.Tbs_Last  := P.Tbs_Last  + Off;
               P.Spki_First := P.Spki_First + Off;
               P.Spki_Last  := P.Spki_Last  + Off;
               P.Sig_First := P.Sig_First + Off;
               P.Sig_Last  := P.Sig_Last  + Off;
               P.Issuer_First := P.Issuer_First + Off;
               P.Issuer_Last  := P.Issuer_Last  + Off;
               P.Subject_First := P.Subject_First + Off;
               P.Subject_Last  := P.Subject_Last  + Off;
               if P.San_Present then
                  P.San_First := P.San_First + Off;
                  P.San_Last  := P.San_Last  + Off;
               end if;
            end;
            Parsed_Chain (I) := P;
         end;
      end loop;
      Leaf_Parsed := Parsed_Chain (1);

      --  Step 2: verify intra-chain links. Each TBS / Sig / SPKI
      --  region is staged into a 1024-byte fixed buffer (~enough for
      --  4K-RSA SPKIs, ECDSA TBSes are <2K). The variable-bound
      --  slice pattern is rejected by SPARK flow analysis (subtype
      --  constraint with variable input), so we copy + slice with a
      --  static-sized buffer instead.
      if Chain_In.Count >= 2 then
         for I in 1 .. Chain_In.Count - 1 loop
            pragma Loop_Invariant
              (Chain_In.Count in 1 .. Max_Chain_Depth);
            declare
               Child  : constant Tls_Core.Cert.Parsed_Cert :=
                 Parsed_Chain (I);
               Parent : constant Tls_Core.Cert.Parsed_Cert :=
                 Parsed_Chain (I + 1);
               TBS_Buf  : Octet_Array (1 .. 16384) := (others => 0);
               Sig_Buf  : Octet_Array (1 .. 512) := (others => 0);
               Spki_Buf : Octet_Array (1 .. 1024) := (others => 0);
               TBS_Len  : constant Natural := Child.Tbs_Last - Child.Tbs_First + 1;
               Sig_Len  : constant Natural := Child.Sig_Last - Child.Sig_First + 1;
               Spki_Len : constant Natural := Parent.Spki_Last - Parent.Spki_First + 1;
               Link_OK : Boolean := False;
            begin
               if Child.Sig_Alg = Tls_Core.Cert.Unknown then
                  Result := Unsupported_Sig_Alg;
                  return;
               end if;
               if TBS_Len not in 1 .. 16384
                 or else Sig_Len not in 1 .. 512
                 or else Spki_Len not in 16 .. 1024
               then
                  Result := Bad_Cert_Format;
                  return;
               end if;
               for K in 0 .. TBS_Len - 1 loop
                  TBS_Buf (1 + K) := All_Certs (Child.Tbs_First + K);
               end loop;
               for K in 0 .. Sig_Len - 1 loop
                  Sig_Buf (1 + K) := All_Certs (Child.Sig_First + K);
               end loop;
               for K in 0 .. Spki_Len - 1 loop
                  Spki_Buf (1 + K) := All_Certs (Parent.Spki_First + K);
               end loop;
               Verify_Signed_TBS
                 (TBS_Bytes => TBS_Buf (1 .. TBS_Len),
                  Sig_Bytes => Sig_Buf (1 .. Sig_Len),
                  Sig_Alg   => Child.Sig_Alg,
                  Spki_Buf  => Spki_Buf (1 .. Spki_Len),
                  OK        => Link_OK);
               if not Link_OK then
                  Result := Bad_Signature;
                  return;
               end if;
            end;
         end loop;
      end if;

      --  Step 3: terminate against trust store. Top of chain is at
      --  index Chain_In.Count; verify its TBS signature against any
      --  trust-store root's SPKI.
      declare
         Top : constant Tls_Core.Cert.Parsed_Cert :=
           Parsed_Chain (Chain_In.Count);
         Top_TBS_Buf  : Octet_Array (1 .. 16384) := (others => 0);
         Top_Sig_Buf  : Octet_Array (1 .. 512) := (others => 0);
         Top_TBS_Len  : constant Natural :=
           Top.Tbs_Last - Top.Tbs_First + 1;
         Top_Sig_Len  : constant Natural :=
           Top.Sig_Last - Top.Sig_First + 1;
      begin
         if Top.Sig_Alg = Tls_Core.Cert.Unknown then
            Result := Unsupported_Sig_Alg;
            return;
         end if;
         if Top_TBS_Len not in 1 .. 16384
           or else Top_Sig_Len not in 1 .. 512
         then
            Result := Bad_Cert_Format;
            return;
         end if;
         for K in 0 .. Top_TBS_Len - 1 loop
            Top_TBS_Buf (1 + K) := All_Certs (Top.Tbs_First + K);
         end loop;
         for K in 0 .. Top_Sig_Len - 1 loop
            Top_Sig_Buf (1 + K) := All_Certs (Top.Sig_First + K);
         end loop;
         if Trust.Count = 0 then
            Result := Unknown_CA;
            return;
         end if;
         for J in 1 .. Trust.Count loop
            pragma Loop_Invariant (Trust.Count in 0 .. Max_Trust_Roots);
            declare
               Ent : constant Trust_Entry := Trust.Entries (J);
               Root_Buf : Octet_Array (1 .. 16384) := (others => 0);
               Root_Len : constant Natural := Ent.Last - Ent.First + 1;
               Root_P : Tls_Core.Cert.Parsed_Cert;
               Root_OK : Boolean;
            begin
               if Root_Len in 16 .. 16384 then
                  for K in 0 .. Root_Len - 1 loop
                     Root_Buf (1 + K) := All_Certs (Ent.First + K);
                  end loop;
                  Tls_Core.Cert.Parse (Root_Buf (1 .. Root_Len),
                                       Root_P, Root_OK);
                  if Root_OK then
                     declare
                        Spki_Buf : Octet_Array (1 .. 1024) := (others => 0);
                        Spki_Len : constant Natural :=
                          Root_P.Spki_Last - Root_P.Spki_First + 1;
                        Link_OK : Boolean := False;
                     begin
                        if Spki_Len in 16 .. 1024 then
                           for K in 0 .. Spki_Len - 1 loop
                              Spki_Buf (1 + K) :=
                                Root_Buf (Root_P.Spki_First + K);
                           end loop;
                           Verify_Signed_TBS
                             (TBS_Bytes => Top_TBS_Buf (1 .. Top_TBS_Len),
                              Sig_Bytes => Top_Sig_Buf (1 .. Top_Sig_Len),
                              Sig_Alg   => Top.Sig_Alg,
                              Spki_Buf  => Spki_Buf (1 .. Spki_Len),
                              OK        => Link_OK);
                           if Link_OK then
                              Result := OK_Validated;
                              return;
                           end if;
                        end if;
                     end;
                  end if;
               end if;
            end;
         end loop;
         Result := Unknown_CA;
      end;
   end Validate_Chain;

   ---------------------------------------------------------------------
   --  Verify_Cert_Verify — TLS 1.3 §4.4.3 CertificateVerify check.
   ---------------------------------------------------------------------
   procedure Verify_Cert_Verify
     (Leaf_Der       : Octet_Array;
      Leaf_Parsed    : Tls_Core.Cert.Parsed_Cert;
      Sig_Scheme     : Interfaces.Unsigned_16;
      Signed_Content : Octet_Array;
      Signature      : Octet_Array;
      OK             : out Boolean)
   is
      Spki_Buf : constant Octet_Array
        (1 .. Leaf_Parsed.Spki_Last - Leaf_Parsed.Spki_First + 1) :=
        Leaf_Der (Leaf_Parsed.Spki_First .. Leaf_Parsed.Spki_Last);

      Spki_OK : Boolean;
      Kind    : Tls_Core.X509_Spki.Key_Kind;
      Key_F   : Natural;
      Key_L   : Natural;
   begin
      OK := False;
      if Spki_Buf'Length < 16 then
         return;
      end if;
      Tls_Core.X509_Spki.Decode (Spki_Buf, Spki_OK, Kind, Key_F, Key_L);
      if not Spki_OK then
         return;
      end if;

      case Sig_Scheme is
         when Sig_Ecdsa_Secp256r1_Sha256 =>
            if Kind /= Tls_Core.X509_Spki.Ecdsa_P256 then
               return;
            end if;
            if Key_L - Key_F + 1 /= 65
              or else Spki_Buf (Key_F) /= 16#04#
            then
               return;
            end if;
            if Signature'Length not in 8 .. 80 then
               return;
            end if;
            declare
               Pub : Tls_Core.Ecdsa_P256.Public_Key_Bytes := (others => 0);
               R, S : Tls_Core.Ecdsa_P256.Component;
               Sig_OK : Boolean;
               Vrf_OK : Boolean;
            begin
               for I in 0 .. 64 loop
                  Pub (1 + I) := Spki_Buf (Key_F + I);
               end loop;
               Parse_Ecdsa_Sig_Der (Signature, R, S, Sig_OK);
               if not Sig_OK then
                  return;
               end if;
               Tls_Core.Ecdsa_P256.Verify
                 (Public_Key => Pub,
                  Message    => Signed_Content,
                  R          => R,
                  S          => S,
                  OK         => Vrf_OK);
               OK := Vrf_OK;
            end;

         when Sig_Rsa_Pss_Rsae_Sha256 =>
            if Kind /= Tls_Core.X509_Spki.Rsa then
               return;
            end if;
            declare
               Inner_Len : constant Natural := Key_L - Key_F + 1;
               Inner_Buf : Octet_Array (1 .. 1024) := (others => 0);
               Rsa_OK : Boolean;
               Mod_F, Mod_L, Exp_F, Exp_L : Natural;
               N : Tls_Core.Bignum_2048.Bigint := (others => 0);
               E : Tls_Core.Bignum_2048.Bigint := (others => 0);
               Sig_BE : Tls_Core.Bignum_2048.Bigint := (others => 0);
            begin
               if Inner_Len < 2 or else Inner_Len > 1024 then
                  return;
               end if;
               for I in 0 .. Inner_Len - 1 loop
                  Inner_Buf (1 + I) := Spki_Buf (Key_F + I);
               end loop;
               Tls_Core.X509_Spki.Decode_Rsa_Key
                 (Inner_Buf (1 .. Inner_Len),
                  Rsa_OK, Mod_F, Mod_L, Exp_F, Exp_L);
               if not Rsa_OK then
                  return;
               end if;
               declare
                  ML : Natural := Mod_L - Mod_F + 1;
                  MP : Natural := Mod_F;
                  EL : Natural := Exp_L - Exp_F + 1;
                  EP : Natural := Exp_F;
               begin
                  if ML > 1 and then Inner_Buf (MP) = 16#00# then
                     MP := MP + 1; ML := ML - 1;
                  end if;
                  if EL > 1 and then Inner_Buf (EP) = 16#00# then
                     EP := EP + 1; EL := EL - 1;
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
               if Signature'Length /= 256 then
                  return;
               end if;
               for I in 0 .. 255 loop
                  Sig_BE (1 + I) := Signature (Signature'First + I);
               end loop;
               declare
                  Vrf_OK : Boolean;
               begin
                  Tls_Core.Rsa_Pss.Verify_Sha256
                    (N => N, E => E,
                     Message => Signed_Content,
                     Signature => Sig_BE,
                     OK => Vrf_OK);
                  OK := Vrf_OK;
               end;
            end;

         when others =>
            OK := False;
      end case;
   end Verify_Cert_Verify;

   ---------------------------------------------------------------------
   --  Authenticate_Server — pipeline glue.
   ---------------------------------------------------------------------
   procedure Authenticate_Server
     (All_Certs       : Octet_Array;
      Chain_In        : Chain;
      Trust           : Trust_Store;
      Hostname        : Octet_Array;
      Sig_Scheme      : Interfaces.Unsigned_16;
      Sig_Body        : Octet_Array;
      Transcript_Hash : Octet_Array;
      Result          : out Validation_Result)
   is
      Leaf_Parsed : Tls_Core.Cert.Parsed_Cert;
      Chain_Result : Validation_Result;
   begin
      --  (a) Validate the chain.
      Validate_Chain
        (All_Certs   => All_Certs,
         Chain_In    => Chain_In,
         Trust       => Trust,
         Result      => Chain_Result,
         Leaf_Parsed => Leaf_Parsed);
      if Chain_Result /= OK_Validated then
         Result := Chain_Result;
         return;
      end if;

      --  (b) Optional SAN match. Stage the SAN body into a fixed
      --  1024-byte buffer (RFC 5280 doesn't fix an upper bound but
      --  sane real-world certs never exceed 1024 bytes of SAN body).
      if Hostname'Length > 0 then
         if not Leaf_Parsed.San_Present then
            Result := Bad_Signature;
            return;
         end if;
         if Leaf_Parsed.San_First in All_Certs'Range
           and then Leaf_Parsed.San_Last in All_Certs'Range
           and then Leaf_Parsed.San_First <= Leaf_Parsed.San_Last
         then
            declare
               San_Buf  : Octet_Array (1 .. 1024) := (others => 0);
               San_Len  : constant Natural :=
                 Leaf_Parsed.San_Last - Leaf_Parsed.San_First + 1;
            begin
               if San_Len = 0 or else San_Len > 1024 then
                  Result := Bad_Cert_Format;
                  return;
               end if;
               for K in 0 .. San_Len - 1 loop
                  San_Buf (1 + K) :=
                    All_Certs (Leaf_Parsed.San_First + K);
               end loop;
               if not Tls_Core.Cert.Match_DNS_SAN
                        (San_Buf (1 .. San_Len), Hostname)
               then
                  Result := Bad_Signature;
                  return;
               end if;
            end;
         else
            Result := Bad_Cert_Format;
            return;
         end if;
      end if;

      --  (c) CertificateVerify signature. Stage the leaf DER into a
      --  16K fixed buffer the same way Validate_Chain does, then
      --  re-parse so Verify_Cert_Verify gets indices local to that
      --  buffer's coordinate frame (Buf'First = 1).
      declare
         Signed_Buf : Octet_Array (1 .. 64 + 33 + 1 + 64);
         Signed_Last : Natural;

         Leaf_Ent : constant Chain_Entry := Chain_In.Entries (1);
         Leaf_Buf : Octet_Array (1 .. 16384) := (others => 0);
         Leaf_Len : constant Natural :=
           Leaf_Ent.Last - Leaf_Ent.First + 1;

         Leaf_P_Local : Tls_Core.Cert.Parsed_Cert;
         Leaf_OK : Boolean;

         CV_OK : Boolean;
      begin
         if Transcript_Hash'Length not in 1 .. 64 then
            Result := Bad_Signature;
            return;
         end if;
         if Leaf_Len < 16 or else Leaf_Len > 16384 then
            Result := Bad_Cert_Format;
            return;
         end if;
         for K in 0 .. Leaf_Len - 1 loop
            Leaf_Buf (1 + K) := All_Certs (Leaf_Ent.First + K);
         end loop;

         Tls_Core.Cert_Verify.Build_Signed_Content
           (Side            => Tls_Core.Cert_Verify.Server,
            Transcript_Hash => Transcript_Hash,
            Out_Buf         => Signed_Buf,
            Out_Last        => Signed_Last);

         Tls_Core.Cert.Parse (Leaf_Buf (1 .. Leaf_Len),
                              Leaf_P_Local, Leaf_OK);
         if not Leaf_OK then
            Result := Bad_Cert_Format;
            return;
         end if;

         if Sig_Body'Length not in 1 .. 1024 then
            Result := Bad_Signature;
            return;
         end if;

         Verify_Cert_Verify
           (Leaf_Der       => Leaf_Buf (1 .. Leaf_Len),
            Leaf_Parsed    => Leaf_P_Local,
            Sig_Scheme     => Sig_Scheme,
            Signed_Content => Signed_Buf (1 .. Signed_Last),
            Signature      => Sig_Body,
            OK             => CV_OK);
         if CV_OK then
            Result := OK_Validated;
         else
            Result := Bad_Signature;
         end if;
      end;
   end Authenticate_Server;

end Tls_Core.Cert_Chain;
