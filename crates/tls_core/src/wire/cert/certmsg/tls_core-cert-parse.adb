separate (Tls_Core.Cert)
   procedure Parse
     (Der : Octet_Array;
      P   : out Parsed_Cert;
      OK  : out Boolean)
   is
      --  Outer Certificate SEQUENCE
      O_Tag    : Octet;
      O_VP     : Natural;
      O_VL     : Natural;
      O_Next   : Natural;
      O_OK     : Boolean;

      --  TBS SEQUENCE
      Tbs_Tag  : Octet;
      Tbs_VP   : Natural;
      Tbs_VL   : Natural;
      Tbs_Next : Natural;
      Tbs_OK   : Boolean;

      --  signatureAlgorithm SEQUENCE (outer)
      Sa_Tag   : Octet;
      Sa_VP    : Natural;
      Sa_VL    : Natural;
      Sa_Next  : Natural;
      Sa_OK    : Boolean;

      --  signatureValue BIT STRING
      Sv_Tag   : Octet;
      Sv_VP    : Natural;
      Sv_VL    : Natural;
      Sv_Next  : Natural;
      Sv_OK    : Boolean;

      Pos      : Natural;
      Step_OK  : Boolean;

      T        : Octet;
      VP, VL, Next_Pos : Natural;
   begin
      P := (Tbs_First    => 0, Tbs_Last     => 0,
            Spki_First   => 0, Spki_Last    => 0,
            Sig_Alg      => Unknown,
            Sig_First    => 0, Sig_Last     => 0,
            Issuer_First => 0, Issuer_Last  => 0,
            Subject_First => 0, Subject_Last => 0,
            San_Present  => False,
            San_First    => 0, San_Last     => 0);
      OK := False;

      if Der'Length < 16 then
         return;
      end if;

      ----------------------------------------------------------------
      --  Outer SEQUENCE
      ----------------------------------------------------------------
      Read_Tlv (Der, Der'First, O_Tag, O_VP, O_VL, O_Next, O_OK);
      if not O_OK or else O_Tag /= Tag_Sequence then
         return;
      end if;
      if O_Next /= Der'Last + 1 then
         return;
      end if;

      ----------------------------------------------------------------
      --  TBS SEQUENCE
      ----------------------------------------------------------------
      Read_Tlv (Der, O_VP, Tbs_Tag, Tbs_VP, Tbs_VL, Tbs_Next, Tbs_OK);
      if not Tbs_OK or else Tbs_Tag /= Tag_Sequence then
         return;
      end if;
      if Tbs_Next - 1 > Der'Last or else Tbs_Next - 1 < Der'First then
         return;
      end if;
      --  TBS must have at least 1 byte of header to be non-empty.
      --  If Tbs_VL = 0 the cert is malformed; reject.
      if Tbs_VL = 0 then
         return;
      end if;
      pragma Assert (O_VP <= Tbs_Next - 1);
      P.Tbs_First := O_VP;
      P.Tbs_Last  := Tbs_Next - 1;

      ----------------------------------------------------------------
      --  signatureAlgorithm SEQUENCE (must be the algorithm the
      --  parent used to sign the TBS)
      ----------------------------------------------------------------
      Read_Tlv (Der, Tbs_Next, Sa_Tag, Sa_VP, Sa_VL, Sa_Next, Sa_OK);
      if not Sa_OK or else Sa_Tag /= Tag_Sequence then
         return;
      end if;
      if Sa_VP > Der'Last then
         return;
      end if;
      --  Check OID inside the SEQUENCE body.
      if Equal_At (Der, Sa_VP, Oid_Ecdsa_Sha256_Tlv) then
         P.Sig_Alg := Ecdsa_With_Sha256;
      elsif Equal_At (Der, Sa_VP, Oid_Rsa_Pss_Tlv) then
         P.Sig_Alg := Rsa_Pss_Sha256;
      else
         P.Sig_Alg := Unknown;
      end if;

      ----------------------------------------------------------------
      --  signatureValue BIT STRING
      ----------------------------------------------------------------
      Read_Tlv (Der, Sa_Next, Sv_Tag, Sv_VP, Sv_VL, Sv_Next, Sv_OK);
      if not Sv_OK or else Sv_Tag /= Tag_Bit_String then
         return;
      end if;
      if Sv_Next /= Der'Last + 1 then
         return;  --  trailing bytes after signature
      end if;
      if Sv_VL < 1 or else Sv_VP > Der'Last then
         return;
      end if;
      if Der (Sv_VP) /= 0 then
         return;  --  unused-bits byte must be zero
      end if;
      --  Signature bytes are V_Pos+1 .. V_Pos+V_Len-1.
      if Sv_VL < 2 then
         return;
      end if;
      if Sv_VP + Sv_VL - 1 > Der'Last then
         return;
      end if;
      P.Sig_First := Sv_VP + 1;
      P.Sig_Last  := Sv_VP + Sv_VL - 1;

      ----------------------------------------------------------------
      --  Walk inside TBS: optional [0] version, serial, sigAlg-inner,
      --  issuer, validity, subject, SPKI, optional v3 extensions [3].
      ----------------------------------------------------------------
      Pos := Tbs_VP;

      --  Optional [0] EXPLICIT version
      if Pos <= P.Tbs_Last and then Der (Pos) = Tag_Context_0 then
         Read_Tlv (Der, Pos, T, VP, VL, Next_Pos, Step_OK);
         if not Step_OK or else Next_Pos > P.Tbs_Last + 1 then
            return;
         end if;
         Pos := Next_Pos;
      end if;

      --  serialNumber INTEGER
      Read_Tlv (Der, Pos, T, VP, VL, Next_Pos, Step_OK);
      if not Step_OK or else T /= Tag_Integer
        or else Next_Pos > P.Tbs_Last + 1
      then
         return;
      end if;
      Pos := Next_Pos;

      --  signature AlgorithmIdentifier (TBS-inner)
      Read_Tlv (Der, Pos, T, VP, VL, Next_Pos, Step_OK);
      if not Step_OK or else T /= Tag_Sequence
        or else Next_Pos > P.Tbs_Last + 1
      then
         return;
      end if;
      Pos := Next_Pos;

      --  issuer Name SEQUENCE
      Read_Tlv (Der, Pos, T, VP, VL, Next_Pos, Step_OK);
      if not Step_OK or else T /= Tag_Sequence
        or else Next_Pos > P.Tbs_Last + 1
      then
         return;
      end if;
      P.Issuer_First := Pos;
      P.Issuer_Last  := Next_Pos - 1;
      Pos := Next_Pos;

      --  validity SEQUENCE — skip
      Read_Tlv (Der, Pos, T, VP, VL, Next_Pos, Step_OK);
      if not Step_OK or else T /= Tag_Sequence
        or else Next_Pos > P.Tbs_Last + 1
      then
         return;
      end if;
      Pos := Next_Pos;

      --  subject Name SEQUENCE
      Read_Tlv (Der, Pos, T, VP, VL, Next_Pos, Step_OK);
      if not Step_OK or else T /= Tag_Sequence
        or else Next_Pos > P.Tbs_Last + 1
      then
         return;
      end if;
      P.Subject_First := Pos;
      P.Subject_Last  := Next_Pos - 1;
      Pos := Next_Pos;

      --  subjectPublicKeyInfo SEQUENCE
      Read_Tlv (Der, Pos, T, VP, VL, Next_Pos, Step_OK);
      if not Step_OK or else T /= Tag_Sequence
        or else Next_Pos > P.Tbs_Last + 1
      then
         return;
      end if;
      P.Spki_First := Pos;
      P.Spki_Last  := Next_Pos - 1;
      Pos := Next_Pos;

      --  Optional [3] EXPLICIT extensions
      if Pos <= P.Tbs_Last and then Der (Pos) = Tag_Context_3 then
         declare
            Found : Boolean;
            San_F : Natural;
            San_L : Natural;
         begin
            Find_SAN_Ext (Der, Pos, Found, San_F, San_L);
            if Found then
               pragma Assert (San_F in Der'Range);
               pragma Assert (San_L in Der'Range);
               pragma Assert (San_F <= San_L);
               P.San_Present := True;
               P.San_First := San_F;
               P.San_Last  := San_L;
            end if;
         end;
      end if;

      OK := True;
   end Parse;
