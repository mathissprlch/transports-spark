separate (Tls_Core.X509)
   procedure Parse_Ed25519_Cert
     (Der        : Octet_Array;
      Tbs_First  : out Natural;
      Tbs_Last   : out Natural;
      Pub_Key    : out Public_Key;
      Sig        : out Signature;
      OK         : out Boolean)
   is
      --  Outer Certificate SEQUENCE.
      Outer_Tag    : Octet;
      Outer_V_Pos  : Natural;
      Outer_V_Len  : Natural;
      Outer_Next   : Natural;
      Outer_OK     : Boolean;

      --  TBS SEQUENCE.
      Tbs_Tag      : Octet;
      Tbs_V_Pos    : Natural;
      Tbs_V_Len    : Natural;
      Tbs_Next     : Natural;
      Tbs_OK       : Boolean;
      Tbs_Tlv_Pos  : Natural;  --  Tag position of the TBS TLV.

      --  signatureAlgorithm + signatureValue cursors.
      Pos          : Natural;
      Step_OK      : Boolean;

      --  Generic TLV scratch.
      T            : Octet;
      V_Pos        : Natural;
      V_Len        : Natural;
      Next         : Natural;
   begin
      Tbs_First := 0;
      Tbs_Last  := 0;
      Pub_Key   := (others => 0);
      Sig       := (others => 0);
      OK        := False;

      if Der'Length < 16 then
         return;
      end if;

      --  -------- Outer Certificate SEQUENCE --------
      Read_Tlv (Der, Der'First,
                Outer_Tag, Outer_V_Pos, Outer_V_Len, Outer_Next, Outer_OK);
      if not Outer_OK or else Outer_Tag /= Tag_Sequence then
         return;
      end if;
      --  The outer TLV must end exactly at Der'Last; trailing bytes
      --  are not allowed for our use.
      if Outer_Next /= Der'Last + 1 then
         return;
      end if;

      --  -------- tbsCertificate SEQUENCE --------
      Tbs_Tlv_Pos := Outer_V_Pos;
      Read_Tlv (Der, Tbs_Tlv_Pos,
                Tbs_Tag, Tbs_V_Pos, Tbs_V_Len, Tbs_Next, Tbs_OK);
      if not Tbs_OK or else Tbs_Tag /= Tag_Sequence then
         return;
      end if;
      --  TBS bytes: from its tag through end-of-value, inclusive.
      Tbs_First := Tbs_Tlv_Pos;
      Tbs_Last  := Tbs_Next - 1;
      if Tbs_First < Der'First or else Tbs_Last > Der'Last then
         return;
      end if;

      --  -------- signatureAlgorithm: must be exactly Ed25519 --------
      Pos := Tbs_Next;
      Read_Tlv (Der, Pos, T, V_Pos, V_Len, Next, Step_OK);
      if not Step_OK or else T /= Tag_Sequence then
         return;
      end if;
      --  The whole TLV (tag+len+value) for Ed25519 AlgorithmIdentifier
      --  is the 7-byte canonical form 30 05 06 03 2B 65 70.
      if Next - Pos /= Alg_Id_Ed25519'Length
        or else not Equal_At (Der, Pos, Alg_Id_Ed25519)
      then
         return;
      end if;

      --  -------- signatureValue BIT STRING --------
      Pos := Next;
      Read_Tlv (Der, Pos, T, V_Pos, V_Len, Next, Step_OK);
      if not Step_OK or else T /= Tag_Bit_String then
         return;
      end if;
      --  Ed25519 signature: 1 unused-bits byte (0) + 64 bytes.
      if V_Len /= 1 + 64
        or else Der (V_Pos) /= 0
      then
         return;
      end if;
      for I in 1 .. 64 loop
         Sig (I) := Der (V_Pos + I);
      end loop;
      --  signatureValue must be the final TLV.
      if Next /= Der'Last + 1 then
         return;
      end if;

      --  -------- Walk inside TBS to locate SPKI --------
      --
      --  TBSCertificate ::= SEQUENCE {
      --     [0] EXPLICIT Version DEFAULT v1,    -- often 0xA0
      --     serialNumber       INTEGER,
      --     signature          AlgorithmIdentifier,
      --     issuer             Name,
      --     validity           Validity,
      --     subject            Name,
      --     subjectPublicKeyInfo  SubjectPublicKeyInfo,
      --     ...optional [1]/[2]/[3] extensions... }
      --
      --  We skip the first six elements, allowing the [0] version
      --  tag to be present or absent, then expect SPKI.
      Pos := Tbs_V_Pos;

      --  Optional [0] EXPLICIT version.
      if Pos <= Tbs_Last and then Der (Pos) = Tag_Context_0 then
         Skip_Tlv (Der, Pos, Pos, Step_OK);
         if not Step_OK or else Pos > Tbs_Last + 1 then
            return;
         end if;
      end if;

      --  serialNumber, signature alg, issuer, validity, subject.
      for K in 1 .. 5 loop
         Skip_Tlv (Der, Pos, Pos, Step_OK);
         if not Step_OK or else Pos > Tbs_Last + 1 then
            return;
         end if;
      end loop;

      --  -------- subjectPublicKeyInfo SEQUENCE --------
      declare
         Spki_Tag : Octet;
         Spki_VP  : Natural;
         Spki_VL  : Natural;
         Spki_Nx  : Natural;
         Spki_OK  : Boolean;

         Inner_Pos  : Natural;
         Alg_T      : Octet;
         Alg_VP     : Natural;
         Alg_VL     : Natural;
         Alg_Nx     : Natural;
         Alg_OK     : Boolean;

         Bs_T       : Octet;
         Bs_VP      : Natural;
         Bs_VL      : Natural;
         Bs_Nx      : Natural;
         Bs_OK      : Boolean;
      begin
         Read_Tlv (Der, Pos,
                   Spki_Tag, Spki_VP, Spki_VL, Spki_Nx, Spki_OK);
         if not Spki_OK or else Spki_Tag /= Tag_Sequence then
            return;
         end if;
         if Spki_Nx - 1 > Tbs_Last then
            return;
         end if;

         --  algorithm AlgorithmIdentifier — must be Ed25519.
         Inner_Pos := Spki_VP;
         Read_Tlv (Der, Inner_Pos,
                   Alg_T, Alg_VP, Alg_VL, Alg_Nx, Alg_OK);
         if not Alg_OK or else Alg_T /= Tag_Sequence then
            return;
         end if;
         if Alg_Nx - Inner_Pos /= Alg_Id_Ed25519'Length
           or else not Equal_At (Der, Inner_Pos, Alg_Id_Ed25519)
         then
            return;
         end if;

         --  subjectPublicKey BIT STRING — must be 1 unused-bits byte
         --  (0) + 32 bytes of public key.
         Read_Tlv (Der, Alg_Nx,
                   Bs_T, Bs_VP, Bs_VL, Bs_Nx, Bs_OK);
         if not Bs_OK or else Bs_T /= Tag_Bit_String then
            return;
         end if;
         if Bs_VL /= 1 + 32
           or else Der (Bs_VP) /= 0
         then
            return;
         end if;
         if Bs_Nx /= Spki_Nx then
            --  BIT STRING didn't fill the SPKI envelope exactly.
            return;
         end if;
         for I in 1 .. 32 loop
            Pub_Key (I) := Der (Bs_VP + I);
         end loop;
      end;

      OK := True;
   end Parse_Ed25519_Cert;
