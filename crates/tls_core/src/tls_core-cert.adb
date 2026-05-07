--  Tls_Core.Cert — body. Pure-Ada SPARK DER walker for X.509 v3.
--
--  Same Read_Tlv shape as Tls_Core.X509: a tag + length parser that
--  returns absolute indices and a "next position" cursor. We add
--  inner walkers to find the SubjectAltName extension.
--
--  Lookup: RFC 5280 §4.1 + RFC 5912 OIDs:
--    ecdsa-with-SHA256       30 0A 06 08 2A 86 48 CE 3D 04 03 02
--    rsassaPss               30 ?? 06 09 2A 86 48 86 F7 0D 01 01 0A ...
--    id-ce-subjectAltName    06 03 55 1D 11

package body Tls_Core.Cert
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use type Tls_Core.Octet;

   --  ASN.1 DER tag bytes we care about.
   Tag_Sequence    : constant Octet := 16#30#;
   Tag_Bit_String  : constant Octet := 16#03#;
   Tag_Octet_Str   : constant Octet := 16#04#;
   Tag_Integer     : constant Octet := 16#02#;
   Tag_Oid         : constant Octet := 16#06#;
   Tag_Boolean     : constant Octet := 16#01#;
   Tag_Context_0   : constant Octet := 16#A0#;
   Tag_Context_3   : constant Octet := 16#A3#;
   Tag_Dns_Name    : constant Octet := 16#82#;  --  GeneralName [2] IMPLICIT

   --  Algorithm OIDs we recognise as the OUTER signature algorithm.
   --
   --  ecdsa-with-SHA256: 1.2.840.10045.4.3.2
   --      OID-only TLV: 06 08 2A 86 48 CE 3D 04 03 02      (10 bytes)
   Oid_Ecdsa_Sha256_Tlv : constant Octet_Array (1 .. 10) :=
     (16#06#, 16#08#,
      16#2A#, 16#86#, 16#48#, 16#CE#, 16#3D#, 16#04#, 16#03#, 16#02#);

   --  rsassaPss: 1.2.840.113549.1.1.10
   --      OID-only TLV: 06 09 2A 86 48 86 F7 0D 01 01 0A    (11 bytes)
   Oid_Rsa_Pss_Tlv : constant Octet_Array (1 .. 11) :=
     (16#06#, 16#09#,
      16#2A#, 16#86#, 16#48#, 16#86#, 16#F7#, 16#0D#, 16#01#, 16#01#,
      16#0A#);

   --  id-ce-subjectAltName: 2.5.29.17
   --      OID-only TLV: 06 03 55 1D 11
   Oid_San_Tlv : constant Octet_Array (1 .. 5) :=
     (16#06#, 16#03#, 16#55#, 16#1D#, 16#11#);

   ---------------------------------------------------------------------
   --  Read a single ASN.1 DER TLV header at Buf (Pos).
   --
   --    On success:
   --      OK         := True,
   --      Tag        := tag byte,
   --      Value_Pos  := first byte of the TLV value (V),
   --      Value_Len  := length of V in bytes,
   --      Next_Pos   := Value_Pos + Value_Len.
   ---------------------------------------------------------------------
   procedure Read_Tlv
     (Buf       : Octet_Array;
      Pos       : Natural;
      Tag       : out Octet;
      Value_Pos : out Natural;
      Value_Len : out Natural;
      Next_Pos  : out Natural;
      OK        : out Boolean)
   with
     Pre  => Buf'First = 1
             and then Buf'Last < Integer'Last - 16,
     Post => (if OK then
                Value_Pos > Pos
                and then Value_Pos in Buf'First .. Buf'Last + 1
                and then Value_Len <= Buf'Length
                and then (if Value_Len > 0 then
                            Value_Pos in Buf'Range
                            and then Value_Pos + Value_Len - 1
                                       in Buf'Range)
                and then Next_Pos = Value_Pos + Value_Len
                and then Next_Pos in Buf'First .. Buf'Last + 1
                and then Next_Pos > Pos);

   procedure Read_Tlv
     (Buf       : Octet_Array;
      Pos       : Natural;
      Tag       : out Octet;
      Value_Pos : out Natural;
      Value_Len : out Natural;
      Next_Pos  : out Natural;
      OK        : out Boolean)
   is
      L0       : Octet;
      Hdr_End  : Natural;
      Len      : Natural := 0;
      N_Octets : Natural;
   begin
      Tag       := 0;
      Value_Pos := Buf'First;
      Value_Len := 0;
      Next_Pos  := Buf'First;
      OK        := False;

      if Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;
      if Pos + 1 > Buf'Last then
         return;
      end if;

      Tag := Buf (Pos);
      L0  := Buf (Pos + 1);

      if L0 < 16#80# then
         Len     := Natural (L0);
         Hdr_End := Pos + 1;
      elsif L0 = 16#80# then
         return;  --  indefinite length forbidden by DER
      else
         N_Octets := Natural (L0 and 16#7F#);
         if N_Octets = 0 or else N_Octets > 3 then
            return;
         end if;
         if Pos + 1 + N_Octets > Buf'Last then
            return;
         end if;
         Len := 0;
         for I in 1 .. N_Octets loop
            if Len > Natural'Last / 256 then
               return;
            end if;
            Len := Len * 256 + Natural (Buf (Pos + 1 + I));
         end loop;
         Hdr_End := Pos + 1 + N_Octets;
      end if;

      --  The whole TLV value must fit inside Buf.
      if Len > Buf'Last - Hdr_End then
         return;
      end if;

      Value_Pos := Hdr_End + 1;
      Value_Len := Len;
      Next_Pos  := Hdr_End + 1 + Len;
      OK        := True;
   end Read_Tlv;

   ---------------------------------------------------------------------
   --  Slice equality: Buf (Pos .. Pos+Ref'Length-1) = Ref ?
   ---------------------------------------------------------------------
   function Equal_At
     (Buf       : Octet_Array;
      Pos       : Natural;
      Reference : Octet_Array) return Boolean
   with Pre => Buf'First = 1
              and then Buf'Last < Integer'Last - 16
              and then Reference'First = 1
              and then Reference'Last < Integer'Last - 16;

   function Equal_At
     (Buf       : Octet_Array;
      Pos       : Natural;
      Reference : Octet_Array) return Boolean
   is
   begin
      if Reference'Length = 0 then
         return True;
      end if;
      if Pos < Buf'First
        or else Pos > Buf'Last
        or else Reference'Length - 1 > Buf'Last - Pos
      then
         return False;
      end if;
      for I in 0 .. Reference'Length - 1 loop
         if Buf (Pos + I) /= Reference (Reference'First + I) then
            return False;
         end if;
      end loop;
      return True;
   end Equal_At;

   ---------------------------------------------------------------------
   --  Find the SubjectAltName extension inside the v3 extensions
   --  list given a cursor pointing at the [3] EXPLICIT context tag.
   --
   --  Sets Found = True and outputs the SAN OCTET STRING body span
   --  if the extension is present. The OCTET STRING body is the
   --  DER-encoded SEQUENCE OF GeneralName.
   ---------------------------------------------------------------------
   procedure Find_SAN_Ext
     (Buf       : Octet_Array;
      Ext_Pos   : Natural;
      Found     : out Boolean;
      San_First : out Natural;
      San_Last  : out Natural)
   with
     Pre  => Buf'First = 1 and then Buf'Last < Integer'Last - 16,
     Post => (if Found then
                San_First in Buf'Range
                and then San_Last in Buf'Range
                and then San_First <= San_Last);

   procedure Find_SAN_Ext
     (Buf       : Octet_Array;
      Ext_Pos   : Natural;
      Found     : out Boolean;
      San_First : out Natural;
      San_Last  : out Natural)
   is
      Ctx_Tag, Seq_Tag : Octet;
      Ctx_VP, Seq_VP   : Natural;
      Ctx_VL, Seq_VL   : Natural;
      Ctx_Next, Seq_Next : Natural;
      OK_Tlv : Boolean;

      Inner_Cursor : Natural;
      List_End     : Natural;
   begin
      Found := False;
      San_First := Buf'First;
      San_Last  := Buf'First;

      --  [3] EXPLICIT extensions header.
      Read_Tlv (Buf, Ext_Pos,
                Ctx_Tag, Ctx_VP, Ctx_VL, Ctx_Next, OK_Tlv);
      if not OK_Tlv or else Ctx_Tag /= Tag_Context_3 then
         return;
      end if;
      --  Inside [3] is exactly one SEQUENCE OF Extension.
      Read_Tlv (Buf, Ctx_VP,
                Seq_Tag, Seq_VP, Seq_VL, Seq_Next, OK_Tlv);
      if not OK_Tlv or else Seq_Tag /= Tag_Sequence then
         return;
      end if;
      --  Walk extensions inside Seq_VP .. Seq_VP + Seq_VL - 1.
      if Seq_VL = 0 then
         return;
      end if;
      Inner_Cursor := Seq_VP;
      List_End := Seq_VP + Seq_VL - 1;
      if List_End > Buf'Last then
         return;
      end if;

      while Inner_Cursor <= List_End loop
         pragma Loop_Invariant
           (Inner_Cursor in Buf'First .. Buf'Last + 1);
         declare
            E_Tag : Octet;
            E_VP, E_VL, E_Next : Natural;
            E_OK : Boolean;
            --  Inside an Extension: OID, optional critical BOOLEAN, OCTET STRING.
            F_Tag : Octet;
            F_VP, F_VL, F_Next : Natural;
            F_OK : Boolean;
         begin
            Read_Tlv (Buf, Inner_Cursor,
                      E_Tag, E_VP, E_VL, E_Next, E_OK);
            exit when not E_OK or else E_Tag /= Tag_Sequence;
            exit when E_Next > List_End + 1;

            --  Field 1: extnID OID.
            Read_Tlv (Buf, E_VP,
                      F_Tag, F_VP, F_VL, F_Next, F_OK);
            exit when not F_OK or else F_Tag /= Tag_Oid;

            --  Is this the SAN OID?
            if E_VP <= Buf'Last
              and then Equal_At (Buf, E_VP, Oid_San_Tlv)
            then
               --  Step past optional critical BOOLEAN.
               declare
                  Inner_C2 : Natural := F_Next;
                  G_Tag : Octet;
                  G_VP, G_VL, G_Next : Natural;
                  G_OK : Boolean;
               begin
                  --  Read next field; if BOOLEAN, skip; expect OCTET STRING.
                  Read_Tlv (Buf, Inner_C2,
                            G_Tag, G_VP, G_VL, G_Next, G_OK);
                  exit when not G_OK;
                  if G_Tag = Tag_Boolean then
                     Inner_C2 := G_Next;
                     Read_Tlv (Buf, Inner_C2,
                               G_Tag, G_VP, G_VL, G_Next, G_OK);
                     exit when not G_OK;
                  end if;
                  exit when G_Tag /= Tag_Octet_Str;

                  --  G_VP .. G_VP + G_VL - 1 is the OCTET STRING body,
                  --  which is itself the DER SEQUENCE OF GeneralName.
                  if G_VL = 0 then
                     exit;
                  end if;
                  if G_VP + G_VL - 1 > Buf'Last then
                     exit;
                  end if;
                  San_First := G_VP;
                  San_Last  := G_VP + G_VL - 1;
                  Found := True;
                  return;
               end;
            end if;

            Inner_Cursor := E_Next;
         end;
      end loop;
   end Find_SAN_Ext;

   ---------------------------------------------------------------------
   --  Parse — public entry point.
   ---------------------------------------------------------------------
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

   ---------------------------------------------------------------------
   --  ASCII case-insensitive byte equality (RFC 6125 §6.4 says DNS
   --  matching is case-insensitive; we apply ASCII tolower on each
   --  byte of both sides; non-ASCII bytes compare exactly).
   ---------------------------------------------------------------------
   function Lower (B : Octet) return Octet
   is (if B in 16#41# .. 16#5A# then B + 16#20# else B);

   function Iequal
     (A : Octet_Array; B : Octet_Array) return Boolean
   with Pre => A'First = 1 and then B'First = 1
              and then A'Last < Integer'Last - 16
              and then B'Last < Integer'Last - 16;
   function Iequal
     (A : Octet_Array; B : Octet_Array) return Boolean
   is
   begin
      if A'Length /= B'Length then
         return False;
      end if;
      for I in 0 .. A'Length - 1 loop
         if Lower (A (A'First + I)) /= Lower (B (B'First + I)) then
            return False;
         end if;
      end loop;
      return True;
   end Iequal;

   ---------------------------------------------------------------------
   --  Match_DNS_SAN — walk a SEQUENCE OF GeneralName looking for a
   --  [2] dNSName whose body equals Hostname (case-insensitive).
   --
   --  San_Body is the body of the SubjectAltName OCTET STRING (per
   --  RFC 5280 §4.2.1.6, that body is itself a DER `SEQUENCE OF
   --  GeneralName`, so it begins with `30 LL`). We descend through
   --  the SEQUENCE header, then iterate the GeneralName entries.
   ---------------------------------------------------------------------
   function Match_DNS_SAN
     (San_Body : Octet_Array;
      Hostname : Octet_Array) return Boolean
   is
      Cursor : Natural;
      Limit  : Natural;
      Result : Boolean := False;

      Seq_Tag    : Octet;
      Seq_VP, Seq_VL, Seq_Next : Natural;
      Seq_OK     : Boolean;
   begin
      if San_Body'Length < 2 or else Hostname'Length = 0 then
         return False;
      end if;

      Read_Tlv (San_Body, San_Body'First,
                Seq_Tag, Seq_VP, Seq_VL, Seq_Next, Seq_OK);
      if not Seq_OK or else Seq_Tag /= Tag_Sequence
        or else Seq_VL = 0
      then
         return False;
      end if;
      if Seq_VP + Seq_VL - 1 > San_Body'Last then
         return False;
      end if;

      Cursor := Seq_VP;
      Limit  := Seq_VP + Seq_VL - 1;

      while Cursor <= Limit loop
         pragma Loop_Invariant
           (Cursor in San_Body'First .. San_Body'Last + 1);
         pragma Loop_Variant (Increases => Cursor);
         declare
            Tag      : Octet;
            VP, VL, Next_Pos : Natural;
            OK_Tlv   : Boolean;
            Old_Cursor : constant Natural := Cursor;
         begin
            Read_Tlv (San_Body, Cursor, Tag, VP, VL, Next_Pos, OK_Tlv);
            exit when not OK_Tlv;
            exit when Next_Pos > Limit + 1;
            --  Read_Tlv guarantees Next_Pos > Cur on success when we
            --  consumed at least the tag+length header (>= 2 bytes).
            exit when Next_Pos <= Old_Cursor;

            if Tag = Tag_Dns_Name and then VL > 0
              and then VP in San_Body'Range
              and then VL <= San_Body'Last - VP + 1
            then
               --  Stage the DNS-name body into a 256-byte buffer so
               --  we can pass a slice with 'First = 1 to Iequal
               --  (DNS labels are <= 255 bytes per RFC 1035 §2.3.4).
               declare
                  Name_Buf : Octet_Array (1 .. 256) := (others => 0);
                  Name_Len : constant Natural := VL;
               begin
                  if Name_Len in 1 .. 256 then
                     for K in 0 .. Name_Len - 1 loop
                        Name_Buf (1 + K) := San_Body (VP + K);
                     end loop;
                     if Iequal (Name_Buf (1 .. Name_Len), Hostname) then
                        Result := True;
                        exit;
                     end if;
                  end if;
               end;
            end if;

            Cursor := Next_Pos;
         end;
      end loop;

      return Result;
   end Match_DNS_SAN;

end Tls_Core.Cert;
