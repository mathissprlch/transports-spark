--  Tls_Core.X509 — body. Pure Ada DER walker for Ed25519 certs.
--
--  Regenerate the test certificate the tests embed with
--      openssl req -x509 -newkey ed25519 -nodes -days 365 \
--          -subj "/CN=test" -outform DER -out test.der
--  then dump the bytes via `xxd -i test.der`.

package body Tls_Core.X509
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use type Tls_Core.Octet;

   --  ASN.1 / DER tag bytes we care about.
   Tag_Sequence    : constant Octet := 16#30#;
   Tag_Bit_String  : constant Octet := 16#03#;
   Tag_Context_0   : constant Octet := 16#A0#;

   --  AlgorithmIdentifier for Ed25519 with no parameters
   --  (RFC 8410 §3, OID 1.3.101.112):
   --      SEQUENCE { OID 1.3.101.112 }   ==   30 05 06 03 2B 65 70
   --  We compare this whole 7-byte TLV byte-for-byte; the OID alone
   --  (06 03 2B 65 70) is just the inner contents.
   Alg_Id_Ed25519 : constant Octet_Array (1 .. 7) :=
     (16#30#, 16#05#,
      16#06#, 16#03#, 16#2B#, 16#65#, 16#70#);

   ---------------------------------------------------------------------
   --  Parse a single ASN.1 DER TLV header at Buf (Pos).
   --
   --    On success:
   --      OK         := True,
   --      Tag        := tag byte,
   --      Value_Pos  := first byte of the TLV value (V),
   --      Value_Len  := length of V in bytes,
   --      Next_Pos   := Value_Pos + Value_Len  (one past the TLV).
   --
   --    On any malformed input (truncation, indefinite length,
   --    multi-byte length > 3 bytes, length running past Buf'Last,
   --    Pos < Buf'First, etc.) sets OK := False.
   --
   --  We accept short form (length < 0x80) and long form with 1, 2,
   --  or 3 length bytes — that covers values up to 16 MiB, far more
   --  than any cert we will meet here.
   ---------------------------------------------------------------------

   procedure Read_Tlv
     (Buf       : Octet_Array;
      Pos       : Natural;
      Tag       : out Octet;
      Value_Pos : out Natural;
      Value_Len : out Natural;
      Next_Pos  : out Natural;
      OK        : out Boolean);

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
      Value_Pos := 0;
      Value_Len := 0;
      Next_Pos  := 0;
      OK        := False;

      if Pos < Buf'First or else Pos > Buf'Last then
         return;
      end if;
      --  Need at least tag + first length byte.
      if Pos + 1 > Buf'Last then
         return;
      end if;

      Tag := Buf (Pos);
      L0  := Buf (Pos + 1);

      if L0 < 16#80# then
         --  Short form: length is L0 itself.
         Len     := Natural (L0);
         Hdr_End := Pos + 1;
      elsif L0 = 16#80# then
         --  Indefinite length: forbidden by DER.
         return;
      else
         --  Long form: low 7 bits of L0 give the count of length
         --  octets that follow, big-endian.
         N_Octets := Natural (L0 and 16#7F#);
         if N_Octets = 0 or else N_Octets > 3 then
            return;
         end if;
         if Pos + 1 + N_Octets > Buf'Last then
            return;
         end if;
         Len := 0;
         for I in 1 .. N_Octets loop
            Len := Len * 256 + Natural (Buf (Pos + 1 + I));
         end loop;
         Hdr_End := Pos + 1 + N_Octets;
      end if;

      --  Value must fit inside Buf.
      if Hdr_End + Len > Buf'Last then
         return;
      end if;

      Value_Pos := Hdr_End + 1;
      Value_Len := Len;
      Next_Pos  := Hdr_End + 1 + Len;
      OK        := True;
   end Read_Tlv;

   ---------------------------------------------------------------------
   --  Skip exactly one TLV at Pos and return Next_Pos. Wraps Read_Tlv
   --  for the call sites that don't care about the contents.
   ---------------------------------------------------------------------

   procedure Skip_Tlv
     (Buf      : Octet_Array;
      Pos      : Natural;
      Next_Pos : out Natural;
      OK       : out Boolean);

   procedure Skip_Tlv
     (Buf      : Octet_Array;
      Pos      : Natural;
      Next_Pos : out Natural;
      OK       : out Boolean)
   is
      Tag       : Octet;
      Value_Pos : Natural;
      Value_Len : Natural;
   begin
      Read_Tlv (Buf, Pos, Tag, Value_Pos, Value_Len, Next_Pos, OK);
   end Skip_Tlv;

   ---------------------------------------------------------------------
   --  Slice equality at a specific offset.
   ---------------------------------------------------------------------

   function Equal_At
     (Buf       : Octet_Array;
      Pos       : Natural;
      Reference : Octet_Array) return Boolean;

   function Equal_At
     (Buf       : Octet_Array;
      Pos       : Natural;
      Reference : Octet_Array) return Boolean
   is
   begin
      if Pos < Buf'First
        or else Pos + Reference'Length - 1 > Buf'Last
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
   --  Parse_Ed25519_Cert — the public entry point.
   ---------------------------------------------------------------------

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

end Tls_Core.X509;
