separate (Tls_Core.X509_Spki)
   procedure Decode
     (Buf       : Octet_Array;
      OK        : out Boolean;
      Kind      : out Key_Kind;
      Key_First : out Natural;
      Key_Last  : out Natural)
   is
      Step_OK : Boolean;

      --  Outer SubjectPublicKeyInfo SEQUENCE.  We only consume the
      --  body-first cursor (header has been parsed away); body-last
      --  and after-cursor are unused but Read_TLV_Header signature
      --  keeps them named for symmetry.
      Outer_BF : Natural;
      Outer_BL : Natural;
      Outer_AF : Natural;

      --  Algorithm SEQUENCE (lives inside outer body)
      Alg_BF : Natural;
      Alg_BL : Natural;  --  also "Alg_End": last byte of algorithm body
      Alg_AF : Natural;  --  cursor where the BIT STRING starts

      --  Algorithm OID
      Oid_BF : Natural;
      Oid_BL : Natural;
      Oid_AF : Natural;

      --  BIT STRING (lives at Alg_AF inside outer body)
      Bs_BF : Natural;
      Bs_BL : Natural;
      Bs_AF : Natural;
   begin
      OK := False;
      Kind := Unknown;
      Key_First := 0;
      Key_Last  := 0;

      --  SubjectPublicKeyInfo ::= SEQUENCE { algorithm, subjectPublicKey }
      Read_TLV_Header
        (Buf, Buf'First, Tag_Sequence,
         Outer_BF, Outer_BL, Outer_AF, Step_OK);
      if not Step_OK then
         return;
      end if;
      --  Outer_BF in Buf'First+2 .. Buf'Last+1 (cursor past header)

      --  AlgorithmIdentifier ::= SEQUENCE { algorithm OID, parameters }
      Read_TLV_Header
        (Buf, Outer_BF, Tag_Sequence,
         Alg_BF, Alg_BL, Alg_AF, Step_OK);
      if not Step_OK then
         return;
      end if;
      --  Alg_BF .. Alg_BL is the algorithm-id body; Alg_AF is the
      --  cursor past it (i.e., where the BIT STRING starts).

      --  algorithm OID
      Read_TLV_Header
        (Buf, Alg_BF, Tag_Oid,
         Oid_BF, Oid_BL, Oid_AF, Step_OK);
      if not Step_OK then
         return;
      end if;
      --  Oid_BL must lie within the algorithm body.
      if Oid_BL > Alg_BL then
         return;
      end if;

      if Oid_BF <= Oid_BL
        and then Slice_Equal (Buf, Oid_BF, Oid_BL, Oid_Rsa)
      then
         Kind := Rsa;
         --  No need to inspect parameters; RFC 8017 says NULL.
      elsif Oid_BF <= Oid_BL
        and then Slice_Equal (Buf, Oid_BF, Oid_BL, Oid_Ec_Pub)
      then
         --  Need parameters carrying the prime256v1 OID.
         declare
            Params_Cur : constant Natural := Oid_AF;
            Curve_BF : Natural;
            Curve_BL : Natural;
            Curve_AF : Natural;
            Sub_OK : Boolean;
         begin
            if Params_Cur > Alg_BL then
               --  Parameters absent — required for ecPublicKey.
               return;
            end if;
            --  Params_Cur in 1 .. Alg_BL <= Buf'Last so it's a valid
            --  cursor for Read_TLV_Header.
            pragma Assert (Params_Cur in Buf'First .. Buf'Last + 1);
            Read_TLV_Header
              (Buf, Params_Cur, Tag_Oid,
               Curve_BF, Curve_BL, Curve_AF, Sub_OK);
            if not Sub_OK then
               return;
            end if;
            if Curve_BL > Alg_BL then
               return;
            end if;
            if Curve_BF <= Curve_BL
              and then Slice_Equal
                         (Buf, Curve_BF, Curve_BL, Oid_P256)
            then
               Kind := Ecdsa_P256;
            else
               return;
            end if;
         end;
      else
         return;
      end if;

      --  subjectPublicKey BIT STRING — lives at cursor Alg_AF.
      Read_TLV_Header
        (Buf, Alg_AF, Tag_Bit_String,
         Bs_BF, Bs_BL, Bs_AF, Step_OK);
      if not Step_OK then
         OK := False;
         Kind := Unknown;
         return;
      end if;
      --  Need at least one byte of content (the unused-bits header).
      if Bs_BF > Bs_BL then
         OK := False;
         Kind := Unknown;
         return;
      end if;
      --  Bs_BF in 1..Buf'Last by Read_TLV_Header post + Bs_BF<=Bs_BL.
      pragma Assert (Bs_BF in Buf'First .. Buf'Last);
      if Buf (Bs_BF) /= 0 then
         OK := False;
         Kind := Unknown;
         return;
      end if;
      --  Key contents follow the unused-bits byte.
      if Bs_BF >= Bs_BL then
         --  empty key body — degenerate; reject.
         OK := False;
         Kind := Unknown;
         return;
      end if;
      --  Bs_BF < Bs_BL <= Buf'Last, so Bs_BF + 1 <= Bs_BL is a valid
      --  index in Buf'Range. Key_First <= Key_Last.
      Key_First := Bs_BF + 1;
      Key_Last  := Bs_BL;
      OK := True;
   end Decode;
