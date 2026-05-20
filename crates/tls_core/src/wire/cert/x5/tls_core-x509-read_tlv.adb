separate (Tls_Core.X509)
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
