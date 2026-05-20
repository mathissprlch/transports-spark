separate (Tls_Core.Cert)
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
   Tag := 0;
   Value_Pos := Buf'First;
   Value_Len := 0;
   Next_Pos := Buf'First;
   OK := False;

   if Pos < Buf'First or else Pos > Buf'Last then
      return;
   end if;
   if Pos + 1 > Buf'Last then
      return;
   end if;

   Tag := Buf (Pos);
   L0 := Buf (Pos + 1);

   if L0 < 16#80# then
      Len := Natural (L0);
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
   Next_Pos := Hdr_End + 1 + Len;
   OK := True;
end Read_Tlv;
