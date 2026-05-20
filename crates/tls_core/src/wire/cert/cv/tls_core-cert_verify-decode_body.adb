separate (Tls_Core.Cert_Verify)
   procedure Decode_Body
     (Buf        : Octet_Array;
      OK         : out Boolean;
      Sig_Scheme : out Unsigned_16;
      Sig_First  : out Natural;
      Sig_Last   : out Natural)
   is
   begin
      OK := False;
      Sig_Scheme := 0;
      Sig_First := 0;
      Sig_Last  := 0;
      if Buf'Length < 4 then
         return;
      end if;
      Sig_Scheme :=
        Unsigned_16 (Buf (Buf'First)) * 256
        + Unsigned_16 (Buf (Buf'First + 1));
      declare
         Sig_Len : constant Natural :=
           Natural (Buf (Buf'First + 2)) * 256
           + Natural (Buf (Buf'First + 3));
      begin
         if 4 + Sig_Len /= Buf'Length then
            return;
         end if;
         if Sig_Len = 0 then
            return;
         end if;
         Sig_First := Buf'First + 4;
         Sig_Last  := Buf'First + 4 + Sig_Len - 1;
         OK := True;
      end;
   end Decode_Body;
