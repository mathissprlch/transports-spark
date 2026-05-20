separate (Tls_Core.X509_Spki)
   procedure Read_Length
     (Buf      : Octet_Array;
      Off      : Natural;
      Out_Len  : out Natural;
      Used     : out Natural;
      OK       : out Boolean)
   is
      B0 : constant Octet := Buf (Off);
   begin
      Out_Len := 0;
      Used    := 0;
      OK      := False;
      if B0 < 16#80# then
         if Natural (B0) > Buf'Length then
            return;  --  short-form length exceeds buffer; reject.
         end if;
         Out_Len := Natural (B0);
         Used    := 1;
         OK      := True;
         return;
      end if;
      declare
         N : constant Natural := Natural (B0) - 16#80#;
         Acc : Natural := 0;
      begin
         if N = 0 or else N > 4 then
            return;  --  indefinite-length (0) and absurd (>4) are
                     --  not supported in DER profiles.
         end if;
         if Off + N > Buf'Last then
            return;
         end if;
         for I in 1 .. N loop
            if Acc > Natural'Last / 256 then
               return;
            end if;
            pragma Assert (Acc <= Natural'Last / 256);
            Acc := Acc * 256 + Natural (Buf (Off + I));
         end loop;
         --  Final clamp to Buf'Length: the encoded length must fit
         --  within the buffer for the parser to be useful.
         if Acc > Buf'Length then
            return;
         end if;
         Out_Len := Acc;
         Used    := 1 + N;
         OK      := True;
      end;
   end Read_Length;
