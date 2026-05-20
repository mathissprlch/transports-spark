separate (Tls_Core.Cert_Verify)
procedure Encode_Body_Single
  (Cert_Data : Octet_Array; Out_Buf : out Octet_Array; Out_Last : out Natural)
is
   Cursor             : Natural := 0;
   Cert_List_Body_Len : constant Natural := 3 + Cert_Data'Length + 2;
begin
   Out_Buf := [others => 0];
   --  request_context length = 0.
   Out_Buf (Cursor + 1) := 0;
   Cursor := Cursor + 1;
   --  certificate_list u24 length.
   Put_U24 (Out_Buf, Cursor, Cert_List_Body_Len);
   --  cert_data u24 length.
   Put_U24 (Out_Buf, Cursor, Cert_Data'Length);
   --  cert_data bytes.
   for I in 1 .. Cert_Data'Length loop
      Out_Buf (Cursor + I) := Cert_Data (Cert_Data'First + I - 1);
   end loop;
   Cursor := Cursor + Cert_Data'Length;
   --  extensions u16 length = 0.
   Put_U16 (Out_Buf, Cursor, 0);
   Out_Last := Cursor;
end Encode_Body_Single;
