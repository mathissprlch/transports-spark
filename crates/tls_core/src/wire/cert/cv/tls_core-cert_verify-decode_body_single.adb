separate (Tls_Core.Cert_Verify)
procedure Decode_Body_Single
  (Buf        : Octet_Array;
   OK         : out Boolean;
   Cert_First : out Natural;
   Cert_Last  : out Natural)
is
   Cursor : Natural := 0;
begin
   OK := False;
   Cert_First := 0;
   Cert_Last := 0;
   if Buf'Length < 1 + 3 + 3 + 1 + 2 then
      return;
   end if;
   --  request_context: must be empty (length byte = 0)
   if Buf (Buf'First) /= 0 then
      return;
   end if;
   Cursor := 1;
   --  certificate_list u24 length
   declare
      List_Len : constant Natural :=
        Natural (Buf (Buf'First + Cursor))
        * 16#10000#
        + Natural (Buf (Buf'First + Cursor + 1)) * 16#100#
        + Natural (Buf (Buf'First + Cursor + 2));
   begin
      Cursor := Cursor + 3;
      if 1 + 3 + List_Len /= Buf'Length then
         return;
      end if;
      if List_Len < 3 + 1 + 2 then
         return;
      end if;
      --  RFC 8446 §4.4.2: certificate_list is a sequence of
      --  CertificateEntry records (u24 cert_data_len + bytes +
      --  u16 extensions_len).  The FIRST entry is the leaf the
      --  server vouches for; subsequent entries are intermediate
      --  CAs (and possibly the root, depending on peer).  v0.5
      --  validates leaf-vs-trust-anchor only, but we MUST accept
      --  the multi-entry list because openssl/gnutls/wolfSSL all
      --  emit the full chain by default.  Capture the leaf
      --  indices, then walk past any remaining entries to verify
      --  the list is well-formed and consumes exactly List_Len.
      declare
         First_Pass : Boolean := True;
         List_End   : constant Natural := Cursor + List_Len;
      begin
         while Cursor < List_End loop
            if Cursor + 3 + 2 > List_End then
               return;
            end if;
            declare
               Cert_Len : constant Natural :=
                 Natural (Buf (Buf'First + Cursor))
                 * 16#10000#
                 + Natural (Buf (Buf'First + Cursor + 1)) * 16#100#
                 + Natural (Buf (Buf'First + Cursor + 2));
            begin
               Cursor := Cursor + 3;
               if Cert_Len = 0 then
                  return;
               end if;
               if Cursor + Cert_Len + 2 > List_End then
                  return;
               end if;
               if First_Pass then
                  Cert_First := Buf'First + Cursor;
                  Cert_Last := Buf'First + Cursor + Cert_Len - 1;
                  First_Pass := False;
               end if;
               Cursor := Cursor + Cert_Len;
               --  extensions u16 length — we accept zero only;
               --  per-cert extensions are server-side OCSP /
               --  SCT and we don't process them in v0.5.
               declare
                  Ext_Len : constant Natural :=
                    Natural (Buf (Buf'First + Cursor))
                    * 256
                    + Natural (Buf (Buf'First + Cursor + 1));
               begin
                  if Ext_Len /= 0 then
                     return;
                  end if;
                  Cursor := Cursor + 2;
               end;
            end;
         end loop;
         --  Must consume exactly List_Len bytes.
         if Cursor /= List_End then
            return;
         end if;
         if First_Pass then
            --  Empty list: no leaf — fail.
            return;
         end if;
      end;
   end;
   OK := True;
end Decode_Body_Single;
