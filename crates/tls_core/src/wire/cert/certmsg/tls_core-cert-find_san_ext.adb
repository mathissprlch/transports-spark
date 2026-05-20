separate (Tls_Core.Cert)
procedure Find_SAN_Ext
  (Buf       : Octet_Array;
   Ext_Pos   : Natural;
   Found     : out Boolean;
   San_First : out Natural;
   San_Last  : out Natural)
is
   Ctx_Tag, Seq_Tag   : Octet;
   Ctx_VP, Seq_VP     : Natural;
   Ctx_VL, Seq_VL     : Natural;
   Ctx_Next, Seq_Next : Natural;
   OK_Tlv             : Boolean;

   Inner_Cursor : Natural;
   List_End     : Natural;
begin
   Found := False;
   San_First := Buf'First;
   San_Last := Buf'First;

   --  [3] EXPLICIT extensions header.
   Read_Tlv (Buf, Ext_Pos, Ctx_Tag, Ctx_VP, Ctx_VL, Ctx_Next, OK_Tlv);
   if not OK_Tlv or else Ctx_Tag /= Tag_Context_3 then
      return;
   end if;
   --  Inside [3] is exactly one SEQUENCE OF Extension.
   Read_Tlv (Buf, Ctx_VP, Seq_Tag, Seq_VP, Seq_VL, Seq_Next, OK_Tlv);
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
      pragma Loop_Invariant (Inner_Cursor in Buf'First .. Buf'Last + 1);
      declare
         E_Tag              : Octet;
         E_VP, E_VL, E_Next : Natural;
         E_OK               : Boolean;
         --  Inside an Extension: OID, optional critical BOOLEAN, OCTET STRING.
         F_Tag              : Octet;
         F_VP, F_VL, F_Next : Natural;
         F_OK               : Boolean;
      begin
         Read_Tlv (Buf, Inner_Cursor, E_Tag, E_VP, E_VL, E_Next, E_OK);
         exit when not E_OK or else E_Tag /= Tag_Sequence;
         exit when E_Next > List_End + 1;

         --  Field 1: extnID OID.
         Read_Tlv (Buf, E_VP, F_Tag, F_VP, F_VL, F_Next, F_OK);
         exit when not F_OK or else F_Tag /= Tag_Oid;

         --  Is this the SAN OID?
         if E_VP <= Buf'Last and then Equal_At (Buf, E_VP, Oid_San_Tlv) then
            --  Step past optional critical BOOLEAN.
            declare
               Inner_C2           : Natural := F_Next;
               G_Tag              : Octet;
               G_VP, G_VL, G_Next : Natural;
               G_OK               : Boolean;
            begin
               --  Read next field; if BOOLEAN, skip; expect OCTET STRING.
               Read_Tlv (Buf, Inner_C2, G_Tag, G_VP, G_VL, G_Next, G_OK);
               exit when not G_OK;
               if G_Tag = Tag_Boolean then
                  Inner_C2 := G_Next;
                  Read_Tlv (Buf, Inner_C2, G_Tag, G_VP, G_VL, G_Next, G_OK);
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
               San_Last := G_VP + G_VL - 1;
               Found := True;
               return;
            end;
         end if;

         Inner_Cursor := E_Next;
      end;
   end loop;
end Find_SAN_Ext;
