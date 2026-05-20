separate (Tls_Core.Cert)
function Match_DNS_SAN
  (San_Body : Octet_Array; Hostname : Octet_Array) return Boolean
is
   Cursor : Natural;
   Limit  : Natural;
   Result : Boolean := False;

   Seq_Tag                  : Octet;
   Seq_VP, Seq_VL, Seq_Next : Natural;
   Seq_OK                   : Boolean;
begin
   if San_Body'Length < 2 or else Hostname'Length = 0 then
      return False;
   end if;

   Read_Tlv
     (San_Body, San_Body'First, Seq_Tag, Seq_VP, Seq_VL, Seq_Next, Seq_OK);
   if not Seq_OK or else Seq_Tag /= Tag_Sequence or else Seq_VL = 0 then
      return False;
   end if;
   if Seq_VP + Seq_VL - 1 > San_Body'Last then
      return False;
   end if;

   Cursor := Seq_VP;
   Limit := Seq_VP + Seq_VL - 1;

   while Cursor <= Limit loop
      pragma Loop_Invariant (Cursor in San_Body'First .. San_Body'Last + 1);
      pragma Loop_Variant (Increases => Cursor);
      declare
         Tag              : Octet;
         VP, VL, Next_Pos : Natural;
         OK_Tlv           : Boolean;
         Old_Cursor       : constant Natural := Cursor;
      begin
         Read_Tlv (San_Body, Cursor, Tag, VP, VL, Next_Pos, OK_Tlv);
         exit when not OK_Tlv;
         exit when Next_Pos > Limit + 1;
         --  Read_Tlv guarantees Next_Pos > Cur on success when we
         --  consumed at least the tag+length header (>= 2 bytes).
         exit when Next_Pos <= Old_Cursor;

         if Tag = Tag_Dns_Name
           and then VL > 0
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
