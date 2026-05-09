with RFLX.RFLX_Builtin_Types;
with RFLX.RFLX_Types;
with RFLX.Server_Hello.Message;
with RFLX.TLS_Extensions;
with RFLX.TLS_Extensions.Extension;
with RFLX.Key_Share;
with RFLX.Key_Share.Server_Hello_Payload;

package body Tls_Core.Hello_Rflx
with SPARK_Mode
is

   use RFLX.RFLX_Builtin_Types;
   use type RFLX.RFLX_Types.Bit_Length;
   use type RFLX.RFLX_Types.Bit_Index;
   use type RFLX.RFLX_Types.Base_Integer;

   procedure Copy_In
     (Buf      : in out RFLX.RFLX_Types.Bytes;
      In_Bytes : Octet_Array)
   is
      J : RFLX.RFLX_Types.Index := Buf'First;
   begin
      for I in In_Bytes'Range loop
         Buf (J) := RFLX.RFLX_Types.Byte (In_Bytes (I));
         J := J + 1;
      end loop;
   end Copy_In;

   procedure Decode_Server_Hello_Fields
     (In_Bytes        : Octet_Array;
      Random          : out Random_Bytes;
      Suite_Code      : out Tls_Core.Suites.U16;
      Sid_First       : out Natural;
      Sid_Last        : out Natural;
      Ext_First       : out Natural;
      Ext_Last        : out Natural;
      OK              : out Boolean)
   is
      package SH renames RFLX.Server_Hello.Message;

      Buf : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'
          (1 .. RFLX.RFLX_Types.Index (In_Bytes'Length) => 0);
      Ctx : SH.Context;
      WL  : constant RFLX.RFLX_Types.Bit_Length :=
        RFLX.RFLX_Types.Bit_Length (In_Bytes'Length) * 8;
   begin
      Random     := (others => 0);
      Suite_Code := 0;
      Sid_First  := 0;
      Sid_Last   := 0;
      Ext_First  := 0;
      Ext_Last   := 0;
      OK         := False;

      Copy_In (Buf.all, In_Bytes);
      SH.Initialize (Ctx, Buf, Written_Last => WL);
      SH.Verify_Message (Ctx);

      if not SH.Well_Formed_Message (Ctx) then
         SH.Take_Buffer (Ctx, Buf);
         RFLX.RFLX_Types.Free (Buf);
         return;
      end if;

      declare
         Rnd : RFLX.RFLX_Types.Bytes (1 .. 32);
      begin
         SH.Get_Random (Ctx, Rnd);
         for I in Rnd'Range loop
            Random (Natural (I)) := Tls_Core.Octet (Rnd (I));
         end loop;
      end;

      Suite_Code := Tls_Core.Suites.U16
        (SH.Get_Selected_Cipher_Suite (Ctx));

      declare
         Sid_Len : constant Natural :=
           Natural (SH.Get_Session_Id_Len (Ctx));
      begin
         if Sid_Len > 0 then
            Sid_First := Natural
              (SH.Field_First (Ctx, SH.F_Session_Id_Echo))
              / 8 + 1;
            Sid_Last := Sid_First + Sid_Len - 1;
         end if;
      end;

      declare
         Ext_Len_Val : constant Natural :=
           Natural (SH.Get_Extensions_Len (Ctx));
      begin
         if Ext_Len_Val > 0 then
            Ext_First := Natural
              (SH.Field_First (Ctx, SH.F_Extensions))
              / 8 + 1;
            Ext_Last := Ext_First + Ext_Len_Val - 1;
         end if;
      end;

      OK := True;
      SH.Take_Buffer (Ctx, Buf);
      RFLX.RFLX_Types.Free (Buf);
   end Decode_Server_Hello_Fields;

   procedure Decode_Server_Hello_Key_Share
     (In_Bytes        : Octet_Array;
      Key_Share_First : out Natural;
      Key_Share_Last  : out Natural;
      OK              : out Boolean)
   is
      package SH renames RFLX.Server_Hello.Message;
      package Ext renames RFLX.TLS_Extensions.Extension;
      package KS renames RFLX.Key_Share.Server_Hello_Payload;

      Buf : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'
          (1 .. RFLX.RFLX_Types.Index (In_Bytes'Length) => 0);
      Ctx : SH.Context;
      WL  : constant RFLX.RFLX_Types.Bit_Length :=
        RFLX.RFLX_Types.Bit_Length (In_Bytes'Length) * 8;
   begin
      Key_Share_First := 0;
      Key_Share_Last  := 0;
      OK              := False;

      Copy_In (Buf.all, In_Bytes);
      SH.Initialize (Ctx, Buf, Written_Last => WL);
      SH.Verify_Message (Ctx);

      if not SH.Well_Formed_Message (Ctx) then
         SH.Take_Buffer (Ctx, Buf);
         RFLX.RFLX_Types.Free (Buf);
         return;
      end if;

      declare
         Ext_Len : constant Natural :=
           Natural (SH.Get_Extensions_Len (Ctx));
         Ef : constant Natural := Natural
           (SH.Field_First (Ctx, SH.F_Extensions)) / 8 + 1;
      begin
         SH.Take_Buffer (Ctx, Buf);

         if Ext_Len < 4 then
            RFLX.RFLX_Types.Free (Buf);
            return;
         end if;

         declare
            Cursor : Natural := Ef;
            El     : constant Natural := Ef + Ext_Len - 1;
         begin
            while Cursor + 3 <= El loop
               declare
                  Ext_Type_Val : constant Natural :=
                    Natural (Buf (RFLX.RFLX_Types.Index (Cursor)))
                      * 256
                    + Natural
                        (Buf (RFLX.RFLX_Types.Index (Cursor + 1)));
                  Ext_Data_Len : constant Natural :=
                    Natural
                      (Buf (RFLX.RFLX_Types.Index (Cursor + 2)))
                      * 256
                    + Natural
                        (Buf (RFLX.RFLX_Types.Index (Cursor + 3)));
                  Ext_Data_F : constant Natural := Cursor + 4;
               begin
                  if Ext_Data_F + Ext_Data_Len - 1 > El then
                     RFLX.RFLX_Types.Free (Buf);
                     return;
                  end if;

                  if Ext_Type_Val = 51 and then
                     Ext_Data_Len >= 4
                  then
                     declare
                        Grp : constant Natural :=
                          Natural (Buf (RFLX.RFLX_Types.Index
                                          (Ext_Data_F))) * 256
                          + Natural (Buf (RFLX.RFLX_Types.Index
                                           (Ext_Data_F + 1)));
                        Kx_Len : constant Natural :=
                          Natural (Buf (RFLX.RFLX_Types.Index
                                          (Ext_Data_F + 2))) * 256
                          + Natural (Buf (RFLX.RFLX_Types.Index
                                           (Ext_Data_F + 3)));
                        Kx_F : constant Natural := Ext_Data_F + 4;
                     begin
                        pragma Unreferenced (Grp);
                        if Kx_Len = 32 and then
                           Kx_F + 31 <= El
                        then
                           Key_Share_First :=
                             In_Bytes'First + Kx_F - 1;
                           Key_Share_Last  :=
                             In_Bytes'First + Kx_F + 30;
                           OK := True;
                        end if;
                     end;
                     RFLX.RFLX_Types.Free (Buf);
                     return;
                  end if;

                  Cursor := Ext_Data_F + Ext_Data_Len;
               end;
            end loop;
         end;
      end;

      RFLX.RFLX_Types.Free (Buf);
   end Decode_Server_Hello_Key_Share;

end Tls_Core.Hello_Rflx;
