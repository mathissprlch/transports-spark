with RFLX.RFLX_Builtin_Types;
with RFLX.RFLX_Types;
with RFLX.Server_Hello.Message;

package body Tls_Core.Hello_Rflx
with SPARK_Mode
is

   use RFLX.RFLX_Builtin_Types;

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
      use type RFLX.RFLX_Types.Bit_Length;
      use type RFLX.RFLX_Types.Bit_Index;
      use type RFLX.RFLX_Types.Base_Integer;

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

      for I in In_Bytes'Range loop
         Buf (RFLX.RFLX_Types.Index (I)) :=
           RFLX.RFLX_Types.Byte (In_Bytes (I));
      end loop;

      SH.Initialize (Ctx, Buf, Written_Last => WL);
      SH.Verify_Message (Ctx);

      if not SH.Valid_Message (Ctx) then
         if SH.Well_Formed_Message (Ctx) then
            OK := True;

            declare
               Rnd : RFLX.RFLX_Types.Bytes (1 .. 32);
            begin
               SH.Get_Random (Ctx, Rnd);
               for I in Rnd'Range loop
                  Random (Natural (I)) :=
                    Tls_Core.Octet (Rnd (I));
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

            SH.Take_Buffer (Ctx, Buf);
            RFLX.RFLX_Types.Free (Buf);
            return;
         end if;

         SH.Take_Buffer (Ctx, Buf);
         RFLX.RFLX_Types.Free (Buf);
         return;
      end if;

      declare
         Rnd : RFLX.RFLX_Types.Bytes (1 .. 32);
      begin
         SH.Get_Random (Ctx, Rnd);
         for I in Rnd'Range loop
            Random (Natural (I)) :=
              Tls_Core.Octet (Rnd (I));
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

end Tls_Core.Hello_Rflx;
