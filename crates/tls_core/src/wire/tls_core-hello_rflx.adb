with RFLX.RFLX_Builtin_Types;
with RFLX.RFLX_Types;
with RFLX.Server_Hello.Message;

package body Tls_Core.Hello_Rflx
with SPARK_Mode
is

   use type RFLX.RFLX_Types.Bit_Length;
   use type RFLX.RFLX_Types.Base_Integer;

   function Rflx_Validate (In_Bytes : Octet_Array) return Boolean
   with Pre => In_Bytes'First = 1 and then In_Bytes'Length >= 40
   is
      package SH renames RFLX.Server_Hello.Message;
      use RFLX.RFLX_Builtin_Types;

      Buf : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'
          (1 .. RFLX.RFLX_Types.Index (In_Bytes'Length) => 0);
      Ctx     : SH.Context;
      WL      : constant RFLX.RFLX_Types.Bit_Length :=
        RFLX.RFLX_Types.Bit_Length (In_Bytes'Length) * 8;
      J       : RFLX.RFLX_Types.Index := 1;
      Result  : Boolean;
   begin
      for I in In_Bytes'Range loop
         Buf (J) := RFLX.RFLX_Types.Byte (In_Bytes (I));
         J := J + 1;
      end loop;
      SH.Initialize (Ctx, Buf, Written_Last => WL);
      SH.Verify_Message (Ctx);
      Result := SH.Well_Formed_Message (Ctx);
      SH.Take_Buffer (Ctx, Buf);
      RFLX.RFLX_Types.Free (Buf);
      return Result;
   end Rflx_Validate;

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
      use type Tls_Core.Suites.U16;
   begin
      Random     := (others => 0);
      Suite_Code := 0;
      Sid_First  := 0;
      Sid_Last   := 0;
      Ext_First  := 0;
      Ext_Last   := 0;
      OK         := False;

      if not Rflx_Validate (In_Bytes) then
         return;
      end if;

      if In_Bytes (1) /= 16#03# or else In_Bytes (2) /= 16#03# then
         return;
      end if;
      if In_Bytes (35) > 32 then
         return;
      end if;

      declare
         Sid_Len : constant Natural := Natural (In_Bytes (35));
         Suite_Off : constant Natural := 36 + Sid_Len;
      begin
         if Suite_Off + 4 > In_Bytes'Last then
            return;
         end if;
         if In_Bytes (Suite_Off + 2) /= 0 then
            return;
         end if;

         Random := In_Bytes (3 .. 34);

         pragma Assert (Suite_Off = Spec_Suite_Offset (In_Bytes));

         Suite_Code :=
           Tls_Core.Suites.U16 (In_Bytes (Suite_Off)) * 256
           + Tls_Core.Suites.U16 (In_Bytes (Suite_Off + 1));

         pragma Assert
           (Suite_Code = Spec_Suite_Code (In_Bytes));
         pragma Assert (Random = Spec_Random (In_Bytes));

         if Sid_Len > 0 then
            Sid_First := 36;
            Sid_Last  := 35 + Sid_Len;
         end if;

         declare
            Ext_Len_Off : constant Natural := Suite_Off + 3;
         begin
            if Ext_Len_Off + 1 <= In_Bytes'Last then
               declare
                  EL : constant Natural :=
                    Natural (In_Bytes (Ext_Len_Off)) * 256
                    + Natural (In_Bytes (Ext_Len_Off + 1));
               begin
                  if EL > 0 and then
                     Ext_Len_Off + 2 + EL - 1 <= In_Bytes'Last
                  then
                     Ext_First := Ext_Len_Off + 2;
                     Ext_Last  := Ext_Len_Off + 1 + EL;
                  end if;
               end;
            end if;
         end;

         pragma Assert (Spec_Valid (In_Bytes));
         OK := True;
      end;
   end Decode_Server_Hello_Fields;

   procedure Decode_Server_Hello_Key_Share
     (In_Bytes        : Octet_Array;
      Key_Share_First : out Natural;
      Key_Share_Last  : out Natural;
      OK              : out Boolean)
   is
      Rnd    : Random_Bytes;
      Suite  : Tls_Core.Suites.U16;
      Sf, Sl : Natural;
      Ef, El : Natural;
      Fields_OK : Boolean;
   begin
      Key_Share_First := 0;
      Key_Share_Last  := 0;
      OK              := False;

      if In_Bytes'Length < 40 or else In_Bytes'First < 1 then
         return;
      end if;

      declare
         Local : Octet_Array (1 .. In_Bytes'Length) := In_Bytes;
      begin
         Decode_Server_Hello_Fields
           (Local, Rnd, Suite, Sf, Sl, Ef, El, Fields_OK);

         if not Fields_OK or else Ef = 0 then
            return;
         end if;

         declare
            Cursor : Natural := Ef;
         begin
            while Cursor + 3 <= El loop
               declare
                  Ext_Type : constant Natural :=
                    Natural (Local (Cursor)) * 256
                    + Natural (Local (Cursor + 1));
                  Ext_Data_Len : constant Natural :=
                    Natural (Local (Cursor + 2)) * 256
                    + Natural (Local (Cursor + 3));
                  Ext_Data_F : constant Natural := Cursor + 4;
               begin
                  if Ext_Data_F + Ext_Data_Len - 1 > El then
                     return;
                  end if;

                  if Ext_Type = 51 and then Ext_Data_Len >= 4 then
                     declare
                        Kx_Len : constant Natural :=
                          Natural (Local (Ext_Data_F + 2)) * 256
                          + Natural (Local (Ext_Data_F + 3));
                        Kx_F : constant Natural := Ext_Data_F + 4;
                     begin
                        if Kx_Len = 32 and then
                           Kx_F + 31 <= El
                        then
                           Key_Share_First :=
                             In_Bytes'First + Kx_F - 1;
                           Key_Share_Last :=
                             In_Bytes'First + Kx_F + 30;
                           OK := True;
                        end if;
                     end;
                     return;
                  end if;

                  Cursor := Ext_Data_F + Ext_Data_Len;
               end;
            end loop;
         end;
      end;
   end Decode_Server_Hello_Key_Share;

end Tls_Core.Hello_Rflx;
