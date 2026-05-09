with RFLX.RFLX_Builtin_Types;
with RFLX.RFLX_Types;
with RFLX.Client_Hello.Message;

package body Tls_Core.Client_Hello_Rflx
with SPARK_Mode
is

   use type RFLX.RFLX_Types.Bit_Length;
   use type RFLX.RFLX_Types.Base_Integer;
   use type RFLX.RFLX_Types.Index;

   function Rflx_Validate_Ch
     (In_Bytes : Octet_Array) return Boolean
   with Pre => In_Bytes'First = 1 and then In_Bytes'Length >= 42
   is
      package CH renames RFLX.Client_Hello.Message;
      Buf : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'
          (1 .. RFLX.RFLX_Types.Index (In_Bytes'Length) => 0);
      Ctx    : CH.Context;
      WL     : constant RFLX.RFLX_Types.Bit_Length :=
        RFLX.RFLX_Types.Bit_Length (In_Bytes'Length) * 8;
      J      : RFLX.RFLX_Types.Index := 1;
      Result : Boolean;
   begin
      for I in In_Bytes'Range loop
         Buf (J) := RFLX.RFLX_Types.Byte (In_Bytes (I));
         J := J + 1;
      end loop;
      CH.Initialize (Ctx, Buf, Written_Last => WL);
      CH.Verify_Message (Ctx);
      Result := CH.Well_Formed_Message (Ctx);
      CH.Take_Buffer (Ctx, Buf);
      RFLX.RFLX_Types.Free (Buf);
      return Result;
   end Rflx_Validate_Ch;

   procedure Decode_Client_Hello_Fields
     (In_Bytes      : Octet_Array;
      Random        : out Random_Bytes;
      Sid_First     : out Natural;
      Sid_Last      : out Natural;
      Suites_First  : out Natural;
      Suites_Last   : out Natural;
      Ext_First     : out Natural;
      Ext_Last      : out Natural;
      OK            : out Boolean)
   is
   begin
      Random       := (others => 0);
      Sid_First    := 0;
      Sid_Last     := 0;
      Suites_First := 0;
      Suites_Last  := 0;
      Ext_First    := 0;
      Ext_Last     := 0;
      OK           := False;

      if not Rflx_Validate_Ch (In_Bytes) then
         return;
      end if;

      if In_Bytes (1) /= 16#03# or else In_Bytes (2) /= 16#03# then
         return;
      end if;
      if In_Bytes (35) > 32 then
         return;
      end if;

      declare
         Sid_Len       : constant Natural := Natural (In_Bytes (35));
         Suites_Off    : constant Natural := 36 + Sid_Len;
      begin
         if Suites_Off + 1 > In_Bytes'Last then
            return;
         end if;

         declare
            S_Len : constant Natural :=
              Natural (In_Bytes (Suites_Off)) * 256
              + Natural (In_Bytes (Suites_Off + 1));
            S_First : constant Natural := Suites_Off + 2;
            S_Last  : constant Natural := S_First + S_Len - 1;
         begin
            if S_Len < 2 or else S_Len mod 2 /= 0 then
               return;
            end if;
            if S_Last > In_Bytes'Last then
               return;
            end if;

            Random := In_Bytes (3 .. 34);

            pragma Assert
              (Suites_Off = CH_Suites_Len_Off (In_Bytes));
            pragma Assert (S_Len = CH_Suites_Len (In_Bytes));
            pragma Assert (S_First = CH_Suites_First (In_Bytes));
            pragma Assert (Random = CH_Random (In_Bytes));

            if Sid_Len > 0 then
               Sid_First := 36;
               Sid_Last  := 35 + Sid_Len;
            end if;

            Suites_First := S_First;
            Suites_Last  := S_Last;

            declare
               Comp_Off : constant Natural := S_Last + 1;
            begin
               if Comp_Off > In_Bytes'Last then
                  OK := True;
                  return;
               end if;
               declare
                  Comp_Len : constant Natural :=
                    Natural (In_Bytes (Comp_Off));
                  Ext_Len_Off : constant Natural :=
                    Comp_Off + 1 + Comp_Len;
               begin
                  if Ext_Len_Off + 1 > In_Bytes'Last then
                     OK := True;
                     return;
                  end if;
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
               end;
            end;

            pragma Assert (CH_Valid (In_Bytes));
            OK := True;
         end;
      end;
   end Decode_Client_Hello_Fields;

end Tls_Core.Client_Hello_Rflx;
