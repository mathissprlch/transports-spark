with RFLX.RFLX_Types;
with RFLX.TLS_Extensions;
with RFLX.TLS_Extensions.Extension;
with RFLX.TLS_Extensions.Extension_List;

package body Tls_Core.Ext_Walk_Rflx
with SPARK_Mode
is

   use type RFLX.RFLX_Types.Bit_Length;
   use type RFLX.RFLX_Types.Index;
   use type RFLX.TLS_Extensions.Extension_Type;
   use type RFLX.RFLX_Types.Bytes_Ptr;

   procedure Walk_Find
     (Ext_Bytes  : Octet_Array;
      Want_Type  : Natural;
      Data_First : out Natural;
      Data_Len   : out Natural;
      Buf_Ref    : out RFLX.RFLX_Types.Bytes_Ptr;
      Found      : out Boolean)
   with
     Pre  => Ext_Bytes'First = 1
             and then Ext_Bytes'Length >= 4
             and then Ext_Bytes'Last < Natural'Last / 2,
     Post =>
       Buf_Ref /= null
       and then (if Found then
                   Data_First >= 1
                   and then Data_Len >= 0
                   and then Data_First + Data_Len - 1
                              <= Ext_Bytes'Length)
   is
      package EL renames RFLX.TLS_Extensions.Extension_List;
      package Ext renames RFLX.TLS_Extensions.Extension;
      Buf     : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'
          (1 .. RFLX.RFLX_Types.Index (Ext_Bytes'Length) => 0);
      Seq_Ctx : EL.Context;
      Ext_Ctx : Ext.Context;
      J       : RFLX.RFLX_Types.Index := 1;
   begin
      Data_First := 0;
      Data_Len   := 0;
      Buf_Ref    := null;
      Found      := False;
      for I in Ext_Bytes'Range loop
         pragma Loop_Invariant
           (J = RFLX.RFLX_Types.Index (I));
         pragma Loop_Invariant (J in Buf'Range);
         Buf (J) := RFLX.RFLX_Types.Byte (Ext_Bytes (I));
         J := J + 1;
      end loop;
      EL.Initialize (Seq_Ctx, Buf);
      while EL.Has_Element (Seq_Ctx) loop
         pragma Loop_Invariant (EL.Has_Buffer (Seq_Ctx));
         EL.Switch (Seq_Ctx, Ext_Ctx);
         Ext.Verify_Message (Ext_Ctx);
         if not Ext.Well_Formed_Message (Ext_Ctx) then
            EL.Update (Seq_Ctx, Ext_Ctx);
            exit;
         end if;
         if Natural (Ext.Get_Ext_Type (Ext_Ctx)) = Want_Type then
            declare
               FF : constant RFLX.RFLX_Types.Bit_Index :=
                 Ext.Field_First (Ext_Ctx, Ext.F_Data);
               DL_Val : constant Natural :=
                 Natural (Ext.Get_Length (Ext_Ctx));
            begin
               pragma Assert (FF >= 1);
               Data_First := Natural (FF) / 8 + 1;
               pragma Assert (Data_First >= 1);
               Data_Len := DL_Val;
               Found := True;
            end;
         end if;
         EL.Update (Seq_Ctx, Ext_Ctx);
         if Found then exit; end if;
      end loop;
      EL.Take_Buffer (Seq_Ctx, Buf);
      Buf_Ref := Buf;
   end Walk_Find;

   procedure Find_Key_Share_X25519
     (Ext_Bytes       : Octet_Array;
      Key_Share_First : out Natural;
      Key_Share_Last  : out Natural;
      Found           : out Boolean)
   is
      Df, Dl : Natural;
      Buf : RFLX.RFLX_Types.Bytes_Ptr;
      Ext_Found : Boolean;
   begin
      Key_Share_First := 0;
      Key_Share_Last  := 0;
      Found           := False;
      Walk_Find (Ext_Bytes, 51, Df, Dl, Buf, Ext_Found);
      if not Ext_Found or else Dl < 6 or else Buf = null
        or else Df < 1
        or else Df + Dl - 1 > Ext_Bytes'Length
        or else Df + 1 > Natural'Last / 2
      then
         if Buf /= null then RFLX.RFLX_Types.Free (Buf); end if;
         return;
      end if;
      pragma Assert (Df >= 1);
      pragma Assert (Df + Dl - 1 <= Ext_Bytes'Length);
      pragma Assert (Dl >= 6);
      pragma Assert (Df + 1 <= Ext_Bytes'Length);
      declare
         Ks_Len : constant Natural :=
           Natural (Buf (RFLX.RFLX_Types.Index (Df))) * 256
           + Natural (Buf (RFLX.RFLX_Types.Index (Df + 1)));
         Ks_Cur : Natural := Df + 2;
         Ks_End : constant Natural := Df + 2 + Ks_Len - 1;
      begin
         if Ks_Len >= 4
           and then Ks_End <= Df + Dl - 1
           and then Ks_End <= Ext_Bytes'Length
           and then Ks_End < Natural'Last - 4
         then
            while Ks_Cur + 3 <= Ks_End loop
               pragma Loop_Invariant
                 (Ks_Cur >= Df + 2
                  and then Ks_Cur <= Ks_End
                  and then Ks_End <= Ext_Bytes'Length
                  and then Ks_Cur + 3 <= Ext_Bytes'Length);
               declare
                  Grp : constant Natural :=
                    Natural (Buf (RFLX.RFLX_Types.Index (Ks_Cur)))
                      * 256
                    + Natural (Buf (RFLX.RFLX_Types.Index
                                      (Ks_Cur + 1)));
                  Kx_L : constant Natural :=
                    Natural (Buf (RFLX.RFLX_Types.Index
                                    (Ks_Cur + 2))) * 256
                    + Natural (Buf (RFLX.RFLX_Types.Index
                                      (Ks_Cur + 3)));
                  Kx_F : constant Natural := Ks_Cur + 4;
               begin
                  if Kx_F + Kx_L - 1 > Ks_End then exit; end if;
                  if Grp = 16#001D# and then Kx_L = 32 then
                     Key_Share_First := Kx_F;
                     Key_Share_Last  := Kx_F + 31;
                     Found := True;
                     exit;
                  end if;
                  Ks_Cur := Kx_F + Kx_L;
               end;
            end loop;
         end if;
      end;
      RFLX.RFLX_Types.Free (Buf);
   end Find_Key_Share_X25519;

   procedure Find_Key_Share_X25519_Sh
     (Ext_Bytes       : Octet_Array;
      Key_Share_First : out Natural;
      Key_Share_Last  : out Natural;
      Found           : out Boolean)
   is
      Df, Dl : Natural;
      Buf : RFLX.RFLX_Types.Bytes_Ptr;
      Ext_Found : Boolean;
   begin
      Key_Share_First := 0;
      Key_Share_Last  := 0;
      Found           := False;
      Walk_Find (Ext_Bytes, 51, Df, Dl, Buf, Ext_Found);
      if Buf /= null then RFLX.RFLX_Types.Free (Buf); end if;
      if not Ext_Found or else Dl < 36
        or else Df < 1
        or else Df + 35 > Ext_Bytes'Length
      then return; end if;
      declare
         Grp : constant Natural :=
           Natural (Ext_Bytes (Df)) * 256
           + Natural (Ext_Bytes (Df + 1));
         Kx_Len : constant Natural :=
           Natural (Ext_Bytes (Df + 2)) * 256
           + Natural (Ext_Bytes (Df + 3));
      begin
         if Grp = 16#001D# and then Kx_Len = 32
           and then Df + 35 <= Ext_Bytes'Length
         then
            Key_Share_First := Df + 4;
            Key_Share_Last  := Df + 35;
            Found := True;
         end if;
      end;
   end Find_Key_Share_X25519_Sh;

   procedure Find_Sig_Algs
     (Ext_Bytes      : Octet_Array;
      Sig_Algs_First : out Natural;
      Sig_Algs_Last  : out Natural;
      Found          : out Boolean)
   is
      Df, Dl : Natural;
      Buf : RFLX.RFLX_Types.Bytes_Ptr;
      Ext_Found : Boolean;
   begin
      Sig_Algs_First := 0;
      Sig_Algs_Last  := 0;
      Found          := False;
      Walk_Find (Ext_Bytes, 13, Df, Dl, Buf, Ext_Found);
      if Buf /= null then RFLX.RFLX_Types.Free (Buf); end if;
      if not Ext_Found or else Dl < 4
        or else Df < 1
        or else Df + Dl - 1 > Ext_Bytes'Length
        or else Df + 1 > Natural'Last / 2
      then return; end if;
      declare
         Sa_Len : constant Natural :=
           Natural (Ext_Bytes (Df)) * 256
           + Natural (Ext_Bytes (Df + 1));
         Sa_F : constant Natural := Df + 2;
      begin
         if Sa_Len >= 2 and then Sa_F + Sa_Len - 1 <= Df + Dl - 1
         then
            Sig_Algs_First := Sa_F;
            Sig_Algs_Last  := Sa_F + Sa_Len - 1;
            Found := True;
         end if;
      end;
   end Find_Sig_Algs;

   procedure Find_Psk_Fields
     (Ext_Bytes       : Octet_Array;
      Identity_First  : out Natural;
      Identity_Last   : out Natural;
      Binder_First    : out Natural;
      Binder_Last     : out Natural;
      Truncated_Last  : out Natural;
      Found           : out Boolean)
   is
      Df, Dl : Natural;
      Buf : RFLX.RFLX_Types.Bytes_Ptr;
      Ext_Found : Boolean;
   begin
      Identity_First := 0; Identity_Last := 0;
      Binder_First := 0; Binder_Last := 0;
      Truncated_Last := 0; Found := False;
      Walk_Find (Ext_Bytes, 41, Df, Dl, Buf, Ext_Found);
      if Buf /= null then RFLX.RFLX_Types.Free (Buf); end if;
      if not Ext_Found or else Dl < 9
        or else Df < 1
        or else Df + Dl - 1 > Ext_Bytes'Length
        or else Df + 1 > Natural'Last / 2
      then return; end if;
      declare
         Ids_Len : constant Natural :=
           Natural (Ext_Bytes (Df)) * 256
           + Natural (Ext_Bytes (Df + 1));
         Ids_F : constant Natural := Df + 2;
      begin
         if Ids_Len < 7 or else Ids_F + Ids_Len - 1 > Df + Dl - 1
         then return; end if;
         declare
            Id_Len : constant Natural :=
              Natural (Ext_Bytes (Ids_F)) * 256
              + Natural (Ext_Bytes (Ids_F + 1));
            Id_F : constant Natural := Ids_F + 2;
         begin
            if Id_Len >= 1 and then
               Id_F + Id_Len - 1 <= Df + Dl - 1
            then
               Identity_First := Id_F;
               Identity_Last  := Id_F + Id_Len - 1;
            end if;
         end;
         declare
            Binders_Off : constant Natural := Ids_F + Ids_Len;
         begin
            Truncated_Last := Binders_Off - 1;
            if Binders_Off + 1 <= Df + Dl - 1 then
               declare
                  Bl : constant Natural :=
                    Natural (Ext_Bytes (Binders_Off)) * 256
                    + Natural (Ext_Bytes (Binders_Off + 1));
                  Bf : constant Natural := Binders_Off + 2;
               begin
                  if Bl >= 33 and then Bf <= Df + Dl - 1 then
                     declare
                        B_Len : constant Natural :=
                          Natural (Ext_Bytes (Bf));
                        B_D : constant Natural := Bf + 1;
                     begin
                        if B_Len >= 32 and then
                           B_D + B_Len - 1 <= Df + Dl - 1
                        then
                           Binder_First := B_D;
                           Binder_Last := B_D + B_Len - 1;
                           Found := True;
                        end if;
                     end;
                  end if;
               end;
            end if;
         end;
      end;
   end Find_Psk_Fields;

end Tls_Core.Ext_Walk_Rflx;
