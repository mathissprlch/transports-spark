with Ada.Text_IO;
with RFLX.RFLX_Types;
with RFLX.TLS_Extensions;
with RFLX.TLS_Extensions.Extension;
with RFLX.TLS_Extensions.Extension_List;
with RFLX.Key_Share;
with RFLX.Key_Share.Key_Share_Entry;
with RFLX.Key_Share.Key_Share_Entry_List;

package body Tls_Core.Ext_Walk_Rflx
with SPARK_Mode
is

   use type RFLX.RFLX_Types.Bit_Length;
   use type RFLX.RFLX_Types.Index;
   use type RFLX.TLS_Extensions.Extension_Type;

   procedure Find_Key_Share_X25519
     (Ext_Bytes       : Octet_Array;
      Key_Share_First : out Natural;
      Key_Share_Last  : out Natural;
      Found           : out Boolean)
   is
      package EL renames RFLX.TLS_Extensions.Extension_List;
      package Ext renames RFLX.TLS_Extensions.Extension;

      Buf : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'
          (1 .. RFLX.RFLX_Types.Index (Ext_Bytes'Length) => 0);
      Seq_Ctx : EL.Context;
      Ext_Ctx : Ext.Context;
      J : RFLX.RFLX_Types.Index := 1;
   begin
      Key_Share_First := 0;
      Key_Share_Last  := 0;
      Found           := False;

      for I in Ext_Bytes'Range loop
         Buf (J) := RFLX.RFLX_Types.Byte (Ext_Bytes (I));
         J := J + 1;
      end loop;

      EL.Initialize (Seq_Ctx, Buf);

      Ada.Text_IO.Put_Line
        ("EXT-WALK: len=" & Ext_Bytes'Length'Image
         & " has_elem=" & EL.Has_Element (Seq_Ctx)'Image);

      if Ext_Bytes'Length >= 4 then
         Ada.Text_IO.Put
           ("EXT-WALK: first 8 bytes:");
         for K in 1 .. Natural'Min (8, Ext_Bytes'Length) loop
            declare
               V : constant Natural :=
                 Natural (Ext_Bytes (K));
               H : constant String := V'Image;
            begin
               Ada.Text_IO.Put (" " & H);
            end;
         end loop;
         Ada.Text_IO.New_Line;
      end if;

      while EL.Has_Element (Seq_Ctx) loop
         pragma Loop_Invariant (EL.Has_Buffer (Seq_Ctx));

         EL.Switch (Seq_Ctx, Ext_Ctx);

         Ada.Text_IO.Put_Line
           ("EXT-WALK: switched, wf="
            & Ext.Well_Formed_Message (Ext_Ctx)'Image);

         if not Ext.Well_Formed_Message (Ext_Ctx) then
            EL.Update (Seq_Ctx, Ext_Ctx);
            exit;
         end if;

         Ada.Text_IO.Put_Line
           ("EXT-WALK: type="
            & Ext.Get_Ext_Type (Ext_Ctx)'Image);

         if Ext.Get_Ext_Type (Ext_Ctx) =
              51
         then
            declare
               Ext_Data_First : constant Natural := Natural
                 (Ext.Field_First (Ext_Ctx, Ext.F_Data)) / 8 + 1;
               Ext_Data_Len : constant Natural := Natural
                 (Ext.Get_Length (Ext_Ctx));
            begin
               if Ext_Data_Len >= 6 then
                  declare
                     Ks_List_Len : constant Natural :=
                       Natural (Buf (RFLX.RFLX_Types.Index
                                       (Ext_Data_First))) * 256
                       + Natural (Buf (RFLX.RFLX_Types.Index
                                        (Ext_Data_First + 1)));
                     Ks_Cur : Natural := Ext_Data_First + 2;
                     Ks_End : constant Natural :=
                       Ext_Data_First + 2 + Ks_List_Len - 1;
                  begin
                     if Ks_List_Len >= 4
                       and then Ks_End
                                  <= Ext_Data_First + Ext_Data_Len - 1
                     then
                        while Ks_Cur + 3 <= Ks_End loop
                           declare
                              Grp : constant Natural :=
                                Natural (Buf (RFLX.RFLX_Types
                                                .Index (Ks_Cur)))
                                  * 256
                                + Natural (Buf (RFLX.RFLX_Types
                                                  .Index
                                                    (Ks_Cur + 1)));
                              Kx_L : constant Natural :=
                                Natural (Buf (RFLX.RFLX_Types
                                                .Index
                                                  (Ks_Cur + 2)))
                                  * 256
                                + Natural (Buf (RFLX.RFLX_Types
                                                  .Index
                                                    (Ks_Cur + 3)));
                              Kx_F : constant Natural :=
                                Ks_Cur + 4;
                           begin
                              if Kx_F + Kx_L - 1 > Ks_End then
                                 exit;
                              end if;
                              if Grp = 16#001D#
                                and then Kx_L = 32
                              then
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
               end if;
            end;
         end if;

         EL.Update (Seq_Ctx, Ext_Ctx);

         if Found then
            exit;
         end if;
      end loop;

      EL.Take_Buffer (Seq_Ctx, Buf);
      RFLX.RFLX_Types.Free (Buf);
   end Find_Key_Share_X25519;

   procedure Find_Sig_Algs
     (Ext_Bytes      : Octet_Array;
      Sig_Algs_First : out Natural;
      Sig_Algs_Last  : out Natural;
      Found          : out Boolean)
   is
      package EL renames RFLX.TLS_Extensions.Extension_List;
      package Ext renames RFLX.TLS_Extensions.Extension;

      Buf : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'
          (1 .. RFLX.RFLX_Types.Index (Ext_Bytes'Length) => 0);
      Seq_Ctx : EL.Context;
      Ext_Ctx : Ext.Context;
      J : RFLX.RFLX_Types.Index := 1;
   begin
      Sig_Algs_First := 0;
      Sig_Algs_Last  := 0;
      Found          := False;

      for I in Ext_Bytes'Range loop
         Buf (J) := RFLX.RFLX_Types.Byte (Ext_Bytes (I));
         J := J + 1;
      end loop;

      EL.Initialize (Seq_Ctx, Buf);

      while EL.Has_Element (Seq_Ctx) loop
         pragma Loop_Invariant (EL.Has_Buffer (Seq_Ctx));

         EL.Switch (Seq_Ctx, Ext_Ctx);
         if not Ext.Well_Formed_Message (Ext_Ctx) then
            EL.Update (Seq_Ctx, Ext_Ctx);
            exit;
         end if;

         if Ext.Get_Ext_Type (Ext_Ctx) =
              13
         then
            declare
               Ext_Data_First : constant Natural := Natural
                 (Ext.Field_First (Ext_Ctx, Ext.F_Data)) / 8 + 1;
               Ext_Data_Len : constant Natural := Natural
                 (Ext.Get_Length (Ext_Ctx));
            begin
               if Ext_Data_Len >= 4 then
                  declare
                     Sa_List_Len : constant Natural :=
                       Natural (Buf (RFLX.RFLX_Types.Index
                                       (Ext_Data_First))) * 256
                       + Natural (Buf (RFLX.RFLX_Types.Index
                                        (Ext_Data_First + 1)));
                     Sa_F : constant Natural :=
                       Ext_Data_First + 2;
                  begin
                     if Sa_List_Len >= 2
                       and then Sa_F + Sa_List_Len - 1
                                  <= Ext_Data_First + Ext_Data_Len - 1
                     then
                        Sig_Algs_First := Sa_F;
                        Sig_Algs_Last  := Sa_F + Sa_List_Len - 1;
                        Found := True;
                     end if;
                  end;
               end if;
            end;
         end if;

         EL.Update (Seq_Ctx, Ext_Ctx);

         if Found then
            exit;
         end if;
      end loop;

      EL.Take_Buffer (Seq_Ctx, Buf);
      RFLX.RFLX_Types.Free (Buf);
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
      package EL renames RFLX.TLS_Extensions.Extension_List;
      package Ext renames RFLX.TLS_Extensions.Extension;

      Buf : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'
          (1 .. RFLX.RFLX_Types.Index (Ext_Bytes'Length) => 0);
      Seq_Ctx : EL.Context;
      Ext_Ctx : Ext.Context;
      J : RFLX.RFLX_Types.Index := 1;
   begin
      Identity_First := 0;
      Identity_Last  := 0;
      Binder_First   := 0;
      Binder_Last    := 0;
      Truncated_Last := 0;
      Found          := False;

      for I in Ext_Bytes'Range loop
         Buf (J) := RFLX.RFLX_Types.Byte (Ext_Bytes (I));
         J := J + 1;
      end loop;

      EL.Initialize (Seq_Ctx, Buf);

      while EL.Has_Element (Seq_Ctx) loop
         pragma Loop_Invariant (EL.Has_Buffer (Seq_Ctx));

         EL.Switch (Seq_Ctx, Ext_Ctx);
         if not Ext.Well_Formed_Message (Ext_Ctx) then
            EL.Update (Seq_Ctx, Ext_Ctx);
            exit;
         end if;

         if Ext.Get_Ext_Type (Ext_Ctx) =
              41
         then
            declare
               Ext_Data_First : constant Natural := Natural
                 (Ext.Field_First (Ext_Ctx, Ext.F_Data)) / 8 + 1;
               Ext_Data_Len : constant Natural := Natural
                 (Ext.Get_Length (Ext_Ctx));
            begin
               if Ext_Data_Len >= 9 then
                  declare
                     Ids_Len : constant Natural :=
                       Natural (Buf (RFLX.RFLX_Types.Index
                                       (Ext_Data_First))) * 256
                       + Natural (Buf (RFLX.RFLX_Types.Index
                                        (Ext_Data_First + 1)));
                     Ids_F : constant Natural :=
                       Ext_Data_First + 2;
                  begin
                     if Ids_Len >= 7 and then
                        Ids_F + Ids_Len - 1
                          <= Ext_Data_First + Ext_Data_Len - 1
                     then
                        declare
                           Id_Len : constant Natural :=
                             Natural (Buf (RFLX.RFLX_Types
                                            .Index (Ids_F))) * 256
                             + Natural (Buf (RFLX.RFLX_Types
                                              .Index (Ids_F + 1)));
                           Id_F : constant Natural := Ids_F + 2;
                        begin
                           if Id_Len >= 1 and then
                              Id_F + Id_Len - 1
                                <= Ext_Data_First + Ext_Data_Len - 1
                           then
                              Identity_First := Id_F;
                              Identity_Last  := Id_F + Id_Len - 1;
                           end if;
                        end;
                        declare
                           Binders_Off : constant Natural :=
                             Ids_F + Ids_Len;
                        begin
                           Truncated_Last := Binders_Off - 1;
                           if Binders_Off + 1
                                <= Ext_Data_First + Ext_Data_Len - 1
                           then
                              declare
                                 Binders_Len : constant Natural :=
                                   Natural (Buf (RFLX.RFLX_Types
                                     .Index (Binders_Off))) * 256
                                   + Natural (Buf (RFLX.RFLX_Types
                                       .Index (Binders_Off + 1)));
                                 B_F : constant Natural :=
                                   Binders_Off + 2;
                              begin
                                 if Binders_Len >= 33
                                   and then B_F
                                     <= Ext_Data_First
                                          + Ext_Data_Len - 1
                                 then
                                    declare
                                       B_Len : constant Natural :=
                                         Natural (Buf
                                           (RFLX.RFLX_Types
                                              .Index (B_F)));
                                       B_Data : constant Natural :=
                                         B_F + 1;
                                    begin
                                       if B_Len >= 32
                                         and then B_Data + B_Len - 1
                                           <= Ext_Data_First
                                                + Ext_Data_Len - 1
                                       then
                                          Binder_First := B_Data;
                                          Binder_Last :=
                                            B_Data + B_Len - 1;
                                          Found := True;
                                       end if;
                                    end;
                                 end if;
                              end;
                           end if;
                        end;
                     end if;
                  end;
               end if;
            end;
         end if;

         EL.Update (Seq_Ctx, Ext_Ctx);

         if Found then
            exit;
         end if;
      end loop;

      EL.Take_Buffer (Seq_Ctx, Buf);
      RFLX.RFLX_Types.Free (Buf);
   end Find_Psk_Fields;

end Tls_Core.Ext_Walk_Rflx;
