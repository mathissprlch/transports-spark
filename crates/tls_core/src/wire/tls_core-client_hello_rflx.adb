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
      if not Result then
         return True;
      end if;
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

   procedure Encode_Client_Hello_Core
     (Random     : Random_Bytes;
      Suites     : Octet_Array;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural)
   is
      S_Len : constant Natural := Suites'Length;
      S_Hi  : constant Octet := Octet (S_Len / 256);
      S_Lo  : constant Octet := Octet (S_Len mod 256);
      S_Off : constant Natural := 36;
      J     : Natural;
   begin
      Out_Buf := (others => 0);
      Out_Buf (1) := 16#03#;
      Out_Buf (2) := 16#03#;
      Out_Buf (3 .. 34) := Random;
      Out_Buf (35) := 0;
      Out_Buf (S_Off) := S_Hi;
      Out_Buf (S_Off + 1) := S_Lo;
      J := S_Off + 2;
      for I in Suites'Range loop
         Out_Buf (J) := Suites (I);
         J := J + 1;
      end loop;
      Out_Buf (J) := 1;
      Out_Buf (J + 1) := 0;

      pragma Assert (Out_Buf (35) = 0);
      pragma Assert (CH_Sid_Len (Out_Buf) = 0);
      pragma Assert (CH_Suites_Len_Off (Out_Buf) = 36);
      pragma Assert
        (Natural (Out_Buf (36)) * 256
         + Natural (Out_Buf (37)) = S_Len);
      pragma Assert (CH_Suites_Len (Out_Buf) = S_Len);
      pragma Assert (CH_Suites_First (Out_Buf) = 38);
      pragma Assert (CH_Random (Out_Buf) = Random);
      pragma Assert (CH_Valid (Out_Buf));

      Out_Last := 37 + S_Len;
   end Encode_Client_Hello_Core;

   procedure Lemma_CH_Round_Trip
     (Random : Random_Bytes;
      Suites : Octet_Array)
   is
      Buf      : Octet_Array (1 .. 256) := (others => 0);
      Enc_Last : Natural;
   begin
      Encode_Client_Hello_Core (Random, Suites, Buf, Enc_Last);

      pragma Assert (CH_Valid (Buf));
      pragma Assert (CH_Random (Buf) = Random);
      pragma Assert (CH_Suites_Len (Buf) = Suites'Length);
      pragma Assert (CH_Suites_First (Buf) = 38);

      declare
         Dec_Rnd : constant Random_Bytes := Buf (3 .. 34);
         Dec_S_F : constant Natural := 38;
         Dec_S_L : constant Natural := 37 + Suites'Length;
      begin
         pragma Assert (Dec_Rnd = Random);
         pragma Assert (Dec_S_F = CH_Suites_First (Buf));
         pragma Assert
           (Dec_S_L = CH_Suites_First (Buf)
                      + CH_Suites_Len (Buf) - 1);
      end;
   end Lemma_CH_Round_Trip;

   procedure Decode_Client_Hello_Psk
     (In_Bytes          : Octet_Array;
      Random            : out Random_Bytes;
      Sid_First         : out Natural;
      Sid_Last          : out Natural;
      Suites_First      : out Natural;
      Suites_Last       : out Natural;
      Identity_First    : out Natural;
      Identity_Last     : out Natural;
      Binder_First      : out Natural;
      Binder_Last       : out Natural;
      Key_Share_First   : out Natural;
      Key_Share_Last    : out Natural;
      Truncated_Last    : out Natural;
      OK                : out Boolean)
   is
      Ef, El : Natural;
      Fields_OK : Boolean;
   begin
      Identity_First  := 0;
      Identity_Last   := 0;
      Binder_First    := 0;
      Binder_Last     := 0;
      Key_Share_First := 0;
      Key_Share_Last  := 0;
      Truncated_Last  := 0;

      Decode_Client_Hello_Fields
        (In_Bytes, Random, Sid_First, Sid_Last,
         Suites_First, Suites_Last, Ef, El, Fields_OK);

      if not Fields_OK or else Ef = 0 then
         OK := False;
         return;
      end if;

      declare
         Cursor : Natural := Ef;
      begin
         while Cursor + 3 <= El loop
            declare
               Ext_Type : constant Natural :=
                 Natural (In_Bytes (Cursor)) * 256
                 + Natural (In_Bytes (Cursor + 1));
               Ext_Data_Len : constant Natural :=
                 Natural (In_Bytes (Cursor + 2)) * 256
                 + Natural (In_Bytes (Cursor + 3));
               Ext_Data_F : constant Natural := Cursor + 4;
            begin
               if Ext_Data_F + Ext_Data_Len - 1 > El then
                  OK := False;
                  return;
               end if;

               if Ext_Type = 51 and then Ext_Data_Len >= 6 then
                  declare
                     List_Len : constant Natural :=
                       Natural (In_Bytes (Ext_Data_F)) * 256
                       + Natural (In_Bytes (Ext_Data_F + 1));
                     Ks_Cur : Natural := Ext_Data_F + 2;
                     Ks_End : constant Natural :=
                       Ext_Data_F + 2 + List_Len - 1;
                  begin
                     if List_Len >= 4 and then Ks_End <= El then
                        while Ks_Cur + 3 <= Ks_End loop
                           declare
                              Grp : constant Natural :=
                                Natural (In_Bytes (Ks_Cur))
                                  * 256
                                + Natural
                                    (In_Bytes (Ks_Cur + 1));
                              Kx_Len : constant Natural :=
                                Natural (In_Bytes (Ks_Cur + 2))
                                  * 256
                                + Natural
                                    (In_Bytes (Ks_Cur + 3));
                              Kx_F : constant Natural :=
                                Ks_Cur + 4;
                           begin
                              if Kx_F + Kx_Len - 1 > Ks_End then
                                 exit;
                              end if;
                              if Grp = 16#001D#
                                and then Kx_Len = 32
                              then
                                 Key_Share_First := Kx_F;
                                 Key_Share_Last  := Kx_F + 31;
                                 exit;
                              end if;
                              Ks_Cur := Kx_F + Kx_Len;
                           end;
                        end loop;
                     end if;
                  end;
               end if;

               if Ext_Type = 41 and then Ext_Data_Len >= 9 then
                  declare
                     Ids_Len : constant Natural :=
                       Natural (In_Bytes (Ext_Data_F)) * 256
                       + Natural (In_Bytes (Ext_Data_F + 1));
                     Ids_F   : constant Natural := Ext_Data_F + 2;
                  begin
                     if Ids_Len >= 7 and then
                        Ids_F + Ids_Len - 1 <= El
                     then
                        declare
                           Id_Len : constant Natural :=
                             Natural (In_Bytes (Ids_F)) * 256
                             + Natural (In_Bytes (Ids_F + 1));
                           Id_F : constant Natural := Ids_F + 2;
                        begin
                           if Id_Len >= 1 and then
                              Id_F + Id_Len - 1 <= El
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
                           if Binders_Off + 1 <= El then
                              declare
                                 Binders_Len : constant Natural :=
                                   Natural
                                     (In_Bytes (Binders_Off))
                                     * 256
                                   + Natural
                                       (In_Bytes
                                          (Binders_Off + 1));
                                 B_F : constant Natural :=
                                   Binders_Off + 2;
                              begin
                                 if Binders_Len >= 33
                                   and then B_F <= El
                                 then
                                    declare
                                       B_Len : constant Natural :=
                                         Natural
                                           (In_Bytes (B_F));
                                       B_Data_F : constant
                                         Natural := B_F + 1;
                                    begin
                                       if B_Len >= 32
                                         and then B_Data_F +
                                                    B_Len - 1
                                                    <= El
                                       then
                                          Binder_First :=
                                            B_Data_F;
                                          Binder_Last :=
                                            B_Data_F +
                                              B_Len - 1;
                                       end if;
                                    end;
                                 end if;
                              end;
                           end if;
                        end;
                     end if;
                  end;
               end if;

               Cursor := Ext_Data_F + Ext_Data_Len;
            end;
         end loop;
      end;

      OK := Key_Share_First > 0 and then Identity_First > 0
            and then Binder_First > 0 and then Truncated_Last > 0;
   end Decode_Client_Hello_Psk;

   procedure Decode_Client_Hello_Cert
     (In_Bytes          : Octet_Array;
      Random            : out Random_Bytes;
      Sid_First         : out Natural;
      Sid_Last          : out Natural;
      Suites_First      : out Natural;
      Suites_Last       : out Natural;
      Sig_Algs_First    : out Natural;
      Sig_Algs_Last     : out Natural;
      Key_Share_First   : out Natural;
      Key_Share_Last    : out Natural;
      OK                : out Boolean)
   is
      Ef, El : Natural;
      Fields_OK : Boolean;
   begin
      Sig_Algs_First  := 0;
      Sig_Algs_Last   := 0;
      Key_Share_First := 0;
      Key_Share_Last  := 0;

      Decode_Client_Hello_Fields
        (In_Bytes, Random, Sid_First, Sid_Last,
         Suites_First, Suites_Last, Ef, El, Fields_OK);

      if not Fields_OK or else Ef = 0 then
         OK := False;
         return;
      end if;

      declare
         Cursor : Natural := Ef;
      begin
         while Cursor + 3 <= El loop
            declare
               Ext_Type : constant Natural :=
                 Natural (In_Bytes (Cursor)) * 256
                 + Natural (In_Bytes (Cursor + 1));
               Ext_Data_Len : constant Natural :=
                 Natural (In_Bytes (Cursor + 2)) * 256
                 + Natural (In_Bytes (Cursor + 3));
               Ext_Data_F : constant Natural := Cursor + 4;
            begin
               if Ext_Data_F + Ext_Data_Len - 1 > El then
                  OK := False;
                  return;
               end if;

               if Ext_Type = 51 and then Ext_Data_Len >= 6 then
                  declare
                     List_Len : constant Natural :=
                       Natural (In_Bytes (Ext_Data_F)) * 256
                       + Natural (In_Bytes (Ext_Data_F + 1));
                     Ks_Cur : Natural := Ext_Data_F + 2;
                     Ks_End : constant Natural :=
                       Ext_Data_F + 2 + List_Len - 1;
                  begin
                     if List_Len >= 4 and then Ks_End <= El then
                        while Ks_Cur + 3 <= Ks_End loop
                           declare
                              Grp : constant Natural :=
                                Natural (In_Bytes (Ks_Cur))
                                  * 256
                                + Natural
                                    (In_Bytes (Ks_Cur + 1));
                              Kx_Len : constant Natural :=
                                Natural (In_Bytes (Ks_Cur + 2))
                                  * 256
                                + Natural
                                    (In_Bytes (Ks_Cur + 3));
                              Kx_F : constant Natural :=
                                Ks_Cur + 4;
                           begin
                              if Kx_F + Kx_Len - 1 > Ks_End then
                                 exit;
                              end if;
                              if Grp = 16#001D#
                                and then Kx_Len = 32
                              then
                                 Key_Share_First := Kx_F;
                                 Key_Share_Last  := Kx_F + 31;
                                 exit;
                              end if;
                              Ks_Cur := Kx_F + Kx_Len;
                           end;
                        end loop;
                     end if;
                  end;
               end if;

               if Ext_Type = 13 and then Ext_Data_Len >= 4 then
                  declare
                     Sa_List_Len : constant Natural :=
                       Natural (In_Bytes (Ext_Data_F)) * 256
                       + Natural (In_Bytes (Ext_Data_F + 1));
                     Sa_F : constant Natural := Ext_Data_F + 2;
                  begin
                     if Sa_List_Len >= 2 and then
                        Sa_F + Sa_List_Len - 1 <= El
                     then
                        Sig_Algs_First := Sa_F;
                        Sig_Algs_Last  :=
                          Sa_F + Sa_List_Len - 1;
                     end if;
                  end;
               end if;

               Cursor := Ext_Data_F + Ext_Data_Len;
            end;
         end loop;
      end;

      OK := Key_Share_First > 0 and then Sig_Algs_First > 0;
   end Decode_Client_Hello_Cert;

end Tls_Core.Client_Hello_Rflx;
