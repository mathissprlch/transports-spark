with RFLX.RFLX_Builtin_Types;
with RFLX.RFLX_Types;
with RFLX.Server_Hello.Message;
with Tls_Core.Ext_Walk_Rflx;

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

      Last_Idx : constant RFLX.RFLX_Types.Index :=
        RFLX.RFLX_Types.Index (In_Bytes'Length);
      Buf      : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. Last_Idx => 0);
      Ctx      : SH.Context;
      WL       : constant RFLX.RFLX_Types.Bit_Length :=
        RFLX.RFLX_Types.Bit_Length (In_Bytes'Length) * 8;
      Result   : Boolean;
   begin
      for K in 1 .. Last_Idx loop
         pragma Loop_Invariant (K in 1 .. Last_Idx);
         Buf (K) := RFLX.RFLX_Types.Byte (In_Bytes (Natural (K)));
      end loop;
      if Last_Idx >= RFLX.RFLX_Types.Index'Last then
         RFLX.RFLX_Types.Free (Buf);
         return False;
      end if;
      SH.Initialize (Ctx, Buf, Written_Last => WL);
      SH.Verify_Message (Ctx);
      Result := SH.Well_Formed_Message (Ctx);
      SH.Take_Buffer (Ctx, Buf);
      RFLX.RFLX_Types.Free (Buf);
      return Result;
   end Rflx_Validate;

   procedure Decode_Server_Hello_Fields
     (In_Bytes   : Octet_Array;
      Random     : out Random_Bytes;
      Suite_Code : out Tls_Core.Suites.U16;
      Sid_First  : out Natural;
      Sid_Last   : out Natural;
      Ext_First  : out Natural;
      Ext_Last   : out Natural;
      OK         : out Boolean)
   is
      use type Tls_Core.Suites.U16;
   begin
      Random := [others => 0];
      Suite_Code := 0;
      Sid_First := 0;
      Sid_Last := 0;
      Ext_First := 0;
      Ext_Last := 0;
      OK := False;

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
         Sid_Len   : constant Natural := Natural (In_Bytes (35));
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
           Tls_Core.Suites.U16 (In_Bytes (Suite_Off))
           * 256
           + Tls_Core.Suites.U16 (In_Bytes (Suite_Off + 1));

         pragma Assert (Suite_Code = Spec_Suite_Code (In_Bytes));
         pragma Assert (Random = Spec_Random (In_Bytes));

         if Sid_Len > 0 then
            Sid_First := 36;
            Sid_Last := 35 + Sid_Len;
         end if;

         declare
            Ext_Len_Off : constant Natural := Suite_Off + 3;
         begin
            if Ext_Len_Off + 1 <= In_Bytes'Last then
               declare
                  EL : constant Natural :=
                    Natural (In_Bytes (Ext_Len_Off))
                    * 256
                    + Natural (In_Bytes (Ext_Len_Off + 1));
               begin
                  if EL > 0 and then Ext_Len_Off + 2 + EL - 1 <= In_Bytes'Last
                  then
                     Ext_First := Ext_Len_Off + 2;
                     Ext_Last := Ext_Len_Off + 1 + EL;
                  end if;
               end;
            end if;
         end;

         pragma Assert (Spec_Valid (In_Bytes));
         OK := True;
      end;
   end Decode_Server_Hello_Fields;

   procedure Encode_Server_Hello_Core
     (Random     : Random_Bytes;
      Suite_Code : Tls_Core.Suites.U16;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural)
   is
      Suite_Hi : constant Octet := Octet (Suite_Code / 16#0100#);
      Suite_Lo : constant Octet := Octet (Suite_Code mod 16#0100#);
   begin
      Out_Buf := [others => 0];
      Out_Buf (1) := 16#03#;
      Out_Buf (2) := 16#03#;
      Out_Buf (3 .. 34) := Random;
      Out_Buf (35) := 0;
      Out_Buf (36) := Suite_Hi;
      Out_Buf (37) := Suite_Lo;
      Out_Buf (38) := 0;
      Out_Buf (39) := 0;
      Out_Buf (40) := 8;
      Out_Buf (41) := 0;
      Out_Buf (42) := 16#2B#;
      Out_Buf (43) := 0;

      pragma Assert (Out_Buf (35) = 0);
      pragma Assert (Spec_Sid_Len (Out_Buf) = 0);
      pragma Assert (Spec_Suite_Offset (Out_Buf) = 36);

      pragma
        Assert
          (Tls_Core.Suites.U16 (Out_Buf (36))
             * 256
             + Tls_Core.Suites.U16 (Out_Buf (37))
             = Suite_Code);

      pragma Assert (Spec_Suite_Code (Out_Buf) = Suite_Code);
      pragma Assert (Spec_Random (Out_Buf) = Random);
      pragma Assert (Spec_Valid (Out_Buf));

      Out_Last := 43;
   end Encode_Server_Hello_Core;

   procedure Lemma_Round_Trip
     (Random : Random_Bytes; Suite_Code : Tls_Core.Suites.U16)
   is
      use type Tls_Core.Suites.U16;
      Buf      : Octet_Array (1 .. 256) := [others => 0];
      Enc_Last : Natural;
   begin
      Encode_Server_Hello_Core (Random, Suite_Code, Buf, Enc_Last);

      pragma Assert (Spec_Valid (Buf));
      pragma Assert (Spec_Random (Buf) = Random);
      pragma Assert (Spec_Suite_Code (Buf) = Suite_Code);

      pragma Assert (Buf (1) = 16#03#);
      pragma Assert (Buf (2) = 16#03#);
      pragma Assert (Buf (35) = 0);
      pragma Assert (Buf (35) <= 32);
      pragma Assert (36 + Natural (Buf (35)) + 4 <= Buf'Last);

      declare
         Sid_Len   : constant Natural := Natural (Buf (35));
         Suite_Off : constant Natural := 36 + Sid_Len;
      begin
         pragma Assert (Suite_Off = 36);
         pragma Assert (Buf (Suite_Off + 2) = 0);

         declare
            Dec_Rnd : constant Random_Bytes := Buf (3 .. 34);
            Dec_Sc  : constant Tls_Core.Suites.U16 :=
              Tls_Core.Suites.U16 (Buf (Suite_Off))
              * 256
              + Tls_Core.Suites.U16 (Buf (Suite_Off + 1));
         begin
            pragma Assert (Dec_Rnd = Spec_Random (Buf));
            pragma Assert (Dec_Sc = Spec_Suite_Code (Buf));

            pragma Assert (Dec_Rnd = Random);
            pragma Assert (Dec_Sc = Suite_Code);
         end;
      end;
   end Lemma_Round_Trip;

   procedure Decode_Server_Hello_Key_Share
     (In_Bytes        : Octet_Array;
      Key_Share_First : out Natural;
      Key_Share_Last  : out Natural;
      OK              : out Boolean)
   is
      Rnd       : Random_Bytes;
      Suite     : Tls_Core.Suites.U16;
      Sf, Sl    : Natural;
      Ef, El    : Natural;
      Fields_OK : Boolean;
   begin
      Key_Share_First := 0;
      Key_Share_Last := 0;
      OK := False;

      if In_Bytes'Length < 40 or else In_Bytes'First < 1 then
         return;
      end if;

      declare
         Local : Octet_Array (1 .. In_Bytes'Length) := In_Bytes;
      begin
         Decode_Server_Hello_Fields
           (Local, Rnd, Suite, Sf, Sl, Ef, El, Fields_OK);

         if not Fields_OK or else Ef = 0 or else El < Ef then
            return;
         end if;
         if El > Local'Last or else Ef < 1 then
            return;
         end if;

         declare
            Ext_Len : constant Natural := El - Ef + 1;
         begin
            if Ext_Len < 4 then
               return;
            end if;
            declare
               Ext_Copy     : Octet_Array (1 .. Ext_Len) := Local (Ef .. El);
               Ks_Ef, Ks_El : Natural;
               Ks_Found     : Boolean;
            begin
               Tls_Core.Ext_Walk_Rflx.Find_Key_Share_X25519_Sh
                 (Ext_Copy, Ks_Ef, Ks_El, Ks_Found);
               if Ks_Found
                 and then Ks_Ef >= 1
                 and then Ks_El >= 1
                 and then Ks_Ef <= Ext_Len
                 and then Ks_El <= Ext_Len
                 and then In_Bytes'First <= Natural'Last - Ext_Len
                 and then Ef - 1 <= Natural'Last - Ks_Ef
                 and then Ef - 1 <= Natural'Last - Ks_El
                 and then In_Bytes'First + (Ef - 1) <= Natural'Last - Ks_Ef
                 and then In_Bytes'First + (Ef - 1) <= Natural'Last - Ks_El
               then
                  Key_Share_First := In_Bytes'First + (Ef - 1) + Ks_Ef - 1;
                  Key_Share_Last := In_Bytes'First + (Ef - 1) + Ks_El - 1;
                  OK := True;
               end if;
            end;
         end;
      end;
   end Decode_Server_Hello_Key_Share;

end Tls_Core.Hello_Rflx;
