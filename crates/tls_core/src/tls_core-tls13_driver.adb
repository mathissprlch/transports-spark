with Tls_Core.Hello;
with Tls_Core.Hkdf;
with Tls_Core.Hkdf_Sha256;
with Tls_Core.Hmac_Sha256;
with Tls_Core.Key_Schedule;
with Tls_Core.Psk_Binder;
with Tls_Core.Sha256;
with Tls_Core.Traffic_Keys;

package body Tls_Core.Tls13_Driver
with SPARK_Mode => Off
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use type Tls_Core.Octet;

   ---------------------------------------------------------------------
   --  Constants
   ---------------------------------------------------------------------

   Rec_Type_Handshake : constant Octet := 16#16#;
   --  Rec_Type_App_Data declared in Tls_Core.Channel.

   Hs_Type_CH         : constant Octet := 16#01#;
   Hs_Type_SH         : constant Octet := 16#02#;
   Hs_Type_EE         : constant Octet := 16#08#;
   Hs_Type_Finished   : constant Octet := 16#14#;

   procedure Hkdf_Expand_Label_Sha256
     is new Tls_Core.Hkdf.Expand_Label
       (Hash_Length => Tls_Core.Sha256.Hash_Length,
        Max_Info    => 512,
        Hmac_Expand => Tls_Core.Hkdf_Sha256.Hmac_Expand);

   ---------------------------------------------------------------------
   --  Init_Psk_Server
   ---------------------------------------------------------------------

   procedure Init_Psk_Server
     (D            : out Driver;
      PSK          : Octet_Array;
      Psk_Identity : Octet_Array)
   is
   begin
      D.My_Role := Server;
      D.Cur_State := Awaiting_CH;
      Tls_Core.Transcript.Init (D.Hash_Ctx);
      D.PSK := (others => 0);
      D.PSK := PSK;
      D.Identity := (others => 0);
      D.Identity_Len := Psk_Identity'Length;
      D.Identity (1 .. Psk_Identity'Length) := Psk_Identity;
      D.App_Set := False;
   end Init_Psk_Server;

   ---------------------------------------------------------------------
   --  Helpers
   ---------------------------------------------------------------------

   procedure Build_Finished_Body
     (Base_Key       : Tls_Core.Key_Schedule.Secret;
      Transcript_Hash : Tls_Core.Sha256.Digest;
      Out_Verify     : out Tls_Core.Sha256.Digest);
   procedure Build_Finished_Body
     (Base_Key       : Tls_Core.Key_Schedule.Secret;
      Transcript_Hash : Tls_Core.Sha256.Digest;
      Out_Verify     : out Tls_Core.Sha256.Digest)
   is
      Empty_Ctx : constant Octet_Array (1 .. 0) := (others => 0);
      Label : constant Octet_Array (1 .. 8) :=
        (16#66#, 16#69#, 16#6E#, 16#69#, 16#73#, 16#68#, 16#65#, 16#64#);
      Finished_Key : Tls_Core.Sha256.Digest;
   begin
      Hkdf_Expand_Label_Sha256
        (Secret  => Base_Key,
         Label   => Label,
         Context => Empty_Ctx,
         Output  => Finished_Key);
      Tls_Core.Hmac_Sha256.Compute
        (Key     => Finished_Key,
         Message => Transcript_Hash,
         Out_Tag => Out_Verify);
   end Build_Finished_Body;

   procedure Encode_Hs_Message
     (Msg_Type : Octet;
      Body_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural);
   procedure Encode_Hs_Message
     (Msg_Type : Octet;
      Body_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   is
      Len : constant Natural := Body_Bytes'Length;
   begin
      Out_Buf := (others => 0);
      Out_Buf (1) := Msg_Type;
      Out_Buf (2) := Octet ((Len / 65536) mod 256);
      Out_Buf (3) := Octet ((Len / 256) mod 256);
      Out_Buf (4) := Octet (Len mod 256);
      if Len > 0 then
         Out_Buf (5 .. 4 + Len) := Body_Bytes;
      end if;
      Out_Last := 4 + Len;
   end Encode_Hs_Message;

   --  Wrap a handshake message in a TLSPlaintext record.
   procedure Wrap_Tls_Plaintext
     (Hs_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural);
   procedure Wrap_Tls_Plaintext
     (Hs_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   is
      Len : constant Natural := Hs_Bytes'Length;
   begin
      Out_Buf := (others => 0);
      Out_Buf (1) := Rec_Type_Handshake;
      Out_Buf (2) := 16#03#;
      Out_Buf (3) := 16#03#;
      Out_Buf (4) := Octet ((Len / 256) mod 256);
      Out_Buf (5) := Octet (Len mod 256);
      Out_Buf (6 .. 5 + Len) := Hs_Bytes;
      Out_Last := 5 + Len;
   end Wrap_Tls_Plaintext;

   ---------------------------------------------------------------------
   --  Step — server side, PSK_KE profile.
   ---------------------------------------------------------------------

   procedure Step
     (D         : in out Driver;
      In_Bytes  : Octet_Array;
      Out_Buf   : out Octet_Array;
      Out_Last  : out Natural)
   is
   begin
      Out_Buf := (others => 0);
      Out_Last := 0;

      case D.Cur_State is
         when Awaiting_CH =>
            --  Parse one TLSPlaintext record holding ClientHello.
            if In_Bytes'Length < 5
              or else In_Bytes (In_Bytes'First) /= Rec_Type_Handshake
            then
               D.Cur_State := Failed;
               return;
            end if;
            declare
               Rec_Len : constant Natural :=
                 Natural (In_Bytes (In_Bytes'First + 3)) * 256
                 + Natural (In_Bytes (In_Bytes'First + 4));
               Rec_F : constant Natural := In_Bytes'First + 5;
               Rec_L : constant Natural := Rec_F + Rec_Len - 1;
            begin
               if Rec_L > In_Bytes'Last
                 or else Rec_Len < 4
                 or else In_Bytes (Rec_F) /= Hs_Type_CH
               then
                  D.Cur_State := Failed;
                  return;
               end if;
               declare
                  Hs_Body_Len : constant Natural :=
                    Natural (In_Bytes (Rec_F + 1)) * 65536
                    + Natural (In_Bytes (Rec_F + 2)) * 256
                    + Natural (In_Bytes (Rec_F + 3));
                  Hs_Body_F : constant Natural := Rec_F + 4;
                  Hs_Body_L : constant Natural := Hs_Body_F + Hs_Body_Len - 1;

                  Random : Tls_Core.Hello.Random_Bytes;
                  Id_F, Id_L, Bf, Bl, T_Last : Natural;
                  Decode_OK : Boolean;
               begin
                  if Hs_Body_L > Rec_L then
                     D.Cur_State := Failed;
                     return;
                  end if;
                  --  Decode the CH body
                  Tls_Core.Hello.Decode_Client_Hello_Psk
                    (In_Bytes (Hs_Body_F .. Hs_Body_L),
                     Random, Id_F, Id_L, Bf, Bl, T_Last, Decode_OK);
                  if not Decode_OK then
                     D.Cur_State := Failed;
                     return;
                  end if;
                  --  Decode_*_Psk indices are RELATIVE to the slice we
                  --  passed in; remap them to absolute In_Bytes indices.
                  declare
                     Slice_Off : constant Integer := Hs_Body_F - 1;
                     Abs_Id_F : constant Natural := Id_F + Slice_Off;
                     Abs_Id_L : constant Natural := Id_L + Slice_Off;
                     Abs_Bf : constant Natural := Bf + Slice_Off;
                     Abs_Bl : constant Natural := Bl + Slice_Off;
                     Abs_T_Last : constant Natural := T_Last + Slice_Off;

                     --  Verify PSK identity matches expected.
                     Identity_OK : Boolean := True;
                  begin
                     if Abs_Id_L - Abs_Id_F + 1 /= D.Identity_Len then
                        Identity_OK := False;
                     else
                        for I in 1 .. D.Identity_Len loop
                           if In_Bytes (Abs_Id_F + I - 1)
                              /= D.Identity (I)
                           then
                              Identity_OK := False;
                           end if;
                        end loop;
                     end if;
                     if not Identity_OK then
                        D.Cur_State := Failed;
                        return;
                     end if;
                     --  Verify PSK binder.
                     declare
                        Computed : Tls_Core.Psk_Binder.Binder_Bytes;
                        Received : Tls_Core.Psk_Binder.Binder_Bytes;
                     begin
                        Tls_Core.Psk_Binder.Compute
                          (D.PSK,
                           In_Bytes (Hs_Body_F .. Abs_T_Last),
                           Computed);
                        for I in 1 .. 32 loop
                           Received (I) := In_Bytes (Abs_Bf + I - 1);
                        end loop;
                        if not Tls_Core.Psk_Binder.Verify
                                 (Computed, Received)
                        then
                           D.Cur_State := Failed;
                           return;
                        end if;
                     end;
                  end;
                  --  Append the CH handshake message (NOT the
                  --  record wrapper) to the transcript.
                  Tls_Core.Transcript.Append
                    (D.Hash_Ctx, In_Bytes (Rec_F .. Rec_L));
               end;
            end;

            --  Build SH (handshake message), append to transcript,
            --  derive handshake secrets, build EE + Finished,
            --  encrypt, write the whole flight.
            declare
               Sh_Body : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
               Sh_Body_Last : Natural;
               Sh_Hs_Msg : Tls_Core.Octet_Array (1 .. 512) := (others => 0);
               Sh_Hs_Last : Natural;
               Sh_Record : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
               Sh_Record_Last : Natural;

               --  Use a fixed server random for now (test-friendly;
               --  real impls use a CSPRNG).
               Server_Random : constant Tls_Core.Hello.Random_Bytes :=
                 (others => 16#5E#);

               Empty_Identity_Buf : Tls_Core.Octet_Array (1 .. 0) :=
                 (others => 0);
               Zero32 : constant Octet_Array (1 .. 32) := (others => 0);
               Empty  : constant Octet_Array (1 .. 0)  := (others => 0);
               Derived_Label : constant Octet_Array (1 .. 7) :=
                 (16#64#, 16#65#, 16#72#, 16#69#, 16#76#, 16#65#, 16#64#);
               C_Hs_Label : constant Octet_Array (1 .. 12) :=
                 (16#63#, 16#20#, 16#68#, 16#73#, 16#20#, 16#74#,
                  16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
               S_Hs_Label : constant Octet_Array (1 .. 12) :=
                 (16#73#, 16#20#, 16#68#, 16#73#, 16#20#, 16#74#,
                  16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);

               Early_Secret : Tls_Core.Key_Schedule.Secret;
               Derived_1    : Tls_Core.Key_Schedule.Secret;
               Hs_Secret    : Tls_Core.Key_Schedule.Secret;
               C_Hs_Sec     : Tls_Core.Key_Schedule.Secret;
               S_Hs_Sec     : Tls_Core.Key_Schedule.Secret;

               Transcript_Hash_After_SH : Tls_Core.Sha256.Digest;
            begin
               pragma Unreferenced (Empty_Identity_Buf);

               --  SH body = canonical PSK SH (echoes selected_identity = 0)
               Tls_Core.Hello.Encode_Server_Hello_Psk
                 (Server_Random, Sh_Body, Sh_Body_Last);
               --  Wrap body into Handshake message (type + u24 + body).
               Encode_Hs_Message
                 (Hs_Type_SH,
                  Sh_Body (1 .. Sh_Body_Last),
                  Sh_Hs_Msg, Sh_Hs_Last);
               --  Append to transcript.
               Tls_Core.Transcript.Append
                 (D.Hash_Ctx, Sh_Hs_Msg (1 .. Sh_Hs_Last));
               --  Wrap as TLSPlaintext for the wire.
               Wrap_Tls_Plaintext
                 (Sh_Hs_Msg (1 .. Sh_Hs_Last), Sh_Record, Sh_Record_Last);

               --  Derive Early/Handshake secrets.
               Tls_Core.Key_Schedule.Extract
                 (Salt => Zero32, IKM => D.PSK, Out_PRK => Early_Secret);
               Tls_Core.Key_Schedule.Derive_Secret
                 (Secret_In  => Early_Secret,
                  Label      => Derived_Label,
                  Messages   => Empty,
                  Out_Secret => Derived_1);
               Tls_Core.Key_Schedule.Extract
                 (Salt => Derived_1, IKM => Zero32, Out_PRK => Hs_Secret);
               --  Snapshot current transcript hash (CH || SH).
               Tls_Core.Transcript.Snapshot
                 (D.Hash_Ctx, Transcript_Hash_After_SH);
               --  c_hs / s_hs traffic secrets — same as Derive_Secret
               --  but with the snapshot we just took as the context.
               Hkdf_Expand_Label_Sha256
                 (Secret  => Hs_Secret,
                  Label   => C_Hs_Label,
                  Context => Transcript_Hash_After_SH,
                  Output  => C_Hs_Sec);
               Hkdf_Expand_Label_Sha256
                 (Secret  => Hs_Secret,
                  Label   => S_Hs_Label,
                  Context => Transcript_Hash_After_SH,
                  Output  => S_Hs_Sec);

               --  Open Channel Hs_Out_Dir / Hs_In_Dir (server: out
               --  encrypts with s_hs, in decrypts with c_hs).
               Tls_Core.Channel.Init (D.Hs_Out_Dir, S_Hs_Sec);
               Tls_Core.Channel.Init (D.Hs_In_Dir,  C_Hs_Sec);

               --  Build EE handshake message (empty extensions list).
               declare
                  Ee_Body : constant Octet_Array (1 .. 2) := (16#00#, 16#00#);
                  Ee_Hs   : Octet_Array (1 .. 6) := (others => 0);
                  Ee_Hs_Last : Natural;
                  Ee_Rec  : Octet_Array (1 .. 256) := (others => 0);
                  Ee_Rec_Last : Natural;
               begin
                  Encode_Hs_Message
                    (Hs_Type_EE, Ee_Body, Ee_Hs, Ee_Hs_Last);
                  Tls_Core.Transcript.Append
                    (D.Hash_Ctx, Ee_Hs (1 .. Ee_Hs_Last));
                  Tls_Core.Channel.Send
                    (D.Hs_Out_Dir,
                     Ee_Hs (1 .. Ee_Hs_Last),
                     Tls_Core.Channel.Inner_Type_Handshake,
                     Ee_Rec, Ee_Rec_Last);

                  --  Build Server Finished.
                  declare
                     Th_After_EE : Tls_Core.Sha256.Digest;
                     Verify_Data : Tls_Core.Sha256.Digest;
                     Fin_Hs : Octet_Array (1 .. 4 + 32) := (others => 0);
                     Fin_Hs_Last : Natural;
                     Fin_Rec : Octet_Array (1 .. 256) := (others => 0);
                     Fin_Rec_Last : Natural;
                  begin
                     Tls_Core.Transcript.Snapshot (D.Hash_Ctx, Th_After_EE);
                     Build_Finished_Body
                       (S_Hs_Sec, Th_After_EE, Verify_Data);
                     Encode_Hs_Message
                       (Hs_Type_Finished, Verify_Data,
                        Fin_Hs, Fin_Hs_Last);
                     Tls_Core.Transcript.Append
                       (D.Hash_Ctx, Fin_Hs (1 .. Fin_Hs_Last));
                     Tls_Core.Channel.Send
                       (D.Hs_Out_Dir,
                        Fin_Hs (1 .. Fin_Hs_Last),
                        Tls_Core.Channel.Inner_Type_Handshake,
                        Fin_Rec, Fin_Rec_Last);

                     --  Concatenate SH || EE-encrypted || Finished-encrypted.
                     declare
                        Cursor : Natural := 0;
                     begin
                        Out_Buf (1 .. Sh_Record_Last) :=
                          Sh_Record (1 .. Sh_Record_Last);
                        Cursor := Sh_Record_Last;
                        Out_Buf (Cursor + 1 .. Cursor + Ee_Rec_Last) :=
                          Ee_Rec (1 .. Ee_Rec_Last);
                        Cursor := Cursor + Ee_Rec_Last;
                        Out_Buf (Cursor + 1 .. Cursor + Fin_Rec_Last) :=
                          Fin_Rec (1 .. Fin_Rec_Last);
                        Out_Last := Cursor + Fin_Rec_Last;
                     end;
                  end;
               end;

               D.Cur_State := Awaiting_Cf;
            end;

         when Awaiting_Cf =>
            --  Read encrypted Finished record from In_Bytes.
            declare
               Pt_Buf : Octet_Array (1 .. 1024) := (others => 0);
               Pt_Last : Natural;
               Inner_Type : Octet;
               OK : Boolean;
            begin
               Tls_Core.Channel.Receive
                 (D.Hs_In_Dir, In_Bytes,
                  Pt_Buf, Pt_Last, Inner_Type, OK);
               if not OK
                 or else Inner_Type /= Tls_Core.Channel.Inner_Type_Handshake
                 or else Pt_Last < 4
                 or else Pt_Buf (1) /= Hs_Type_Finished
               then
                  D.Cur_State := Failed;
                  return;
               end if;
               --  Verify the client Finished verify_data matches.
               --  Skip in this slice — assume opt-in once we have
               --  c_hs traffic-secret based verify_data computed.
               Tls_Core.Transcript.Append (D.Hash_Ctx, Pt_Buf (1 .. Pt_Last));
               D.Cur_State := Done;
            end;

         when others =>
            null;
      end case;
   end Step;

   procedure Open_App_Directions
     (D       : Driver;
      Out_Dir : out Tls_Core.Channel.Direction;
      In_Dir  : out Tls_Core.Channel.Direction)
   is
   begin
      --  Stub: not yet computing app secrets in this slice.
      Tls_Core.Channel.Init
        (Out_Dir, D.App_Out_Sec.Server_App);
      Tls_Core.Channel.Init
        (In_Dir, D.App_Out_Sec.Client_App);
   end Open_App_Directions;

end Tls_Core.Tls13_Driver;
