with Tls_Core.Aead_Channel;
with Tls_Core.Alert;
with Tls_Core.Hello;
with Tls_Core.Hello_Retry;
with Tls_Core.Key_Sched;
with Tls_Core.Psk_Binder;
with Tls_Core.Transcript;
with Tls_Core.X25519;
with Tls_Core.Tls13_Driver.Helpers; use Tls_Core.Tls13_Driver.Helpers;

package body Tls_Core.Tls13_Driver.Step_Awaiting_Ch_Psk
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   procedure Handle
     (D        : in out Driver;
      In_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   is
   begin
      Out_Buf := (others => 0);
      Out_Last := 0;

      if In_Bytes'Length < 5
        or else In_Bytes (In_Bytes'First) /= Rec_Type_Handshake
      then
         Fail_Plaintext
           (D, Tls_Core.Alert.Desc_Decode_Error,
            Out_Buf, Out_Last);
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
            Sid_F, Sid_L : Natural;
            Suites_F, Suites_L : Natural;
            Id_F, Id_L, Bf, Bl, T_Last : Natural;
            Ks_F, Ks_L : Natural;
            Decode_OK : Boolean;
         begin
            if Hs_Body_L > Rec_L then
               D.Cur_State := Failed;
               return;
            end if;
            Tls_Core.Hello.Decode_Client_Hello_Psk
              (In_Bytes (Hs_Body_F .. Hs_Body_L),
               Random,
               Sid_F, Sid_L,
               Suites_F, Suites_L,
               Id_F, Id_L, Bf, Bl,
               Ks_F, Ks_L, T_Last, Decode_OK);
            if not Decode_OK then
               D.Cur_State := Failed;
               return;
            end if;
            if Sid_F > 0 and then Sid_L >= Sid_F
              and then Sid_L - Sid_F + 1 <= 32
            then
               D.Session_Id_Echo_Len := Sid_L - Sid_F + 1;
               D.Session_Id_Echo (1 .. D.Session_Id_Echo_Len) :=
                 In_Bytes (Sid_F .. Sid_L);
            else
               D.Session_Id_Echo_Len := 0;
            end if;
            declare
               Peer_Pub : Tls_Core.X25519.Bytes_32;
               Shared   : Tls_Core.X25519.Bytes_32;
            begin
               for I in 1 .. 32 loop
                  pragma Loop_Invariant (I in 1 .. 32);
                  Peer_Pub (I) := In_Bytes (Ks_F + I - 1);
               end loop;
               D.Peer_Ecdhe_Pub := Peer_Pub;
               Tls_Core.X25519.Scalar_Mult
                 (D.My_Ecdhe_Priv, Peer_Pub, Shared);
               D.Ecdhe_Shared := Shared;
            end;
            declare
               use type Tls_Core.Suites.U16;
               Found : Boolean := False;
               Code  : Tls_Core.Suites.U16;
               Q : Natural := Suites_F;
            begin
               while Q + 1 <= Suites_L loop
                  pragma Loop_Invariant
                    (Q in Suites_F .. Suites_L + 1);
                  Code :=
                    Tls_Core.Suites.U16 (In_Bytes (Q)) * 256
                    + Tls_Core.Suites.U16 (In_Bytes (Q + 1));
                  if Code = Tls_Core.Suites.TLS_AES_128_GCM_SHA256 then
                     D.Suite := Tls_Core.Suites.Aes_128_Gcm_Sha256;
                     Found := True;
                     exit;
                  elsif Code =
                        Tls_Core.Suites.TLS_CHACHA20_POLY1305_SHA256
                  then
                     D.Suite := Tls_Core.Suites.Chacha20_Poly1305_Sha256;
                     Found := True;
                     exit;
                  elsif Code =
                        Tls_Core.Suites.TLS_AES_256_GCM_SHA384
                  then
                     D.Suite := Tls_Core.Suites.Aes_256_Gcm_Sha384;
                     Found := True;
                     exit;
                  end if;
                  Q := Q + 2;
               end loop;
               if not Found then
                  D.Cur_State := Failed;
                  return;
               end if;
            end;
            declare
               Abs_Id_F : constant Natural := Id_F;
               Abs_Id_L : constant Natural := Id_L;
               Abs_Bf : constant Natural := Bf;
               Abs_Bl : constant Natural := Bl;
               Abs_T_Last : constant Natural := T_Last;

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
               declare
                  Computed : Tls_Core.Psk_Binder.Binder_Bytes := (others => 0);
                  Received : Tls_Core.Psk_Binder.Binder_Bytes := (others => 0);
                  Trunc_Len : constant Natural :=
                    Abs_T_Last - Rec_F + 1;
                  Hs_Trunc : Octet_Array (1 .. 16640) :=
                    (others => 0);
               begin
                  if Trunc_Len > Hs_Trunc'Length then
                     D.Cur_State := Failed;
                     return;
                  end if;
                  Hs_Trunc (1 .. Trunc_Len) :=
                    In_Bytes (Rec_F .. Abs_T_Last);
                  Tls_Core.Psk_Binder.Compute
                    (D.PSK,
                     Hs_Trunc (1 .. Trunc_Len),
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
            Tls_Core.Key_Sched.Transcript_Append
              (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, In_Bytes (Rec_F .. Rec_L));
         end;
      end;

      --  HRR emission branch (RFC 8446 §4.1.4)
      if D.Hrr_Demand and then not D.Hrr_Sent then
         declare
            Hrr_Body     : Tls_Core.Octet_Array (1 .. 256) :=
              (others => 0);
            Hrr_Body_Last : Natural;
            Hrr_Hs       : Tls_Core.Octet_Array (1 .. 512) :=
              (others => 0);
            Hrr_Hs_Last  : Natural;
            Hrr_Rec      : Tls_Core.Octet_Array (1 .. 1024) :=
              (others => 0);
            Hrr_Rec_Last : Natural;
            Synthetic    : Tls_Core.Octet_Array (1 .. 36) :=
              (others => 0);
            Cookie_Slice : constant Tls_Core.Octet_Array :=
              D.Hrr_Cookie (1 .. D.Hrr_Cookie_Len);
         begin
            Tls_Core.Key_Sched.Transcript_Snapshot
              (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, D.Hrr_Ch1_Hash);
            Tls_Core.Hello_Retry.Encode_Hrr
              (Selected_Suite => Tls_Core.Suites.Code_Of_Suite (D.Suite),
               Selected_Group => D.Hrr_Group,
               Cookie         => Cookie_Slice,
               Out_Buf        => Hrr_Body,
               Out_Last       => Hrr_Body_Last);
            Encode_Hs_Message
              (Hs_Type_SH,
               Hrr_Body (1 .. Hrr_Body_Last),
               Hrr_Hs, Hrr_Hs_Last);
            Tls_Core.Hello_Retry.Build_Synthetic_Msg_Sha256
              (D.Hrr_Ch1_Hash (1 .. 32), Synthetic);
            Tls_Core.Transcript.Init (D.Hash_Ctx);
            Tls_Core.Key_Sched.Transcript_Append
              (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Synthetic);
            Tls_Core.Key_Sched.Transcript_Append
              (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Hrr_Hs (1 .. Hrr_Hs_Last));
            Wrap_Tls_Plaintext
              (Hrr_Hs (1 .. Hrr_Hs_Last), Hrr_Rec, Hrr_Rec_Last);
            Out_Buf (1 .. Hrr_Rec_Last) :=
              Hrr_Rec (1 .. Hrr_Rec_Last);
            Out_Last := Hrr_Rec_Last;
            D.Hrr_Sent := True;
            D.Cur_State := Awaiting_Ch_2;
            return;
         end;
      end if;

      --  Build SH + key schedule + EE + Finished
      declare
         Sh_Body : Tls_Core.Octet_Array (1 .. 256) := (others => 0);
         Sh_Body_Last : Natural;
         Sh_Hs_Msg : Tls_Core.Octet_Array (1 .. 512) := (others => 0);
         Sh_Hs_Last : Natural;
         Sh_Record : Tls_Core.Octet_Array (1 .. 1024) := (others => 0);
         Sh_Record_Last : Natural;

         Server_Random : constant Tls_Core.Hello.Random_Bytes :=
           (others => 16#5E#);

         Empty_Identity_Buf : Tls_Core.Octet_Array (1 .. 0) :=
           (others => 0);

         Transcript_Hash_After_SH : Tls_Core.Key_Sched.Max_Digest;
      begin
         pragma Unreferenced (Empty_Identity_Buf);

         Tls_Core.Hello.Encode_Server_Hello_Psk
           (Server_Random,
            D.Session_Id_Echo (1 .. D.Session_Id_Echo_Len),
            Tls_Core.Suites.Code_Of_Suite (D.Suite),
            D.My_Ecdhe_Pub,
            Sh_Body, Sh_Body_Last);
         Encode_Hs_Message
           (Hs_Type_SH,
            Sh_Body (1 .. Sh_Body_Last),
            Sh_Hs_Msg, Sh_Hs_Last);
         Tls_Core.Key_Sched.Transcript_Append
              (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Sh_Hs_Msg (1 .. Sh_Hs_Last));
         Wrap_Tls_Plaintext
           (Sh_Hs_Msg (1 .. Sh_Hs_Last), Sh_Record, Sh_Record_Last);

         Tls_Core.Key_Sched.Transcript_Snapshot
              (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Transcript_Hash_After_SH);
         Tls_Core.Key_Sched.Derive_Handshake_Secrets
           (Suite        => D.Suite,
            PSK          => D.PSK,
            Ecdhe_Shared => D.Ecdhe_Shared,
            Th_After_Sh  => Transcript_Hash_After_SH,
            C_Hs_Sec     => D.C_Hs_Sec,
            S_Hs_Sec     => D.S_Hs_Sec,
            Hs_Secret    => D.Hs_Secret);

         Tls_Core.Key_Sched.Init_Hs_Channel
           (D.Suite, D.Hs_Out_Dir, D.S_Hs_Sec);
         Tls_Core.Key_Sched.Init_Hs_Channel
           (D.Suite, D.Hs_In_Dir, D.C_Hs_Sec);

         declare
            Ee_Body : constant Octet_Array (1 .. 2) := (16#00#, 16#00#);
            Ee_Hs   : Octet_Array (1 .. 6) := (others => 0);
            Ee_Hs_Last : Natural;
            Ee_Rec  : Octet_Array (1 .. 256) := (others => 0);
            Ee_Rec_Last : Natural;
         begin
            Encode_Hs_Message
              (Hs_Type_EE, Ee_Body, Ee_Hs, Ee_Hs_Last);
            Tls_Core.Key_Sched.Transcript_Append
              (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Ee_Hs (1 .. Ee_Hs_Last));
            Tls_Core.Aead_Channel.Send
              (D.Hs_Out_Dir,
               Ee_Hs (1 .. Ee_Hs_Last),
               Tls_Core.Aead_Channel.Inner_Type_Handshake,
               Ee_Rec, Ee_Rec_Last);

            declare
               Th_After_EE : Tls_Core.Key_Sched.Max_Digest;
               Verify_Data : Tls_Core.Key_Sched.Max_Digest;
               Fin_Hs : Octet_Array (1 .. 4 + 48) := (others => 0);
               Fin_Hs_Last : Natural;
               Fin_Rec : Octet_Array (1 .. 256) := (others => 0);
               Fin_Rec_Last : Natural;
            begin
               Tls_Core.Key_Sched.Transcript_Snapshot
              (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Th_After_EE);
               Tls_Core.Key_Sched.Build_Finished
                 (D.Suite, D.S_Hs_Sec, Th_After_EE, Verify_Data);
               Encode_Hs_Message
                 (Hs_Type_Finished, Verify_Data (1 .. Tls_Core.Key_Sched.Hash_Len (D.Suite)),
                  Fin_Hs, Fin_Hs_Last);
               Tls_Core.Key_Sched.Transcript_Append
              (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Fin_Hs (1 .. Fin_Hs_Last));
               Tls_Core.Aead_Channel.Send
                 (D.Hs_Out_Dir,
                  Fin_Hs (1 .. Fin_Hs_Last),
                  Tls_Core.Aead_Channel.Inner_Type_Handshake,
                  Fin_Rec, Fin_Rec_Last);

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

               declare
                  Th_After_SF : Tls_Core.Key_Sched.Max_Digest;
                  Master_Secret : Tls_Core.Key_Sched.Max_Secret;
               begin
                  Tls_Core.Key_Sched.Transcript_Snapshot
              (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Th_After_SF);

                  Tls_Core.Key_Sched.Derive_App_Secrets
                    (Suite       => D.Suite,
                     Hs_Secret   => D.Hs_Secret,
                     Th_After_Sf => Th_After_SF,
                     App_C_Ap    => D.App_C_Ap,
                     App_S_Ap    => D.App_S_Ap,
                     Master_Sec  => Master_Secret);
                  D.App_Set := True;
                  D.Master_Sec := Master_Secret;
                  D.Master_Set := True;

                  Tls_Core.Key_Sched.Build_Finished
                    (D.Suite, D.C_Hs_Sec, Th_After_SF, D.Expected_Cf);
               end;
            end;
         end;

         D.Cur_State := Awaiting_Cf;
      end;

   end Handle;

end Tls_Core.Tls13_Driver.Step_Awaiting_Ch_Psk;
