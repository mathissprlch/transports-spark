with Tls_Core.Aead_Channel;
with Tls_Core.Alert;
with Tls_Core.Handshake_Buffer;
with Tls_Core.Hello;
with Tls_Core.Hello_Rflx;
with Tls_Core.Key_Schedule;
with Tls_Core.Key_Sched;
with Tls_Core.X25519;
with Tls_Core.Tls13_Driver.Helpers; use Tls_Core.Tls13_Driver.Helpers;

package body Tls_Core.Tls13_Driver.Step_Awaiting_Sf_Psk
  with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   procedure Handle
     (D        : in out Driver;
      In_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural) is
   begin
      Out_Buf := (others => 0);
      Out_Last := 0;

      if D.My_Role /= Client then
         D.Cur_State := Failed;
         return;
      end if;

      declare
         Cursor : Natural := In_Bytes'First;

         --  Used to derive c_hs / s_hs after parsing SH.
         Empty_Hash  : Tls_Core.Key_Sched.Max_Digest;
         Empty_In    : constant Octet_Array (1 .. 0) := (others => 0);
         Zero_Secret : constant Tls_Core.Key_Sched.Max_Secret := (others => 0);
         Derived_Lab : constant Octet_Array (1 .. 7) :=
           (16#64#, 16#65#, 16#72#, 16#69#, 16#76#, 16#65#, 16#64#);
         C_Hs_Lab    : constant Octet_Array (1 .. 12) :=
           (16#63#,
            16#20#,
            16#68#,
            16#73#,
            16#20#,
            16#74#,
            16#72#,
            16#61#,
            16#66#,
            16#66#,
            16#69#,
            16#63#);
         S_Hs_Lab    : constant Octet_Array (1 .. 12) :=
           (16#73#,
            16#20#,
            16#68#,
            16#73#,
            16#20#,
            16#74#,
            16#72#,
            16#61#,
            16#66#,
            16#66#,
            16#69#,
            16#63#);
         C_Ap_Lab    : constant Octet_Array (1 .. 12) :=
           (16#63#,
            16#20#,
            16#61#,
            16#70#,
            16#20#,
            16#74#,
            16#72#,
            16#61#,
            16#66#,
            16#66#,
            16#69#,
            16#63#);
         S_Ap_Lab    : constant Octet_Array (1 .. 12) :=
           (16#73#,
            16#20#,
            16#61#,
            16#70#,
            16#20#,
            16#74#,
            16#72#,
            16#61#,
            16#66#,
            16#66#,
            16#69#,
            16#63#);

         Early_Secret : Tls_Core.Key_Sched.Max_Secret;
         Derived_1    : Tls_Core.Key_Sched.Max_Secret;
         Th_After_Sh  : Tls_Core.Key_Sched.Max_Digest;
         Th_After_Ee  : Tls_Core.Key_Sched.Max_Digest;
         Th_After_Sf  : Tls_Core.Key_Sched.Max_Digest;
      begin
         --  Step 1: parse SH TLSPlaintext.
         if Cursor + 4 > In_Bytes'Last
           or else In_Bytes (Cursor) /= Rec_Type_Handshake
         then
            D.Cur_State := Failed;
            return;
         end if;
         declare
            use type Tls_Core.Suites.U16;
            Sh_Rec_Len : constant Natural :=
              Natural (In_Bytes (Cursor + 3))
              * 256
              + Natural (In_Bytes (Cursor + 4));
            Sh_Rec_F   : constant Natural := Cursor + 5;
            Sh_Rec_L   : constant Natural := Sh_Rec_F + Sh_Rec_Len - 1;
         begin
            if Sh_Rec_L > In_Bytes'Last
              or else Sh_Rec_Len < 4
              or else In_Bytes (Sh_Rec_F) /= Hs_Type_SH
            then
               D.Cur_State := Failed;
               return;
            end if;
            --  Extract server's selected cipher_suite from SH
            --  per RFC 8446 §4.1.3. SH wire layout (after the
            --  4-byte Handshake header at Sh_Rec_F):
            --    + 4 ..  5  legacy_version  (0x0303)
            --    + 6 .. 37  random          (32 bytes)
            --    + 38       session_id_len  (== 0 for v0.5)
            --    + 39 .. 40 cipher_suite    (u16)
            if Sh_Rec_F + 40 > In_Bytes'Last
              or else In_Bytes (Sh_Rec_F + 38) /= 0
            then
               D.Cur_State := Failed;
               return;
            end if;
            declare
               Code : constant Tls_Core.Suites.U16 :=
                 Tls_Core.Suites.U16 (In_Bytes (Sh_Rec_F + 39))
                 * 256
                 + Tls_Core.Suites.U16 (In_Bytes (Sh_Rec_F + 40));
            begin
               if not Tls_Core.Suites.Is_Supported_Suite (Code) then
                  --  Unrecognised, or AES-256-GCM-SHA384 (driver
                  --  schedule path is SHA-256-only — see package
                  --  wall-hit note).
                  D.Cur_State := Failed;
                  return;
               end if;
               D.Suite := Tls_Core.Suites.Suite_Of_Code (Code);
            end;
            --  RFC 8446 §4.2.8 / §7.1 mode 3 — extract the
            --  server's X25519 public key from the SH key_share
            --  extension and compute the ECDHE shared secret.
            --  Decode_Server_Hello_Psk_Key_Share takes the SH
            --  body (bytes after the 4-byte handshake header).
            declare
               Sh_Body_F  : constant Natural := Sh_Rec_F + 4;
               Sh_Body_L  : constant Natural := Sh_Rec_L;
               Ks_F, Ks_L : Natural;
               Ks_OK      : Boolean;
               Peer_Pub   : Tls_Core.X25519.Bytes_32;
               Shared     : Tls_Core.X25519.Bytes_32;
            begin
               Tls_Core.Hello_Rflx.Decode_Server_Hello_Key_Share
                 (In_Bytes (Sh_Body_F .. Sh_Body_L), Ks_F, Ks_L, Ks_OK);
               if not Ks_OK then
                  D.Cur_State := Failed;
                  return;
               end if;
               for I in 1 .. Tls_Core.Key_Sched.Hash_Len (D.Suite) loop
                  pragma Loop_Invariant (I in 1 .. 32);
                  Peer_Pub (I) := In_Bytes (Ks_F + I - 1);
               end loop;
               D.Peer_Ecdhe_Pub := Peer_Pub;
               Tls_Core.X25519.Scalar_Mult (D.My_Ecdhe_Priv, Peer_Pub, Shared);
               D.Ecdhe_Shared := Shared;
            end;
            --  Append SH handshake message to transcript.
            Tls_Core.Key_Sched.Transcript_Append
              (D.Suite,
               D.Hash_Ctx,
               D.Hash_Ctx_384,
               In_Bytes (Sh_Rec_F .. Sh_Rec_L));
            Cursor := Sh_Rec_L + 1;
         end;

         --  Skip legacy ChangeCipherSpec if present (RFC 8446 §5.1).
         if Cursor + 5 <= In_Bytes'Last and then In_Bytes (Cursor) = 16#14#
         then
            declare
               Ccs_Len : constant Natural :=
                 Natural (In_Bytes (Cursor + 3))
                 * 256
                 + Natural (In_Bytes (Cursor + 4));
            begin
               Cursor := Cursor + 5 + Ccs_Len;
            end;
         end if;

         --  Step 2: derive handshake secrets. RFC 8446 §7.1 mode 3:
         --    Handshake_Secret = HKDF-Extract(Derived_1, ECDHE_secret)
         --  where ECDHE_secret is the X25519 shared we just computed.
         Tls_Core.Key_Sched.Transcript_Snapshot
           (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Th_After_Sh);
         Tls_Core.Key_Sched.Derive_Handshake_Secrets
           (Suite        => D.Suite,
            PSK          => D.PSK,
            Ecdhe_Shared => D.Ecdhe_Shared,
            Th_After_Sh  => Th_After_Sh,
            C_Hs_Sec     => D.C_Hs_Sec,
            S_Hs_Sec     => D.S_Hs_Sec,
            Hs_Secret    => D.Hs_Secret);
         --  Client: in decrypts with s_hs; out encrypts with c_hs.
         --  Init_Sha256 dispatches the AEAD by D.Suite.
         Tls_Core.Key_Sched.Init_Hs_Channel (D.Suite, D.Hs_In_Dir, D.S_Hs_Sec);
         Tls_Core.Key_Sched.Init_Hs_Channel
           (D.Suite, D.Hs_Out_Dir, D.C_Hs_Sec);

         --  Step 3+4: decrypt every subsequent record on the
         --  handshake stream, push the inner plaintext through
         --  Tls_Core.Handshake_Buffer, and pop complete handshake
         --  messages in expected order. RFC 8446 §5.1 allows a
         --  handshake message to span multiple records; §4 also
         --  permits multiple handshake messages packed in a
         --  single record. Both shapes are handled by the
         --  buffer + per-message pop loop.
         --
         --  Substate transitions:
         --    Expect_EE  → after EE appended to transcript and
         --                 Th_After_Ee snapshotted (for §4.4.4
         --                 SF verify_data binding) →  Expect_SF
         --    Expect_SF  → after SF verify_data check passes →
         --                 Done_Sub (loop exits)
         declare
            type Sub_State is (Expect_EE, Expect_SF, Done_Sub);
            Sub         : Sub_State := Expect_EE;
            --  Per-record scratch.
            Pt_Buf      : Octet_Array (1 .. 16640) := (others => 0);
            Pt_Last     : Natural;
            Inner_Type  : Octet;
            Aead_OK     : Boolean;
            Rec_Len     : Natural;
            Rec_End     : Natural;
            Push_OK     : Boolean;
            --  Per-message scratch.
            Msg_Buf     :
              Octet_Array (1 .. Tls_Core.Handshake_Buffer.Max_Buf) :=
                (others => 0);
            Msg_Last    : Natural;
            Body_Len    : Natural;
            Expected_Sf : Tls_Core.Key_Sched.Max_Digest;
            Diff        : Octet;
         begin
            Tls_Core.Handshake_Buffer.Init (D.Hs_In_Buf);

            --  Outer loop: walk inbound records.
            while Cursor <= In_Bytes'Last and then Sub /= Done_Sub loop
               pragma
                 Loop_Invariant
                   (Cursor in In_Bytes'First .. In_Bytes'Last + 1);
               if Cursor + 4 > In_Bytes'Last
                 or else In_Bytes (Cursor)
                         /= Tls_Core.Aead_Channel.Inner_Type_Application_Data
               then
                  Fail_Encrypted
                    (D, Tls_Core.Alert.Desc_Decode_Error, Out_Buf, Out_Last);
                  return;
               end if;
               Rec_Len :=
                 Natural (In_Bytes (Cursor + 3))
                 * 256
                 + Natural (In_Bytes (Cursor + 4));
               Rec_End := Cursor + 5 + Rec_Len - 1;
               if Rec_End > In_Bytes'Last then
                  Fail_Encrypted
                    (D, Tls_Core.Alert.Desc_Decode_Error, Out_Buf, Out_Last);
                  return;
               end if;
               Tls_Core.Aead_Channel.Receive
                 (D.Hs_In_Dir,
                  In_Bytes (Cursor .. Rec_End),
                  Pt_Buf,
                  Pt_Last,
                  Inner_Type,
                  Aead_OK);
               if not Aead_OK then
                  Fail_Encrypted
                    (D, Tls_Core.Alert.Desc_Bad_Record_Mac, Out_Buf, Out_Last);
                  return;
               end if;
               if Inner_Type /= Tls_Core.Aead_Channel.Inner_Type_Handshake then
                  Fail_Encrypted
                    (D,
                     Tls_Core.Alert.Desc_Unexpected_Message,
                     Out_Buf,
                     Out_Last);
                  return;
               end if;
               --  Push this record's inner plaintext into the
               --  reassembly buffer.
               if Pt_Last > Tls_Core.Handshake_Buffer.Max_Buf then
                  Fail_Encrypted
                    (D, Tls_Core.Alert.Desc_Decode_Error, Out_Buf, Out_Last);
                  return;
               end if;
               Tls_Core.Handshake_Buffer.Push_Record_Bytes
                 (D.Hs_In_Buf, Pt_Buf (1 .. Pt_Last), Push_OK);
               if not Push_OK then
                  Fail_Encrypted
                    (D, Tls_Core.Alert.Desc_Internal_Error, Out_Buf, Out_Last);
                  return;
               end if;
               Cursor := Rec_End + 1;

               --  Inner loop: drain complete handshake messages.
               while Tls_Core.Handshake_Buffer.Has_Complete_Message
                       (D.Hs_In_Buf)
                 and then Sub /= Done_Sub
               loop
                  pragma Loop_Invariant (Sub in Expect_EE | Expect_SF);
                  Body_Len :=
                    Tls_Core.Handshake_Buffer.Peek_Body_Length (D.Hs_In_Buf);
                  if Body_Len + 4 > Msg_Buf'Length then
                     Fail_Encrypted
                       (D,
                        Tls_Core.Alert.Desc_Decode_Error,
                        Out_Buf,
                        Out_Last);
                     return;
                  end if;
                  Tls_Core.Handshake_Buffer.Pop_Complete_Message
                    (D.Hs_In_Buf, Msg_Buf, Msg_Last);

                  case Sub is
                     when Expect_EE =>
                        if Msg_Last < 4 or else Msg_Buf (1) /= Hs_Type_EE then
                           Fail_Encrypted
                             (D,
                              Tls_Core.Alert.Desc_Decode_Error,
                              Out_Buf,
                              Out_Last);
                           return;
                        end if;
                        Tls_Core.Key_Sched.Transcript_Append
                          (D.Suite,
                           D.Hash_Ctx,
                           D.Hash_Ctx_384,
                           Msg_Buf (1 .. Msg_Last));
                        Tls_Core.Key_Sched.Transcript_Snapshot
                          (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Th_After_Ee);
                        Sub := Expect_SF;

                     when Expect_SF =>
                        if Msg_Last /= 4 + 32
                          or else Msg_Buf (1) /= Hs_Type_Finished
                        then
                           Fail_Encrypted
                             (D,
                              Tls_Core.Alert.Desc_Decode_Error,
                              Out_Buf,
                              Out_Last);
                           return;
                        end if;
                        --  Verify server Finished verify_data:
                        --  HMAC of s_hs_finished_key over Th_After_Ee.
                        Tls_Core.Key_Sched.Build_Finished
                          (D.Suite, D.S_Hs_Sec, Th_After_Ee, Expected_Sf);
                        Diff := 0;
                        for I in 1 .. Tls_Core.Key_Sched.Hash_Len (D.Suite)
                        loop
                           pragma Loop_Invariant (I in 1 .. 32);
                           Diff :=
                             Diff or (Msg_Buf (4 + I) xor Expected_Sf (I));
                        end loop;
                        if Diff /= 0 then
                           D.Cur_State := Failed;
                           return;
                        end if;
                        Tls_Core.Key_Sched.Transcript_Append
                          (D.Suite,
                           D.Hash_Ctx,
                           D.Hash_Ctx_384,
                           Msg_Buf (1 .. Msg_Last));
                        Sub := Done_Sub;

                     when Done_Sub  =>
                        null;
                  end case;
               end loop;
            end loop;

            if Sub /= Done_Sub then
               --  Ran out of records before SF was popped.
               Fail_Encrypted
                 (D, Tls_Core.Alert.Desc_Decode_Error, Out_Buf, Out_Last);
               return;
            end if;
         end;

         --  Step 5: derive app secrets.
         Tls_Core.Key_Sched.Transcript_Snapshot
           (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Th_After_Sf);
         declare
            Master_Secret : Tls_Core.Key_Sched.Max_Secret;
         begin
            Tls_Core.Key_Sched.Derive_App_Secrets
              (Suite       => D.Suite,
               Hs_Secret   => D.Hs_Secret,
               Th_After_Sf => Th_After_Sf,
               App_C_Ap    => D.App_C_Ap,
               App_S_Ap    => D.App_S_Ap,
               Master_Sec  => Master_Secret);
            D.App_Set := True;
            D.Master_Sec := Master_Secret;
            D.Master_Set := True;
         end;

         --  Step 6: build + send client Finished.
         declare
            Cf_Verify   : Tls_Core.Key_Sched.Max_Digest;
            Cf_Hs       : Octet_Array (1 .. 4 + 48) := (others => 0);
            Cf_Hs_Last  : Natural;
            Cf_Rec      : Octet_Array (1 .. 256) := (others => 0);
            Cf_Rec_Last : Natural;
         begin
            Tls_Core.Key_Sched.Build_Finished
              (D.Suite, D.C_Hs_Sec, Th_After_Sf, Cf_Verify);
            Encode_Hs_Message
              (Hs_Type_Finished,
               Cf_Verify (1 .. Tls_Core.Key_Sched.Hash_Len (D.Suite)),
               Cf_Hs,
               Cf_Hs_Last);
            Tls_Core.Key_Sched.Transcript_Append
              (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Cf_Hs (1 .. Cf_Hs_Last));
            Tls_Core.Aead_Channel.Send
              (D.Hs_Out_Dir,
               Cf_Hs (1 .. Cf_Hs_Last),
               Tls_Core.Aead_Channel.Inner_Type_Handshake,
               Cf_Rec,
               Cf_Rec_Last);
            Out_Buf (1 .. Cf_Rec_Last) := Cf_Rec (1 .. Cf_Rec_Last);
            Out_Last := Cf_Rec_Last;
         end;

         --  Derive resumption_master_secret per RFC 8446 §7.1:
         --    Derive-Secret(Master_Secret, "res master", CH..CF)
         --  Client side: Master_Sec was saved above when
         --  App_C_Ap / App_S_Ap were derived; the transcript
         --  now spans CH..CF (we just appended CF).
         if D.Master_Set then
            declare
               Th_After_Cf : Tls_Core.Key_Sched.Max_Digest;
            begin
               Tls_Core.Key_Sched.Transcript_Snapshot
                 (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Th_After_Cf);
               Tls_Core.Key_Sched.Derive_Resumption_Master_Secret
                 (Suite             => D.Suite,
                  Master_Secret     => D.Master_Sec,
                  Th_After_Cf       => Th_After_Cf,
                  Resumption_Secret => D.Res_Master_Sec);
               D.Res_Master_Set := True;
            end;
         end if;

         D.Cur_State := Done;
      end;

   end Handle;

end Tls_Core.Tls13_Driver.Step_Awaiting_Sf_Psk;
