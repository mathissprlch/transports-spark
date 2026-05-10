with Tls_Core.Aead_Channel;
with Tls_Core.Alert;
with Tls_Core.Cert_Chain;
with Tls_Core.Cert_Verify;
with Tls_Core.Handshake_Buffer;
with Tls_Core.Hello;
with Tls_Core.Hello_Rflx;
with Tls_Core.Key_Schedule;
with Tls_Core.Session_Ticket;
with Tls_Core.X25519;
with Tls_Core.Key_Sched;
with Tls_Core.Tls13_Driver.Helpers; use Tls_Core.Tls13_Driver.Helpers;

package body Tls_Core.Tls13_Driver.Step_Awaiting_Sf_Cert
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

      if D.My_Role /= Client then
         D.Cur_State := Failed;
         return;
      end if;

      --  Cert-mode flight reception.  Same SH parse + ECDHE
      --  computation as PSK mode, but key schedule uses PSK = 0
      --  (RFC 8446 §7.1) and the sub-state machine after the
      --  handshake-stage Aead_Channel is opened expects four
      --  encrypted messages: EE -> Cert -> CertVerify -> SF.
      declare
         Cursor : Natural := In_Bytes'First;

         Empty_In    : constant Octet_Array (1 .. 0) :=
           (others => 0);
         Zero_Secret : constant Tls_Core.Key_Sched.Max_Secret :=
           (others => 0);
         Zero32      : constant Octet_Array (1 .. 32) :=
           (others => 0);
         Empty_Hash  : Tls_Core.Key_Sched.Max_Digest;

         Th_After_Sh   : Tls_Core.Key_Sched.Max_Digest;
         Th_After_Cert : Tls_Core.Key_Sched.Max_Digest;
         Th_After_CV   : Tls_Core.Key_Sched.Max_Digest;
         Th_After_Sf   : Tls_Core.Key_Sched.Max_Digest;

         --  Leaf-cert scratch -- the raw DER bytes recovered
         --  from the 4.4.2 Certificate message body.
         Leaf_Buf : Octet_Array (1 .. 4096) := (others => 0);
         Leaf_Len : Natural := 0;
      begin
         --  Step 1: parse SH TLSPlaintext (same shape as
         --  PSK SH; just no pre_shared_key extension).
         if Cursor + 4 > In_Bytes'Last
           or else In_Bytes (Cursor) /= Rec_Type_Handshake
         then
            D.Cur_State := Failed;
            return;
         end if;
         declare
            use type Tls_Core.Suites.U16;
            Sh_Rec_Len : constant Natural :=
              Natural (In_Bytes (Cursor + 3)) * 256
              + Natural (In_Bytes (Cursor + 4));
            Sh_Rec_F : constant Natural := Cursor + 5;
            Sh_Rec_L : constant Natural :=
              Sh_Rec_F + Sh_Rec_Len - 1;
         begin
            if Sh_Rec_L > In_Bytes'Last
              or else Sh_Rec_Len < 4
              or else In_Bytes (Sh_Rec_F) /= Hs_Type_SH
            then
               D.Cur_State := Failed;
               return;
            end if;
            if Sh_Rec_F + 40 > In_Bytes'Last
              or else In_Bytes (Sh_Rec_F + 38) /= 0
            then
               D.Cur_State := Failed;
               return;
            end if;
            declare
               Code : constant Tls_Core.Suites.U16 :=
                 Tls_Core.Suites.U16
                   (In_Bytes (Sh_Rec_F + 39)) * 256
                 + Tls_Core.Suites.U16
                     (In_Bytes (Sh_Rec_F + 40));
            begin
               if not Tls_Core.Suites.Is_Supported_Suite (Code)
               then
                  D.Cur_State := Failed;
                  return;
               end if;
               D.Suite := Tls_Core.Suites.Suite_Of_Code (Code);
            end;
            declare
               Sh_Body_F : constant Natural := Sh_Rec_F + 4;
               Sh_Body_L : constant Natural := Sh_Rec_L;
               Ks_F, Ks_L : Natural;
               Ks_OK : Boolean;
               Peer_Pub : Tls_Core.X25519.Bytes_32;
               Shared   : Tls_Core.X25519.Bytes_32;
            begin
               Tls_Core.Hello_Rflx.Decode_Server_Hello_Key_Share
                 (In_Bytes (Sh_Body_F .. Sh_Body_L),
                  Ks_F, Ks_L, Ks_OK);
               if not Ks_OK then
                  D.Cur_State := Failed;
                  return;
               end if;
               for I in 1 .. 32 loop
                  Peer_Pub (I) := In_Bytes (Ks_F + I - 1);
               end loop;
               D.Peer_Ecdhe_Pub := Peer_Pub;
               Tls_Core.X25519.Scalar_Mult
                 (D.My_Ecdhe_Priv, Peer_Pub, Shared);
               D.Ecdhe_Shared := Shared;
            end;
            Tls_Core.Key_Sched.Transcript_Append
              (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384,
               In_Bytes (Sh_Rec_F .. Sh_Rec_L));
            Cursor := Sh_Rec_L + 1;
         end;

         --  Skip legacy ChangeCipherSpec if present (RFC 8446 §5.1).
         if Cursor + 5 <= In_Bytes'Last
           and then In_Bytes (Cursor) = 16#14#
         then
            declare
               Ccs_Len : constant Natural :=
                 Natural (In_Bytes (Cursor + 3)) * 256
                 + Natural (In_Bytes (Cursor + 4));
            begin
               Cursor := Cursor + 5 + Ccs_Len;
            end;
         end if;

         --  Step 2: cert-mode key schedule (PSK = 0).
         Tls_Core.Key_Sched.Transcript_Snapshot
           (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Th_After_Sh);
         Tls_Core.Key_Sched.Derive_Handshake_Secrets
           (Suite        => D.Suite,
            PSK          => Zero_Secret,
            Ecdhe_Shared => D.Ecdhe_Shared,
            Th_After_Sh  => Th_After_Sh,
            C_Hs_Sec     => D.C_Hs_Sec,
            S_Hs_Sec     => D.S_Hs_Sec,
            Hs_Secret    => D.Hs_Secret);
         Tls_Core.Key_Sched.Init_Hs_Channel
           (D.Suite, D.Hs_In_Dir, D.S_Hs_Sec);
         Tls_Core.Key_Sched.Init_Hs_Channel
           (D.Suite, D.Hs_Out_Dir, D.C_Hs_Sec);

         --  Step 3: drain encrypted records, dispatch on
         --  EE / Cert / CertVerify / SF.
         declare
            type Sub_State is
              (Expect_EE, Expect_Cert, Expect_CertVerify,
               Expect_SF, Done_Sub);
            Sub  : Sub_State := Expect_EE;
            Pt_Buf : Octet_Array (1 .. 16640) := (others => 0);
            Pt_Last : Natural;
            Inner_Type : Octet;
            Aead_OK : Boolean;
            Rec_Len : Natural;
            Rec_End : Natural;
            Push_OK : Boolean;
            Msg_Buf : Octet_Array
              (1 .. Tls_Core.Handshake_Buffer.Max_Buf) :=
                (others => 0);
            Msg_Last : Natural;
            Body_Len : Natural;
            Expected_Sf : Tls_Core.Key_Sched.Max_Digest;
            Diff : Octet;
         begin
            Tls_Core.Handshake_Buffer.Init (D.Hs_In_Buf);
            while Cursor <= In_Bytes'Last
              and then Sub /= Done_Sub
            loop
               pragma Loop_Invariant
                 (Cursor in In_Bytes'First .. In_Bytes'Last + 1);
               if Cursor + 4 > In_Bytes'Last
                 or else In_Bytes (Cursor) /=
                   Tls_Core.Aead_Channel.Inner_Type_Application_Data
               then
                  Fail_Encrypted
                    (D, Tls_Core.Alert.Desc_Decode_Error,
                     Out_Buf, Out_Last);
                  return;
               end if;
               Rec_Len := Natural (In_Bytes (Cursor + 3)) * 256
                          + Natural (In_Bytes (Cursor + 4));
               Rec_End := Cursor + 5 + Rec_Len - 1;
               if Rec_End > In_Bytes'Last then
                  Fail_Encrypted
                    (D, Tls_Core.Alert.Desc_Decode_Error,
                     Out_Buf, Out_Last);
                  return;
               end if;
               Tls_Core.Aead_Channel.Receive
                 (D.Hs_In_Dir, In_Bytes (Cursor .. Rec_End),
                  Pt_Buf, Pt_Last, Inner_Type, Aead_OK);
               if not Aead_OK then
                  Fail_Encrypted
                    (D, Tls_Core.Alert.Desc_Bad_Record_Mac,
                     Out_Buf, Out_Last);
                  return;
               end if;
               if Inner_Type /=
                    Tls_Core.Aead_Channel.Inner_Type_Handshake
               then
                  Fail_Encrypted
                    (D, Tls_Core.Alert.Desc_Unexpected_Message,
                     Out_Buf, Out_Last);
                  return;
               end if;
               if Pt_Last >
                    Tls_Core.Handshake_Buffer.Max_Buf
               then
                  Fail_Encrypted
                    (D, Tls_Core.Alert.Desc_Decode_Error,
                     Out_Buf, Out_Last);
                  return;
               end if;
               Tls_Core.Handshake_Buffer.Push_Record_Bytes
                 (D.Hs_In_Buf, Pt_Buf (1 .. Pt_Last), Push_OK);
               if not Push_OK then
                  Fail_Encrypted
                    (D, Tls_Core.Alert.Desc_Internal_Error,
                     Out_Buf, Out_Last);
                  return;
               end if;
               Cursor := Rec_End + 1;

               while Tls_Core.Handshake_Buffer
                       .Has_Complete_Message (D.Hs_In_Buf)
                 and then Sub /= Done_Sub
               loop
                  pragma Loop_Invariant
                    (Sub in Expect_EE | Expect_Cert
                          | Expect_CertVerify | Expect_SF);
                  Body_Len :=
                    Tls_Core.Handshake_Buffer.Peek_Body_Length
                      (D.Hs_In_Buf);
                  if Body_Len + 4 > Msg_Buf'Length then
                     Fail_Encrypted
                       (D, Tls_Core.Alert.Desc_Decode_Error,
                        Out_Buf, Out_Last);
                     return;
                  end if;
                  Tls_Core.Handshake_Buffer
                    .Pop_Complete_Message
                      (D.Hs_In_Buf, Msg_Buf, Msg_Last);

                  case Sub is
                     when Expect_EE =>
                        if Msg_Last < 4
                          or else Msg_Buf (1) /= Hs_Type_EE
                        then
                           Fail_Encrypted
                             (D, Tls_Core.Alert
                                   .Desc_Decode_Error,
                              Out_Buf, Out_Last);
                           return;
                        end if;
                        Tls_Core.Key_Sched.Transcript_Append
                          (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384,
                           Msg_Buf (1 .. Msg_Last));
                        Sub := Expect_Cert;

                     when Expect_Cert =>
                        --  §4.4.2 -- handshake_type 0x0B.
                        --  Body: opaque cert_request_context
                        --        (u8 len), CertificateEntry
                        --        list (u24 len + entries).
                        if Msg_Last < 4 + 1 + 3
                          or else Msg_Buf (1) /= Hs_Type_Cert
                        then
                           Fail_Encrypted
                             (D, Tls_Core.Alert
                                   .Desc_Decode_Error,
                              Out_Buf, Out_Last);
                           return;
                        end if;
                        declare
                           OK : Boolean;
                           Cert_F, Cert_L : Natural;
                           Body_Bytes : Octet_Array
                             (1 .. Msg_Last - 4);
                        begin
                           Body_Bytes :=
                             Msg_Buf (5 .. Msg_Last);
                           Tls_Core.Cert_Verify
                             .Decode_Body_Single
                               (Body_Bytes,
                                OK, Cert_F, Cert_L);
                           if not OK
                             or else Cert_L < Cert_F
                             or else Cert_L - Cert_F + 1
                                     > Leaf_Buf'Length
                           then
                              --  Use Decode_Error to
                              --  distinguish from
                              --  Bad_Certificate (which is
                              --  reserved for chain/sig
                              --  failure below).
                              Fail_Encrypted
                                (D, Tls_Core.Alert
                                      .Desc_Decode_Error,
                                 Out_Buf, Out_Last);
                              return;
                           end if;
                           Leaf_Len := Cert_L - Cert_F + 1;
                           Leaf_Buf (1 .. Leaf_Len) :=
                             Body_Bytes (Cert_F .. Cert_L);
                        end;
                        Tls_Core.Key_Sched.Transcript_Append
                          (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384,
                           Msg_Buf (1 .. Msg_Last));
                        Tls_Core.Key_Sched.Transcript_Snapshot
                          (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384,
                           Th_After_Cert);
                        Sub := Expect_CertVerify;

                     when Expect_CertVerify =>
                        if Msg_Last < 4 + 4
                          or else Msg_Buf (1) /=
                                    Hs_Type_Cert_Verify
                        then
                           Fail_Encrypted
                             (D, Tls_Core.Alert
                                   .Desc_Decode_Error,
                              Out_Buf, Out_Last);
                           return;
                        end if;
                        declare
                           OK : Boolean;
                           Sig_Scheme : Interfaces.Unsigned_16;
                           Sig_F, Sig_L : Natural;
                           Body_Bytes : Octet_Array
                             (1 .. Msg_Last - 4);
                           use type Interfaces.Unsigned_16;
                        begin
                           Body_Bytes :=
                             Msg_Buf (5 .. Msg_Last);
                           Tls_Core.Cert_Verify.Decode_Body
                             (Body_Bytes,
                              OK, Sig_Scheme, Sig_F, Sig_L);
                           if not OK
                             or else Sig_Scheme /= 16#0403#
                           then
                              Fail_Encrypted
                                (D, Tls_Core.Alert
                                      .Desc_Decode_Error,
                                 Out_Buf, Out_Last);
                              return;
                           end if;
                           --  Build All_Certs = leaf || trust
                           --  anchors so the validator's
                           --  Chain_In and Trust offsets share
                           --  one backing buffer.
                           declare
                              Total_Len : constant Natural :=
                                Leaf_Len + D.Trust_Anchor_Len;
                              All_Certs : Octet_Array
                                (1 .. Total_Len) :=
                                  (others => 0);
                              Chain_In : Tls_Core.Cert_Chain
                                .Chain;
                              Trust : Tls_Core.Cert_Chain
                                .Trust_Store;
                              Result : Tls_Core.Cert_Chain
                                .Validation_Result;
                           begin
                              if Total_Len < 16 then
                                 Fail_Encrypted
                                   (D, Tls_Core.Alert
                                         .Desc_Bad_Certificate,
                                    Out_Buf, Out_Last);
                                 return;
                              end if;
                              All_Certs (1 .. Leaf_Len) :=
                                Leaf_Buf (1 .. Leaf_Len);
                              All_Certs
                                (Leaf_Len + 1 .. Total_Len) :=
                                D.Trust_Anchor_Bytes
                                  (1 .. D.Trust_Anchor_Len);
                              Chain_In.Count := 1;
                              Chain_In.Entries (1) :=
                                (First => 1, Last => Leaf_Len);
                              Trust.Count :=
                                D.Trust_Anchor_Spec.Count;
                              for I in 1
                                .. D.Trust_Anchor_Spec.Count
                              loop
                                 pragma Loop_Invariant
                                   (I in 1
                                    .. D.Trust_Anchor_Spec
                                         .Count);
                                 Trust.Entries (I) :=
                                   (First =>
                                      D.Trust_Anchor_Spec
                                        .Entries (I).First
                                      + Leaf_Len,
                                    Last =>
                                      D.Trust_Anchor_Spec
                                        .Entries (I).Last
                                      + Leaf_Len);
                              end loop;
                              Tls_Core.Cert_Chain
                                .Authenticate_Server
                                  (All_Certs       => All_Certs,
                                   Chain_In        => Chain_In,
                                   Trust           => Trust,
                                   Hostname        =>
                                     D.Sni_Hostname
                                       (1 .. D.Sni_Len),
                                   Sig_Scheme      => Sig_Scheme,
                                   Sig_Body        =>
                                     Body_Bytes
                                       (Sig_F .. Sig_L),
                                   Transcript_Hash =>
                                     Th_After_Cert (1 .. 32),
                                   Result          => Result);
                              if not Tls_Core.Cert_Chain
                                       ."=" (Result, Tls_Core
                                                       .Cert_Chain
                                                       .OK_Validated)
                              then
                                 Fail_Encrypted
                                   (D, Tls_Core.Alert
                                         .Desc_Bad_Certificate,
                                    Out_Buf, Out_Last);
                                 return;
                              end if;
                           end;
                        end;
                        Tls_Core.Key_Sched.Transcript_Append
                          (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384,
                           Msg_Buf (1 .. Msg_Last));
                        Tls_Core.Key_Sched.Transcript_Snapshot
                          (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384,
                           Th_After_CV);
                        Sub := Expect_SF;

                     when Expect_SF =>
                        if Msg_Last /= 4 + 32
                          or else Msg_Buf (1) /=
                                    Hs_Type_Finished
                        then
                           Fail_Encrypted
                             (D, Tls_Core.Alert
                                   .Desc_Decode_Error,
                              Out_Buf, Out_Last);
                           return;
                        end if;
                        Tls_Core.Key_Sched.Build_Finished
                          (D.Suite, D.S_Hs_Sec,
                           Th_After_CV, Expected_Sf);
                        Diff := 0;
                        for I in 1 ..
                          Tls_Core.Key_Sched.Hash_Len (D.Suite)
                        loop
                           pragma Loop_Invariant
                             (I in 1 .. 32);
                           Diff := Diff or
                             (Msg_Buf (4 + I)
                              xor Expected_Sf (I));
                        end loop;
                        if Diff /= 0 then
                           D.Cur_State := Failed;
                           return;
                        end if;
                        Tls_Core.Key_Sched.Transcript_Append
                          (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384,
                           Msg_Buf (1 .. Msg_Last));
                        Sub := Done_Sub;

                     when Done_Sub =>
                        null;
                  end case;
               end loop;
            end loop;
            if Sub /= Done_Sub then
               Fail_Encrypted
                 (D, Tls_Core.Alert.Desc_Decode_Error,
                  Out_Buf, Out_Last);
               return;
            end if;
         end;

         --  Step 4: app traffic secrets.
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

         --  Step 5: build + send client Finished.
         declare
            Cf_Verify : Tls_Core.Key_Sched.Max_Digest;
            Cf_Hs : Octet_Array (1 .. 4 + 48) := (others => 0);
            Cf_Hs_Last : Natural;
            Cf_Rec : Octet_Array (1 .. 256) := (others => 0);
            Cf_Rec_Last : Natural;
         begin
            Tls_Core.Key_Sched.Build_Finished
              (D.Suite, D.C_Hs_Sec, Th_After_Sf, Cf_Verify);
            Encode_Hs_Message
              (Hs_Type_Finished,
               Cf_Verify
                 (1 .. Tls_Core.Key_Sched.Hash_Len (D.Suite)),
               Cf_Hs, Cf_Hs_Last);
            Tls_Core.Key_Sched.Transcript_Append
              (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384,
               Cf_Hs (1 .. Cf_Hs_Last));
            Tls_Core.Aead_Channel.Send
              (D.Hs_Out_Dir,
               Cf_Hs (1 .. Cf_Hs_Last),
               Tls_Core.Aead_Channel.Inner_Type_Handshake,
               Cf_Rec, Cf_Rec_Last);
            Out_Buf (1 .. Cf_Rec_Last) :=
              Cf_Rec (1 .. Cf_Rec_Last);
            Out_Last := Cf_Rec_Last;
         end;

         --  resumption_master_secret per §7.1 (CH..CF).
         if D.Master_Set then
            declare
               Th_After_Cf : Tls_Core.Key_Sched.Max_Digest;
            begin
               Tls_Core.Key_Sched.Transcript_Snapshot
                 (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384,
                  Th_After_Cf);
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

end Tls_Core.Tls13_Driver.Step_Awaiting_Sf_Cert;
