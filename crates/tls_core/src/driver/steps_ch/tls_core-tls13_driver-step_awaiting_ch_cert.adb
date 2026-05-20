with Interfaces;
with Tls_Core.Aead_Channel;
with Tls_Core.Alert;
with Tls_Core.Cert;
with Tls_Core.Cert_Chain;
with Tls_Core.Client_Hello_Rflx;
with Tls_Core.Cert_Verify;
with Tls_Core.Ecdsa_P256;
with Tls_Core.Hello;
with Tls_Core.Key_Sched;
with Tls_Core.X25519;
with Tls_Core.Tls13_Driver.Helpers; use Tls_Core.Tls13_Driver.Helpers;

package body Tls_Core.Tls13_Driver.Step_Awaiting_Ch_Cert
  with SPARK_Mode
is


   use type Tls_Core.Octet;

   procedure Handle
     (D        : in out Driver;
      In_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural) is
   begin
      Out_Buf := [others => 0];
      Out_Last := 0;

      if In_Bytes'Length < 5
        or else In_Bytes (In_Bytes'First) /= Rec_Type_Handshake
      then
         Fail_Plaintext
           (D, Tls_Core.Alert.Desc_Decode_Error, Out_Buf, Out_Last);
         return;
      end if;
      declare
         Rec_Len : constant Natural :=
           Natural (In_Bytes (In_Bytes'First + 3))
           * 256
           + Natural (In_Bytes (In_Bytes'First + 4));
         Rec_F   : constant Natural := In_Bytes'First + 5;
         Rec_L   : constant Natural := Rec_F + Rec_Len - 1;
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
              Natural (In_Bytes (Rec_F + 1))
              * 65536
              + Natural (In_Bytes (Rec_F + 2)) * 256
              + Natural (In_Bytes (Rec_F + 3));
            Hs_Body_F   : constant Natural := Rec_F + 4;
            Hs_Body_L   : constant Natural := Hs_Body_F + Hs_Body_Len - 1;

            Random                 : Tls_Core.Hello.Random_Bytes;
            Sid_F, Sid_L           : Natural;
            Suites_F, Suites_L     : Natural;
            Sig_Algs_F, Sig_Algs_L : Natural;
            Ks_F, Ks_L             : Natural;
            Decode_OK              : Boolean;
         begin
            if Hs_Body_L > Rec_L then
               D.Cur_State := Failed;
               return;
            end if;
            --  CH minimum 42 bytes per RFC 8446 §4.1.2: legacy
            --  version (2) + random (32) + sid_len (1) + suites_len
            --  (2) + at least one suite (2) + compression (2) +
            --  ext_len (2) ≥ 43 with empty extensions.  Reject
            --  shorter inputs below the decoder Pre.
            if Hs_Body_L - Hs_Body_F + 1 < 42 then
               D.Cur_State := Failed;
               return;
            end if;
            declare
               CH_Len : constant Natural := Hs_Body_L - Hs_Body_F + 1;
               CH_Buf : Octet_Array (1 .. CH_Len);
            begin
               CH_Buf := In_Bytes (Hs_Body_F .. Hs_Body_L);
               Tls_Core.Client_Hello_Rflx.Decode_Client_Hello_Cert
                 (CH_Buf,
                  Random,
                  Sid_F,
                  Sid_L,
                  Suites_F,
                  Suites_L,
                  Sig_Algs_F,
                  Sig_Algs_L,
                  Ks_F,
                  Ks_L,
                  Decode_OK);
               if Decode_OK then
                  declare
                     Off : constant Natural := Hs_Body_F - 1;
                  begin
                     if Sid_F > 0 then
                        Sid_F := Sid_F + Off;
                        Sid_L := Sid_L + Off;
                     end if;
                     Suites_F := Suites_F + Off;
                     Suites_L := Suites_L + Off;
                     if Suites_L > In_Bytes'Last then
                        Decode_OK := False;
                     end if;
                     Sig_Algs_F := Sig_Algs_F + Off;
                     Sig_Algs_L := Sig_Algs_L + Off;
                     Ks_F := Ks_F + Off;
                     Ks_L := Ks_L + Off;
                  end;
               end if;
            end;
            if not Decode_OK then
               D.Cur_State := Failed;
               return;
            end if;
            pragma Unreferenced (Sig_Algs_F, Sig_Algs_L);
            if Sid_F > 0
              and then Sid_L >= Sid_F
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
               Tls_Core.X25519.Scalar_Mult (D.My_Ecdhe_Priv, Peer_Pub, Shared);
               D.Ecdhe_Shared := Shared;
            end;
            pragma Assert (Suites_L <= In_Bytes'Last);
            declare
               use type Tls_Core.Suites.U16;
               Found : Boolean := False;
               Code  : Tls_Core.Suites.U16;
               Q     : Natural := Suites_F;
            begin
               while Q + 1 <= Suites_L loop
                  pragma
                    Loop_Invariant
                      (Q in Suites_F .. Suites_L
                         and then Suites_L <= In_Bytes'Last);
                  Code :=
                    Tls_Core.Suites.U16 (In_Bytes (Q))
                    * 256
                    + Tls_Core.Suites.U16 (In_Bytes (Q + 1));
                  if Code = Tls_Core.Suites.TLS_AES_128_GCM_SHA256 then
                     D.Suite := Tls_Core.Suites.Aes_128_Gcm_Sha256;
                     Found := True;
                     exit;
                  elsif Code = Tls_Core.Suites.TLS_CHACHA20_POLY1305_SHA256
                  then
                     D.Suite := Tls_Core.Suites.Chacha20_Poly1305_Sha256;
                     Found := True;
                     exit;
                  elsif Code = Tls_Core.Suites.TLS_AES_256_GCM_SHA384 then
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
            Tls_Core.Key_Sched.Transcript_Append
              (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, In_Bytes (Rec_F .. Rec_L));
         end;
      end;

      --  Build SH + key schedule + EE + Cert + CertVerify + SF.
      declare
         Server_Random : constant Tls_Core.Hello.Random_Bytes :=
           [others => 16#5E#];

         Sh_Body      : Octet_Array (1 .. 256) := [others => 0];
         Sh_Body_Last : Natural;
         Sh_Hs        : Octet_Array (1 .. 512) := [others => 0];
         Sh_Hs_Last   : Natural;
         Sh_Rec       : Octet_Array (1 .. 1024) := [others => 0];
         Sh_Rec_Last  : Natural;

         Zero32 : constant Octet_Array (1 .. 32) := [others => 0];

         Th_After_Sh   : Tls_Core.Key_Sched.Max_Digest;
         Th_After_Cert : Tls_Core.Key_Sched.Max_Digest;
         Th_After_CV   : Tls_Core.Key_Sched.Max_Digest;
         Th_After_Sf   : Tls_Core.Key_Sched.Max_Digest;
         Flight_Last   : Natural := 0;

         Out_Cursor : Natural := 0;
      begin
         Tls_Core.Hello.Encode_Server_Hello_Cert
           (Server_Random,
            D.Session_Id_Echo (1 .. D.Session_Id_Echo_Len),
            Tls_Core.Suites.Code_Of_Suite (D.Suite),
            D.My_Ecdhe_Pub,
            Sh_Body,
            Sh_Body_Last);
         Encode_Hs_Message
           (Hs_Type_SH, Sh_Body (1 .. Sh_Body_Last), Sh_Hs, Sh_Hs_Last);
         Tls_Core.Key_Sched.Transcript_Append
           (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Sh_Hs (1 .. Sh_Hs_Last));
         Wrap_Tls_Plaintext (Sh_Hs (1 .. Sh_Hs_Last), Sh_Rec, Sh_Rec_Last);

         Tls_Core.Key_Sched.Transcript_Snapshot
           (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Th_After_Sh);
         Tls_Core.Key_Sched.Derive_Handshake_Secrets
           (Suite        => D.Suite,
            PSK          => Zero32,
            Ecdhe_Shared => D.Ecdhe_Shared,
            Th_After_Sh  => Th_After_Sh,
            C_Hs_Sec     => D.C_Hs_Sec,
            S_Hs_Sec     => D.S_Hs_Sec,
            Hs_Secret    => D.Hs_Secret);
         Tls_Core.Key_Sched.Init_Hs_Channel
           (D.Suite, D.Hs_Out_Dir, D.S_Hs_Sec);
         Tls_Core.Key_Sched.Init_Hs_Channel (D.Suite, D.Hs_In_Dir, D.C_Hs_Sec);

         Out_Buf (1 .. Sh_Rec_Last) := Sh_Rec (1 .. Sh_Rec_Last);
         Out_Cursor := Sh_Rec_Last;

         --  EE — RFC 8446 §4.3.1. Include ALPN if selected.
         declare
            Alpn_N       : constant Natural := D.Selected_Alpn_Len;
            Ee_Ext_Len   : constant Natural :=
              (if Alpn_N > 0 then 4 + 2 + 1 + Alpn_N else 0);
            Ext_List_Len : constant Natural := Ee_Ext_Len;
            Ee_Body      : Octet_Array (1 .. 2 + Ext_List_Len) :=
              (others => 0);
            Ee_Hs        : Octet_Array (1 .. 6 + Ext_List_Len) :=
              (others => 0);
            Ee_Hs_Last   : Natural;
            Ee_Rec       : Octet_Array (1 .. 256) := [others => 0];
            Ee_Rec_Last  : Natural;
         begin
            Ee_Body (1) := Octet (Ext_List_Len / 256);
            Ee_Body (2) := Octet (Ext_List_Len mod 256);
            if Alpn_N > 0 then
               declare
                  List_Len : constant Natural := 1 + Alpn_N;
               begin
                  Ee_Body (3) := 16#00#;
                  Ee_Body (4) := 16#10#;
                  Ee_Body (5) := Octet ((2 + List_Len) / 256);
                  Ee_Body (6) := Octet ((2 + List_Len) mod 256);
                  Ee_Body (7) := Octet (List_Len / 256);
                  Ee_Body (8) := Octet (List_Len mod 256);
                  Ee_Body (9) := Octet (Alpn_N);
                  Ee_Body (10 .. 9 + Alpn_N) := D.Selected_Alpn (1 .. Alpn_N);
               end;
            end if;
            Encode_Hs_Message (Hs_Type_EE, Ee_Body, Ee_Hs, Ee_Hs_Last);
            Tls_Core.Key_Sched.Transcript_Append
              (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Ee_Hs (1 .. Ee_Hs_Last));
            Tls_Core.Aead_Channel.Send
              (D.Hs_Out_Dir,
               Ee_Hs (1 .. Ee_Hs_Last),
               Tls_Core.Aead_Channel.Inner_Type_Handshake,
               Ee_Rec,
               Ee_Rec_Last);
            Out_Buf (Out_Cursor + 1 .. Out_Cursor + Ee_Rec_Last) :=
              Ee_Rec (1 .. Ee_Rec_Last);
            Out_Cursor := Out_Cursor + Ee_Rec_Last;
         end;

         --  Certificate (RFC 8446 §4.4.2)
         declare
            Leaf_F         : constant Natural :=
              D.Cert_Chain_Spec.Entries (1).First;
            Leaf_L         : constant Natural :=
              D.Cert_Chain_Spec.Entries (1).Last;
            Cert_Body      : Octet_Array (1 .. 1 + 3 + 3 + 2 + 2048) :=
              [others => 0];
            Cert_Body_Last : Natural;
            Cert_Hs        : Octet_Array (1 .. 4 + 1 + 3 + 3 + 2 + 2048) :=
              [others => 0];
            Cert_Hs_Last   : Natural;
            Cert_Rec       :
              Octet_Array (1 .. 4 + 1 + 3 + 3 + 2 + 2048 + 32) :=
                [others => 0];
            Cert_Rec_Last  : Natural;
         begin
            if Leaf_F < D.Cert_Chain_Bytes'First
              or else Leaf_L > D.Cert_Chain_Bytes'Last
              or else Leaf_F > Leaf_L
              or else Leaf_L - Leaf_F + 1 > 2048
            then
               D.Cur_State := Failed;
               return;
            end if;
            Tls_Core.Cert_Verify.Encode_Body_Single
              (D.Cert_Chain_Bytes (Leaf_F .. Leaf_L),
               Cert_Body,
               Cert_Body_Last);
            Encode_Hs_Message
              (Hs_Type_Cert,
               Cert_Body (1 .. Cert_Body_Last),
               Cert_Hs,
               Cert_Hs_Last);
            Tls_Core.Key_Sched.Transcript_Append
              (D.Suite,
               D.Hash_Ctx,
               D.Hash_Ctx_384,
               Cert_Hs (1 .. Cert_Hs_Last));
            Tls_Core.Aead_Channel.Send
              (D.Hs_Out_Dir,
               Cert_Hs (1 .. Cert_Hs_Last),
               Tls_Core.Aead_Channel.Inner_Type_Handshake,
               Cert_Rec,
               Cert_Rec_Last);
            if Out_Cursor + Cert_Rec_Last > Out_Buf'Last then
               D.Cur_State := Failed;
               return;
            end if;
            Out_Buf (Out_Cursor + 1 .. Out_Cursor + Cert_Rec_Last) :=
              Cert_Rec (1 .. Cert_Rec_Last);
            Out_Cursor := Out_Cursor + Cert_Rec_Last;
         end;

         --  CertificateVerify (RFC 8446 §4.4.3)
         Tls_Core.Key_Sched.Transcript_Snapshot
           (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Th_After_Cert);
         declare
            Signed_Buf   :
              Octet_Array
                (1 .. 64 + 33 + 1 + Tls_Core.Key_Sched.Max_Hash_Len) :=
                [others => 0];
            Signed_Last  : Natural;
            K_Bytes      : Tls_Core.Ecdsa_P256.Component;
            K_OK         : Boolean;
            R, S         : Tls_Core.Ecdsa_P256.Component;
            Sign_OK      : Boolean;
            Der_Sig      : Octet_Array (1 .. 72) := [others => 0];
            Der_Last     : Natural;
            Cv_Body      : Octet_Array (1 .. 4 + 72) := [others => 0];
            Cv_Body_Last : Natural;
            Cv_Hs        : Octet_Array (1 .. 4 + 4 + 72) := [others => 0];
            Cv_Hs_Last   : Natural;
            Cv_Rec       : Octet_Array (1 .. 256) := [others => 0];
            Cv_Rec_Last  : Natural;
         begin
            Tls_Core.Cert_Verify.Build_Signed_Content
              (Side            => Tls_Core.Cert_Verify.Server,
               Transcript_Hash =>
                 Th_After_Cert (1 .. Tls_Core.Key_Sched.Hash_Len (D.Suite)),
               Out_Buf         => Signed_Buf,
               Out_Last        => Signed_Last);
            Tls_Core.Ecdsa_P256.Derive_K_Rfc6979
              (Private_Key => D.Server_Sign_Priv,
               Message     => Signed_Buf (1 .. Signed_Last),
               Out_K       => K_Bytes,
               OK          => K_OK);
            if not K_OK then
               D.Cur_State := Failed;
               return;
            end if;
            Tls_Core.Ecdsa_P256.Sign
              (Private_Key => D.Server_Sign_Priv,
               Message     => Signed_Buf (1 .. Signed_Last),
               K           => K_Bytes,
               Out_R       => R,
               Out_S       => S,
               OK          => Sign_OK);
            if not Sign_OK then
               D.Cur_State := Failed;
               return;
            end if;
            Tls_Core.Cert_Verify.Encode_Ecdsa_Sig_Der
              (R, S, Der_Sig, Der_Last);
            Tls_Core.Cert_Verify.Encode_Body
              (Sig_Scheme => Interfaces.Unsigned_16 (D.Sig_Alg),
               Signature  => Der_Sig (1 .. Der_Last),
               Out_Buf    => Cv_Body,
               Out_Last   => Cv_Body_Last);
            Encode_Hs_Message
              (Hs_Type_Cert_Verify,
               Cv_Body (1 .. Cv_Body_Last),
               Cv_Hs,
               Cv_Hs_Last);
            Tls_Core.Key_Sched.Transcript_Append
              (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Cv_Hs (1 .. Cv_Hs_Last));
            Tls_Core.Aead_Channel.Send
              (D.Hs_Out_Dir,
               Cv_Hs (1 .. Cv_Hs_Last),
               Tls_Core.Aead_Channel.Inner_Type_Handshake,
               Cv_Rec,
               Cv_Rec_Last);
            if Out_Cursor + Cv_Rec_Last > Out_Buf'Last then
               D.Cur_State := Failed;
               return;
            end if;
            Out_Buf (Out_Cursor + 1 .. Out_Cursor + Cv_Rec_Last) :=
              Cv_Rec (1 .. Cv_Rec_Last);
            Out_Cursor := Out_Cursor + Cv_Rec_Last;
         end;

         --  Server Finished (§4.4.4)
         Tls_Core.Key_Sched.Transcript_Snapshot
           (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Th_After_CV);
         declare
            Verify_Data  : Tls_Core.Key_Sched.Max_Digest;
            Fin_Hs       : Octet_Array (1 .. 4 + 48) := [others => 0];
            Fin_Hs_Last  : Natural;
            Fin_Rec      : Octet_Array (1 .. 256) := [others => 0];
            Fin_Rec_Last : Natural;
         begin
            Tls_Core.Key_Sched.Build_Finished
              (D.Suite, D.S_Hs_Sec, Th_After_CV, Verify_Data);
            Encode_Hs_Message
              (Hs_Type_Finished,
               Verify_Data (1 .. Tls_Core.Key_Sched.Hash_Len (D.Suite)),
               Fin_Hs,
               Fin_Hs_Last);
            Tls_Core.Key_Sched.Transcript_Append
              (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Fin_Hs (1 .. Fin_Hs_Last));
            Tls_Core.Aead_Channel.Send
              (D.Hs_Out_Dir,
               Fin_Hs (1 .. Fin_Hs_Last),
               Tls_Core.Aead_Channel.Inner_Type_Handshake,
               Fin_Rec,
               Fin_Rec_Last);
            if Out_Cursor + Fin_Rec_Last > Out_Buf'Last then
               D.Cur_State := Failed;
               return;
            end if;
            Out_Buf (Out_Cursor + 1 .. Out_Cursor + Fin_Rec_Last) :=
              Fin_Rec (1 .. Fin_Rec_Last);
            Flight_Last := Out_Cursor + Fin_Rec_Last;
         end;

         --  App secrets + expected client Finished.
         --  Per miTLS pattern: finalize D state BEFORE assigning
         --  Out_Last so the prover has the Out_Last bound fresh
         --  at procedure end (no intervening D mutations to
         --  invalidate the frame).
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
            Tls_Core.Key_Sched.Build_Finished
              (D.Suite, D.C_Hs_Sec, Th_After_Sf, D.Expected_Cf);
         end;

         D.Cur_State := Awaiting_Cf;
         Out_Last := Flight_Last;
      end;
   end Handle;

end Tls_Core.Tls13_Driver.Step_Awaiting_Ch_Cert;
