with Tls_Core.Aead_Channel;
with Tls_Core.Alert;
with Tls_Core.Cert;
with Tls_Core.Cert_Chain;
with Tls_Core.Cert_Verify;
with Tls_Core.Ecdsa_P256;
with Tls_Core.Handshake_Buffer;
with Tls_Core.Hello;
with Tls_Core.Key_Schedule;
with Tls_Core.Psk_Binder;
with Tls_Core.Session_Ticket;
with Tls_Core.X25519;
with Tls_Core.Key_Sched;
with Tls_Core.Tls13_Driver.Helpers; use Tls_Core.Tls13_Driver.Helpers;

package body Tls_Core.Tls13_Driver.Step_Awaiting_Ch
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use type Tls_Core.Octet;

   procedure Handle
     (D        : in out Driver;
      In_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   is
   begin
      Out_Buf := (others => 0);
      Out_Last := 0;

      --  RFC 8446 §4.1.3 cert-mode dispatch: parse cert CH,
      --  emit SH+EE+Cert+CertVerify+SF flight, transition to
      --  Awaiting_Cf. Mirrors the PSK branch's structure but
      --  with no binder check, no PSK extension, and the
      --  §4.4.2 + §4.4.3 cert/sig wire pieces inserted between
      --  EE and SF.
      if D.Mode = Cert_Mode then
         --  Step 1: parse outer TLSPlaintext + handshake header.
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
               Hs_Body_L : constant Natural :=
                 Hs_Body_F + Hs_Body_Len - 1;

               Random : Tls_Core.Hello.Random_Bytes;
               Sid_F, Sid_L : Natural;
               Suites_F, Suites_L : Natural;
               Sig_Algs_F, Sig_Algs_L : Natural;
               Ks_F, Ks_L : Natural;
               Decode_OK : Boolean;
            begin
               if Hs_Body_L > Rec_L then
                  D.Cur_State := Failed;
                  return;
               end if;
               Tls_Core.Hello.Decode_Client_Hello_Cert
                 (In_Bytes (Hs_Body_F .. Hs_Body_L),
                  Random, Sid_F, Sid_L,
                  Suites_F, Suites_L,
                  Sig_Algs_F, Sig_Algs_L,
                  Ks_F, Ks_L, Decode_OK);
               if not Decode_OK then
                  D.Cur_State := Failed;
                  return;
               end if;
               pragma Unreferenced (Sig_Algs_F, Sig_Algs_L);
               --  Capture legacy_session_id for SH echo (§4.1.3).
               if Sid_F > 0 and then Sid_L >= Sid_F
                 and then Sid_L - Sid_F + 1 <= 32
               then
                  D.Session_Id_Echo_Len := Sid_L - Sid_F + 1;
                  D.Session_Id_Echo (1 .. D.Session_Id_Echo_Len) :=
                    In_Bytes (Sid_F .. Sid_L);
               else
                  D.Session_Id_Echo_Len := 0;
               end if;
               --  v0.5 sig_algs scope is fixed at
               --  ecdsa_secp256r1_sha256; client is required to
               --  offer it. Decode_Client_Hello_Cert already
               --  asserts presence; per-scheme picking is a
               --  v0.5.x refinement.
               declare
                  Peer_Pub : Tls_Core.X25519.Bytes_32;
                  Shared   : Tls_Core.X25519.Bytes_32;
               begin
                  for I in 1 .. Tls_Core.Key_Sched.Hash_Len (D.Suite) loop
                     pragma Loop_Invariant (I in 1 .. 32);
                     Peer_Pub (I) := In_Bytes (Ks_F + I - 1);
                  end loop;
                  D.Peer_Ecdhe_Pub := Peer_Pub;
                  Tls_Core.X25519.Scalar_Mult
                    (D.My_Ecdhe_Priv, Peer_Pub, Shared);
                  D.Ecdhe_Shared := Shared;
               end;
               --  Cipher-suite selection — same v0.5 SHA-256
               --  restriction as PSK branch.
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
                     if Code =
                          Tls_Core.Suites.TLS_AES_128_GCM_SHA256
                     then
                        D.Suite :=
                          Tls_Core.Suites.Aes_128_Gcm_Sha256;
                        Found := True;
                        exit;
                     elsif Code =
                             Tls_Core.Suites
                               .TLS_CHACHA20_POLY1305_SHA256
                     then
                        D.Suite :=
                          Tls_Core.Suites
                            .Chacha20_Poly1305_Sha256;
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
               --  Append CH (handshake message) to transcript.
               Tls_Core.Key_Sched.Transcript_Append (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, In_Bytes (Rec_F .. Rec_L));
            end;
         end;

         --  Step 2: build SH + key schedule + EE + Cert +
         --  CertVerify + SF.  Cert-mode key schedule (§7.1):
         --    Early_Secret = HKDF-Extract(Zero, Zero)  -- PSK = 0
         --    Derived_1    = Derive-Secret(Early, "derived", "")
         --    Hs_Secret    = HKDF-Extract(Derived_1, ECDHE)
         declare
            Server_Random : constant Tls_Core.Hello.Random_Bytes :=
              (others => 16#5E#);

            Sh_Body : Octet_Array (1 .. 256) := (others => 0);
            Sh_Body_Last : Natural;
            Sh_Hs    : Octet_Array (1 .. 512) := (others => 0);
            Sh_Hs_Last : Natural;
            Sh_Rec   : Octet_Array (1 .. 1024) := (others => 0);
            Sh_Rec_Last : Natural;

            Zero32   : constant Octet_Array (1 .. 32) :=
              (others => 0);
            Empty_In : constant Octet_Array (1 .. 0) :=
              (others => 0);
            Empty_Hash : Tls_Core.Key_Sched.Max_Digest;

            Derived_Lab : constant Octet_Array (1 .. 7) :=
              (16#64#, 16#65#, 16#72#, 16#69#, 16#76#, 16#65#,
               16#64#);
            C_Hs_Lab : constant Octet_Array (1 .. 12) :=
              (16#63#, 16#20#, 16#68#, 16#73#, 16#20#, 16#74#,
               16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
            S_Hs_Lab : constant Octet_Array (1 .. 12) :=
              (16#73#, 16#20#, 16#68#, 16#73#, 16#20#, 16#74#,
               16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
            C_Ap_Lab : constant Octet_Array (1 .. 12) :=
              (16#63#, 16#20#, 16#61#, 16#70#, 16#20#, 16#74#,
               16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
            S_Ap_Lab : constant Octet_Array (1 .. 12) :=
              (16#73#, 16#20#, 16#61#, 16#70#, 16#20#, 16#74#,
               16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);

            Early_Secret : Tls_Core.Key_Sched.Max_Secret;
            Derived_1    : Tls_Core.Key_Sched.Max_Secret;

            Th_After_Sh   : Tls_Core.Key_Sched.Max_Digest;
            Th_After_Cert : Tls_Core.Key_Sched.Max_Digest;
            Th_After_CV   : Tls_Core.Key_Sched.Max_Digest;
            Th_After_Sf   : Tls_Core.Key_Sched.Max_Digest;

            Out_Cursor : Natural := 0;
         begin
            --  Build SH (cert-mode SH = no pre_shared_key ext).
            Tls_Core.Hello.Encode_Server_Hello_Cert
              (Server_Random,
               D.Session_Id_Echo (1 .. D.Session_Id_Echo_Len),
               Tls_Core.Suites.Code_Of_Suite (D.Suite),
               D.My_Ecdhe_Pub,
               Sh_Body, Sh_Body_Last);
            Encode_Hs_Message
              (Hs_Type_SH, Sh_Body (1 .. Sh_Body_Last),
               Sh_Hs, Sh_Hs_Last);
            Tls_Core.Key_Sched.Transcript_Append (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Sh_Hs (1 .. Sh_Hs_Last));
            Wrap_Tls_Plaintext
              (Sh_Hs (1 .. Sh_Hs_Last), Sh_Rec, Sh_Rec_Last);

            --  Cert-mode key schedule.
            Tls_Core.Key_Sched.Transcript_Snapshot (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Th_After_Sh);
            Tls_Core.Key_Sched.Derive_Handshake_Secrets
              (Suite        => D.Suite,
               PSK          => Zero32,
               Ecdhe_Shared => D.Ecdhe_Shared,
               Th_After_Sh  => Th_After_Sh,
               C_Hs_Sec     => D.C_Hs_Sec,
               S_Hs_Sec     => D.S_Hs_Sec,
               Hs_Secret    => D.Hs_Secret);
            --  Open handshake-stage Aead_Channel directions.
            Tls_Core.Key_Sched.Init_Hs_Channel
              (D.Suite, D.Hs_Out_Dir, D.S_Hs_Sec);
            Tls_Core.Key_Sched.Init_Hs_Channel
              (D.Suite, D.Hs_In_Dir, D.C_Hs_Sec);

            --  Output buffer accumulator: SH (TLSPlaintext)
            --  followed by encrypted EE/Cert/CertVerify/SF
            --  records.
            Out_Buf (1 .. Sh_Rec_Last) := Sh_Rec (1 .. Sh_Rec_Last);
            Out_Cursor := Sh_Rec_Last;

            --  EE — empty extensions.
            declare
               Ee_Body : constant Octet_Array (1 .. 2) :=
                 (16#00#, 16#00#);
               Ee_Hs   : Octet_Array (1 .. 6) := (others => 0);
               Ee_Hs_Last : Natural;
               Ee_Rec  : Octet_Array (1 .. 256) := (others => 0);
               Ee_Rec_Last : Natural;
            begin
               Encode_Hs_Message
                 (Hs_Type_EE, Ee_Body, Ee_Hs, Ee_Hs_Last);
               Tls_Core.Key_Sched.Transcript_Append (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Ee_Hs (1 .. Ee_Hs_Last));
               Tls_Core.Aead_Channel.Send
                 (D.Hs_Out_Dir,
                  Ee_Hs (1 .. Ee_Hs_Last),
                  Tls_Core.Aead_Channel.Inner_Type_Handshake,
                  Ee_Rec, Ee_Rec_Last);
               Out_Buf (Out_Cursor + 1 ..
                          Out_Cursor + Ee_Rec_Last) :=
                 Ee_Rec (1 .. Ee_Rec_Last);
               Out_Cursor := Out_Cursor + Ee_Rec_Last;
            end;

            --  Certificate (RFC 8446 §4.4.2). v0.5 emits the
            --  leaf cert only — a single CertificateEntry.
            --  Cert_Chain_Spec.Entries (1) names the leaf
            --  (First..Last) inside D.Cert_Chain_Bytes.
            declare
               Leaf_F : constant Natural :=
                 D.Cert_Chain_Spec.Entries (1).First;
               Leaf_L : constant Natural :=
                 D.Cert_Chain_Spec.Entries (1).Last;
               Cert_Body : Octet_Array (1 .. 1 + 3 + 3 + 2 + 2048)
                 := (others => 0);
               Cert_Body_Last : Natural;
               Cert_Hs   : Octet_Array (1 .. 4 + 1 + 3 + 3 + 2 + 2048)
                 := (others => 0);
               Cert_Hs_Last : Natural;
               Cert_Rec  : Octet_Array (1 .. 4 + 1 + 3 + 3 + 2 + 2048 + 32)
                 := (others => 0);
               Cert_Rec_Last : Natural;
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
                  Cert_Body, Cert_Body_Last);
               Encode_Hs_Message
                 (Hs_Type_Cert, Cert_Body (1 .. Cert_Body_Last),
                  Cert_Hs, Cert_Hs_Last);
               Tls_Core.Key_Sched.Transcript_Append (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Cert_Hs (1 .. Cert_Hs_Last));
               Tls_Core.Aead_Channel.Send
                 (D.Hs_Out_Dir,
                  Cert_Hs (1 .. Cert_Hs_Last),
                  Tls_Core.Aead_Channel.Inner_Type_Handshake,
                  Cert_Rec, Cert_Rec_Last);
               if Out_Cursor + Cert_Rec_Last > Out_Buf'Last then
                  D.Cur_State := Failed;
                  return;
               end if;
               Out_Buf (Out_Cursor + 1 ..
                          Out_Cursor + Cert_Rec_Last) :=
                 Cert_Rec (1 .. Cert_Rec_Last);
               Out_Cursor := Out_Cursor + Cert_Rec_Last;
            end;

            --  CertificateVerify (RFC 8446 §4.4.3).
            Tls_Core.Key_Sched.Transcript_Snapshot (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Th_After_Cert);
            declare
               Signed_Buf : Octet_Array (1 .. 64 + 33 + 1 + 32) :=
                 (others => 0);
               Signed_Last : Natural;
               K_Bytes : Tls_Core.Ecdsa_P256.Component;
               K_OK    : Boolean;
               R, S   : Tls_Core.Ecdsa_P256.Component;
               Sign_OK : Boolean;
               Der_Sig : Octet_Array (1 .. 72) := (others => 0);
               Der_Last : Natural;
               Cv_Body  : Octet_Array (1 .. 4 + 72) := (others => 0);
               Cv_Body_Last : Natural;
               Cv_Hs    : Octet_Array (1 .. 4 + 4 + 72) :=
                 (others => 0);
               Cv_Hs_Last : Natural;
               Cv_Rec   : Octet_Array (1 .. 256) := (others => 0);
               Cv_Rec_Last : Natural;
            begin
               Tls_Core.Cert_Verify.Build_Signed_Content
                 (Side            => Tls_Core.Cert_Verify.Server,
                  Transcript_Hash => Th_After_Cert (1 .. 32),
                  Out_Buf         => Signed_Buf,
                  Out_Last        => Signed_Last);
               --  RFC 6979 §3.2 deterministic K — same K
               --  openssl / Go / rustls / BoringSSL would
               --  derive for the same (priv, message) pair, so
               --  Tier-D external matrix can compare bit-for-bit.
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
                  Cv_Hs, Cv_Hs_Last);
               Tls_Core.Key_Sched.Transcript_Append (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Cv_Hs (1 .. Cv_Hs_Last));
               Tls_Core.Aead_Channel.Send
                 (D.Hs_Out_Dir,
                  Cv_Hs (1 .. Cv_Hs_Last),
                  Tls_Core.Aead_Channel.Inner_Type_Handshake,
                  Cv_Rec, Cv_Rec_Last);
               if Out_Cursor + Cv_Rec_Last > Out_Buf'Last then
                  D.Cur_State := Failed;
                  return;
               end if;
               Out_Buf (Out_Cursor + 1 ..
                          Out_Cursor + Cv_Rec_Last) :=
                 Cv_Rec (1 .. Cv_Rec_Last);
               Out_Cursor := Out_Cursor + Cv_Rec_Last;
            end;

            --  Server Finished — HMAC of s_hs_finished_key over
            --  transcript-after-CertVerify (§4.4.4).
            Tls_Core.Key_Sched.Transcript_Snapshot (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Th_After_CV);
            declare
               Verify_Data : Tls_Core.Key_Sched.Max_Digest;
               Fin_Hs : Octet_Array (1 .. 4 + 32) := (others => 0);
               Fin_Hs_Last : Natural;
               Fin_Rec : Octet_Array (1 .. 256) := (others => 0);
               Fin_Rec_Last : Natural;
            begin
               Tls_Core.Key_Sched.Build_Finished
                 (D.Suite, D.S_Hs_Sec, Th_After_CV, Verify_Data);
               Encode_Hs_Message
                 (Hs_Type_Finished, Verify_Data (1 .. 32),
                  Fin_Hs, Fin_Hs_Last);
               Tls_Core.Key_Sched.Transcript_Append (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Fin_Hs (1 .. Fin_Hs_Last));
               Tls_Core.Aead_Channel.Send
                 (D.Hs_Out_Dir,
                  Fin_Hs (1 .. Fin_Hs_Last),
                  Tls_Core.Aead_Channel.Inner_Type_Handshake,
                  Fin_Rec, Fin_Rec_Last);
               if Out_Cursor + Fin_Rec_Last > Out_Buf'Last then
                  D.Cur_State := Failed;
                  return;
               end if;
               Out_Buf (Out_Cursor + 1 ..
                          Out_Cursor + Fin_Rec_Last) :=
                 Fin_Rec (1 .. Fin_Rec_Last);
               Out_Last := Out_Cursor + Fin_Rec_Last;
            end;

            --  Application traffic secrets + expected client
            --  Finished verify_data.
            Tls_Core.Key_Sched.Transcript_Snapshot (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Th_After_Sf);
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
         end;
         return;
      end if;

      --  Parse one TLSPlaintext record holding ClientHello.
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
            --  Decode the CH body — also validates the client
            --  advertises psk_dhe_ke (mode 1) and includes a
            --  valid x25519 key_share. Returns absolute indices.
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
            --  Capture legacy_session_id for SH echo (§4.1.3).
            if Sid_F > 0 and then Sid_L >= Sid_F
              and then Sid_L - Sid_F + 1 <= 32
            then
               D.Session_Id_Echo_Len := Sid_L - Sid_F + 1;
               D.Session_Id_Echo (1 .. D.Session_Id_Echo_Len) :=
                 In_Bytes (Sid_F .. Sid_L);
            else
               D.Session_Id_Echo_Len := 0;
            end if;
            --  RFC 8446 §4.2.8 + §7.1 mode 3 — extract the
            --  client's X25519 public key and compute ECDHE
            --  shared secret on the server side.
            declare
               Peer_Pub : Tls_Core.X25519.Bytes_32;
               Shared   : Tls_Core.X25519.Bytes_32;
            begin
               for I in 1 .. Tls_Core.Key_Sched.Hash_Len (D.Suite) loop
                  pragma Loop_Invariant (I in 1 .. 32);
                  Peer_Pub (I) := In_Bytes (Ks_F + I - 1);
               end loop;
               D.Peer_Ecdhe_Pub := Peer_Pub;
               Tls_Core.X25519.Scalar_Mult
                 (D.My_Ecdhe_Priv, Peer_Pub, Shared);
               D.Ecdhe_Shared := Shared;
            end;
            --  Server cipher-suite selection (RFC 8446 §4.1.3):
            --  walk client's offered list in order and pick
            --  the first that we actually accept. v0.5 driver
            --  internal key schedule is SHA-256-only (see
            --  package wall-hit note), so we only accept the
            --  two SHA-256-based suites here. If none match
            --  → Failed (handshake_failure equivalent).
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
                  end if;
                  Q := Q + 2;
               end loop;
               if not Found then
                  D.Cur_State := Failed;
                  return;
               end if;
            end;
            --  Decode_*_Psk returns absolute indices into the
            --  In_Bytes slice it was passed; that slice has
            --  'First = Hs_Body_F so the indices already are
            --  in our outer In_Bytes' coordinate space.
            declare
               Abs_Id_F : constant Natural := Id_F;
               Abs_Id_L : constant Natural := Id_L;
               Abs_Bf : constant Natural := Bf;
               Abs_Bl : constant Natural := Bl;
               Abs_T_Last : constant Natural := T_Last;

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
               --  Verify PSK binder.  RFC 8446 §4.2.11.2 + §4.4.1:
               --  the binder is computed over the truncated
               --  *handshake message* (Rec_F .. Abs_T_Last
               --  spans CH type byte through last pre-binders
               --  body byte), NOT the body alone (Hs_Body_F ..
               --  Abs_T_Last).  Copy into a local 'First=1
               --  buffer so Compute's 'First=1 Pre is satisfied.
               declare
                  Computed : Tls_Core.Psk_Binder.Binder_Bytes;
                  Received : Tls_Core.Psk_Binder.Binder_Bytes;
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
                  for I in 1 .. Tls_Core.Key_Sched.Hash_Len (D.Suite) loop
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
            Tls_Core.Key_Sched.Transcript_Append (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, In_Bytes (Rec_F .. Rec_L));
         end;
      end;

      --  RFC 8446 §4.1.4 — HelloRetryRequest emission branch.
      --
      --  If the server was initialised with Hrr_Demand and has
      --  not yet sent an HRR, we now emit one *instead* of the
      --  SH+EE+SF flight. We also rebuild the transcript per
      --  §4.4.1: snapshot CH1's current accumulator, re-init,
      --  feed synthetic message_hash, then feed HRR. Subsequent
      --  CH2 will be appended on top of that.
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
            --  Snapshot CH1 hash (transcript currently holds
            --  exactly CH1) — we save it for diagnostic
            --  introspection and feed it into the synthetic.
            Tls_Core.Key_Sched.Transcript_Snapshot
              (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, D.Hrr_Ch1_Hash);
            --  Encode HRR body.
            Tls_Core.Hello_Retry.Encode_Hrr
              (Selected_Suite => Tls_Core.Suites.Code_Of_Suite (D.Suite),
               Selected_Group => D.Hrr_Group,
               Cookie         => Cookie_Slice,
               Out_Buf        => Hrr_Body,
               Out_Last       => Hrr_Body_Last);
            --  Wrap as a Handshake message (type 0x02 — same
            --  type as ServerHello per §4.1.4).
            Encode_Hs_Message
              (Hs_Type_SH,
               Hrr_Body (1 .. Hrr_Body_Last),
               Hrr_Hs, Hrr_Hs_Last);
            --  Rebuild transcript per RFC 8446 §4.4.1:
            --    new transcript = synthetic(CH1_hash) || HRR
            Tls_Core.Hello_Retry.Build_Synthetic_Msg_Sha256
              (D.Hrr_Ch1_Hash (1 .. 32), Synthetic);
            Tls_Core.Transcript.Init (D.Hash_Ctx);
            Tls_Core.Key_Sched.Transcript_Append (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Synthetic);
            Tls_Core.Key_Sched.Transcript_Append (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Hrr_Hs (1 .. Hrr_Hs_Last));
            --  Wrap HRR as TLSPlaintext on the wire.
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

         Early_Secret : Tls_Core.Key_Sched.Max_Secret;
         Derived_1    : Tls_Core.Key_Sched.Max_Secret;
         Hs_Secret    : Tls_Core.Key_Sched.Max_Secret;
         C_Hs_Sec     : Tls_Core.Key_Sched.Max_Secret;
         S_Hs_Sec     : Tls_Core.Key_Sched.Max_Secret;

         Transcript_Hash_After_SH : Tls_Core.Key_Sched.Max_Digest;
      begin
         pragma Unreferenced (Empty_Identity_Buf);

         --  SH body = canonical PSK SH (echoes selected_identity = 0
         --  and the server's chosen cipher suite per RFC 8446 §4.1.3).
         --  The key_share carries the server's X25519 public key,
         --  echoing the named-group the client offered (x25519).
         Tls_Core.Hello.Encode_Server_Hello_Psk
           (Server_Random,
            D.Session_Id_Echo (1 .. D.Session_Id_Echo_Len),
            Tls_Core.Suites.Code_Of_Suite (D.Suite),
            D.My_Ecdhe_Pub,
            Sh_Body, Sh_Body_Last);
         --  Wrap body into Handshake message (type + u24 + body).
         Encode_Hs_Message
           (Hs_Type_SH,
            Sh_Body (1 .. Sh_Body_Last),
            Sh_Hs_Msg, Sh_Hs_Last);
         --  Append to transcript.
         Tls_Core.Key_Sched.Transcript_Append (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Sh_Hs_Msg (1 .. Sh_Hs_Last));
         --  Wrap as TLSPlaintext for the wire.
         Wrap_Tls_Plaintext
           (Sh_Hs_Msg (1 .. Sh_Hs_Last), Sh_Record, Sh_Record_Last);

         --  Derive Early/Handshake secrets. RFC 8446 §7.1 mode 3:
         --    Handshake_Secret = HKDF-Extract(Derived_1, ECDHE_secret)
         --  D.Ecdhe_Shared was computed at CH parse time.
         Tls_Core.Key_Sched.Transcript_Snapshot (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Transcript_Hash_After_SH);
         Tls_Core.Key_Sched.Derive_Handshake_Secrets
           (Suite        => D.Suite,
            PSK          => D.PSK,
            Ecdhe_Shared => D.Ecdhe_Shared,
            Th_After_Sh  => Transcript_Hash_After_SH,
            C_Hs_Sec     => C_Hs_Sec,
            S_Hs_Sec     => S_Hs_Sec,
            Hs_Secret    => Hs_Secret);

         --  Open Aead_Channel Hs_Out_Dir / Hs_In_Dir (server:
         --  out encrypts with s_hs, in decrypts with c_hs). The
         --  Init_Sha256 dispatcher pins the variant to D.Suite.
         Tls_Core.Key_Sched.Init_Hs_Channel
           (D.Suite, D.Hs_Out_Dir, S_Hs_Sec);
         Tls_Core.Key_Sched.Init_Hs_Channel
           (D.Suite, D.Hs_In_Dir, C_Hs_Sec);

         --  Save the secrets for later finished-key derivation
         --  + master-secret derivation in this same Step body.
         D.C_Hs_Sec := C_Hs_Sec;
         D.S_Hs_Sec := S_Hs_Sec;
         D.Hs_Secret := Hs_Secret;

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
            Tls_Core.Key_Sched.Transcript_Append (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Ee_Hs (1 .. Ee_Hs_Last));
            Tls_Core.Aead_Channel.Send
              (D.Hs_Out_Dir,
               Ee_Hs (1 .. Ee_Hs_Last),
               Tls_Core.Aead_Channel.Inner_Type_Handshake,
               Ee_Rec, Ee_Rec_Last);

            --  Build Server Finished.
            declare
               Th_After_EE : Tls_Core.Key_Sched.Max_Digest;
               Verify_Data : Tls_Core.Key_Sched.Max_Digest;
               Fin_Hs : Octet_Array (1 .. 4 + 32) := (others => 0);
               Fin_Hs_Last : Natural;
               Fin_Rec : Octet_Array (1 .. 256) := (others => 0);
               Fin_Rec_Last : Natural;
            begin
               Tls_Core.Key_Sched.Transcript_Snapshot (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Th_After_EE);
               Tls_Core.Key_Sched.Build_Finished
                 (D.Suite, S_Hs_Sec, Th_After_EE, Verify_Data);
               Encode_Hs_Message
                 (Hs_Type_Finished, Verify_Data (1 .. 32),
                  Fin_Hs, Fin_Hs_Last);
               Tls_Core.Key_Sched.Transcript_Append (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Fin_Hs (1 .. Fin_Hs_Last));
               Tls_Core.Aead_Channel.Send
                 (D.Hs_Out_Dir,
                  Fin_Hs (1 .. Fin_Hs_Last),
                  Tls_Core.Aead_Channel.Inner_Type_Handshake,
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

               --  Snapshot transcript hash CH || SH || EE || SF
               --  and use it for both:
               --    * expected client Finished verify_data (via c_hs)
               --    * application traffic secrets (via Master_Secret)
               declare
                  Th_After_SF : Tls_Core.Key_Sched.Max_Digest;

                  Empty_Hash : Tls_Core.Key_Sched.Max_Digest;
                  Empty_In   : constant Octet_Array (1 .. 0) :=
                    (others => 0);
                  Derived_2_Sec : Tls_Core.Key_Sched.Max_Secret;
                  Master_Secret : Tls_Core.Key_Sched.Max_Secret;
                  Zero_Secret : constant Tls_Core.Key_Sched.Max_Secret :=
                    (others => 0);
                  Derived_Lab : constant Octet_Array (1 .. 7) :=
                    (16#64#, 16#65#, 16#72#, 16#69#, 16#76#, 16#65#, 16#64#);
                  C_Ap_Lab : constant Octet_Array (1 .. 12) :=
                    (16#63#, 16#20#, 16#61#, 16#70#, 16#20#, 16#74#,
                     16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
                  S_Ap_Lab : constant Octet_Array (1 .. 12) :=
                    (16#73#, 16#20#, 16#61#, 16#70#, 16#20#, 16#74#,
                     16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
               begin
                  Tls_Core.Key_Sched.Transcript_Snapshot (D.Suite, D.Hash_Ctx, D.Hash_Ctx_384, Th_After_SF);

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

                  --  Expected client Finished body — HMAC of
                  --  c_hs_finished_key over Th_After_SF.
                  Tls_Core.Key_Sched.Build_Finished
                    (D.Suite, D.C_Hs_Sec, Th_After_SF, D.Expected_Cf);
               end;
            end;
         end;

         D.Cur_State := Awaiting_Cf;
      end;


   end Handle;

end Tls_Core.Tls13_Driver.Step_Awaiting_Ch;
