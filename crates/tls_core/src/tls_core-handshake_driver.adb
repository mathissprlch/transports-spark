with Tls_Core.Sha256;

package body Tls_Core.Handshake_Driver
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   use type Tls_Core.Octet;

   --  Wire framing for PSK_KE only: we model each Handshake as a
   --  single byte type + u24 length-prefixed body. This is the
   --  same shape as the RecordFlux Handshake_Layer envelope, but
   --  inlined here so the driver doesn't depend on the RFLX
   --  serializer (which lives outside SPARK_Mode).

   HS_Client_Hello       : constant := 16#01#;
   HS_Server_Hello       : constant := 16#02#;
   HS_Certificate        : constant := 16#0B#;
   HS_Certificate_Verify : constant := 16#0F#;
   HS_Finished           : constant := 16#14#;

   ---------------------------------------------------------------------
   --  Encode_Handshake — produce a 4-byte header + Body bytes into Buf.
   ---------------------------------------------------------------------

   procedure Encode_Handshake
     (Type_Of : Octet;
      Body_Bytes   : Octet_Array;
      Buf     : out Octet_Array;
      Last    : out Natural)
   with Pre =>
       Body_Bytes'Length <= 16#FFFFFF#
       and then Buf'First = 1
       and then Buf'Length >= 4 + Body_Bytes'Length;

   --  RFC 8446 §4.4.3 sig context for server CertificateVerify:
   --   64 × 0x20 || "TLS 1.3, server CertificateVerify" || 0x00 ||
   --   transcript_hash
   --  The Sha256 transcript hash is 32 bytes; total = 130.
   procedure Build_Cert_Verify_Sig_Material
     (Transcript_Hash : Tls_Core.Sha256.Digest;
      Out_Bytes       : out Octet_Array;
      Out_Last        : out Natural);
   procedure Build_Cert_Verify_Sig_Material
     (Transcript_Hash : Tls_Core.Sha256.Digest;
      Out_Bytes       : out Octet_Array;
      Out_Last        : out Natural)
   is
      --  "TLS 1.3, server CertificateVerify" — 33 bytes.
      Ctx_Str : constant Octet_Array (1 .. 33) :=
        (16#54#, 16#4C#, 16#53#, 16#20#, 16#31#, 16#2E#, 16#33#, 16#2C#,
         16#20#, 16#73#, 16#65#, 16#72#, 16#76#, 16#65#, 16#72#, 16#20#,
         16#43#, 16#65#, 16#72#, 16#74#, 16#69#, 16#66#, 16#69#, 16#63#,
         16#61#, 16#74#, 16#65#, 16#56#, 16#65#, 16#72#, 16#69#, 16#66#,
         16#79#);
   begin
      Out_Bytes := (others => 0);
      Out_Bytes (1 .. 64) := (others => 16#20#);
      Out_Bytes (65 .. 97) := Ctx_Str;
      Out_Bytes (98) := 16#00#;
      Out_Bytes (99 .. 130) := Transcript_Hash;
      Out_Last := 130;
   end Build_Cert_Verify_Sig_Material;

   procedure Encode_Handshake
     (Type_Of : Octet;
      Body_Bytes   : Octet_Array;
      Buf     : out Octet_Array;
      Last    : out Natural)
   is
      Len_24 : constant Natural := Body_Bytes'Length;
   begin
      Buf := (others => 0);
      Buf (1) := Type_Of;
      Buf (2) := Octet ((Len_24 / 65536) mod 256);
      Buf (3) := Octet ((Len_24 / 256) mod 256);
      Buf (4) := Octet (Len_24 mod 256);
      if Body_Bytes'Length > 0 then
         Buf (5 .. 4 + Body_Bytes'Length) := Body_Bytes;
      end if;
      Last := 4 + Body_Bytes'Length;
   end Encode_Handshake;

   ---------------------------------------------------------------------
   --  Init
   ---------------------------------------------------------------------

   procedure Init
     (D        : out Driver;
      For_Role : Role;
      PSK      : Octet_Array)
   is
   begin
      D.My_Role := For_Role;
      D.My_Mode := PSK_KE;
      D.PSK := PSK;
      D.My_Priv := (others => 0);
      D.My_Pub := (others => 0);
      D.Peer_Pub := (others => 0);
      D.Shared := (others => 0);
      D.CH_Buf := (others => 0);
      D.CH_Len := 0;
      D.SH_Buf := (others => 0);
      D.SH_Len := 0;
      D.SF_Buf := (others => 0);
      D.SF_Len := 0;
      D.Secrets_Set := False;
      D.Secrets.Client_Handshake := (others => 0);
      D.Secrets.Server_Handshake := (others => 0);
      D.Secrets.Client_App       := (others => 0);
      D.Secrets.Server_App       := (others => 0);
      Tls_Core.Transcript.Init (D.Hash_Ctx);
      case For_Role is
         when Client => D.Cur_State := Idle;
         when Server => D.Cur_State := Awaiting_Client_Hello;
      end case;
   end Init;

   ---------------------------------------------------------------------
   --  Common Ecdhe-mode initialisation helper.
   ---------------------------------------------------------------------

   procedure Init_Ecdhe_Common
     (D           : out Driver;
      For_Role    : Role;
      My_Mode     : Mode;
      Private_Key : Tls_Core.X25519.Bytes_32);
   procedure Init_Ecdhe_Common
     (D           : out Driver;
      For_Role    : Role;
      My_Mode     : Mode;
      Private_Key : Tls_Core.X25519.Bytes_32)
   is
      Pub : Tls_Core.X25519.Bytes_32;
   begin
      D.My_Role := For_Role;
      D.My_Mode := My_Mode;
      D.PSK := (others => 0);
      D.My_Priv := Private_Key;
      Tls_Core.X25519.Derive_Public (Private_Key, Pub);
      D.My_Pub := Pub;
      D.Peer_Pub := (others => 0);
      D.Shared := (others => 0);
      D.Sign_Seed := (others => 0);
      D.Sign_Pub := (others => 0);
      D.Trusted_Pub := (others => 0);
      D.CH_Buf := (others => 0);
      D.CH_Len := 0;
      D.SH_Buf := (others => 0);
      D.SH_Len := 0;
      D.SF_Buf := (others => 0);
      D.SF_Len := 0;
      D.Secrets_Set := False;
      D.Secrets.Client_Handshake := (others => 0);
      D.Secrets.Server_Handshake := (others => 0);
      D.Secrets.Client_App       := (others => 0);
      D.Secrets.Server_App       := (others => 0);
      Tls_Core.Transcript.Init (D.Hash_Ctx);
      case For_Role is
         when Client => D.Cur_State := Idle;
         when Server => D.Cur_State := Awaiting_Client_Hello;
      end case;
   end Init_Ecdhe_Common;

   procedure Init_Ecdhe
     (D            : out Driver;
      For_Role     : Role;
      Private_Key  : Tls_Core.X25519.Bytes_32)
   is
   begin
      Init_Ecdhe_Common (D, For_Role, ECDHE, Private_Key);
   end Init_Ecdhe;

   procedure Init_Ecdhe_With_Cert
     (D           : out Driver;
      Private_Key : Tls_Core.X25519.Bytes_32;
      Sign_Seed   : Tls_Core.Ed25519.Bytes_32)
   is
   begin
      Init_Ecdhe_Common (D, Server, ECDHE_With_Cert, Private_Key);
      D.Sign_Seed := Sign_Seed;
      Tls_Core.Ed25519.Public_Of_Seed (Sign_Seed, D.Sign_Pub);
   end Init_Ecdhe_With_Cert;

   procedure Init_Ecdhe_Verify
     (D               : out Driver;
      Private_Key     : Tls_Core.X25519.Bytes_32;
      Trusted_Pub_Key : Tls_Core.Ed25519.Bytes_32)
   is
   begin
      Init_Ecdhe_Common (D, Client, ECDHE_With_Cert, Private_Key);
      D.Trusted_Pub := Trusted_Pub_Key;
   end Init_Ecdhe_Verify;

   ---------------------------------------------------------------------
   --  Helpers — store an inbound message into the per-side Hello_Bytes
   --  buffers and feed it to the running transcript.
   ---------------------------------------------------------------------

   procedure Store
     (Dst     : in out Hello_Bytes;
      Dst_Len : in out Natural;
      Src     : Octet_Array)
   with Pre => Src'Length <= 1024;
   procedure Store
     (Dst     : in out Hello_Bytes;
      Dst_Len : in out Natural;
      Src     : Octet_Array)
   is
   begin
      if Src'Length > 0 then
         Dst (1 .. Src'Length) := Src;
      end if;
      Dst_Len := Src'Length;
   end Store;

   ---------------------------------------------------------------------
   --  Compute_Secrets — once both Hellos and SF are recorded, feed
   --  them to Tls_Core.Handshake.Derive_Psk_Secrets.
   ---------------------------------------------------------------------

   procedure Compute_Secrets (D : in out Driver)
   with Pre => D.CH_Len in 1 .. 1024
              and then D.SH_Len in 1 .. 1024
              and then D.SF_Len in 0 .. 1024;
   procedure Compute_Secrets (D : in out Driver) is
   begin
      case D.My_Mode is
         when PSK_KE =>
            Tls_Core.Handshake.Derive_Psk_Secrets
              (PSK             => D.PSK,
               Client_Hello    => D.CH_Buf (1 .. D.CH_Len),
               Server_Hello    => D.SH_Buf (1 .. D.SH_Len),
               Server_Finished => D.SF_Buf (1 .. D.SF_Len),
               Out_Secrets     => D.Secrets);
         when ECDHE | ECDHE_With_Cert =>
            Tls_Core.Handshake.Derive_Ecdhe_Secrets
              (ECDHE_Shared    => D.Shared,
               Client_Hello    => D.CH_Buf (1 .. D.CH_Len),
               Server_Hello    => D.SH_Buf (1 .. D.SH_Len),
               Server_Finished => D.SF_Buf (1 .. D.SF_Len),
               Out_Secrets     => D.Secrets);
      end case;
      D.Secrets_Set := True;
   end Compute_Secrets;

   ---------------------------------------------------------------------
   --  Step — the workhorse. Branches on current state + role.
   ---------------------------------------------------------------------

   procedure Step
     (D         : in out Driver;
      In_Bytes  : Octet_Array;
      Out_Buf   : out Octet_Array;
      Out_Last  : out Natural)
   is
      Empty : constant Octet_Array (1 .. 0) := (others => 0);
   begin
      Out_Buf := (others => 0);
      Out_Last := 0;

      --  Body_Of for emitted Hellos / Finished:
      --    PSK_KE  → reflect the PSK as the body bytes (deterministic,
      --              keeps both peers' transcripts identical).
      --    ECDHE   → for CH / SH the body is My_Pub (the X25519
      --              key_share extension's contents). Finished uses
      --              an arbitrary deterministic body (PSK is zero
      --              in this mode, but the body shape doesn't have
      --              to be the real verify_data for our loopback
      --              proof — both peers just need to agree on the
      --              transcript bytes).
      case D.Cur_State is
         when Idle =>
            if D.My_Role = Client then
               declare
                  Body_Of : constant Octet_Array :=
                    (if D.My_Mode = ECDHE
                       or else D.My_Mode = ECDHE_With_Cert
                     then D.My_Pub else D.PSK);
                  Wire    : Octet_Array (1 .. 4 + Body_Of'Length);
                  Wire_Last : Natural;
               begin
                  Encode_Handshake (HS_Client_Hello, Body_Of, Wire, Wire_Last);
                  Tls_Core.Transcript.Append (D.Hash_Ctx, Wire);
                  Store (D.CH_Buf, D.CH_Len, Wire);
                  Out_Buf (1 .. Wire_Last) := Wire (1 .. Wire_Last);
                  Out_Last := Wire_Last;
                  D.Cur_State := Awaiting_Server_Hello;
               end;
            else
               D.Cur_State := Failed;
            end if;

         when Awaiting_Client_Hello =>
            if D.My_Role = Server and then In_Bytes'Length >= 36 then
               Tls_Core.Transcript.Append (D.Hash_Ctx, In_Bytes);
               Store (D.CH_Buf, D.CH_Len, In_Bytes);

               --  ECDHE / ECDHE_With_Cert: extract peer's public key
               --  from CH body and compute the shared secret.
               if D.My_Mode = ECDHE
                 or else D.My_Mode = ECDHE_With_Cert
               then
                  for I in 1 .. 32 loop
                     D.Peer_Pub (I) := In_Bytes (In_Bytes'First + 4 + I - 1);
                  end loop;
                  Tls_Core.X25519.Scalar_Mult
                    (Scalar  => D.My_Priv,
                     U_Coord => D.Peer_Pub,
                     Out_Q   => D.Shared);
               end if;

               declare
                  Body_Of : constant Octet_Array :=
                    (if D.My_Mode = ECDHE
                       or else D.My_Mode = ECDHE_With_Cert
                     then D.My_Pub
                     else D.PSK);
                  Sh_Wire   : Octet_Array (1 .. 4 + Body_Of'Length);
                  Sh_Last   : Natural;
                  Fin_Body  : constant Octet_Array := D.PSK;
                  Sf_Wire   : Octet_Array (1 .. 4 + Fin_Body'Length);
                  Sf_Last   : Natural;

                  --  Cert + CV are only used in ECDHE_With_Cert.
                  Cert_Wire   : Octet_Array (1 .. 4 + 32);
                  Cert_Last   : Natural := 0;
                  Cv_Wire     : Octet_Array (1 .. 4 + 64);
                  Cv_Last     : Natural := 0;

                  Cursor : Natural;
               begin
                  Encode_Handshake
                    (HS_Server_Hello, Body_Of, Sh_Wire, Sh_Last);
                  Tls_Core.Transcript.Append (D.Hash_Ctx, Sh_Wire);
                  Store (D.SH_Buf, D.SH_Len, Sh_Wire);

                  --  Cert mode: append Certificate (= our Ed25519
                  --  public key, raw 32 bytes) and CertificateVerify
                  --  (signature over the transcript prefix per
                  --  RFC 8446 §4.4.3) before the Finished.
                  if D.My_Mode = ECDHE_With_Cert then
                     Encode_Handshake
                       (HS_Certificate, D.Sign_Pub, Cert_Wire, Cert_Last);
                     Tls_Core.Transcript.Append (D.Hash_Ctx, Cert_Wire);

                     declare
                        Snap : Tls_Core.Sha256.Digest;
                        Sig_Material : Octet_Array (1 .. 130);
                        Sig_Last     : Natural;
                        Sig          : Tls_Core.Ed25519.Signature;
                     begin
                        Tls_Core.Transcript.Snapshot (D.Hash_Ctx, Snap);
                        Build_Cert_Verify_Sig_Material
                          (Snap, Sig_Material, Sig_Last);
                        Tls_Core.Ed25519.Sign
                          (D.Sign_Seed,
                           Sig_Material (1 .. Sig_Last),
                           Sig);
                        Encode_Handshake (HS_Certificate_Verify, Sig,
                                          Cv_Wire, Cv_Last);
                     end;
                     Tls_Core.Transcript.Append (D.Hash_Ctx, Cv_Wire);
                  end if;

                  Encode_Handshake
                    (HS_Finished, Fin_Body, Sf_Wire, Sf_Last);
                  Tls_Core.Transcript.Append (D.Hash_Ctx, Sf_Wire);
                  Store (D.SF_Buf, D.SF_Len, Sf_Wire);

                  Compute_Secrets (D);

                  --  Pack the flight: SH || [Cert || CV] || SF.
                  Cursor := 0;
                  Out_Buf (Cursor + 1 .. Cursor + Sh_Last) :=
                    Sh_Wire (1 .. Sh_Last);
                  Cursor := Cursor + Sh_Last;
                  if D.My_Mode = ECDHE_With_Cert then
                     Out_Buf (Cursor + 1 .. Cursor + Cert_Last) :=
                       Cert_Wire (1 .. Cert_Last);
                     Cursor := Cursor + Cert_Last;
                     Out_Buf (Cursor + 1 .. Cursor + Cv_Last) :=
                       Cv_Wire (1 .. Cv_Last);
                     Cursor := Cursor + Cv_Last;
                  end if;
                  Out_Buf (Cursor + 1 .. Cursor + Sf_Last) :=
                    Sf_Wire (1 .. Sf_Last);
                  Out_Last := Cursor + Sf_Last;

                  D.Cur_State := Awaiting_Finished;
               end;
            else
               D.Cur_State := Failed;
            end if;

         when Awaiting_Server_Hello =>
            if D.My_Role = Client and then In_Bytes'Length > 8 then
               declare
                  Sh_Body_Len : constant Natural :=
                    Natural (In_Bytes (In_Bytes'First + 1)) * 65536
                    + Natural (In_Bytes (In_Bytes'First + 2)) * 256
                    + Natural (In_Bytes (In_Bytes'First + 3));
                  Sh_End : constant Natural :=
                    In_Bytes'First + 4 + Sh_Body_Len - 1;
               begin
                  if Sh_Body_Len <= 1024
                    and then Sh_End <= In_Bytes'Last
                    and then Sh_End + 4 <= In_Bytes'Last
                  then
                     declare
                        Sh_Bytes : constant Octet_Array :=
                          In_Bytes (In_Bytes'First .. Sh_End);
                        Cursor : Natural := Sh_End + 1;
                        Cert_OK : Boolean := True;
                     begin
                        --  ECDHE / ECDHE_With_Cert: SH body holds peer pubkey.
                        if (D.My_Mode = ECDHE
                            or else D.My_Mode = ECDHE_With_Cert)
                          and then Sh_Body_Len = 32
                        then
                           for I in 1 .. 32 loop
                              D.Peer_Pub (I) :=
                                Sh_Bytes (Sh_Bytes'First + 4 + I - 1);
                           end loop;
                           Tls_Core.X25519.Scalar_Mult
                             (Scalar  => D.My_Priv,
                              U_Coord => D.Peer_Pub,
                              Out_Q   => D.Shared);
                        end if;
                        Tls_Core.Transcript.Append (D.Hash_Ctx, Sh_Bytes);
                        Store (D.SH_Buf, D.SH_Len, Sh_Bytes);

                        --  Cert mode: parse Certificate + CertificateVerify
                        --  before falling through to the Finished.
                        if D.My_Mode = ECDHE_With_Cert then
                           --  Certificate
                           if Cursor + 3 > In_Bytes'Last
                             or else In_Bytes (Cursor) /= HS_Certificate
                           then
                              Cert_OK := False;
                           else
                              declare
                                 Cert_Body_Len : constant Natural :=
                                   Natural (In_Bytes (Cursor + 1)) * 65536
                                   + Natural (In_Bytes (Cursor + 2)) * 256
                                   + Natural (In_Bytes (Cursor + 3));
                                 Cert_End : constant Natural :=
                                   Cursor + 4 + Cert_Body_Len - 1;
                              begin
                                 if Cert_Body_Len /= 32
                                   or else Cert_End > In_Bytes'Last
                                 then
                                    Cert_OK := False;
                                 else
                                    --  Body bytes are the Ed25519 pubkey;
                                    --  pin against Trusted_Pub.
                                    for I in 1 .. 32 loop
                                       if In_Bytes (Cursor + 4 + I - 1)
                                            /= D.Trusted_Pub (I)
                                       then
                                          Cert_OK := False;
                                       end if;
                                    end loop;
                                    Tls_Core.Transcript.Append
                                      (D.Hash_Ctx,
                                       In_Bytes (Cursor .. Cert_End));
                                    Cursor := Cert_End + 1;
                                 end if;
                              end;
                           end if;

                           --  CertificateVerify
                           if Cert_OK
                             and then Cursor + 3 <= In_Bytes'Last
                             and then In_Bytes (Cursor) = HS_Certificate_Verify
                           then
                              declare
                                 Cv_Body_Len : constant Natural :=
                                   Natural (In_Bytes (Cursor + 1)) * 65536
                                   + Natural (In_Bytes (Cursor + 2)) * 256
                                   + Natural (In_Bytes (Cursor + 3));
                                 Cv_End : constant Natural :=
                                   Cursor + 4 + Cv_Body_Len - 1;
                                 Snap : Tls_Core.Sha256.Digest;
                                 Sig_Material : Octet_Array (1 .. 130);
                                 Sig_Last : Natural;
                                 Sig : Tls_Core.Ed25519.Signature;
                              begin
                                 if Cv_Body_Len /= 64
                                   or else Cv_End > In_Bytes'Last
                                 then
                                    Cert_OK := False;
                                 else
                                    --  Snapshot transcript at this point
                                    --  (CH || SH || Cert) — what the
                                    --  signature was computed over per
                                    --  RFC 8446 §4.4.3.
                                    Tls_Core.Transcript.Snapshot
                                      (D.Hash_Ctx, Snap);
                                    Build_Cert_Verify_Sig_Material
                                      (Snap, Sig_Material, Sig_Last);
                                    for I in 1 .. 64 loop
                                       Sig (I) :=
                                         In_Bytes (Cursor + 4 + I - 1);
                                    end loop;
                                    if not Tls_Core.Ed25519.Verify
                                         (D.Trusted_Pub,
                                          Sig_Material (1 .. Sig_Last),
                                          Sig)
                                    then
                                       Cert_OK := False;
                                    end if;
                                    Tls_Core.Transcript.Append
                                      (D.Hash_Ctx,
                                       In_Bytes (Cursor .. Cv_End));
                                    Cursor := Cv_End + 1;
                                 end if;
                              end;
                           else
                              Cert_OK := False;
                           end if;

                           if not Cert_OK then
                              D.Cur_State := Failed;
                              return;
                           end if;
                        end if;

                        --  Finished bytes are whatever remains.
                        declare
                           Sf_Bytes : constant Octet_Array :=
                             In_Bytes (Cursor .. In_Bytes'Last);
                        begin
                           Tls_Core.Transcript.Append (D.Hash_Ctx, Sf_Bytes);
                           Store (D.SF_Buf, D.SF_Len, Sf_Bytes);
                        end;
                        Compute_Secrets (D);
                        D.Cur_State := Awaiting_Finished;
                     end;
                  else
                     D.Cur_State := Failed;
                  end if;
               end;
            else
               D.Cur_State := Failed;
            end if;

         when Awaiting_Finished =>
            if D.My_Role = Client then
               --  Client emits its Finished in this step (no peer
               --  input is expected — secrets were derived in the
               --  Awaiting_Server_Hello step).
               declare
                  Body_Of : constant Octet_Array := D.PSK;
                  Wire    : Octet_Array (1 .. 4 + Body_Of'Length);
                  Wire_Last : Natural;
               begin
                  Encode_Handshake (HS_Finished, Body_Of, Wire, Wire_Last);
                  Tls_Core.Transcript.Append (D.Hash_Ctx, Wire);
                  Out_Buf (1 .. Wire_Last) := Wire (1 .. Wire_Last);
                  Out_Last := Wire_Last;
                  D.Cur_State := Done;
               end;
            else
               --  Server: receive client's Finished, transition to
               --  Done. Secrets were computed earlier when SH || SF
               --  was emitted.
               if In_Bytes'Length > 4 then
                  Tls_Core.Transcript.Append (D.Hash_Ctx, In_Bytes);
                  D.Cur_State := Done;
               else
                  D.Cur_State := Failed;
               end if;
            end if;

         when Done | Failed =>
            null;
      end case;

      pragma Unreferenced (Empty);
   end Step;

   ---------------------------------------------------------------------
   --  Get_Secrets
   ---------------------------------------------------------------------

   procedure Get_Secrets
     (D       : Driver;
      Out_Sec : out Tls_Core.Handshake.Traffic_Secrets)
   is
   begin
      Out_Sec := D.Secrets;
   end Get_Secrets;

end Tls_Core.Handshake_Driver;
