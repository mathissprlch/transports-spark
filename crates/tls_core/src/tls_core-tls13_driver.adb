with Tls_Core.Aead_Channel;
with Tls_Core.Hello;
with Tls_Core.Hkdf;
with Tls_Core.Hkdf_Sha256;
with Tls_Core.Hmac_Sha256;
with Tls_Core.Key_Schedule;
with Tls_Core.Key_Update;
with Tls_Core.Psk_Binder;
with Tls_Core.Sha256;
with Tls_Core.Suites;

package body Tls_Core.Tls13_Driver
with SPARK_Mode
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
       (Hash_Length      => Tls_Core.Sha256.Hash_Length,
        Max_Info         => 512,
        Spec_Hmac_Expand => Tls_Core.Hkdf_Sha256.Spec_HKDF_Expand,
        Hmac_Expand      => Tls_Core.Hkdf_Sha256.Hmac_Expand);

   ---------------------------------------------------------------------
   --  Init_Psk_Server
   ---------------------------------------------------------------------

   --  Helper: prime the Driver's variant-record / secret fields so
   --  flow analysis sees every member as initialised even though
   --  the actual handshake logic in Step overwrites them later.
   --  Hs_Out_Dir / Hs_In_Dir start as the default chacha20 variant;
   --  Step swaps them to the negotiated variant once D.Suite is set.
   procedure Prime_Driver_Defaults (D : in out Driver);
   procedure Prime_Driver_Defaults (D : in out Driver) is
      Zero_Secret : constant Tls_Core.Key_Schedule.Secret := (others => 0);
      Zero_Digest : constant Tls_Core.Sha256.Digest := (others => 0);
   begin
      D.Suite := Tls_Core.Suites.Chacha20_Poly1305_Sha256;
      D.C_Hs_Sec  := Zero_Secret;
      D.S_Hs_Sec  := Zero_Secret;
      D.Hs_Secret := Zero_Secret;
      D.Expected_Cf := Zero_Digest;
      D.App_C_Ap := Zero_Secret;
      D.App_S_Ap := Zero_Secret;
      Tls_Core.Aead_Channel.Init_Sha256
        (D.Hs_Out_Dir, Tls_Core.Suites.Chacha20_Poly1305_Sha256, Zero_Secret);
      Tls_Core.Aead_Channel.Init_Sha256
        (D.Hs_In_Dir,  Tls_Core.Suites.Chacha20_Poly1305_Sha256, Zero_Secret);
   end Prime_Driver_Defaults;

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
      Prime_Driver_Defaults (D);
   end Init_Psk_Server;

   procedure Init_Psk_Client
     (D            : out Driver;
      PSK          : Octet_Array;
      Psk_Identity : Octet_Array)
   is
   begin
      D.My_Role := Client;
      D.Cur_State := Idle;
      Tls_Core.Transcript.Init (D.Hash_Ctx);
      D.PSK := (others => 0);
      D.PSK := PSK;
      D.Identity := (others => 0);
      D.Identity_Len := Psk_Identity'Length;
      D.Identity (1 .. Psk_Identity'Length) := Psk_Identity;
      D.App_Set := False;
      Prime_Driver_Defaults (D);
   end Init_Psk_Client;

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
      Cur_State_Old : constant State := D.Cur_State;
   begin
      Out_Buf := (others => 0);
      Out_Last := 0;

      case D.Cur_State is
         when Idle =>
            --  Client only: emit ClientHello with PSK extension and
            --  binder. Wrap as TLSPlaintext record.
            if D.My_Role /= Client then
               D.Cur_State := Failed;
               return;
            end if;
            declare
               Client_Random : constant Tls_Core.Hello.Random_Bytes :=
                 (others => 16#A1#);
               Ch_Body : Octet_Array (1 .. 512) := (others => 0);
               Ch_Body_Last : Natural;
               T_Last  : Natural;
               Binder  : Tls_Core.Psk_Binder.Binder_Bytes;
               Ch_Hs   : Octet_Array (1 .. 1024) := (others => 0);
               Ch_Hs_Last : Natural;
               Ch_Rec  : Octet_Array (1 .. 1024) := (others => 0);
               Ch_Rec_Last : Natural;
            begin
               Tls_Core.Hello.Encode_Client_Hello_Psk
                 (Client_Random,
                  D.Identity (1 .. D.Identity_Len),
                  Ch_Body, Ch_Body_Last, T_Last);
               --  Compute binder over Ch_Body (1 .. T_Last).
               Tls_Core.Psk_Binder.Compute
                 (D.PSK,
                  Ch_Body (1 .. T_Last),
                  Binder);
               Ch_Body (T_Last + 2 .. T_Last + 33) := Binder;
               --  Wrap as handshake message (type 0x01 + u24 + body).
               Encode_Hs_Message
                 (Hs_Type_CH, Ch_Body (1 .. Ch_Body_Last),
                  Ch_Hs, Ch_Hs_Last);
               --  Append handshake message (NOT record wrapper) to transcript.
               Tls_Core.Transcript.Append
                 (D.Hash_Ctx, Ch_Hs (1 .. Ch_Hs_Last));
               --  Wrap in TLSPlaintext record.
               Wrap_Tls_Plaintext
                 (Ch_Hs (1 .. Ch_Hs_Last), Ch_Rec, Ch_Rec_Last);
               Out_Buf (1 .. Ch_Rec_Last) := Ch_Rec (1 .. Ch_Rec_Last);
               Out_Last := Ch_Rec_Last;
               D.Cur_State := Awaiting_Sf;
            end;

         when Awaiting_Sf =>
            --  Client: parse server flight = TLSPlaintext SH ||
            --  TLSCiphertext EE || TLSCiphertext Server-Finished.
            --  After verifying SF, emit encrypted client Finished.
            if D.My_Role /= Client then
               D.Cur_State := Failed;
               return;
            end if;
            declare
               Cursor : Natural := In_Bytes'First;

               --  Used to derive c_hs / s_hs after parsing SH.
               Empty_Hash    : Tls_Core.Sha256.Digest;
               Empty_In      : constant Octet_Array (1 .. 0) :=
                 (others => 0);
               Zero_Secret   : constant Tls_Core.Key_Schedule.Secret :=
                 (others => 0);
               Derived_Lab   : constant Octet_Array (1 .. 7) :=
                 (16#64#, 16#65#, 16#72#, 16#69#, 16#76#, 16#65#, 16#64#);
               C_Hs_Lab      : constant Octet_Array (1 .. 12) :=
                 (16#63#, 16#20#, 16#68#, 16#73#, 16#20#, 16#74#,
                  16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
               S_Hs_Lab      : constant Octet_Array (1 .. 12) :=
                 (16#73#, 16#20#, 16#68#, 16#73#, 16#20#, 16#74#,
                  16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
               C_Ap_Lab      : constant Octet_Array (1 .. 12) :=
                 (16#63#, 16#20#, 16#61#, 16#70#, 16#20#, 16#74#,
                  16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);
               S_Ap_Lab      : constant Octet_Array (1 .. 12) :=
                 (16#73#, 16#20#, 16#61#, 16#70#, 16#20#, 16#74#,
                  16#72#, 16#61#, 16#66#, 16#66#, 16#69#, 16#63#);

               Early_Secret  : Tls_Core.Key_Schedule.Secret;
               Derived_1     : Tls_Core.Key_Schedule.Secret;
               Th_After_Sh   : Tls_Core.Sha256.Digest;
               Th_After_Ee   : Tls_Core.Sha256.Digest;
               Th_After_Sf   : Tls_Core.Sha256.Digest;
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
                    Natural (In_Bytes (Cursor + 3)) * 256
                    + Natural (In_Bytes (Cursor + 4));
                  Sh_Rec_F : constant Natural := Cursor + 5;
                  Sh_Rec_L : constant Natural := Sh_Rec_F + Sh_Rec_Len - 1;
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
                       Tls_Core.Suites.U16 (In_Bytes (Sh_Rec_F + 39)) * 256
                       + Tls_Core.Suites.U16 (In_Bytes (Sh_Rec_F + 40));
                  begin
                     if not Tls_Core.Suites.Is_Supported_Suite (Code)
                       or else Code =
                                 Tls_Core.Suites.TLS_AES_256_GCM_SHA384
                     then
                        --  Unrecognised, or AES-256-GCM-SHA384 (driver
                        --  schedule path is SHA-256-only — see package
                        --  wall-hit note).
                        D.Cur_State := Failed;
                        return;
                     end if;
                     D.Suite := Tls_Core.Suites.Suite_Of_Code (Code);
                  end;
                  --  Append SH handshake message to transcript.
                  Tls_Core.Transcript.Append
                    (D.Hash_Ctx, In_Bytes (Sh_Rec_F .. Sh_Rec_L));
                  Cursor := Sh_Rec_L + 1;
               end;

               --  Step 2: derive handshake secrets.
               Tls_Core.Transcript.Snapshot (D.Hash_Ctx, Th_After_Sh);
               Tls_Core.Key_Schedule.Extract
                 (Salt => Zero_Secret, IKM => D.PSK,
                  Out_PRK => Early_Secret);
               Tls_Core.Key_Schedule.Derive_Secret
                 (Secret_In => Early_Secret,
                  Label     => Derived_Lab,
                  Messages  => Empty_In,
                  Out_Secret => Derived_1);
               Tls_Core.Key_Schedule.Extract
                 (Salt => Derived_1, IKM => Zero_Secret,
                  Out_PRK => D.Hs_Secret);
               Hkdf_Expand_Label_Sha256
                 (Secret  => D.Hs_Secret,
                  Label   => C_Hs_Lab,
                  Context => Th_After_Sh,
                  Output  => D.C_Hs_Sec);
               Hkdf_Expand_Label_Sha256
                 (Secret  => D.Hs_Secret,
                  Label   => S_Hs_Lab,
                  Context => Th_After_Sh,
                  Output  => D.S_Hs_Sec);
               --  Client: in decrypts with s_hs; out encrypts with c_hs.
               --  Init_Sha256 dispatches the AEAD by D.Suite.
               Tls_Core.Aead_Channel.Init_Sha256
                 (D.Hs_In_Dir,  D.Suite, D.S_Hs_Sec);
               Tls_Core.Aead_Channel.Init_Sha256
                 (D.Hs_Out_Dir, D.Suite, D.C_Hs_Sec);

               --  Step 3: decrypt EE record.
               declare
                  Pt_Buf : Octet_Array (1 .. 1024) := (others => 0);
                  Pt_Last : Natural;
                  Inner_Type : Octet;
                  OK : Boolean;
                  Rec_Len : Natural;
                  Rec_End : Natural;
               begin
                  if Cursor + 4 > In_Bytes'Last
                    or else In_Bytes (Cursor) /=
                              Tls_Core.Aead_Channel.Inner_Type_Application_Data
                  then
                     D.Cur_State := Failed;
                     return;
                  end if;
                  Rec_Len := Natural (In_Bytes (Cursor + 3)) * 256
                             + Natural (In_Bytes (Cursor + 4));
                  Rec_End := Cursor + 5 + Rec_Len - 1;
                  if Rec_End > In_Bytes'Last then
                     D.Cur_State := Failed;
                     return;
                  end if;
                  Tls_Core.Aead_Channel.Receive
                    (D.Hs_In_Dir, In_Bytes (Cursor .. Rec_End),
                     Pt_Buf, Pt_Last, Inner_Type, OK);
                  if not OK
                    or else Inner_Type /=
                              Tls_Core.Aead_Channel.Inner_Type_Handshake
                    or else Pt_Last < 4
                    or else Pt_Buf (1) /= Hs_Type_EE
                  then
                     D.Cur_State := Failed;
                     return;
                  end if;
                  Tls_Core.Transcript.Append
                    (D.Hash_Ctx, Pt_Buf (1 .. Pt_Last));
                  Cursor := Rec_End + 1;
               end;

               --  Step 4: decrypt server Finished record.
               Tls_Core.Transcript.Snapshot (D.Hash_Ctx, Th_After_Ee);
               declare
                  Pt_Buf : Octet_Array (1 .. 1024) := (others => 0);
                  Pt_Last : Natural;
                  Inner_Type : Octet;
                  OK : Boolean;
                  Rec_Len : Natural;
                  Rec_End : Natural;
                  Expected_Sf : Tls_Core.Sha256.Digest;
                  Diff : Octet := 0;
               begin
                  if Cursor + 4 > In_Bytes'Last
                    or else In_Bytes (Cursor) /=
                              Tls_Core.Aead_Channel.Inner_Type_Application_Data
                  then
                     D.Cur_State := Failed;
                     return;
                  end if;
                  Rec_Len := Natural (In_Bytes (Cursor + 3)) * 256
                             + Natural (In_Bytes (Cursor + 4));
                  Rec_End := Cursor + 5 + Rec_Len - 1;
                  if Rec_End > In_Bytes'Last then
                     D.Cur_State := Failed;
                     return;
                  end if;
                  Tls_Core.Aead_Channel.Receive
                    (D.Hs_In_Dir, In_Bytes (Cursor .. Rec_End),
                     Pt_Buf, Pt_Last, Inner_Type, OK);
                  if not OK
                    or else Inner_Type /=
                              Tls_Core.Aead_Channel.Inner_Type_Handshake
                    or else Pt_Last /= 4 + 32
                    or else Pt_Buf (1) /= Hs_Type_Finished
                  then
                     D.Cur_State := Failed;
                     return;
                  end if;
                  --  Verify server Finished verify_data: HMAC of
                  --  s_hs_finished_key over Th_After_Ee.
                  Build_Finished_Body
                    (D.S_Hs_Sec, Th_After_Ee, Expected_Sf);
                  for I in 1 .. 32 loop
                     Diff := Diff or
                       (Pt_Buf (4 + I) xor Expected_Sf (I));
                  end loop;
                  if Diff /= 0 then
                     D.Cur_State := Failed;
                     return;
                  end if;
                  Tls_Core.Transcript.Append
                    (D.Hash_Ctx, Pt_Buf (1 .. Pt_Last));
                  Cursor := Rec_End + 1;
               end;

               --  Step 5: derive app secrets.
               Tls_Core.Transcript.Snapshot (D.Hash_Ctx, Th_After_Sf);
               declare
                  Derived_2_Sec : Tls_Core.Key_Schedule.Secret;
                  Master_Secret : Tls_Core.Key_Schedule.Secret;
               begin
                  Tls_Core.Sha256.Hash (Empty_In, Empty_Hash);
                  Hkdf_Expand_Label_Sha256
                    (Secret  => D.Hs_Secret,
                     Label   => Derived_Lab,
                     Context => Empty_Hash,
                     Output  => Derived_2_Sec);
                  Tls_Core.Key_Schedule.Extract
                    (Salt => Derived_2_Sec, IKM => Zero_Secret,
                     Out_PRK => Master_Secret);
                  Hkdf_Expand_Label_Sha256
                    (Secret  => Master_Secret,
                     Label   => C_Ap_Lab,
                     Context => Th_After_Sf,
                     Output  => D.App_C_Ap);
                  Hkdf_Expand_Label_Sha256
                    (Secret  => Master_Secret,
                     Label   => S_Ap_Lab,
                     Context => Th_After_Sf,
                     Output  => D.App_S_Ap);
                  D.App_Set := True;
               end;

               --  Step 6: build + send client Finished.
               declare
                  Cf_Verify : Tls_Core.Sha256.Digest;
                  Cf_Hs : Octet_Array (1 .. 4 + 32) := (others => 0);
                  Cf_Hs_Last : Natural;
                  Cf_Rec : Octet_Array (1 .. 256) := (others => 0);
                  Cf_Rec_Last : Natural;
               begin
                  Build_Finished_Body
                    (D.C_Hs_Sec, Th_After_Sf, Cf_Verify);
                  Encode_Hs_Message
                    (Hs_Type_Finished, Cf_Verify,
                     Cf_Hs, Cf_Hs_Last);
                  Tls_Core.Transcript.Append
                    (D.Hash_Ctx, Cf_Hs (1 .. Cf_Hs_Last));
                  Tls_Core.Aead_Channel.Send
                    (D.Hs_Out_Dir,
                     Cf_Hs (1 .. Cf_Hs_Last),
                     Tls_Core.Aead_Channel.Inner_Type_Handshake,
                     Cf_Rec, Cf_Rec_Last);
                  Out_Buf (1 .. Cf_Rec_Last) := Cf_Rec (1 .. Cf_Rec_Last);
                  Out_Last := Cf_Rec_Last;
               end;

               D.Cur_State := Done;
            end;

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
                  Suites_F, Suites_L : Natural;
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
                     Random,
                     Suites_F, Suites_L,
                     Id_F, Id_L, Bf, Bl, T_Last, Decode_OK);
                  if not Decode_OK then
                     D.Cur_State := Failed;
                     return;
                  end if;
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

               --  SH body = canonical PSK SH (echoes selected_identity = 0
               --  and the server's chosen cipher suite per RFC 8446 §4.1.3).
               Tls_Core.Hello.Encode_Server_Hello_Psk
                 (Server_Random,
                  Tls_Core.Suites.Code_Of_Suite (D.Suite),
                  Sh_Body, Sh_Body_Last);
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

               --  Open Aead_Channel Hs_Out_Dir / Hs_In_Dir (server:
               --  out encrypts with s_hs, in decrypts with c_hs). The
               --  Init_Sha256 dispatcher pins the variant to D.Suite.
               Tls_Core.Aead_Channel.Init_Sha256
                 (D.Hs_Out_Dir, D.Suite, S_Hs_Sec);
               Tls_Core.Aead_Channel.Init_Sha256
                 (D.Hs_In_Dir,  D.Suite, C_Hs_Sec);

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
                  Tls_Core.Transcript.Append
                    (D.Hash_Ctx, Ee_Hs (1 .. Ee_Hs_Last));
                  Tls_Core.Aead_Channel.Send
                    (D.Hs_Out_Dir,
                     Ee_Hs (1 .. Ee_Hs_Last),
                     Tls_Core.Aead_Channel.Inner_Type_Handshake,
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
                        Th_After_SF : Tls_Core.Sha256.Digest;

                        Empty_Hash : Tls_Core.Sha256.Digest;
                        Empty_In   : constant Octet_Array (1 .. 0) :=
                          (others => 0);
                        Derived_2_Sec : Tls_Core.Key_Schedule.Secret;
                        Master_Secret : Tls_Core.Key_Schedule.Secret;
                        Zero_Secret : constant Tls_Core.Key_Schedule.Secret :=
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
                        Tls_Core.Transcript.Snapshot
                          (D.Hash_Ctx, Th_After_SF);

                        --  Derived_2 = Derive-Secret(Hs_Secret, "derived", "")
                        Tls_Core.Sha256.Hash (Empty_In, Empty_Hash);
                        Hkdf_Expand_Label_Sha256
                          (Secret  => D.Hs_Secret,
                           Label   => Derived_Lab,
                           Context => Empty_Hash,
                           Output  => Derived_2_Sec);
                        Tls_Core.Key_Schedule.Extract
                          (Salt    => Derived_2_Sec,
                           IKM     => Zero_Secret,
                           Out_PRK => Master_Secret);
                        Hkdf_Expand_Label_Sha256
                          (Secret  => Master_Secret,
                           Label   => C_Ap_Lab,
                           Context => Th_After_SF,
                           Output  => D.App_C_Ap);
                        Hkdf_Expand_Label_Sha256
                          (Secret  => Master_Secret,
                           Label   => S_Ap_Lab,
                           Context => Th_After_SF,
                           Output  => D.App_S_Ap);
                        D.App_Set := True;

                        --  Expected client Finished body — HMAC of
                        --  c_hs_finished_key over Th_After_SF.
                        Build_Finished_Body
                          (D.C_Hs_Sec, Th_After_SF, D.Expected_Cf);
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
               Tls_Core.Aead_Channel.Receive
                 (D.Hs_In_Dir, In_Bytes,
                  Pt_Buf, Pt_Last, Inner_Type, OK);
               if not OK
                 or else Inner_Type /=
                           Tls_Core.Aead_Channel.Inner_Type_Handshake
                 or else Pt_Last /= 4 + 32
                 or else Pt_Buf (1) /= Hs_Type_Finished
               then
                  D.Cur_State := Failed;
                  return;
               end if;
               --  Constant-time compare of received verify_data
               --  against the expected value computed at SF send time.
               declare
                  Diff : Octet := 0;
               begin
                  for I in 1 .. 32 loop
                     Diff := Diff or (Pt_Buf (4 + I) xor D.Expected_Cf (I));
                  end loop;
                  if Diff /= 0 then
                     D.Cur_State := Failed;
                     return;
                  end if;
               end;
               Tls_Core.Transcript.Append (D.Hash_Ctx, Pt_Buf (1 .. Pt_Last));
               D.Cur_State := Done;
            end;

         when others =>
            null;
      end case;
   end Step;

   procedure Open_App_Directions
     (D          : Driver;
      Out_Dir    : out Tls_Core.Aead_Channel.Direction;
      In_Dir     : out Tls_Core.Aead_Channel.Direction;
      Out_Secret : out Tls_Core.Key_Schedule.Secret;
      In_Secret  : out Tls_Core.Key_Schedule.Secret)
   is
   begin
      case D.My_Role is
         when Server =>
            --  Server: out encrypts with s_ap; in decrypts with c_ap.
            Out_Secret := D.App_S_Ap;
            In_Secret  := D.App_C_Ap;
            Tls_Core.Aead_Channel.Init_Sha256
              (Out_Dir, D.Suite, Out_Secret);
            Tls_Core.Aead_Channel.Init_Sha256
              (In_Dir,  D.Suite, In_Secret);
         when Client =>
            --  Client: out encrypts with c_ap; in decrypts with s_ap.
            Out_Secret := D.App_C_Ap;
            In_Secret  := D.App_S_Ap;
            Tls_Core.Aead_Channel.Init_Sha256
              (Out_Dir, D.Suite, Out_Secret);
            Tls_Core.Aead_Channel.Init_Sha256
              (In_Dir,  D.Suite, In_Secret);
      end case;
   end Open_App_Directions;

   ---------------------------------------------------------------------
   --  Open_App_Directions — backward-compat shim that drops the secrets.
   ---------------------------------------------------------------------

   procedure Open_App_Directions
     (D       : Driver;
      Out_Dir : out Tls_Core.Aead_Channel.Direction;
      In_Dir  : out Tls_Core.Aead_Channel.Direction)
   is
      Discard_Out_Sec : Tls_Core.Key_Schedule.Secret;
      Discard_In_Sec  : Tls_Core.Key_Schedule.Secret;
   begin
      Open_App_Directions
        (D, Out_Dir, In_Dir, Discard_Out_Sec, Discard_In_Sec);
      pragma Unreferenced (Discard_Out_Sec, Discard_In_Sec);
   end Open_App_Directions;

   ---------------------------------------------------------------------
   --  Send_Key_Update — RFC 8446 §4.6.3.
   --
   --  Wire layout: ONE TLSCiphertext record carrying the 5-byte
   --  KeyUpdate handshake message, encrypted under the *current*
   --  Out_Dir traffic key (because §4.6.3 says: "after sending the
   --  KeyUpdate, the sender SHALL send all its traffic using the
   --  next generation of keys"). Key rotation happens AFTER Send.
   ---------------------------------------------------------------------

   procedure Send_Key_Update
     (D              : Driver;
      Out_Dir        : in out Tls_Core.Aead_Channel.Direction;
      Send_Secret    : in out Tls_Core.Key_Schedule.Secret;
      Request_Update : Octet;
      Out_Buf        : out Octet_Array;
      Out_Last       : out Natural)
   is
      pragma Unreferenced (D);
      Ku_Msg : Octet_Array (1 .. Tls_Core.Key_Update.Wire_Size) :=
        (others => 0);
      Ku_Last : Natural;
      Next_Secret : Tls_Core.Key_Schedule.Secret;
   begin
      Out_Buf := (others => 0);
      Out_Last := 0;

      --  1. Build the KeyUpdate handshake message (5 bytes total).
      Tls_Core.Key_Update.Encode (Request_Update, Ku_Msg, Ku_Last);

      --  2. Encrypt under the current send key as one record. The
      --     inner content type is "handshake" (post-handshake
      --     messages keep the handshake content type per §4.6).
      Tls_Core.Aead_Channel.Send
        (Out_Dir,
         Ku_Msg (1 .. Ku_Last),
         Tls_Core.Aead_Channel.Inner_Type_Handshake,
         Out_Buf, Out_Last);

      --  3. Derive the next traffic secret per §7.2 and rotate the
      --     local send key + IV + sequence counter.
      Tls_Core.Key_Update.Derive_Next_Sha256 (Send_Secret, Next_Secret);
      Send_Secret := Next_Secret;
      Tls_Core.Aead_Channel.Rotate_Sha256 (Out_Dir, Send_Secret);
   end Send_Key_Update;

   ---------------------------------------------------------------------
   --  Process_Inbound_Key_Update — RFC 8446 §4.6.3.
   --
   --  In_Plaintext is the 5-byte handshake-content-type plaintext
   --  decrypted from the peer's KeyUpdate record. We validate it,
   --  rotate the In_Dir + Recv_Secret to the next §7.2 secret, and
   --  surface Want_Reply so the caller can fire Send_Key_Update
   --  (with request_update = update_not_requested) if needed.
   ---------------------------------------------------------------------

   procedure Process_Inbound_Key_Update
     (D            : Driver;
      In_Plaintext : Octet_Array;
      In_Dir       : in out Tls_Core.Aead_Channel.Direction;
      Recv_Secret  : in out Tls_Core.Key_Schedule.Secret;
      Want_Reply   : out Boolean;
      OK           : out Boolean)
   is
      pragma Unreferenced (D);
      Request_Update : Octet;
      Decode_OK : Boolean;
      Next_Secret : Tls_Core.Key_Schedule.Secret;
   begin
      Want_Reply := False;
      OK := False;
      Tls_Core.Key_Update.Decode (In_Plaintext, Request_Update, Decode_OK);
      if not Decode_OK then
         return;
      end if;

      --  Rotate the peer-side decrypt key per §7.2.
      Tls_Core.Key_Update.Derive_Next_Sha256 (Recv_Secret, Next_Secret);
      Recv_Secret := Next_Secret;
      Tls_Core.Aead_Channel.Rotate_Sha256 (In_Dir, Recv_Secret);

      Want_Reply :=
        Request_Update = Tls_Core.Key_Update.Update_Requested;
      OK := True;
   end Process_Inbound_Key_Update;

end Tls_Core.Tls13_Driver;
