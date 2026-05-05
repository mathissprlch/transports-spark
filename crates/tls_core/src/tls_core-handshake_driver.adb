with Tls_Core.Sha256;

package body Tls_Core.Handshake_Driver
with SPARK_Mode => Off
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   --  Wire framing for PSK_KE only: we model each Handshake as a
   --  single byte type + u24 length-prefixed body. This is the
   --  same shape as the RecordFlux Handshake_Layer envelope, but
   --  inlined here so the driver doesn't depend on the RFLX
   --  serializer (which lives outside SPARK_Mode).

   HS_Client_Hello   : constant := 16#01#;
   HS_Server_Hello   : constant := 16#02#;
   HS_Finished       : constant := 16#14#;

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
      D.PSK := (others => 0);
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
   --  Init_Ecdhe — set up X25519 keypair from a private scalar.
   ---------------------------------------------------------------------

   procedure Init_Ecdhe
     (D            : out Driver;
      For_Role     : Role;
      Private_Key  : Tls_Core.X25519.Bytes_32)
   is
      Pub : Tls_Core.X25519.Bytes_32;
   begin
      D.My_Role := For_Role;
      D.My_Mode := ECDHE;
      D.PSK := (others => 0);
      D.My_Priv := Private_Key;
      Tls_Core.X25519.Derive_Public (Private_Key, Pub);
      D.My_Pub := Pub;
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
   end Init_Ecdhe;

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
         when ECDHE =>
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
                    (if D.My_Mode = ECDHE then D.My_Pub else D.PSK);
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

               --  ECDHE: extract peer's public key from the CH body
               --  (bytes 5..36 inside the handshake message).
               if D.My_Mode = ECDHE then
                  for I in 1 .. 32 loop
                     D.Peer_Pub (I) := In_Bytes (In_Bytes'First + 4 + I - 1);
                  end loop;
                  Tls_Core.X25519.Scalar_Mult
                    (Scalar  => D.My_Priv,
                     U_Coord => D.Peer_Pub,
                     Out_Q   => D.Shared);
               end if;

               declare
                  Body_Of   : constant Octet_Array :=
                    (if D.My_Mode = ECDHE then D.My_Pub else D.PSK);
                  Sh_Wire   : Octet_Array (1 .. 4 + Body_Of'Length);
                  Sh_Last   : Natural;
                  Fin_Body  : constant Octet_Array := D.PSK;
                  Sf_Wire   : Octet_Array (1 .. 4 + Fin_Body'Length);
                  Sf_Last   : Natural;
               begin
                  Encode_Handshake
                    (HS_Server_Hello, Body_Of, Sh_Wire, Sh_Last);
                  Tls_Core.Transcript.Append (D.Hash_Ctx, Sh_Wire);
                  Store (D.SH_Buf, D.SH_Len, Sh_Wire);

                  Encode_Handshake
                    (HS_Finished, Fin_Body, Sf_Wire, Sf_Last);
                  Tls_Core.Transcript.Append (D.Hash_Ctx, Sf_Wire);
                  Store (D.SF_Buf, D.SF_Len, Sf_Wire);

                  Compute_Secrets (D);

                  if Sh_Last + Sf_Last <= Out_Buf'Length then
                     Out_Buf (1 .. Sh_Last) := Sh_Wire (1 .. Sh_Last);
                     Out_Buf (Sh_Last + 1 .. Sh_Last + Sf_Last) :=
                       Sf_Wire (1 .. Sf_Last);
                     Out_Last := Sh_Last + Sf_Last;
                  end if;
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
                        Sf_Bytes : constant Octet_Array :=
                          In_Bytes (Sh_End + 1 .. In_Bytes'Last);
                     begin
                        --  ECDHE: SH body holds peer's public key.
                        if D.My_Mode = ECDHE
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
                        Tls_Core.Transcript.Append (D.Hash_Ctx, Sf_Bytes);
                        Store (D.SF_Buf, D.SF_Len, Sf_Bytes);
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
