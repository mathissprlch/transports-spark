separate (Tls_Core.Tls13_Driver)
   procedure Process_Post_Handshake_Plaintext
     (D            : Driver;
      Plaintext    : Octet_Array;
      Inner_Type   : Octet;
      In_Dir       : in out Tls_Core.Aead_Channel.Direction;
      Recv_Secret  : in out Tls_Core.Key_Sched.Max_Secret;
      Cache        : in out Tls_Core.Session_Cache.Cache;
      Saw_Nst      : out Boolean;
      Saw_KeyUpdate : out Boolean;
      Want_Reply   : out Boolean;
      OK           : out Boolean)
   is
      Hs_Type_New_Session_Ticket : constant Octet := 16#04#;
   begin
      Saw_Nst := False;
      Saw_KeyUpdate := False;
      Want_Reply := False;
      OK := True;

      --  Inner_Type 0x17 (Application_Data) is not our concern —
      --  caller treats Plaintext as app data.
      if Inner_Type /= Tls_Core.Aead_Channel.Inner_Type_Handshake then
         return;
      end if;

      --  RFC 8446 §4.6 post-handshake messages all carry inner type
      --  Handshake (0x16) and start with the §4 handshake header
      --  (1-byte type + uint24 length + body).  Need at least 4
      --  bytes to read the header.
      if Plaintext'Length < 4 then
         OK := False;
         return;
      end if;

      if Plaintext (Plaintext'First) = Hs_Type_New_Session_Ticket then
         --  RFC 8446 §4.6.1.  Validate the header length, then
         --  decode + insert into Cache (mirror of the post-decrypt
         --  block in Receive_New_Session_Ticket).
         declare
            Hi : constant Natural :=
              Natural (Plaintext (Plaintext'First + 1));
            Mid : constant Natural :=
              Natural (Plaintext (Plaintext'First + 2));
            Lo : constant Natural :=
              Natural (Plaintext (Plaintext'First + 3));
            L : constant Natural := Hi * 65536 + Mid * 256 + Lo;
         begin
            if 4 + L /= Plaintext'Length
              or else L < 14
              or else L >
                Tls_Core.Session_Ticket.Max_Nst_Body_Length
            then
               OK := False;
               return;
            end if;
            declare
               Body_Slice : constant Octet_Array (1 .. L) :=
                 Plaintext (Plaintext'First + 4 ..
                            Plaintext'First + 3 + L);
               Lt   : Tls_Core.Session_Ticket.U32;
               Ag   : Tls_Core.Session_Ticket.U32;
               Nf, Tf : Natural;
               Nl, Tl : Integer;
               Decode_OK : Boolean;
            begin
               Tls_Core.Session_Ticket.Decode_Body
                 (In_Buf       => Body_Slice,
                  Lifetime     => Lt,
                  Age_Add      => Ag,
                  Nonce_First  => Nf,
                  Nonce_Last   => Nl,
                  Ticket_First => Tf,
                  Ticket_Last  => Tl,
                  OK           => Decode_OK);
               if not Decode_OK then
                  OK := False;
                  return;
               end if;
               if Nl >= Nf then
                  Tls_Core.Session_Cache.Insert
                    (C                 => Cache,
                     Lifetime          => Lt,
                     Age_Add           => Ag,
                     Ticket_Nonce      => Body_Slice (Nf .. Nl),
                     Ticket            => Body_Slice (Tf .. Tl),
                     Resumption_Secret => D.Res_Master_Sec (1 .. 32),
                     Suite             => D.Suite);
               else
                  declare
                     Empty_Nonce : constant Octet_Array (1 .. 0) :=
                       (others => 0);
                  begin
                     Tls_Core.Session_Cache.Insert
                       (C                 => Cache,
                        Lifetime          => Lt,
                        Age_Add           => Ag,
                        Ticket_Nonce      => Empty_Nonce,
                        Ticket            => Body_Slice (Tf .. Tl),
                        Resumption_Secret => D.Res_Master_Sec (1 .. 32),
                        Suite             => D.Suite);
                  end;
               end if;
               Saw_Nst := True;
            end;
         end;
      elsif Plaintext (Plaintext'First) =
              Tls_Core.Key_Update.Hs_Type_Key_Update
      then
         --  RFC 8446 §4.6.3.  Process_Inbound_Key_Update operates
         --  on plaintext + rotates In_Dir + Recv_Secret in place.
         --  In_Dir.Seq must be < Last for the Pre to hold; v0.5
         --  callers re-Init the dir each demux call to keep this.
         declare
            Inner_OK : Boolean;
         begin
            Process_Inbound_Key_Update
              (D            => D,
               In_Plaintext => Plaintext,
               In_Dir       => In_Dir,
               Recv_Secret  => Recv_Secret,
               Want_Reply   => Want_Reply,
               OK           => Inner_OK);
            if not Inner_OK then
               OK := False;
               return;
            end if;
            Saw_KeyUpdate := True;
         end;
      else
         --  RFC 8446 §4.6 doesn't define any other post-handshake
         --  handshake-message type for this profile (no Cert_Request
         --  in PSK mode).  Per §6.2 unexpected_message — leave
         --  OK := False; caller decides whether to alert.
         OK := False;
      end if;
   end Process_Post_Handshake_Plaintext;
