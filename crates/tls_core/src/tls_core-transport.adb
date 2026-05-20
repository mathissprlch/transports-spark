package body Tls_Core.Transport
  with SPARK_Mode => Off
is


   --  Maximum wire bytes a single TLS 1.3 record can occupy:
   --  5-byte TLSCiphertext header + 16384 max plaintext + 16-byte
   --  AEAD tag. The Send pre-condition caps plaintext at 16384.
   Max_Record_Wire : constant := 5 + 16384 + 16;

   --  A record on the wire has at least header (5) + tag (16) bytes
   --  even when fragment is empty; AEAD-protected fragments always
   --  carry at least the 16-byte tag.
   Min_Record_Wire : constant := 5 + 16;

   ---------------------------------------------------------------------
   --  Init
   ---------------------------------------------------------------------

   procedure Init
     (P       : out Pipe;
      Role_Of : Role;
      Secrets : Tls_Core.Handshake.Traffic_Secrets) is
   begin
      P.My_Role := Role_Of;
      P.Outbound := [others => 0];
      P.Outbound_Last := 0;
      P.Inbound := [others => 0];
      P.Inbound_Last := 0;

      case Role_Of is
         when Client =>
            --  Client encrypts client→server with Client_App,
            --  decrypts server→client with Server_App.
            Tls_Core.Channel.Init (P.Send_Dir, Secrets.Client_App);
            Tls_Core.Channel.Init (P.Recv_Dir, Secrets.Server_App);

         when Server =>
            --  Server is the mirror.
            Tls_Core.Channel.Init (P.Send_Dir, Secrets.Server_App);
            Tls_Core.Channel.Init (P.Recv_Dir, Secrets.Client_App);
      end case;
   end Init;

   ---------------------------------------------------------------------
   --  Send — encrypt one record into a scratch buffer, then append
   --  the produced wire bytes to the outbound queue.
   ---------------------------------------------------------------------

   procedure Send (P : in out Pipe; Plaintext : Octet_Array) is
      Wire     : Octet_Array (1 .. Max_Record_Wire) := [others => 0];
      Wire_Len : Natural := 0;
   begin
      Tls_Core.Channel.Send
        (D         => P.Send_Dir,
         Plaintext => Plaintext,
         Out_Buf   => Wire,
         Out_Last  => Wire_Len);

      --  Append to the outbound buffer. Buffer is sized so that a
      --  reasonable number of full-size records fit; if a caller
      --  somehow overflows we leave the buffer untouched. (No
      --  exception path: a real adapter would Drain often.)
      if P.Outbound_Last + Wire_Len <= P.Outbound'Last then
         P.Outbound (P.Outbound_Last + 1 .. P.Outbound_Last + Wire_Len) :=
           Wire (1 .. Wire_Len);
         P.Outbound_Last := P.Outbound_Last + Wire_Len;
      end if;
   end Send;

   ---------------------------------------------------------------------
   --  Inject — append peer-produced wire bytes to the inbound queue.
   ---------------------------------------------------------------------

   procedure Inject (P : in out Pipe; Bytes : Octet_Array) is
   begin
      if Bytes'Length = 0 then
         return;
      end if;

      if P.Inbound_Last + Bytes'Length <= P.Inbound'Last then
         P.Inbound (P.Inbound_Last + 1 .. P.Inbound_Last + Bytes'Length) :=
           Bytes;
         P.Inbound_Last := P.Inbound_Last + Bytes'Length;
      end if;
   end Inject;

   ---------------------------------------------------------------------
   --  Drain — hand out the queued outbound bytes; reset the queue.
   ---------------------------------------------------------------------

   procedure Drain
     (P : in out Pipe; Out_Buf : out Octet_Array; Out_Last : out Natural)
   is
      Take : constant Natural := P.Outbound_Last;
   begin
      Out_Buf := [others => 0];
      Out_Last := 0;

      if Take = 0 then
         return;
      end if;

      --  Refuse to truncate: if caller's buffer is smaller, signal
      --  empty so they can size up. Match the Channel-style "buffer
      --  too small" handling.
      if Out_Buf'Length < Take then
         return;
      end if;

      Out_Buf (Out_Buf'First .. Out_Buf'First + Take - 1) :=
        P.Outbound (1 .. Take);
      Out_Last := Take;

      --  Reset the outbound queue.
      P.Outbound := [others => 0];
      P.Outbound_Last := 0;
   end Drain;

   ---------------------------------------------------------------------
   --  Receive — peek the next record off the head of the inbound
   --  queue, decrypt it via Recv_Dir, then compact the queue by
   --  the record's wire length.
   ---------------------------------------------------------------------

   procedure Receive
     (P        : in out Pipe;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural;
      OK       : out Boolean) is
   begin
      Out_Buf := [others => 0];
      Out_Last := 0;
      OK := False;

      --  Need at least a header + tag's worth of bytes.
      if P.Inbound_Last < Min_Record_Wire then
         return;
      end if;

      --  Parse just enough of the TLSCiphertext header to know the
      --  length of this record on the wire. (Channel.Receive does
      --  the same check internally; we mirror it here so we know
      --  how many bytes to drop from the queue on success.)
      declare
         Len_Hi   : constant Natural := Natural (P.Inbound (4));
         Len_Lo   : constant Natural := Natural (P.Inbound (5));
         Frag_Len : constant Natural := Len_Hi * 256 + Len_Lo;
         Wire_Len : Natural;
      begin
         --  Sanity: fragment must include the AEAD tag (16) and the
         --  full record must be present in the queue.
         if Frag_Len < 16 or else 5 + Frag_Len > P.Inbound_Last then
            return;
         end if;

         Wire_Len := 5 + Frag_Len;

         declare
            Local_Out  : Octet_Array (1 .. Out_Buf'Length) := (others => 0);
            Local_Last : Natural := 0;
            Local_OK   : Boolean := False;
         begin
            Tls_Core.Channel.Receive
              (D        => P.Recv_Dir,
               In_Buf   => P.Inbound (1 .. Wire_Len),
               Out_Buf  => Local_Out,
               Out_Last => Local_Last,
               OK       => Local_OK);

            if not Local_OK then
               --  Tampered record: do NOT drop bytes from the queue.
               --  The caller can re-Init or otherwise recover. The
               --  sequence number on Recv_Dir HAS already been
               --  consumed by Channel.Receive; that's the same
               --  drop-the-connection semantics RFC 8446 §5.2 has.
               return;
            end if;

            --  Copy plaintext out and compact the queue.
            if Local_Last > 0 then
               Out_Buf (Out_Buf'First .. Out_Buf'First + Local_Last - 1) :=
                 Local_Out (1 .. Local_Last);
            end if;
            Out_Last := Local_Last;
            OK := True;

            --  Drop the consumed wire bytes off the front of the
            --  inbound queue, slide the rest down.
            if P.Inbound_Last > Wire_Len then
               P.Inbound (1 .. P.Inbound_Last - Wire_Len) :=
                 P.Inbound (Wire_Len + 1 .. P.Inbound_Last);
            end if;
            --  Zero the now-unused tail so we don't leak old
            --  ciphertext into later Inject's wire view.
            P.Inbound (P.Inbound_Last - Wire_Len + 1 .. P.Inbound_Last) :=
              [others => 0];
            P.Inbound_Last := P.Inbound_Last - Wire_Len;
         end;
      end;
   end Receive;

end Tls_Core.Transport;
