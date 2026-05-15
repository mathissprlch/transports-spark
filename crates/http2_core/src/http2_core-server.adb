with RFLX.RFLX_Types; use type RFLX.RFLX_Types.Index;
with RFLX.Http2_Parameters;
with RFLX.Stream.Open.FSM;

with Http2_Core.Wire;
with Logger;

package body Http2_Core.Server is

   use type Flow_Gate.Window_Bytes;
   use type Flow_Gate.Decision;
   use type RFLX.Http2_Parameters.HTTP_2_Settings_Enum;

   use type RFLX.RFLX_Builtin_Types.Bytes_Ptr;
   use type RFLX.RFLX_Builtin_Types.Bit_Length;
   use type RFLX.RFLX_Builtin_Types.Byte;
   use type RFLX.Http2_Parameters.HTTP_2_Frame_Type_Enum;
   use type RFLX.RFLX_Types.Length;

   subtype U8       is RFLX.RFLX_Types.Byte;
   subtype Bit_Len  is RFLX.RFLX_Builtin_Types.Bit_Length;

   ---------------------------------------------------------------------
   --  Listen / Stop / Buffer attachment
   ---------------------------------------------------------------------

   procedure Listen
     (L    : in out Listener;
      Host : String;
      Port : Natural)
   is
   begin
      Transport.Listen (L.Trans, Host, Port);
   end Listen;

   procedure Stop (L : in out Listener) is
   begin
      if Transport.Is_Listening (L.Trans) then
         Transport.Stop (L.Trans);
      end if;
   end Stop;

   function Get_Transport (L : aliased in out Listener)
     return Transport_Listener_Acc is
   begin
      return L.Trans'Unchecked_Access;
   end Get_Transport;

   procedure Attach_Buffers
     (L            : in out Listener;
      Buf          : in out RFLX.RFLX_Types.Bytes_Ptr;
      Inbound_Buf  : in out RFLX.RFLX_Types.Bytes_Ptr;
      Outgoing_Buf : in out RFLX.RFLX_Types.Bytes_Ptr)
   is
   begin
      L.Buf          := Buf;
      L.Inbound_Buf  := Inbound_Buf;
      L.Outgoing_Buf := Outgoing_Buf;
      Buf            := null;
      Inbound_Buf    := null;
      Outgoing_Buf   := null;
   end Attach_Buffers;

   procedure Detach_Buffers
     (L            : in out Listener;
      Buf          : out RFLX.RFLX_Types.Bytes_Ptr;
      Inbound_Buf  : out RFLX.RFLX_Types.Bytes_Ptr;
      Outgoing_Buf : out RFLX.RFLX_Types.Bytes_Ptr)
   is
   begin
      Buf            := L.Buf;
      Inbound_Buf    := L.Inbound_Buf;
      Outgoing_Buf   := L.Outgoing_Buf;
      L.Buf          := null;
      L.Inbound_Buf  := null;
      L.Outgoing_Buf := null;
   end Detach_Buffers;

   ---------------------------------------------------------------------
   --  Read_Frame — same shape as the client's local helper, but
   --  reads from a passed-in Channel rather than a Connection.
   ---------------------------------------------------------------------

   procedure Read_Frame
     (Trans   : Transport.Channel;
      Buf     : RFLX.RFLX_Types.Bytes_Ptr;
      Header  :    out Wire.Frame_Header;
      Last    :    out RFLX.RFLX_Types.Index;
      Success :    out Boolean);

   procedure Read_Frame
     (Trans   : Transport.Channel;
      Buf     : RFLX.RFLX_Types.Bytes_Ptr;
      Header  :    out Wire.Frame_Header;
      Last    :    out RFLX.RFLX_Types.Index;
      Success :    out Boolean)
   is
      Hdr_Slice : RFLX.RFLX_Types.Bytes (Buf'First .. Buf'First + 8);
      Hdr_OK    : Boolean;
   begin
      Header  := (others => <>);
      Last    := Buf'First;
      Success := False;
      Transport.Receive_Full (Trans, Hdr_Slice, Hdr_OK);
      if not Hdr_OK then
         return;
      end if;
      Buf.all (Buf'First .. Buf'First + 8) := Hdr_Slice;
      Wire.Decode_Frame_Header
        (Buffer => Buf.all (Buf'First .. Buf'First + 8),
         Header => Header,
         Valid  => Hdr_OK);
      if not Hdr_OK then
         return;
      end if;
      if Header.Length = 0 then
         Last    := Buf'First + 8;
         Success := True;
         return;
      end if;
      if Bit_Len (Buf'Length) < Header.Length + 9 then
         return;
      end if;
      declare
         Body_Slice : RFLX.RFLX_Types.Bytes
           (Buf'First + 9 ..
              Buf'First + 8 + RFLX.RFLX_Types.Index (Header.Length));
         Body_OK : Boolean;
      begin
         Transport.Receive_Full (Trans, Body_Slice, Body_OK);
         if not Body_OK then
            return;
         end if;
         Buf.all (Body_Slice'Range) := Body_Slice;
         Last    := Body_Slice'Last;
         Success := True;
      end;
   end Read_Frame;

   ---------------------------------------------------------------------
   --  Common helpers shared by all four Accept_And_Serve_* variants.
   --  Each extracts a phase that was previously inlined four times
   --  (~80–100 lines per variant).
   ---------------------------------------------------------------------

   --  §3.4 — read 24-byte connection preface, validate. Closes Chan
   --  + raises Server_Error on EOF or mismatch.
   procedure Receive_Preface
     (Chan : Transport.Channel);

   procedure Receive_Preface
     (Chan : Transport.Channel)
   is
      Pref_Bytes : RFLX.RFLX_Types.Bytes
        (RFLX.RFLX_Types.Index'First ..
           RFLX.RFLX_Types.Index'First +
           RFLX.RFLX_Types.Index (Wire.Preface'Length) - 1);
      Pref_OK : Boolean;
   begin
      Transport.Receive_Full (Chan, Pref_Bytes, Pref_OK);
      if not Pref_OK then
         raise Server_Error with "EOF before preface";
      end if;
      for I in Pref_Bytes'Range loop
         if Pref_Bytes (I) /=
           U8 (Character'Pos
                 (Wire.Preface
                    (Wire.Preface'First +
                       Integer (I - Pref_Bytes'First))))
         then
            raise Server_Error with "bad preface";
         end if;
      end loop;
   end Receive_Preface;

   --  §6.5 — emit our initial SETTINGS frame (HEADER_TABLE_SIZE=0,
   --  ENABLE_PUSH=0, MAX_CONCURRENT_STREAMS=1).
   procedure Send_Initial_Settings
     (L    : in out Listener;
      Chan : Transport.Channel);

   procedure Send_Initial_Settings
     (L    : in out Listener;
      Chan : Transport.Channel)
   is
      Last : RFLX.RFLX_Types.Index;
      Params : constant Wire.Settings_List (1 .. 4) :=
        ((Identifier => RFLX.Http2_Parameters.HEADER_TABLE_SIZE,
          Value      => 0),
         (Identifier => RFLX.Http2_Parameters.ENABLE_PUSH,
          Value      => 0),
         (Identifier => RFLX.Http2_Parameters.MAX_CONCURRENT_STREAMS,
          Value      => 1),
         (Identifier => RFLX.Http2_Parameters.INITIAL_WINDOW_SIZE,
          Value      => 4 * 1024 * 1024));
   begin
      Wire.Encode_Settings (L.Buf, Last, Params);
      Transport.Send (Chan, L.Buf.all (L.Buf'First .. Last));
   end Send_Initial_Settings;

   --  HPACK-encode `Headers` and emit as one HEADERS frame.
   procedure Encode_And_Send_Headers
     (L          : in out Listener;
      Chan       : Transport.Channel;
      Stream_Id  : Bit_Len;
      Headers    : Hpack.Header_Block;
      End_Stream : Boolean);

   procedure Encode_And_Send_Headers
     (L          : in out Listener;
      Chan       : Transport.Channel;
      Stream_Id  : Bit_Len;
      Headers    : Hpack.Header_Block;
      End_Stream : Boolean)
   is
      Frag_Out  : Hpack.Octet_Array
        (1 .. Hpack.Max_Header_Length * Hpack.Max_Headers);
      Frag_Last : Natural;
      Frag_OK   : Boolean;
      Frame_Last : RFLX.RFLX_Types.Index;
   begin
      Hpack.Encode
        (Headers     => Headers,
         Output      => Frag_Out,
         Output_Last => Frag_Last,
         Output_OK   => Frag_OK);
      if not Frag_OK then
         raise Server_Error with "HPACK encode failed";
      end if;
      declare
         Frag_Bytes : RFLX.RFLX_Types.Bytes
           (1 .. RFLX.RFLX_Types.Index (Frag_Last));
      begin
         for I in 1 .. Frag_Last loop
            Frag_Bytes (RFLX.RFLX_Types.Index (I)) :=
              U8 (Frag_Out (I));
         end loop;
         Wire.Encode_Headers
           (Buffer => L.Buf, Last => Frame_Last,
            Stream_Id => Stream_Id, Fragment => Frag_Bytes,
            End_Stream => End_Stream);
      end;
      Transport.Send (Chan, L.Buf.all (L.Buf'First .. Frame_Last));
   end Encode_And_Send_Headers;

   --  Process a SETTINGS payload (already body-only) into the gate
   --  state: extract INITIAL_WINDOW_SIZE if present and stash on the
   --  Listener for use on the next Init_Stream call. §6.5.2 default
   --  is 65535 — left untouched if peer didn't override.
   procedure Process_Peer_Settings_Body
     (L      : in out Listener;
      Body_S : RFLX.RFLX_Types.Bytes);

   procedure Process_Peer_Settings_Body
     (L      : in out Listener;
      Body_S : RFLX.RFLX_Types.Bytes)
   is
      Params      : Wire.Settings_List (1 .. 16);
      Params_Last : Natural;
      Valid       : Boolean;
   begin
      Wire.Decode_Settings_Payload
        (Buffer       => Body_S,
         Valid        => Valid,
         Params       => Params,
         Params_Last  => Params_Last);
      if not Valid then
         return;
      end if;
      for I in Params'First .. Params_Last loop
         if Params (I).Identifier =
              RFLX.Http2_Parameters.INITIAL_WINDOW_SIZE
         then
            --  §6.9.1: value MUST NOT exceed 2**31-1. The structural
            --  Window_Bytes range catches overflow at the conversion;
            --  if the peer sent a violating value Bit_Len > 2**31-1
            --  we leave Peer_Initial_Window untouched.
            if Params (I).Value <= 2 ** 31 - 1 then
               L.Peer_Initial_Window :=
                 Flow_Gate.Window_Bytes (Params (I).Value);
               Logger.Log
                 (Logger.Debug,
                  "h2srv: peer INITIAL_WINDOW_SIZE="
                  & Flow_Gate.Window_Bytes'Image
                      (L.Peer_Initial_Window));
            end if;
         end if;
      end loop;
   end Process_Peer_Settings_Body;

   --  Process an inbound WINDOW_UPDATE frame into the gate.
   --  Body_S is the 4-byte payload (header already stripped).
   --  Stream_Id distinguishes connection-level (0) vs per-stream.
   --  Returns OK=False on §6.9.1 overflow (caller should fail conn).
   procedure Process_Inbound_Wu
     (L         : in out Listener;
      Stream_Id : Bit_Len;
      Body_S    : RFLX.RFLX_Types.Bytes;
      OK        : out Boolean);

   procedure Process_Inbound_Wu
     (L         : in out Listener;
      Stream_Id : Bit_Len;
      Body_S    : RFLX.RFLX_Types.Bytes;
      OK        : out Boolean)
   is
      Increment : Bit_Len;
      Wu_Valid  : Boolean;
   begin
      OK := True;
      Wire.Decode_Window_Update_Payload
        (Buffer    => Body_S,
         Increment => Increment,
         Valid     => Wu_Valid);
      if not Wu_Valid or else Increment = 0 then
         --  §6.9.1: Increment=0 is PROTOCOL_ERROR. Skip the apply;
         --  surface as flow error so caller decides.
         OK := False;
         return;
      end if;
      if Stream_Id = 0 then
         Flow_Gate.Apply_Wu_Conn
           (L.Gate,
            Flow_Gate.Window_Bytes (Increment),
            OK);
      else
         Flow_Gate.Apply_Wu_Stream
           (L.Gate,
            Flow_Gate.Window_Bytes (Increment),
            OK);
      end if;
      Logger.Log
        (Logger.Debug,
         "h2srv: wu stream=" & Bit_Len'Image (Stream_Id)
         & " inc=" & Bit_Len'Image (Increment)
         & " ok=" & Boolean'Image (OK));
   end Process_Inbound_Wu;

   --  Block-read inbound frames until the gate authorizes Bytes
   --  bytes (i.e., we observe at least one WU large enough to
   --  unblock). Reads from Chan via L.Buf. ACKs PINGs inline.
   --  PRECONDITION: caller already received Decision_Deny from the
   --  gate; this procedure is the wait-loop. POSTCONDITION on
   --  success (OK=True): a follow-up Request_Send for Bytes will
   --  return Decision_Allow.
   procedure Wait_For_Window
     (L         : in out Listener;
      Chan      : Transport.Channel;
      Bytes     : Flow_Gate.Window_Bytes;
      OK        : out Boolean);

   procedure Wait_For_Window
     (L         : in out Listener;
      Chan      : Transport.Channel;
      Bytes     : Flow_Gate.Window_Bytes;
      OK        : out Boolean)
   is
      Hdr      : Wire.Frame_Header;
      Last     : RFLX.RFLX_Types.Index;
      Read_OK  : Boolean;
   begin
      OK := False;
      Logger.Log
        (Logger.Debug,
         "h2srv: gate blocked; waiting for WU bytes="
         & Flow_Gate.Window_Bytes'Image (Bytes));
      loop
         Read_Frame (Chan, L.Buf, Hdr, Last, Read_OK);
         if not Read_OK then
            return;  --  peer closed; OK stays False
         end if;
         case Hdr.Frame_Type_Value is
            when RFLX.Http2_Parameters.WINDOW_UPDATE =>
               declare
                  Body_S : constant RFLX.RFLX_Types.Bytes :=
                    L.Buf.all (L.Buf'First + 9 .. Last);
                  Apply_OK : Boolean;
                  Probe    : Flow_Gate.Decision;
               begin
                  Process_Inbound_Wu
                    (L, Hdr.Stream_Identifier, Body_S, Apply_OK);
                  if not Apply_OK then
                     return;  --  flow error
                  end if;
                  --  Re-check whether we now have enough credit.
                  Flow_Gate.Request_Send (L.Gate, Bytes, Probe);
                  if Probe = Flow_Gate.Decision_Allow then
                     OK := True;
                     return;
                  end if;
                  --  Still blocked — loop.
               end;
            when RFLX.Http2_Parameters.PING =>
               if (Hdr.Flags and Wire.Flag_ACK) = 0
                 and Hdr.Length = 8
               then
                  declare
                     Ack_Last : RFLX.RFLX_Types.Index;
                     Echo     : constant RFLX.RFLX_Types.Bytes :=
                       L.Buf.all (L.Buf'First + 9 ..
                                    L.Buf'First + 16);
                  begin
                     Wire.Encode_Ping
                       (Buffer => L.Buf, Last => Ack_Last,
                        Opaque_Data => Echo, Ack => True);
                     Transport.Send
                       (Chan, L.Buf.all (L.Buf'First .. Ack_Last));
                  end;
               end if;
            when RFLX.Http2_Parameters.SETTINGS =>
               --  Re-settings mid-stream: refresh stream window basis
               --  for future streams (§6.5.3); doesn't replenish
               --  current credit.
               if (Hdr.Flags and Wire.Flag_ACK) = 0 then
                  declare
                     Body_S : constant RFLX.RFLX_Types.Bytes :=
                       L.Buf.all (L.Buf'First + 9 .. Last);
                     Ack_Last : RFLX.RFLX_Types.Index;
                  begin
                     Process_Peer_Settings_Body (L, Body_S);
                     Wire.Encode_Settings_Ack (L.Buf, Ack_Last);
                     Transport.Send
                       (Chan, L.Buf.all (L.Buf'First .. Ack_Last));
                  end;
               end if;
            when RFLX.Http2_Parameters.GOAWAY |
                 RFLX.Http2_Parameters.RST_STREAM =>
               --  Peer is tearing down. Stop waiting.
               return;
            when others =>
               --  Other frames while we're stalled are unexpected
               --  but not fatal. Continue waiting.
               null;
         end case;
      end loop;
   end Wait_For_Window;

   --  Wrap caller's gRPC-framed payload in DATA frames and emit,
   --  honouring the §6.9 flow-control window via the gate. Each
   --  chunk is gated; on Deny we read inbound until a WU
   --  replenishes credit (or peer disconnects, in which case we
   --  abandon the response — the caller's stream is dead anyway).
   procedure Send_Data_Frame
     (L          : in out Listener;
      Chan       : Transport.Channel;
      Stream_Id  : Bit_Len;
      Payload    : RFLX.RFLX_Types.Bytes;
      End_Stream : Boolean);

   procedure Send_Data_Frame
     (L          : in out Listener;
      Chan       : Transport.Channel;
      Stream_Id  : Bit_Len;
      Payload    : RFLX.RFLX_Types.Bytes;
      End_Stream : Boolean)
   is
      --  RFC 9113 §6.1: DATA frame payload bounded by SETTINGS_MAX_FRAME_SIZE.
      --  Split into 16384-byte chunks so >16 KB payloads work.
      --  Length (0-based) so the final Remaining-Chunk to 0 passes
      --  the range check.
      Max_Payload : constant := 16_384;
      Remaining   : RFLX.RFLX_Types.Length :=
        RFLX.RFLX_Types.Length (Payload'Length);
      Offset      : RFLX.RFLX_Types.Index := Payload'First;
   begin
      if Remaining = 0 then
         declare
            Data_Last : RFLX.RFLX_Types.Index;
         begin
            --  Empty DATA with END_STREAM doesn't consume window.
            Wire.Encode_Data
              (Buffer => L.Buf, Last => Data_Last,
               Stream_Id => Stream_Id,
               Payload => Payload (Payload'First .. Payload'First - 1),
               End_Stream => End_Stream);
            Transport.Send
              (Chan, L.Buf.all (L.Buf'First .. Data_Last));
         end;
         return;
      end if;
      while Remaining > 0 loop
         declare
            Chunk     : constant RFLX.RFLX_Types.Length :=
              RFLX.RFLX_Types.Length'Min (Remaining, Max_Payload);
            Is_Last   : constant Boolean :=
              Chunk = Remaining and then End_Stream;
            Data_Last : RFLX.RFLX_Types.Index;
            Outcome   : Flow_Gate.Decision;
            Gate_OK   : Boolean;
         begin
            --  Gate the emit: structural guarantee that we don't
            --  exceed peer's window. See specs/flow_gate.rflx.
            Flow_Gate.Request_Send
              (L.Gate,
               Flow_Gate.Window_Bytes (Chunk),
               Outcome);
            if Outcome = Flow_Gate.Decision_Deny then
               Wait_For_Window
                 (L, Chan,
                  Flow_Gate.Window_Bytes (Chunk),
                  Gate_OK);
               if not Gate_OK then
                  --  Peer disconnected or flow error — abandon the
                  --  rest of the response. Caller's stream is dead.
                  Logger.Log
                    (Logger.Warn,
                     "h2srv: gate wait failed; aborting send");
                  return;
               end if;
            elsif Outcome = Flow_Gate.Decision_Flow_Error then
               Logger.Log
                 (Logger.Warn, "h2srv: gate flow-error on send");
               return;
            end if;
            --  Either gate Allow on the first try, or Wait_For_Window
            --  succeeded (which itself called Request_Send and got
            --  Allow). Either way, credit is debited — emit.
            Wire.Encode_Data
              (Buffer => L.Buf, Last => Data_Last,
               Stream_Id => Stream_Id,
               Payload => Payload
                 (Offset ..
                    Offset + RFLX.RFLX_Types.Index (Chunk) - 1),
               End_Stream => Is_Last);
            Transport.Send
              (Chan, L.Buf.all (L.Buf'First .. Data_Last));
            Offset    := Offset + RFLX.RFLX_Types.Index (Chunk);
            Remaining := Remaining - Chunk;
         end;
      end loop;
   end Send_Data_Frame;

   --  Post-response cleanup. Reads up to 5 client frames; if a
   --  PING arrives, ACK it (so Python grpcio doesn't surface
   --  TCP-FIN as Socket_Closed). Then emit GOAWAY(NO_ERROR) and
   --  close the socket.
   procedure Drain_And_Goodbye
     (L         : in out Listener;
      Chan      : in out Transport.Channel;
      Stream_Id : Bit_Len);

   procedure Drain_And_Goodbye
     (L         : in out Listener;
      Chan      : in out Transport.Channel;
      Stream_Id : Bit_Len)
   is
   begin
      for K in 1 .. 5 loop
         declare
            Hdr2 : Wire.Frame_Header;
            Last2 : RFLX.RFLX_Types.Index;
            OK2 : Boolean;
         begin
            Read_Frame (Chan, L.Buf, Hdr2, Last2, OK2);
            exit when not OK2;
            if Hdr2.Frame_Type_Value = RFLX.Http2_Parameters.PING
              and (Hdr2.Flags and Wire.Flag_ACK) = 0
              and Hdr2.Length = 8
            then
               declare
                  Ack_Last : RFLX.RFLX_Types.Index;
                  Echo : constant RFLX.RFLX_Types.Bytes :=
                    L.Buf.all (L.Buf'First + 9 .. L.Buf'First + 16);
               begin
                  Wire.Encode_Ping
                    (Buffer => L.Buf, Last => Ack_Last,
                     Opaque_Data => Echo, Ack => True);
                  Transport.Send
                    (Chan, L.Buf.all (L.Buf'First .. Ack_Last));
               end;
               exit;
            end if;
         exception
            when others => exit;
         end;
      end loop;

      declare
         Goaway_Last : RFLX.RFLX_Types.Index;
         Empty : constant RFLX.RFLX_Types.Bytes (1 .. 0) :=
           (others => 0);
      begin
         Wire.Encode_Goaway
           (Buffer => L.Buf, Last => Goaway_Last,
            Last_Stream_Id => Stream_Id,
            Error_Code => 0,
            Debug_Data => Empty);
         Transport.Send (Chan, L.Buf.all (L.Buf'First .. Goaway_Last));
      exception
         when others => null;
      end;

      Transport.Close (Chan);
   end Drain_And_Goodbye;

   ---------------------------------------------------------------------
   --  Accept_And_Serve — full server-side handshake + one RPC.
   ---------------------------------------------------------------------

   procedure Accept_And_Serve (L : in out Listener)
   is
      Chan      : Transport.Channel;
      Stream_Id : Bit_Len := 0;

      Got_Peer_Settings : Boolean := False;
      Got_Settings_Ack  : Boolean := False;
   begin
      if L.Buf = null
        or else L.Inbound_Buf = null
        or else L.Outgoing_Buf = null
      then
         raise Server_Error
           with "Http2_Core.Server.Attach_Buffers must be called first";
      end if;

      Transport.Accept_One (L.Trans, Chan);

      --  RFC 7541 §2.2: HPACK dynamic table is per-connection. Reset
      --  before each new client so state from the previous connection
      --  doesn't poison this one's decode.
      Hpack.Dynamic_Table.Initialize (L.Hpack_Decoder);

      --  RFC 9113 §6.9.1: flow-control gate spans the lifetime of
      --  the TCP connection. Reset it per-connection so leftover
      --  state from a previous peer doesn't bleed in.
      Flow_Gate.Initialize (L.Gate);
      L.Peer_Initial_Window := 65535;  --  §6.5.2 default

      Receive_Preface (Chan);
      Send_Initial_Settings (L, Chan);

      --  RFC 9113 §6.9.1: bump the connection-level receive window to
      --  4 MB so we can sustain long-running clients (multi-stream).
      --  Without this, the connection window exhausts after ~64 KB of
      --  cumulative inbound DATA across all streams.
      declare
         Wu_Ptr : RFLX.RFLX_Types.Bytes_Ptr :=
           new RFLX.RFLX_Types.Bytes'(1 .. 26 => 0);
         Wu_Last : RFLX.RFLX_Types.Index;
      begin
         Wire.Encode_Window_Update
           (Buffer    => Wu_Ptr,
            Last      => Wu_Last,
            Stream_Id => 0,
            Increment => 2 ** 30);
         Transport.Send (Chan, Wu_Ptr.all (Wu_Ptr'First .. Wu_Last));
         pragma Unreferenced (Wu_Ptr);
      end;

      --  Note: we don't run a separate SETTINGS-handshake loop here.
      --  The FSM's Awaiting_Headers state already enumerates SETTINGS
      --  in its dispatch table (Forwarding_Connection_Frame), so we
      --  let the main FSM driver handle SETTINGS, PING, etc. inline
      --  with the HEADERS frame the client pipelines after them.
      --  Reading SETTINGS in a separate prologue would race with
      --  the HEADERS frame and silently drop it.
      pragma Unreferenced (Got_Peer_Settings);
      pragma Unreferenced (Got_Settings_Ack);

      --  Multi-stream loop: serve sequential RPCs on the same TCP
      --  connection until the client disconnects. Each iteration spins
      --  up a fresh Stream::Open FSM; the HPACK decoder dynamic table
      --  in L.Hpack_Decoder persists across streams (per RFC 7541 §2.2).
      Stream_Loop :
      loop
      --  Drive Stream::Open FSM through the request/response cycle.
      declare
         package FSM renames RFLX.Stream.Open.FSM;
         use type FSM.State;
         Ctx : FSM.Context;

         Request_Headers : Hpack.Header_Block (1 .. 16);
         Request_Headers_Last : Natural;
         Request_Body  : RFLX.RFLX_Types.Bytes (1 .. 1024 * 1024) :=
           (others => 0);
         Request_Body_Cursor : Integer :=
           Integer (Request_Body'First) - 1;
         Got_End_Of_Request : Boolean := False;
      begin
         FSM.Initialize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
         Request_Headers_Last := Request_Headers'First - 1;
         --  RFC 9113 §6.9.2 — every new stream starts with the
         --  per-stream send window seeded by peer's
         --  SETTINGS_INITIAL_WINDOW_SIZE. Connection window
         --  persists from the previous stream.
         Flow_Gate.Init_Stream (L.Gate, L.Peer_Initial_Window);

         --  Pre-feed: the FSM's first state (Awaiting_Headers) does
         --  Network'Read; if no data has been fed before the first
         --  Run, Verify_Message fails on empty buffer and the FSM
         --  goes straight to S_Final. Same trap as MQTT's Receive
         --  machine — see the MQTT driver for the same pattern.
         declare
            Frame_Last : RFLX.RFLX_Types.Index;
            Frame_Hdr  : Wire.Frame_Header;
            Read_OK    : Boolean;
         begin
            Read_Frame (Chan, L.Buf, Frame_Hdr, Frame_Last, Read_OK);
            if not Read_OK then
               --  Clean client disconnect between RPCs (or before any).
               FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
               exit Stream_Loop;
            end if;
            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               FSM.Write
                 (Ctx, FSM.C_Network,
                  L.Buf.all (L.Buf'First .. Frame_Last));
            end if;
         end;

         --  Phase 1: read request HEADERS + body. Drive FSM until
         --  it transitions out of the request side (Loading_Response
         --  next-state).
         Drive_Request :
         loop
            FSM.Run (Ctx);
            exit Drive_Request when not FSM.Active (Ctx);
            exit Drive_Request when
              FSM.Next_State (Ctx) = FSM.S_Loading_Response;

            if FSM.Has_Data (Ctx, FSM.C_Network) then
               --  Server-side FSM might have ACK frames to send.
               declare
                  N : constant RFLX.RFLX_Types.Length :=
                    FSM.Read_Buffer_Size (Ctx, FSM.C_Network);
                  View : RFLX.RFLX_Types.Bytes
                    (L.Buf'First ..
                       L.Buf'First + RFLX.RFLX_Types.Index (N) - 1);
               begin
                  FSM.Read (Ctx, FSM.C_Network, View);
                  Transport.Send (Chan, View);
               end;
            end if;

            if FSM.Has_Data (Ctx, FSM.C_App_Pending) then
               declare
                  N : constant RFLX.RFLX_Types.Length :=
                    FSM.Read_Buffer_Size (Ctx, FSM.C_App_Pending);
                  View : RFLX.RFLX_Types.Bytes
                    (L.Buf'First ..
                       L.Buf'First + RFLX.RFLX_Types.Index (N) - 1);
                  Hdr        : Wire.Frame_Header;
                  Hdr_Valid  : Boolean;
               begin
                  FSM.Read (Ctx, FSM.C_App_Pending, View);
                  if View'Length < 9 then
                     FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                     Transport.Close (Chan);
                     raise Server_Error with "short pending frame";
                  end if;
                  Wire.Decode_Frame_Header
                    (Buffer => View (View'First .. View'First + 8),
                     Header => Hdr,
                     Valid  => Hdr_Valid);
                  if not Hdr_Valid then
                     FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                     Transport.Close (Chan);
                     raise Server_Error with "bad pending frame header";
                  end if;
                  case Hdr.Frame_Type_Value is
                     when RFLX.Http2_Parameters.HEADERS =>
                        Stream_Id := Hdr.Stream_Identifier;
                        --  Decode HPACK fragment.
                        if (Hdr.Flags and Wire.Flag_END_HEADERS) = 0 then
                           FSM.Finalize
                             (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                           Transport.Close (Chan);
                           raise Server_Error
                             with "CONTINUATION not supported";
                        end if;
                        declare
                           Frag_First : RFLX.RFLX_Types.Index :=
                             View'First + 9;
                           Frag_Last  : constant RFLX.RFLX_Types.Index :=
                             View'Last;
                           Decode_OK  : Boolean;
                        begin
                           if (Hdr.Flags and Wire.Flag_PRIORITY) /= 0 then
                              Frag_First := Frag_First + 5;
                           end if;
                           declare
                              Frag : Hpack.Octet_Array
                                (1 ..
                                   Natural (Frag_Last - Frag_First) + 1);
                           begin
                              for I in Frag'Range loop
                                 Frag (I) :=
                                   Hpack.Octet
                                     (View
                                        (Frag_First
                                         + RFLX.RFLX_Types.Index (I)
                                         - 1));
                              end loop;
                              Hpack.Decode
                                (Input         => Frag,
                                 Headers       => Request_Headers,
                                 Headers_Last  => Request_Headers_Last,
                                 Output_OK     => Decode_OK,
                                 Decoder_State => L.Hpack_Decoder);
                              if not Decode_OK then
                                 FSM.Finalize
                                   (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                                 Transport.Close (Chan);
                                 raise Server_Error
                                   with "HPACK decode failed";
                              end if;
                           end;
                        end;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0 then
                           Got_End_Of_Request := True;
                        end if;
                     when RFLX.Http2_Parameters.DATA =>
                        if Hdr.Length > 0 then
                           declare
                              Need : constant Integer :=
                                Request_Body_Cursor + 1
                                + Integer (Hdr.Length);
                           begin
                              if Need > Integer (Request_Body'Last) then
                                 FSM.Finalize
                                   (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                                 Transport.Close (Chan);
                                 raise Server_Error
                                   with "request body overflow";
                              end if;
                              for I in 1 .. Integer (Hdr.Length) loop
                                 Request_Body_Cursor :=
                                   Request_Body_Cursor + 1;
                                 Request_Body
                                   (RFLX.RFLX_Types.Index
                                      (Request_Body_Cursor)) :=
                                   View
                                     (View'First + 8
                                      + RFLX.RFLX_Types.Index (I));
                              end loop;
                           end;
                        end if;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0 then
                           Got_End_Of_Request := True;
                        end if;
                     when RFLX.Http2_Parameters.RST_STREAM =>
                        FSM.Finalize
                          (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                        
                        exit Stream_Loop;
                     when RFLX.Http2_Parameters.PING =>
                        if (Hdr.Flags and Wire.Flag_ACK) = 0 then
                           declare
                              Ack_Last : RFLX.RFLX_Types.Index;
                              Echo : constant RFLX.RFLX_Types.Bytes :=
                                View
                                  (View'First + 9 ..
                                     View'First + 16);
                           begin
                              Wire.Encode_Ping
                                (Buffer => L.Buf, Last => Ack_Last,
                                 Opaque_Data => Echo, Ack => True);
                              Transport.Send
                                (Chan,
                                 L.Buf.all (L.Buf'First .. Ack_Last));
                           end;
                        end if;
                     when RFLX.Http2_Parameters.SETTINGS =>
                        if (Hdr.Flags and Wire.Flag_ACK) = 0 then
                           declare
                              Ack_Last : RFLX.RFLX_Types.Index;
                              Body_S : constant RFLX.RFLX_Types.Bytes :=
                                View (View'First + 9 .. View'Last);
                           begin
                              --  §6.5.2 — parse + apply peer's
                              --  INITIAL_WINDOW_SIZE before ACKing.
                              Process_Peer_Settings_Body (L, Body_S);
                              Wire.Encode_Settings_Ack
                                (L.Buf, Ack_Last);
                              Transport.Send
                                (Chan,
                                 L.Buf.all (L.Buf'First .. Ack_Last));
                           end;
                        end if;
                     when RFLX.Http2_Parameters.WINDOW_UPDATE =>
                        --  §6.9 — feed inbound WU into the gate so
                        --  Send_Data_Frame can debit its credit.
                        if Hdr.Length = 4 then
                           declare
                              Body_S : constant RFLX.RFLX_Types.Bytes :=
                                View (View'First + 9 .. View'Last);
                              Wu_OK : Boolean;
                           begin
                              Process_Inbound_Wu
                                (L,
                                 Hdr.Stream_Identifier,
                                 Body_S,
                                 Wu_OK);
                              if not Wu_OK then
                                 Logger.Log
                                   (Logger.Warn,
                                    "h2srv: WU flow_error stream="
                                    & Bit_Len'Image
                                        (Hdr.Stream_Identifier));
                              end if;
                           end;
                        end if;
                     when RFLX.Http2_Parameters.GOAWAY =>
                        --  Clean client shutdown.
                        FSM.Finalize
                          (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                        exit Stream_Loop;
                     when others =>
                        null;
                  end case;
               end;
            end if;

            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               declare
                  Frame_Last : RFLX.RFLX_Types.Index;
                  Frame_Hdr  : Wire.Frame_Header;
                  Read_OK    : Boolean;
               begin
                  Read_Frame (Chan, L.Buf, Frame_Hdr, Frame_Last, Read_OK);
                  if not Read_OK then
                     FSM.Finalize
                       (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                     
                     exit Stream_Loop;
                  end if;
                  if FSM.Needs_Data (Ctx, FSM.C_Network) then
                     FSM.Write
                       (Ctx, FSM.C_Network,
                        L.Buf.all (L.Buf'First .. Frame_Last));
                  end if;
               end;
            end if;
         end loop Drive_Request;

         --  Phase 2: invoke caller's handler.
         declare
            Resp_Hdrs : Hpack.Header_Block (1 .. 16);
            Resp_Hdrs_Last : Natural;
            Resp_Body : RFLX.RFLX_Types.Bytes (1 .. 1024 * 1024) :=
              (others => 0);
            Resp_Body_Last : Natural;
            Trailers : Hpack.Header_Block (1 .. 8);
            Trailers_Last : Natural;
         begin
            declare
               Empty_Slice : constant RFLX.RFLX_Types.Bytes (1 .. 0) :=
                 (others => 0);
               Have_Body   : constant Boolean :=
                 Request_Body_Cursor >= Integer (Request_Body'First);
            begin
            Handle_Request
              (Request_Headers       => Request_Headers,
               Request_Headers_Last  => Request_Headers_Last,
               Request_Body          =>
                 (if Have_Body then
                    Request_Body
                      (Request_Body'First ..
                         RFLX.RFLX_Types.Index (Request_Body_Cursor))
                  else Empty_Slice),
               Request_Body_Last     => Request_Body_Cursor,
               Response_Headers      => Resp_Hdrs,
               Response_Headers_Last => Resp_Hdrs_Last,
               Response_Body         => Resp_Body,
               Response_Body_Last    => Resp_Body_Last,
               Trailers              => Trailers,
               Trailers_Last         => Trailers_Last);

            --  Phase 3: emit response. Compose the three frames
            --  (HEADERS, DATA, trailing-HEADERS) into L.Buf and
            --  hand to FSM via App_Outbox one at a time. Drive
            --  Loading_Response → Sending_Response loop.

            Encode_And_Send_Headers
              (L, Chan, Stream_Id,
               Resp_Hdrs (Resp_Hdrs'First .. Resp_Hdrs_Last),
               End_Stream => False);

            if Resp_Body_Last >= Integer (Resp_Body'First) then
               Send_Data_Frame
                 (L, Chan, Stream_Id,
                  Resp_Body
                    (Resp_Body'First ..
                       RFLX.RFLX_Types.Index (Resp_Body_Last)),
                  End_Stream => False);
            end if;

            Encode_And_Send_Headers
              (L, Chan, Stream_Id,
               Trailers (Trailers'First .. Trailers_Last),
               End_Stream => True);
            end;  --  declare Have_Body / Empty_Slice
         end;

         FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
         pragma Unreferenced (Got_End_Of_Request);
      end;
      --  Refill the connection-level inbound window after each stream.
      --  Without this, the window monotonically shrinks across streams
      --  on a persistent connection and eventually deadlocks.
      declare
         Wu_Ptr : RFLX.RFLX_Types.Bytes_Ptr :=
           new RFLX.RFLX_Types.Bytes'(1 .. 26 => 0);
         Wu_Last : RFLX.RFLX_Types.Index;
      begin
         Wire.Encode_Window_Update
           (Buffer    => Wu_Ptr,
            Last      => Wu_Last,
            Stream_Id => 0,
            Increment => 2 ** 20);
         Transport.Send (Chan, Wu_Ptr.all (Wu_Ptr'First .. Wu_Last));
         pragma Unreferenced (Wu_Ptr);
      exception
         when others => exit Stream_Loop;
      end;
      end loop Stream_Loop;

      Drain_And_Goodbye (L, Chan, Stream_Id);
      Flow_Gate.Finalize (L.Gate);
   end Accept_And_Serve;

   ---------------------------------------------------------------------
   --  Accept_And_Serve_Server_Stream — same request phase as
   --  Accept_And_Serve, but emits N DATA frames pulled from the
   --  caller's Next_Reply function before sending trailing HEADERS.
   --
   --  Request side is identical (modulo the handler interface) so the
   --  body is largely a copy of Accept_And_Serve up through Phase 2.
   --  Phase 3's response phase is the streaming difference.
   ---------------------------------------------------------------------

   procedure Accept_And_Serve_Server_Stream (L : in out Listener)
   is
      Chan      : Transport.Channel;
      Stream_Id : Bit_Len := 0;
      Got_Peer_Settings : Boolean := False;
      Got_Settings_Ack  : Boolean := False;
   begin
      if L.Buf = null
        or else L.Inbound_Buf = null
        or else L.Outgoing_Buf = null
      then
         raise Server_Error
           with "Http2_Core.Server.Attach_Buffers must be called first";
      end if;

      Transport.Accept_One (L.Trans, Chan);

      Hpack.Dynamic_Table.Initialize (L.Hpack_Decoder);
      Flow_Gate.Initialize (L.Gate);
      L.Peer_Initial_Window := 65535;

      Receive_Preface (Chan);
      Send_Initial_Settings (L, Chan);

      pragma Unreferenced (Got_Peer_Settings);
      pragma Unreferenced (Got_Settings_Ack);

      --  FSM-driven request phase (identical to unary).
      declare
         package FSM renames RFLX.Stream.Open.FSM;
         use type FSM.State;
         Ctx : FSM.Context;

         Request_Headers : Hpack.Header_Block (1 .. 16);
         Request_Headers_Last : Natural;
         Request_Body  : RFLX.RFLX_Types.Bytes (1 .. 16384) :=
           (others => 0);
         Request_Body_Cursor : Integer :=
           Integer (Request_Body'First) - 1;
         Got_End_Of_Request : Boolean := False;
      begin
         FSM.Initialize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
         Request_Headers_Last := Request_Headers'First - 1;
         --  RFC 9113 §6.9.2 — seed per-stream send window.
         Flow_Gate.Init_Stream (L.Gate, L.Peer_Initial_Window);

         --  Pre-feed first frame.
         declare
            Frame_Last : RFLX.RFLX_Types.Index;
            Frame_Hdr  : Wire.Frame_Header;
            Read_OK    : Boolean;
         begin
            Read_Frame (Chan, L.Buf, Frame_Hdr, Frame_Last, Read_OK);
            if not Read_OK then
               FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
               Transport.Close (Chan);
               raise Server_Error with "EOF before first frame";
            end if;
            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               FSM.Write
                 (Ctx, FSM.C_Network,
                  L.Buf.all (L.Buf'First .. Frame_Last));
            end if;
         end;

         Drive_Request :
         loop
            FSM.Run (Ctx);
            exit Drive_Request when not FSM.Active (Ctx);
            exit Drive_Request when
              FSM.Next_State (Ctx) = FSM.S_Loading_Response;

            if FSM.Has_Data (Ctx, FSM.C_Network) then
               declare
                  N : constant RFLX.RFLX_Types.Length :=
                    FSM.Read_Buffer_Size (Ctx, FSM.C_Network);
                  View : RFLX.RFLX_Types.Bytes
                    (L.Buf'First ..
                       L.Buf'First + RFLX.RFLX_Types.Index (N) - 1);
               begin
                  FSM.Read (Ctx, FSM.C_Network, View);
                  Transport.Send (Chan, View);
               end;
            end if;

            if FSM.Has_Data (Ctx, FSM.C_App_Pending) then
               declare
                  N : constant RFLX.RFLX_Types.Length :=
                    FSM.Read_Buffer_Size (Ctx, FSM.C_App_Pending);
                  View : RFLX.RFLX_Types.Bytes
                    (L.Buf'First ..
                       L.Buf'First + RFLX.RFLX_Types.Index (N) - 1);
                  Hdr        : Wire.Frame_Header;
                  Hdr_Valid  : Boolean;
               begin
                  FSM.Read (Ctx, FSM.C_App_Pending, View);
                  if View'Length < 9 then
                     FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                     Transport.Close (Chan);
                     raise Server_Error with "short pending frame";
                  end if;
                  Wire.Decode_Frame_Header
                    (Buffer => View (View'First .. View'First + 8),
                     Header => Hdr,
                     Valid  => Hdr_Valid);
                  if not Hdr_Valid then
                     FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                     Transport.Close (Chan);
                     raise Server_Error with "bad pending frame header";
                  end if;
                  case Hdr.Frame_Type_Value is
                     when RFLX.Http2_Parameters.HEADERS =>
                        Stream_Id := Hdr.Stream_Identifier;
                        if (Hdr.Flags and Wire.Flag_END_HEADERS) = 0 then
                           FSM.Finalize
                             (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                           Transport.Close (Chan);
                           raise Server_Error
                             with "CONTINUATION not supported";
                        end if;
                        declare
                           Frag_First : RFLX.RFLX_Types.Index :=
                             View'First + 9;
                           Frag_Last  : constant RFLX.RFLX_Types.Index :=
                             View'Last;
                           Decode_OK  : Boolean;
                        begin
                           if (Hdr.Flags and Wire.Flag_PRIORITY) /= 0 then
                              Frag_First := Frag_First + 5;
                           end if;
                           declare
                              Frag : Hpack.Octet_Array
                                (1 ..
                                   Natural (Frag_Last - Frag_First) + 1);
                           begin
                              for I in Frag'Range loop
                                 Frag (I) :=
                                   Hpack.Octet
                                     (View
                                        (Frag_First
                                         + RFLX.RFLX_Types.Index (I)
                                         - 1));
                              end loop;
                              Hpack.Decode
                                (Input         => Frag,
                                 Headers       => Request_Headers,
                                 Headers_Last  => Request_Headers_Last,
                                 Output_OK     => Decode_OK,
                                 Decoder_State => L.Hpack_Decoder);
                              if not Decode_OK then
                                 FSM.Finalize
                                   (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                                 Transport.Close (Chan);
                                 raise Server_Error
                                   with "HPACK decode failed";
                              end if;
                           end;
                        end;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0 then
                           Got_End_Of_Request := True;
                        end if;
                     when RFLX.Http2_Parameters.DATA =>
                        if Hdr.Length > 0 then
                           declare
                              Need : constant Integer :=
                                Request_Body_Cursor + 1
                                + Integer (Hdr.Length);
                           begin
                              if Need > Integer (Request_Body'Last) then
                                 FSM.Finalize
                                   (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                                 Transport.Close (Chan);
                                 raise Server_Error
                                   with "request body overflow";
                              end if;
                              for I in 1 .. Integer (Hdr.Length) loop
                                 Request_Body_Cursor :=
                                   Request_Body_Cursor + 1;
                                 Request_Body
                                   (RFLX.RFLX_Types.Index
                                      (Request_Body_Cursor)) :=
                                   View
                                     (View'First + 8
                                      + RFLX.RFLX_Types.Index (I));
                              end loop;
                           end;
                        end if;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0 then
                           Got_End_Of_Request := True;
                        end if;
                     when RFLX.Http2_Parameters.RST_STREAM =>
                        FSM.Finalize
                          (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                        Transport.Close (Chan);
                        raise Server_Error with "client RST_STREAM";
                     when RFLX.Http2_Parameters.PING =>
                        if (Hdr.Flags and Wire.Flag_ACK) = 0 then
                           declare
                              Ack_Last : RFLX.RFLX_Types.Index;
                              Echo : constant RFLX.RFLX_Types.Bytes :=
                                View
                                  (View'First + 9 ..
                                     View'First + 16);
                           begin
                              Wire.Encode_Ping
                                (Buffer => L.Buf, Last => Ack_Last,
                                 Opaque_Data => Echo, Ack => True);
                              Transport.Send
                                (Chan,
                                 L.Buf.all (L.Buf'First .. Ack_Last));
                           end;
                        end if;
                     when RFLX.Http2_Parameters.SETTINGS =>
                        if (Hdr.Flags and Wire.Flag_ACK) = 0 then
                           declare
                              Ack_Last : RFLX.RFLX_Types.Index;
                              Body_S : constant RFLX.RFLX_Types.Bytes :=
                                View (View'First + 9 .. View'Last);
                           begin
                              --  §6.5.2 — parse + apply peer's
                              --  INITIAL_WINDOW_SIZE before ACKing.
                              Process_Peer_Settings_Body (L, Body_S);
                              Wire.Encode_Settings_Ack
                                (L.Buf, Ack_Last);
                              Transport.Send
                                (Chan,
                                 L.Buf.all (L.Buf'First .. Ack_Last));
                           end;
                        end if;
                     when RFLX.Http2_Parameters.WINDOW_UPDATE =>
                        --  §6.9 — feed inbound WU into the gate so
                        --  Send_Data_Frame can debit its credit.
                        if Hdr.Length = 4 then
                           declare
                              Body_S : constant RFLX.RFLX_Types.Bytes :=
                                View (View'First + 9 .. View'Last);
                              Wu_OK : Boolean;
                           begin
                              Process_Inbound_Wu
                                (L,
                                 Hdr.Stream_Identifier,
                                 Body_S,
                                 Wu_OK);
                              if not Wu_OK then
                                 Logger.Log
                                   (Logger.Warn,
                                    "h2srv: WU flow_error stream="
                                    & Bit_Len'Image
                                        (Hdr.Stream_Identifier));
                              end if;
                           end;
                        end if;
                     when RFLX.Http2_Parameters.GOAWAY =>
                        FSM.Finalize
                          (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                        Transport.Close (Chan);
                        raise Server_Error with "client GOAWAY";
                     when others =>
                        null;
                  end case;
               end;
            end if;

            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               declare
                  Frame_Last : RFLX.RFLX_Types.Index;
                  Frame_Hdr  : Wire.Frame_Header;
                  Read_OK    : Boolean;
               begin
                  Read_Frame (Chan, L.Buf, Frame_Hdr, Frame_Last, Read_OK);
                  if not Read_OK then
                     FSM.Finalize
                       (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                     Transport.Close (Chan);
                     raise Server_Error with "EOF in request";
                  end if;
                  if FSM.Needs_Data (Ctx, FSM.C_Network) then
                     FSM.Write
                       (Ctx, FSM.C_Network,
                        L.Buf.all (L.Buf'First .. Frame_Last));
                  end if;
               end;
            end if;
         end loop Drive_Request;

         pragma Unreferenced (Got_End_Of_Request);

         --  STREAMING RESPONSE PHASE.
         declare
            Resp_Hdrs : Hpack.Header_Block (1 .. 16);
            Resp_Hdrs_Last : Natural;
            Trailers : Hpack.Header_Block (1 .. 8);
            Trailers_Last : Natural;
            Empty_Slice : constant RFLX.RFLX_Types.Bytes (1 .. 0) :=
              (others => 0);
            Have_Body   : constant Boolean :=
              Request_Body_Cursor >= Integer (Request_Body'First);
         begin
            Setup_Response
              (Request_Headers       => Request_Headers,
               Request_Headers_Last  => Request_Headers_Last,
               Request_Body          =>
                 (if Have_Body then
                    Request_Body
                      (Request_Body'First ..
                         RFLX.RFLX_Types.Index (Request_Body_Cursor))
                  else Empty_Slice),
               Request_Body_Last     => Request_Body_Cursor,
               Response_Headers      => Resp_Hdrs,
               Response_Headers_Last => Resp_Hdrs_Last,
               Trailers              => Trailers,
               Trailers_Last         => Trailers_Last);

            Encode_And_Send_Headers
              (L, Chan, Stream_Id,
               Resp_Hdrs (Resp_Hdrs'First .. Resp_Hdrs_Last),
               End_Stream => False);

            --  Streaming loop: pull each reply via Next_Reply, send
            --  as one DATA frame. Caller is responsible for the
            --  5-byte gRPC framing prefix on each message.
            Stream_Loop :
            loop
               declare
                  Msg_Buf  : RFLX.RFLX_Types.Bytes (1 .. 16384) :=
                    (others => 0);
                  Msg_Last : RFLX.RFLX_Types.Index;
                  Has_Msg  : Boolean;
               begin
                  Has_Msg := Next_Reply (Msg_Buf, Msg_Last);
                  exit Stream_Loop when not Has_Msg;
                  Send_Data_Frame
                    (L, Chan, Stream_Id,
                     Msg_Buf (Msg_Buf'First .. Msg_Last),
                     End_Stream => False);
               end;
            end loop Stream_Loop;

            Encode_And_Send_Headers
              (L, Chan, Stream_Id,
               Trailers (Trailers'First .. Trailers_Last),
               End_Stream => True);
         end;

         FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
      end;

      Drain_And_Goodbye (L, Chan, Stream_Id);
      Flow_Gate.Finalize (L.Gate);
   end Accept_And_Serve_Server_Stream;

   ---------------------------------------------------------------------
   --  Strip the 5-byte gRPC framing prefix from a DATA-frame
   --  payload. Empty-or-too-short inputs return an empty slice.
   ---------------------------------------------------------------------

   function Strip_Grpc_Frame
     (View : RFLX.RFLX_Types.Bytes) return RFLX.RFLX_Types.Bytes;

   function Strip_Grpc_Frame
     (View : RFLX.RFLX_Types.Bytes) return RFLX.RFLX_Types.Bytes is
   begin
      if View'Length < 5 then
         return View (View'First .. View'First - 1);
      end if;
      declare
         Msg_Len_64 : constant Long_Long_Integer :=
           Long_Long_Integer (View (View'First + 1)) * 16777216
           + Long_Long_Integer (View (View'First + 2)) * 65536
           + Long_Long_Integer (View (View'First + 3)) * 256
           + Long_Long_Integer (View (View'First + 4));
      begin
         if Msg_Len_64 <= 0
           or else Msg_Len_64 > Long_Long_Integer (View'Length) - 5
         then
            return View (View'First .. View'First - 1);
         end if;
         declare
            Msg_Len : constant Natural := Natural (Msg_Len_64);
         begin
            return View
                     (View'First + 5 ..
                        View'First + 4
                        + RFLX.RFLX_Types.Index (Msg_Len));
         end;
      end;
   end Strip_Grpc_Frame;

   ---------------------------------------------------------------------
   --  Accept_And_Serve_Client_Stream — N requests → 1 response.
   ---------------------------------------------------------------------

   procedure Accept_And_Serve_Client_Stream (L : in out Listener)
   is
      Chan      : Transport.Channel;
      Stream_Id : Bit_Len := 0;
   begin
      if L.Buf = null
        or else L.Inbound_Buf = null
        or else L.Outgoing_Buf = null
      then
         raise Server_Error
           with "Http2_Core.Server.Attach_Buffers must be called first";
      end if;

      Transport.Accept_One (L.Trans, Chan);

      Receive_Preface (Chan);
      Send_Initial_Settings (L, Chan);

      --  FSM-driven request phase, but each DATA frame's gRPC message
      --  is delivered to On_Request_Message immediately (no body
      --  accumulation).
      declare
         package FSM renames RFLX.Stream.Open.FSM;
         use type FSM.State;
         Ctx : FSM.Context;

         Request_Headers : Hpack.Header_Block (1 .. 16);
         Request_Headers_Last : Natural;
         Got_End_Of_Request : Boolean := False;
      begin
         FSM.Initialize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
         Request_Headers_Last := Request_Headers'First - 1;
         --  RFC 9113 §6.9.2 — seed per-stream send window.
         Flow_Gate.Init_Stream (L.Gate, L.Peer_Initial_Window);

         declare
            Frame_Last : RFLX.RFLX_Types.Index;
            Frame_Hdr  : Wire.Frame_Header;
            Read_OK    : Boolean;
         begin
            Read_Frame (Chan, L.Buf, Frame_Hdr, Frame_Last, Read_OK);
            if not Read_OK then
               FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
               Transport.Close (Chan);
               raise Server_Error with "EOF before first frame";
            end if;
            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               FSM.Write
                 (Ctx, FSM.C_Network,
                  L.Buf.all (L.Buf'First .. Frame_Last));
            end if;
         end;

         Drive_Request :
         loop
            FSM.Run (Ctx);
            exit Drive_Request when not FSM.Active (Ctx);
            exit Drive_Request when
              FSM.Next_State (Ctx) = FSM.S_Loading_Response;

            if FSM.Has_Data (Ctx, FSM.C_App_Pending) then
               declare
                  N : constant RFLX.RFLX_Types.Length :=
                    FSM.Read_Buffer_Size (Ctx, FSM.C_App_Pending);
                  View : RFLX.RFLX_Types.Bytes
                    (L.Buf'First ..
                       L.Buf'First + RFLX.RFLX_Types.Index (N) - 1);
                  Hdr : Wire.Frame_Header;
                  Hdr_Valid : Boolean;
               begin
                  FSM.Read (Ctx, FSM.C_App_Pending, View);
                  Wire.Decode_Frame_Header
                    (Buffer => View (View'First .. View'First + 8),
                     Header => Hdr,
                     Valid  => Hdr_Valid);
                  if not Hdr_Valid then
                     FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                     Transport.Close (Chan);
                     raise Server_Error with "bad pending frame header";
                  end if;
                  case Hdr.Frame_Type_Value is
                     when RFLX.Http2_Parameters.HEADERS =>
                        Stream_Id := Hdr.Stream_Identifier;
                        if (Hdr.Flags and Wire.Flag_END_HEADERS) = 0 then
                           FSM.Finalize
                             (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                           Transport.Close (Chan);
                           raise Server_Error
                             with "CONTINUATION not supported";
                        end if;
                        declare
                           Frag_First : RFLX.RFLX_Types.Index :=
                             View'First + 9;
                           Frag_Last : constant RFLX.RFLX_Types.Index :=
                             View'Last;
                           Decode_OK : Boolean;
                        begin
                           if (Hdr.Flags and Wire.Flag_PRIORITY) /= 0 then
                              Frag_First := Frag_First + 5;
                           end if;
                           declare
                              Frag : Hpack.Octet_Array
                                (1 ..
                                   Natural (Frag_Last - Frag_First) + 1);
                           begin
                              for I in Frag'Range loop
                                 Frag (I) :=
                                   Hpack.Octet
                                     (View
                                        (Frag_First
                                         + RFLX.RFLX_Types.Index (I)
                                         - 1));
                              end loop;
                              Hpack.Decode
                                (Input         => Frag,
                                 Headers       => Request_Headers,
                                 Headers_Last  => Request_Headers_Last,
                                 Output_OK     => Decode_OK,
                                 Decoder_State => L.Hpack_Decoder);
                              if not Decode_OK then
                                 FSM.Finalize
                                   (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                                 Transport.Close (Chan);
                                 raise Server_Error
                                   with "HPACK decode failed";
                              end if;
                           end;
                        end;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0 then
                           Got_End_Of_Request := True;
                        end if;
                     when RFLX.Http2_Parameters.DATA =>
                        --  Differs from unary: each DATA frame's
                        --  gRPC message is surfaced immediately
                        --  rather than accumulated.
                        if Hdr.Length > 0 then
                           declare
                              Payload : constant RFLX.RFLX_Types.Bytes :=
                                View
                                  (View'First + 9
                                   .. View'First + 8
                                      + RFLX.RFLX_Types.Index (Hdr.Length));
                              Msg : constant RFLX.RFLX_Types.Bytes :=
                                Strip_Grpc_Frame (Payload);
                           begin
                              if Msg'Length > 0 then
                                 On_Request_Message (Msg);
                              end if;
                           end;
                        end if;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0 then
                           Got_End_Of_Request := True;
                        end if;
                     when RFLX.Http2_Parameters.RST_STREAM =>
                        FSM.Finalize
                          (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                        Transport.Close (Chan);
                        raise Server_Error with "client RST_STREAM";
                     when RFLX.Http2_Parameters.PING =>
                        if (Hdr.Flags and Wire.Flag_ACK) = 0 then
                           declare
                              Ack_Last : RFLX.RFLX_Types.Index;
                              Echo : constant RFLX.RFLX_Types.Bytes :=
                                View (View'First + 9 ..
                                        View'First + 16);
                           begin
                              Wire.Encode_Ping
                                (Buffer => L.Buf, Last => Ack_Last,
                                 Opaque_Data => Echo, Ack => True);
                              Transport.Send
                                (Chan,
                                 L.Buf.all (L.Buf'First .. Ack_Last));
                           end;
                        end if;
                     when RFLX.Http2_Parameters.SETTINGS =>
                        if (Hdr.Flags and Wire.Flag_ACK) = 0 then
                           declare
                              Ack_Last : RFLX.RFLX_Types.Index;
                              Body_S : constant RFLX.RFLX_Types.Bytes :=
                                View (View'First + 9 .. View'Last);
                           begin
                              --  §6.5.2 — parse + apply peer's
                              --  INITIAL_WINDOW_SIZE before ACKing.
                              Process_Peer_Settings_Body (L, Body_S);
                              Wire.Encode_Settings_Ack
                                (L.Buf, Ack_Last);
                              Transport.Send
                                (Chan,
                                 L.Buf.all (L.Buf'First .. Ack_Last));
                           end;
                        end if;
                     when RFLX.Http2_Parameters.WINDOW_UPDATE =>
                        --  §6.9 — feed inbound WU into the gate so
                        --  Send_Data_Frame can debit its credit.
                        if Hdr.Length = 4 then
                           declare
                              Body_S : constant RFLX.RFLX_Types.Bytes :=
                                View (View'First + 9 .. View'Last);
                              Wu_OK : Boolean;
                           begin
                              Process_Inbound_Wu
                                (L,
                                 Hdr.Stream_Identifier,
                                 Body_S,
                                 Wu_OK);
                              if not Wu_OK then
                                 Logger.Log
                                   (Logger.Warn,
                                    "h2srv: WU flow_error stream="
                                    & Bit_Len'Image
                                        (Hdr.Stream_Identifier));
                              end if;
                           end;
                        end if;
                     when RFLX.Http2_Parameters.GOAWAY =>
                        FSM.Finalize
                          (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                        Transport.Close (Chan);
                        raise Server_Error with "client GOAWAY";
                     when others =>
                        null;
                  end case;
               end;
            end if;

            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               declare
                  Frame_Last : RFLX.RFLX_Types.Index;
                  Frame_Hdr  : Wire.Frame_Header;
                  Read_OK    : Boolean;
               begin
                  Read_Frame (Chan, L.Buf, Frame_Hdr, Frame_Last, Read_OK);
                  if not Read_OK then
                     FSM.Finalize
                       (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                     Transport.Close (Chan);
                     raise Server_Error with "EOF in request";
                  end if;
                  if FSM.Needs_Data (Ctx, FSM.C_Network) then
                     FSM.Write
                       (Ctx, FSM.C_Network,
                        L.Buf.all (L.Buf'First .. Frame_Last));
                  end if;
               end;
            end if;
         end loop Drive_Request;

         pragma Unreferenced (Got_End_Of_Request);

         --  RESPONSE PHASE — single response (like unary).
         declare
            Resp_Hdrs : Hpack.Header_Block (1 .. 16);
            Resp_Hdrs_Last : Natural;
            Resp_Body : RFLX.RFLX_Types.Bytes (1 .. 1024 * 1024) :=
              (others => 0);
            Resp_Body_Last : Natural;
            Trailers : Hpack.Header_Block (1 .. 8);
            Trailers_Last : Natural;
         begin
            Build_Response
              (Request_Headers       => Request_Headers,
               Request_Headers_Last  => Request_Headers_Last,
               Response_Headers      => Resp_Hdrs,
               Response_Headers_Last => Resp_Hdrs_Last,
               Response_Body         => Resp_Body,
               Response_Body_Last    => Resp_Body_Last,
               Trailers              => Trailers,
               Trailers_Last         => Trailers_Last);

            Encode_And_Send_Headers
              (L, Chan, Stream_Id,
               Resp_Hdrs (Resp_Hdrs'First .. Resp_Hdrs_Last),
               End_Stream => False);

            if Resp_Body_Last >= Integer (Resp_Body'First) then
               Send_Data_Frame
                 (L, Chan, Stream_Id,
                  Resp_Body
                    (Resp_Body'First ..
                       RFLX.RFLX_Types.Index (Resp_Body_Last)),
                  End_Stream => False);
            end if;

            Encode_And_Send_Headers
              (L, Chan, Stream_Id,
               Trailers (Trailers'First .. Trailers_Last),
               End_Stream => True);
         end;

         FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
      end;

      Drain_And_Goodbye (L, Chan, Stream_Id);
      Flow_Gate.Finalize (L.Gate);
   end Accept_And_Serve_Client_Stream;

   ---------------------------------------------------------------------
   --  Accept_And_Serve_Bidi_Stream — full duplex.
   --
   --  After receiving client HEADERS, server emits its response
   --  HEADERS immediately (so the client can start expecting
   --  replies), then enters an interleave loop. Each iteration:
   --    1. Drain any FSM-pending inbound (DATA → On_Request_Message).
   --    2. If client hasn't END_STREAM'd, try a non-blocking-ish read
   --       on Network and feed FSM.
   --    3. If we still have replies (Next_Reply returns True),
   --       emit one DATA frame.
   --  Loop ends when both Next_Reply returned False AND client
   --  END_STREAM'd. Trailers are sent after.
   ---------------------------------------------------------------------

   procedure Accept_And_Serve_Bidi_Stream (L : in out Listener)
   is
      Chan      : Transport.Channel;
      Stream_Id : Bit_Len := 0;
   begin
      if L.Buf = null
        or else L.Inbound_Buf = null
        or else L.Outgoing_Buf = null
      then
         raise Server_Error
           with "Http2_Core.Server.Attach_Buffers must be called first";
      end if;

      Transport.Accept_One (L.Trans, Chan);

      Receive_Preface (Chan);
      Send_Initial_Settings (L, Chan);

      --  Drive request side until HEADERS arrives + emit response
      --  HEADERS so client can start receiving replies. Then
      --  interleave inbound DATA / outbound DATA.
      declare
         package FSM renames RFLX.Stream.Open.FSM;
         use type FSM.State;
         Ctx : FSM.Context;

         Request_Headers : Hpack.Header_Block (1 .. 16);
         Request_Headers_Last : Natural;
         Got_Request_Headers : Boolean := False;
         Got_End_Of_Request : Boolean := False;
         No_More_Replies : Boolean := False;
         Resp_Hdrs : Hpack.Header_Block (1 .. 16);
         Resp_Hdrs_Last : Natural;
         Trailers : Hpack.Header_Block (1 .. 8);
         Trailers_Last : Natural;
      begin
         FSM.Initialize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
         Request_Headers_Last := Request_Headers'First - 1;
         --  RFC 9113 §6.9.2 — seed per-stream send window.
         Flow_Gate.Init_Stream (L.Gate, L.Peer_Initial_Window);

         --  Pre-feed first frame.
         declare
            Frame_Last : RFLX.RFLX_Types.Index;
            Frame_Hdr  : Wire.Frame_Header;
            Read_OK    : Boolean;
         begin
            Read_Frame (Chan, L.Buf, Frame_Hdr, Frame_Last, Read_OK);
            if not Read_OK then
               FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
               Transport.Close (Chan);
               raise Server_Error with "EOF before first frame";
            end if;
            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               FSM.Write
                 (Ctx, FSM.C_Network,
                  L.Buf.all (L.Buf'First .. Frame_Last));
            end if;
         end;

         --  Inner helper: process one App_Pending frame.
         --  HEADERS → fold into Request_Headers (set Got_Request_Headers).
         --  DATA → strip gRPC framing, deliver to On_Request_Message.
         --  Connection-mgmt → ack inline.

         --  Drive the FSM until we've seen the HEADERS frame. Then
         --  emit our response HEADERS and enter interleave mode.
         Drive_Until_Headers :
         loop
            FSM.Run (Ctx);
            exit Drive_Until_Headers when not FSM.Active (Ctx);

            if FSM.Has_Data (Ctx, FSM.C_App_Pending) then
               declare
                  N : constant RFLX.RFLX_Types.Length :=
                    FSM.Read_Buffer_Size (Ctx, FSM.C_App_Pending);
                  View : RFLX.RFLX_Types.Bytes
                    (L.Buf'First ..
                       L.Buf'First + RFLX.RFLX_Types.Index (N) - 1);
                  Hdr : Wire.Frame_Header;
                  Hdr_Valid : Boolean;
               begin
                  FSM.Read (Ctx, FSM.C_App_Pending, View);
                  Wire.Decode_Frame_Header
                    (Buffer => View (View'First .. View'First + 8),
                     Header => Hdr,
                     Valid  => Hdr_Valid);
                  if not Hdr_Valid then
                     FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                     Transport.Close (Chan);
                     raise Server_Error with "bad pending frame header";
                  end if;
                  case Hdr.Frame_Type_Value is
                     when RFLX.Http2_Parameters.HEADERS =>
                        Stream_Id := Hdr.Stream_Identifier;
                        declare
                           Frag_First : RFLX.RFLX_Types.Index :=
                             View'First + 9;
                           Frag_Last : constant RFLX.RFLX_Types.Index :=
                             View'Last;
                           Decode_OK : Boolean;
                        begin
                           if (Hdr.Flags and Wire.Flag_PRIORITY) /= 0 then
                              Frag_First := Frag_First + 5;
                           end if;
                           declare
                              Frag : Hpack.Octet_Array
                                (1 ..
                                   Natural (Frag_Last - Frag_First) + 1);
                           begin
                              for I in Frag'Range loop
                                 Frag (I) :=
                                   Hpack.Octet
                                     (View
                                        (Frag_First
                                         + RFLX.RFLX_Types.Index (I)
                                         - 1));
                              end loop;
                              Hpack.Decode
                                (Input         => Frag,
                                 Headers       => Request_Headers,
                                 Headers_Last  => Request_Headers_Last,
                                 Output_OK     => Decode_OK,
                                 Decoder_State => L.Hpack_Decoder);
                              if not Decode_OK then
                                 FSM.Finalize
                                   (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                                 Transport.Close (Chan);
                                 raise Server_Error
                                   with "HPACK decode failed";
                              end if;
                           end;
                        end;
                        Got_Request_Headers := True;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0 then
                           Got_End_Of_Request := True;
                        end if;
                        exit Drive_Until_Headers;
                     when RFLX.Http2_Parameters.SETTINGS =>
                        if (Hdr.Flags and Wire.Flag_ACK) = 0 then
                           declare
                              Ack_Last : RFLX.RFLX_Types.Index;
                           begin
                              Wire.Encode_Settings_Ack
                                (L.Buf, Ack_Last);
                              Transport.Send
                                (Chan,
                                 L.Buf.all (L.Buf'First .. Ack_Last));
                           end;
                        end if;
                     when others =>
                        null;
                  end case;
               end;
            end if;

            if FSM.Needs_Data (Ctx, FSM.C_Network) then
               declare
                  Frame_Last : RFLX.RFLX_Types.Index;
                  Frame_Hdr  : Wire.Frame_Header;
                  Read_OK    : Boolean;
               begin
                  Read_Frame
                    (Chan, L.Buf, Frame_Hdr, Frame_Last, Read_OK);
                  if not Read_OK then
                     FSM.Finalize
                       (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
                     Transport.Close (Chan);
                     raise Server_Error with "EOF in request";
                  end if;
                  if FSM.Needs_Data (Ctx, FSM.C_Network) then
                     FSM.Write
                       (Ctx, FSM.C_Network,
                        L.Buf.all (L.Buf'First .. Frame_Last));
                  end if;
               end;
            end if;
         end loop Drive_Until_Headers;

         if not Got_Request_Headers then
            FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
            Transport.Close (Chan);
            raise Server_Error with "no HEADERS";
         end if;

         --  Caller sets up response headers + trailers up front.
         Setup_Response
           (Request_Headers       => Request_Headers,
            Request_Headers_Last  => Request_Headers_Last,
            Response_Headers      => Resp_Hdrs,
            Response_Headers_Last => Resp_Hdrs_Last,
            Trailers              => Trailers,
            Trailers_Last         => Trailers_Last);

         Encode_And_Send_Headers
           (L, Chan, Stream_Id,
            Resp_Hdrs (Resp_Hdrs'First .. Resp_Hdrs_Last),
            End_Stream => False);

         --  Pure-interleave bidi loop. Each iteration:
         --    1. If a client frame is queued (Has_Pending poll), read
         --       it, feed FSM. We don't try to drain socket bytes in
         --       this step — one frame per iteration keeps inbound
         --       and outbound balanced.
         --    2. Drive FSM. Drain *all* queued App_Pending frames:
         --       multiple frames may have been demuxed from a single
         --       Network write, and re-checking once isn't enough.
         --       For each DATA frame, deliver payload to
         --       On_Request_Message; track END_STREAM flag.
         --    3. Pull one reply from Next_Reply; if available, send
         --       as a DATA frame.
         --    4. If nothing happened this iteration, sleep 1 ms so
         --       we don't busy-spin while waiting on the client.
         --  Loop ends when the client has END_STREAM'd AND
         --  Next_Reply returned False (no more replies queued).
         pragma Unreferenced (No_More_Replies);
         Bidi_Loop :
         loop
            declare
               Made_Progress : Boolean := False;
               Reply_Pending : Boolean := False;
            begin
               --  (1) Inbound: only read if the channel has bytes
               --  ready, else we'd block while the app has replies
               --  to send.
               if not Got_End_Of_Request
                 and then Transport.Has_Pending (Chan)
               then
                  declare
                     Frame_Last : RFLX.RFLX_Types.Index;
                     Frame_Hdr  : Wire.Frame_Header;
                     Read_OK    : Boolean;
                  begin
                     Read_Frame
                       (Chan, L.Buf, Frame_Hdr, Frame_Last, Read_OK);
                     if not Read_OK then
                        Got_End_Of_Request := True;
                     else
                        Made_Progress := True;
                        if FSM.Needs_Data (Ctx, FSM.C_Network) then
                           FSM.Write
                             (Ctx, FSM.C_Network,
                              L.Buf.all (L.Buf'First .. Frame_Last));
                        end if;
                     end if;
                  end;
               end if;

               --  (2) Drive FSM and drain every queued App_Pending
               --  frame. The single-Read_Frame above can deliver a
               --  buffered burst that produces N App_Pending events
               --  in a row.
               FSM.Run (Ctx);
               Drain_App :
               loop
                  exit Drain_App when
                    not FSM.Has_Data (Ctx, FSM.C_App_Pending);
                  declare
                     N : constant RFLX.RFLX_Types.Length :=
                       FSM.Read_Buffer_Size (Ctx, FSM.C_App_Pending);
                     View : RFLX.RFLX_Types.Bytes
                       (L.Buf'First ..
                          L.Buf'First +
                            RFLX.RFLX_Types.Index (N) - 1);
                     Hdr : Wire.Frame_Header;
                     Hdr_Valid : Boolean;
                  begin
                     FSM.Read (Ctx, FSM.C_App_Pending, View);
                     Wire.Decode_Frame_Header
                       (Buffer => View (View'First .. View'First + 8),
                        Header => Hdr,
                        Valid  => Hdr_Valid);
                     if Hdr_Valid
                       and then Hdr.Frame_Type_Value =
                                  RFLX.Http2_Parameters.DATA
                     then
                        if Hdr.Length > 0 then
                           declare
                              Payload : constant
                                RFLX.RFLX_Types.Bytes :=
                                  View
                                    (View'First + 9
                                     .. View'First + 8
                                        + RFLX.RFLX_Types.Index
                                            (Hdr.Length));
                              Msg : constant RFLX.RFLX_Types.Bytes :=
                                Strip_Grpc_Frame (Payload);
                           begin
                              if Msg'Length > 0 then
                                 On_Request_Message (Msg);
                                 Made_Progress := True;
                              end if;
                           end;
                        end if;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0
                        then
                           Got_End_Of_Request := True;
                        end if;
                     end if;
                  end;
                  --  After delivering a request message, give the
                  --  application a chance to enqueue its reply for
                  --  the next outbound step. Re-Run so further
                  --  buffered network bytes can produce more
                  --  App_Pending entries.
                  FSM.Run (Ctx);
               end loop Drain_App;

               --  (3) Outbound: pull one reply per iteration. We
               --  don't drain to exhaustion here — that would let
               --  a chatty server starve inbound polling.
               declare
                  Msg_Buf  : RFLX.RFLX_Types.Bytes (1 .. 16384) :=
                    (others => 0);
                  Msg_Last : RFLX.RFLX_Types.Index;
                  Has_Msg  : Boolean;
               begin
                  Has_Msg := Next_Reply (Msg_Buf, Msg_Last);
                  if Has_Msg then
                     Send_Data_Frame
                       (L, Chan, Stream_Id,
                        Msg_Buf (Msg_Buf'First .. Msg_Last),
                        End_Stream => False);
                     Made_Progress := True;
                     Reply_Pending := True;
                  end if;
               end;

               exit Bidi_Loop when
                 Got_End_Of_Request and not Reply_Pending;

               if not Made_Progress then
                  delay 0.001;
               end if;
            end;
         end loop Bidi_Loop;

         Encode_And_Send_Headers
           (L, Chan, Stream_Id,
            Trailers (Trailers'First .. Trailers_Last),
            End_Stream => True);

         FSM.Finalize (Ctx, L.Inbound_Buf, L.Outgoing_Buf);
      end;

      Drain_And_Goodbye (L, Chan, Stream_Id);
      Flow_Gate.Finalize (L.Gate);
   end Accept_And_Serve_Bidi_Stream;

end Http2_Core.Server;
