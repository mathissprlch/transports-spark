with Ada.Unchecked_Deallocation;

with RFLX.RFLX_Builtin_Types;
with RFLX.RFLX_Types;
use type RFLX.RFLX_Types.Index;
use type RFLX.RFLX_Types.Length;
use type RFLX.RFLX_Types.Byte;
use type RFLX.RFLX_Types.Bytes_Ptr;
use type RFLX.RFLX_Builtin_Types.Bit_Length;

with RFLX.Http2_Parameters;
use type RFLX.Http2_Parameters.HTTP_2_Frame_Type_Enum;
with RFLX.Stream.Open.FSM;
use type RFLX.Stream.Open.FSM.State;

with Http2_Core.Wire;

package body Http2_Core.Mux_Server is

   subtype U8 is RFLX.RFLX_Types.Byte;

   Buffer_Size : constant := 16384;

   procedure Free is new Ada.Unchecked_Deallocation
     (RFLX.RFLX_Types.Bytes, RFLX.RFLX_Types.Bytes_Ptr);

   ---------------------------------------------------------------------
   --  Read_Frame — same shape as Http2_Core.Server's helper. Drains
   --  one HTTP/2 frame from the socket into Buf and surfaces its
   --  decoded header. Buf must be large enough for the frame.
   ---------------------------------------------------------------------

   procedure Read_Frame
     (Chan    : Transport.Channel;
      Buf     : RFLX.RFLX_Types.Bytes_Ptr;
      Header  : out Wire.Frame_Header;
      Last    : out RFLX.RFLX_Types.Index;
      Success : out Boolean);

   procedure Read_Frame
     (Chan    : Transport.Channel;
      Buf     : RFLX.RFLX_Types.Bytes_Ptr;
      Header  : out Wire.Frame_Header;
      Last    : out RFLX.RFLX_Types.Index;
      Success : out Boolean)
   is
      Hdr_Bytes : RFLX.RFLX_Types.Bytes
        (Buf'First .. Buf'First + 8);
      Hdr_OK : Boolean;
   begin
      Header  := (others => <>);
      Last    := Buf'First;
      Success := False;

      Transport.Receive_Full (Chan, Hdr_Bytes, Hdr_OK);
      if not Hdr_OK then
         return;
      end if;
      Buf.all (Hdr_Bytes'Range) := Hdr_Bytes;

      declare
         Hdr_Valid : Boolean;
      begin
         Wire.Decode_Frame_Header
           (Buffer => Hdr_Bytes, Header => Header, Valid => Hdr_Valid);
         if not Hdr_Valid then
            return;
         end if;
      end;

      if Header.Length = 0 then
         Last    := Hdr_Bytes'Last;
         Success := True;
         return;
      end if;

      declare
         Body_First : constant RFLX.RFLX_Types.Index :=
           Hdr_Bytes'Last + 1;
         Body_Last  : constant RFLX.RFLX_Types.Index :=
           Body_First + RFLX.RFLX_Types.Index (Header.Length) - 1;
         Body_Slice : RFLX.RFLX_Types.Bytes (Body_First .. Body_Last);
         Body_OK    : Boolean;
      begin
         Transport.Receive_Full (Chan, Body_Slice, Body_OK);
         if not Body_OK then
            return;
         end if;
         Buf.all (Body_Slice'Range) := Body_Slice;
         Last    := Body_Slice'Last;
         Success := True;
      end;
   end Read_Frame;

   ---------------------------------------------------------------------
   --  Listen / Attach / Detach / Stop.
   ---------------------------------------------------------------------

   procedure Listen
     (L    : in out Listener;
      Host : String;
      Port : Natural)
   is
   begin
      Transport.Listen (L.Trans, Host, Port);
      for I in L.Pool'Range loop
         L.Pool (I) :=
           (Phase        => Free,
            Stream_Id    => 0,
            Inbound_Buf  =>
              new RFLX.RFLX_Types.Bytes'
                (1 .. Buffer_Size => 0),
            Outgoing_Buf =>
              new RFLX.RFLX_Types.Bytes'
                (1 .. Buffer_Size => 0));
      end loop;
   end Listen;

   procedure Attach_Buffer
     (L   : in out Listener;
      Buf : in out RFLX.RFLX_Types.Bytes_Ptr)
   is
   begin
      L.Buf := Buf;
      Buf := null;
   end Attach_Buffer;

   procedure Detach_Buffer
     (L   : in out Listener;
      Buf : out RFLX.RFLX_Types.Bytes_Ptr)
   is
   begin
      Buf := L.Buf;
      L.Buf := null;
   end Detach_Buffer;

   procedure Stop (L : in out Listener) is
   begin
      if Transport.Is_Listening (L.Trans) then
         Transport.Stop (L.Trans);
      end if;
      for I in L.Pool'Range loop
         if L.Pool (I).Inbound_Buf /= null then
            Free (L.Pool (I).Inbound_Buf);
         end if;
         if L.Pool (I).Outgoing_Buf /= null then
            Free (L.Pool (I).Outgoing_Buf);
         end if;
      end loop;
   end Stop;

   ---------------------------------------------------------------------
   --  Accept_And_Serve_Multi
   ---------------------------------------------------------------------

   procedure Accept_And_Serve_Multi (L : in out Listener) is
      package FSM renames RFLX.Stream.Open.FSM;

      Chan : Transport.Channel;

      --  Per-stream FSM contexts live alongside their slot but the
      --  Context type isn't trivially default-initializable inside
      --  a record (it's limited and tied to its Initialize call), so
      --  we keep them in a parallel array here.
      type Ctx_Pool is array (1 .. Max_Streams) of FSM.Context;
      Ctxs : Ctx_Pool;

      --  Per-stream request accumulators. Allocated as locals (not
      --  on the heap) — Max_Streams * (16384 + headers) is ~512KB
      --  for the demo's 16 streams; if we ever bump Max_Streams we
      --  should probably move these to the Listener record.
      type Hdr_Pool is array (1 .. Max_Streams) of
        Hpack.Header_Block (1 .. 16);
      type Hdr_Last_Pool is array (1 .. Max_Streams) of Natural;
      type Body_Pool is array (1 .. Max_Streams) of
        RFLX.RFLX_Types.Bytes (1 .. 16384);
      type Cursor_Pool is array (1 .. Max_Streams) of Integer;


      Headers : Hdr_Pool := (others => (others => (Name_Last => 0,
                                                  Value_Last => 0,
                                                  Name => (others => ' '),
                                                  Value => (others => ' '))));
      Headers_Last : Hdr_Last_Pool := (others => 0);
      Bodies : Body_Pool;
      Body_Cursor : Cursor_Pool := (others => 0);

      Goaway_Pending : Boolean := False;
      Last_Stream_Id : Bit_Len := 0;

      ---------------------------------------------------------------
      --  Connection-prologue: 24-byte preface + initial SETTINGS.
      ---------------------------------------------------------------

      procedure Receive_Preface;
      procedure Receive_Preface is
         Pref_Bytes : RFLX.RFLX_Types.Bytes
           (RFLX.RFLX_Types.Index'First ..
              RFLX.RFLX_Types.Index'First +
              RFLX.RFLX_Types.Index (Wire.Preface'Length) - 1);
         Pref_OK : Boolean;
      begin
         Transport.Receive_Full (Chan, Pref_Bytes, Pref_OK);
         if not Pref_OK then
            raise Mux_Server_Error with "EOF before preface";
         end if;
         for I in Pref_Bytes'Range loop
            if Pref_Bytes (I) /=
              U8 (Character'Pos
                    (Wire.Preface
                       (Wire.Preface'First +
                          Integer (I - Pref_Bytes'First))))
            then
               raise Mux_Server_Error with "bad preface";
            end if;
         end loop;
      end Receive_Preface;

      procedure Send_Initial_Settings;
      procedure Send_Initial_Settings is
         Last : RFLX.RFLX_Types.Index;
         Params : constant Wire.Settings_List (1 .. 3) :=
           ((Identifier => RFLX.Http2_Parameters.HEADER_TABLE_SIZE,
             Value      => 0),
            (Identifier => RFLX.Http2_Parameters.ENABLE_PUSH,
             Value      => 0),
            (Identifier => RFLX.Http2_Parameters.MAX_CONCURRENT_STREAMS,
             Value      => Max_Streams));
      begin
         Wire.Encode_Settings (L.Buf, Last, Params);
         Transport.Send (Chan, L.Buf.all (L.Buf'First .. Last));
      end Send_Initial_Settings;

      ---------------------------------------------------------------
      --  Stream-pool helpers.
      ---------------------------------------------------------------

      function Find_Slot (Stream_Id : Bit_Len) return Natural;
      function Find_Slot (Stream_Id : Bit_Len) return Natural is
      begin
         for I in L.Pool'Range loop
            if L.Pool (I).Phase /= Free
              and then L.Pool (I).Stream_Id = Stream_Id
            then
               return I;
            end if;
         end loop;
         return 0;
      end Find_Slot;

      function Allocate_Slot (Stream_Id : Bit_Len) return Natural;
      function Allocate_Slot (Stream_Id : Bit_Len) return Natural is
      begin
         for I in L.Pool'Range loop
            if L.Pool (I).Phase = Free then
               L.Pool (I).Phase := Awaiting_Body;
               L.Pool (I).Stream_Id := Stream_Id;
               Headers_Last (I) := Headers (I)'First - 1;
               Body_Cursor (I) := Integer (Bodies (I)'First) - 1;
               FSM.Initialize
                 (Ctxs (I),
                  L.Pool (I).Inbound_Buf,
                  L.Pool (I).Outgoing_Buf);
               return I;
            end if;
         end loop;
         return 0;
      end Allocate_Slot;

      procedure Release_Slot (I : Positive);
      procedure Release_Slot (I : Positive) is
      begin
         if FSM.Initialized (Ctxs (I)) then
            FSM.Finalize
              (Ctxs (I),
               L.Pool (I).Inbound_Buf,
               L.Pool (I).Outgoing_Buf);
         end if;
         L.Pool (I).Phase := Free;
         L.Pool (I).Stream_Id := 0;
      end Release_Slot;

      ---------------------------------------------------------------
      --  Frame senders (operate on the connection-scope Buf).
      ---------------------------------------------------------------

      procedure Send_Headers_Frame
        (Stream_Id  : Bit_Len;
         Headers_In : Hpack.Header_Block;
         End_Stream : Boolean);
      procedure Send_Headers_Frame
        (Stream_Id  : Bit_Len;
         Headers_In : Hpack.Header_Block;
         End_Stream : Boolean)
      is
         Frag_Out  : Hpack.Octet_Array
           (1 .. Hpack.Max_Header_Length * Hpack.Max_Headers);
         Frag_Last : Natural;
         Frag_OK   : Boolean;
         Frame_Last : RFLX.RFLX_Types.Index;
      begin
         Hpack.Encode
           (Headers     => Headers_In,
            Output      => Frag_Out,
            Output_Last => Frag_Last,
            Output_OK   => Frag_OK);
         if not Frag_OK then
            raise Mux_Server_Error with "HPACK encode failed";
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
      end Send_Headers_Frame;

      procedure Send_Data_Frame
        (Stream_Id  : Bit_Len;
         Payload    : RFLX.RFLX_Types.Bytes;
         End_Stream : Boolean);
      procedure Send_Data_Frame
        (Stream_Id  : Bit_Len;
         Payload    : RFLX.RFLX_Types.Bytes;
         End_Stream : Boolean)
      is
         Last : RFLX.RFLX_Types.Index;
      begin
         Wire.Encode_Data
           (Buffer => L.Buf, Last => Last,
            Stream_Id => Stream_Id, Payload => Payload,
            End_Stream => End_Stream);
         Transport.Send (Chan, L.Buf.all (L.Buf'First .. Last));
      end Send_Data_Frame;

      ---------------------------------------------------------------
      --  Strip gRPC 5-byte length prefix.
      ---------------------------------------------------------------

      ---------------------------------------------------------------
      --  Per-stream: drain App_Pending after FSM.Run. Decodes
      --  HEADERS into Headers(I); appends DATA payloads into Body
      --  (I); flips Phase to Body_Complete on END_STREAM.
      ---------------------------------------------------------------

      procedure Drain_Stream_App (I : Positive);
      procedure Drain_Stream_App (I : Positive) is
      begin
         loop
            FSM.Run (Ctxs (I));
            exit when not FSM.Has_Data (Ctxs (I), FSM.C_App_Pending);
            declare
               N : constant RFLX.RFLX_Types.Length :=
                 FSM.Read_Buffer_Size (Ctxs (I), FSM.C_App_Pending);
               View : RFLX.RFLX_Types.Bytes
                 (L.Buf'First ..
                    L.Buf'First + RFLX.RFLX_Types.Index (N) - 1);
               Hdr : Wire.Frame_Header;
               Hdr_Valid : Boolean;
            begin
               FSM.Read (Ctxs (I), FSM.C_App_Pending, View);
               Wire.Decode_Frame_Header
                 (Buffer => View (View'First .. View'First + 8),
                  Header => Hdr, Valid => Hdr_Valid);
               if Hdr_Valid then
                  case Hdr.Frame_Type_Value is
                     when RFLX.Http2_Parameters.HEADERS =>
                        declare
                           Frag_First : RFLX.RFLX_Types.Index :=
                             View'First + 9;
                           Frag_Last  : constant RFLX.RFLX_Types.Index :=
                             View'Last;
                           Decode_OK : Boolean;
                        begin
                           if (Hdr.Flags and Wire.Flag_PRIORITY) /= 0
                           then
                              Frag_First := Frag_First + 5;
                           end if;
                           declare
                              Frag : Hpack.Octet_Array
                                (1 ..
                                   Natural (Frag_Last - Frag_First) + 1);
                           begin
                              for K in Frag'Range loop
                                 Frag (K) :=
                                   Hpack.Octet
                                     (View
                                        (Frag_First
                                         + RFLX.RFLX_Types.Index (K)
                                         - 1));
                              end loop;
                              Hpack.Decode
                                (Input        => Frag,
                                 Headers      => Headers (I),
                                 Headers_Last => Headers_Last (I),
                                 Output_OK    => Decode_OK);
                              if not Decode_OK then
                                 raise Mux_Server_Error
                                   with "HPACK decode failed";
                              end if;
                           end;
                        end;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0
                        then
                           L.Pool (I).Phase := Body_Complete;
                        end if;

                     when RFLX.Http2_Parameters.DATA =>
                        if Hdr.Length > 0 then
                           declare
                              First : constant RFLX.RFLX_Types.Index :=
                                View'First + 9;
                              Lst   : constant RFLX.RFLX_Types.Index :=
                                First +
                                RFLX.RFLX_Types.Index (Hdr.Length) - 1;
                              Pay   : constant RFLX.RFLX_Types.Bytes :=
                                View (First .. Lst);
                           begin
                              if Body_Cursor (I)
                                + Pay'Length
                                <= Integer (Bodies (I)'Last)
                              then
                                 Bodies (I)
                                   (RFLX.RFLX_Types.Index
                                      (Body_Cursor (I) + 1)
                                    .. RFLX.RFLX_Types.Index
                                         (Body_Cursor (I) + Pay'Length)
                                   ) := Pay;
                                 Body_Cursor (I) :=
                                   Body_Cursor (I) + Pay'Length;
                              end if;
                           end;
                        end if;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0
                        then
                           L.Pool (I).Phase := Body_Complete;
                        end if;

                     when others =>
                        --  Connection-mgmt frames bubble up on the
                        --  per-stream FSM's App_Pending too (because
                        --  Stream::Open's transition table forwards
                        --  them). They've already been handled at the
                        --  connection layer via the stream-id == 0
                        --  fast path; ignore here.
                        null;
                  end case;
               end if;
            end;
         end loop;
      end Drain_Stream_App;

      ---------------------------------------------------------------
      --  Run the handler for a Body_Complete stream and emit its
      --  three response frames.
      ---------------------------------------------------------------

      procedure Dispatch_Stream (I : Positive);
      procedure Dispatch_Stream (I : Positive) is
         Resp_Hdrs : Hpack.Header_Block (1 .. 16);
         Resp_Hdrs_Last : Natural;
         Resp_Body : RFLX.RFLX_Types.Bytes (1 .. 16384) :=
           (others => 0);
         Resp_Body_Last : Natural;
         Trailers : Hpack.Header_Block (1 .. 8);
         Trailers_Last : Natural;
      begin
         Resp_Hdrs_Last := Resp_Hdrs'First - 1;
         Trailers_Last := Trailers'First - 1;
         Resp_Body_Last := Integer (Resp_Body'First) - 1;

         Handle_Request
           (Slot                  => I,
            Request_Headers       => Headers (I),
            Request_Headers_Last  => Headers_Last (I),
            Request_Body          =>
              Bodies (I)
                (Bodies (I)'First ..
                   RFLX.RFLX_Types.Index (Body_Cursor (I))),
            Request_Body_Last     => Body_Cursor (I),
            Response_Headers      => Resp_Hdrs,
            Response_Headers_Last => Resp_Hdrs_Last,
            Response_Body         => Resp_Body,
            Response_Body_Last    => Resp_Body_Last,
            Trailers              => Trailers,
            Trailers_Last         => Trailers_Last);

         Send_Headers_Frame
           (L.Pool (I).Stream_Id,
            Resp_Hdrs (Resp_Hdrs'First .. Resp_Hdrs_Last),
            End_Stream => False);
         if Resp_Body_Last >= Integer (Resp_Body'First) then
            Send_Data_Frame
              (L.Pool (I).Stream_Id,
               Resp_Body
                 (Resp_Body'First ..
                    RFLX.RFLX_Types.Index (Resp_Body_Last)),
               End_Stream => False);
         end if;
         Send_Headers_Frame
           (L.Pool (I).Stream_Id,
            Trailers (Trailers'First .. Trailers_Last),
            End_Stream => True);

         L.Pool (I).Phase := Closed;
         Last_Stream_Id := L.Pool (I).Stream_Id;
      end Dispatch_Stream;

      ---------------------------------------------------------------
      --  Handle one inbound frame at the connection layer. Either
      --  an inline ack (PING / SETTINGS), a routed per-stream feed,
      --  or — on stream-id 0 — a connection event (GOAWAY).
      ---------------------------------------------------------------

      procedure Handle_Frame
        (Hdr  : Wire.Frame_Header;
         Last : RFLX.RFLX_Types.Index);
      procedure Handle_Frame
        (Hdr  : Wire.Frame_Header;
         Last : RFLX.RFLX_Types.Index)
      is
      begin
         if Hdr.Stream_Identifier = 0 then
            case Hdr.Frame_Type_Value is
               when RFLX.Http2_Parameters.PING =>
                  if (Hdr.Flags and Wire.Flag_ACK) = 0
                    and Hdr.Length = 8
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
                  end if;
               when RFLX.Http2_Parameters.SETTINGS =>
                  if (Hdr.Flags and Wire.Flag_ACK) = 0 then
                     declare
                        Ack_Last : RFLX.RFLX_Types.Index;
                     begin
                        Wire.Encode_Settings_Ack (L.Buf, Ack_Last);
                        Transport.Send
                          (Chan, L.Buf.all (L.Buf'First .. Ack_Last));
                     end;
                  end if;
               when RFLX.Http2_Parameters.GOAWAY =>
                  Goaway_Pending := True;
               when others =>
                  null;
            end case;
            return;
         end if;

         --  Per-stream: route to slot.
         declare
            Slot : Natural := Find_Slot (Hdr.Stream_Identifier);
         begin
            if Slot = 0 then
               --  New stream.
               if Hdr.Frame_Type_Value =
                 RFLX.Http2_Parameters.HEADERS
               then
                  Slot := Allocate_Slot (Hdr.Stream_Identifier);
                  if Slot = 0 then
                     --  Pool exhausted — RST_STREAM with
                     --  REFUSED_STREAM (RFC 9113 §5.1.2).
                     declare
                        RST_Last : RFLX.RFLX_Types.Index;
                     begin
                        Wire.Encode_Rst_Stream
                          (Buffer => L.Buf, Last => RST_Last,
                           Stream_Id => Hdr.Stream_Identifier,
                           Error_Code => 7);  --  REFUSED_STREAM
                        Transport.Send
                          (Chan,
                           L.Buf.all (L.Buf'First .. RST_Last));
                     end;
                     return;
                  end if;
               else
                  --  Frame for a stream we don't track — likely
                  --  closed already; ignore.
                  return;
               end if;
            end if;

            if FSM.Needs_Data (Ctxs (Slot), FSM.C_Network) then
               FSM.Write
                 (Ctxs (Slot),
                  FSM.C_Network,
                  L.Buf.all (L.Buf'First .. Last));
            end if;
            Drain_Stream_App (Slot);
         end;
      end Handle_Frame;

      ---------------------------------------------------------------
      --  Send GOAWAY, drain remaining frames, close socket.
      ---------------------------------------------------------------

      procedure Goodbye;
      procedure Goodbye is
         Goaway_Last : RFLX.RFLX_Types.Index;
         Empty : constant RFLX.RFLX_Types.Bytes (1 .. 0) :=
           (others => 0);
      begin
         Wire.Encode_Goaway
           (Buffer => L.Buf, Last => Goaway_Last,
            Last_Stream_Id => Last_Stream_Id,
            Error_Code => 0,
            Debug_Data => Empty);
         Transport.Send (Chan, L.Buf.all (L.Buf'First .. Goaway_Last));
      exception
         when others => null;
      end Goodbye;

   begin
      if L.Buf = null then
         raise Mux_Server_Error
           with "Http2_Core.Mux_Server.Attach_Buffer must be called first";
      end if;

      Transport.Accept_One (L.Trans, Chan);
      Receive_Preface;
      Send_Initial_Settings;

      Connection_Loop :
      loop
         exit Connection_Loop when Goaway_Pending;

         declare
            Made_Progress : Boolean := False;
         begin
            --  Inbound: read up to one frame per iteration.
            if Transport.Has_Pending (Chan) then
               declare
                  Frame_Hdr : Wire.Frame_Header;
                  Frame_Last : RFLX.RFLX_Types.Index;
                  OK : Boolean;
               begin
                  Read_Frame
                    (Chan, L.Buf, Frame_Hdr, Frame_Last, OK);
                  exit Connection_Loop when not OK;
                  Handle_Frame (Frame_Hdr, Frame_Last);
                  Made_Progress := True;
               end;
            end if;

            --  Outbound: dispatch any Body_Complete streams.
            for I in L.Pool'Range loop
               if L.Pool (I).Phase = Body_Complete then
                  Dispatch_Stream (I);
                  Release_Slot (I);
                  Made_Progress := True;
               elsif L.Pool (I).Phase = Closed then
                  Release_Slot (I);
                  Made_Progress := True;
               end if;
            end loop;

            if not Made_Progress then
               delay 0.001;
            end if;
         end;
      end loop Connection_Loop;

      --  Drain post-shutdown PING ack just like the single-stream
      --  server does, for Python grpcio's cleanup expectations.
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

      Goodbye;

      --  Release any straggling slots.
      for I in L.Pool'Range loop
         if L.Pool (I).Phase /= Free then
            Release_Slot (I);
         end if;
      end loop;

      Transport.Close (Chan);
   end Accept_And_Serve_Multi;

   procedure Accept_And_Serve_Multi_Server_Stream
     (L : in out Listener)
   is
      package FSM renames RFLX.Stream.Open.FSM;

      Chan : Transport.Channel;

      type Ctx_Pool is array (1 .. Max_Streams) of FSM.Context;
      Ctxs : Ctx_Pool;

      type Hdr_Pool is array (1 .. Max_Streams) of
        Hpack.Header_Block (1 .. 16);
      type Hdr_Last_Pool is array (1 .. Max_Streams) of Natural;
      type Body_Pool is array (1 .. Max_Streams) of
        RFLX.RFLX_Types.Bytes (1 .. 16384);
      type Cursor_Pool is array (1 .. Max_Streams) of Integer;
      type Trailers_Pool is array (1 .. Max_Streams) of
        Hpack.Header_Block (1 .. 8);

      Headers : Hdr_Pool := (others => (others => (Name_Last => 0,
                                                  Value_Last => 0,
                                                  Name => (others => ' '),
                                                  Value => (others => ' '))));
      Headers_Last : Hdr_Last_Pool := (others => 0);
      Bodies : Body_Pool;
      Body_Cursor : Cursor_Pool := (others => 0);

      --  Stream-specific: per-slot trailers cached at Setup time so
      --  we can emit them once Next_Reply returns False.
      Slot_Trailers      : Trailers_Pool :=
        (others => (others => (Name_Last => 0,
                               Value_Last => 0,
                               Name => (others => ' '),
                               Value => (others => ' '))));
      Slot_Trailers_Last : Hdr_Last_Pool := (others => 0);

      Goaway_Pending : Boolean := False;
      Last_Stream_Id : Bit_Len := 0;

      procedure Receive_Preface;
      procedure Receive_Preface is
         Pref_Bytes : RFLX.RFLX_Types.Bytes
           (RFLX.RFLX_Types.Index'First ..
              RFLX.RFLX_Types.Index'First +
              RFLX.RFLX_Types.Index (Wire.Preface'Length) - 1);
         Pref_OK : Boolean;
      begin
         Transport.Receive_Full (Chan, Pref_Bytes, Pref_OK);
         if not Pref_OK then
            raise Mux_Server_Error with "EOF before preface";
         end if;
         for I in Pref_Bytes'Range loop
            if Pref_Bytes (I) /=
              U8 (Character'Pos
                    (Wire.Preface
                       (Wire.Preface'First +
                          Integer (I - Pref_Bytes'First))))
            then
               raise Mux_Server_Error with "bad preface";
            end if;
         end loop;
      end Receive_Preface;

      procedure Send_Initial_Settings;
      procedure Send_Initial_Settings is
         Last : RFLX.RFLX_Types.Index;
         Params : constant Wire.Settings_List (1 .. 3) :=
           ((Identifier => RFLX.Http2_Parameters.HEADER_TABLE_SIZE,
             Value      => 0),
            (Identifier => RFLX.Http2_Parameters.ENABLE_PUSH,
             Value      => 0),
            (Identifier => RFLX.Http2_Parameters.MAX_CONCURRENT_STREAMS,
             Value      => Max_Streams));
      begin
         Wire.Encode_Settings (L.Buf, Last, Params);
         Transport.Send (Chan, L.Buf.all (L.Buf'First .. Last));
      end Send_Initial_Settings;

      function Find_Slot (Stream_Id : Bit_Len) return Natural;
      function Find_Slot (Stream_Id : Bit_Len) return Natural is
      begin
         for I in L.Pool'Range loop
            if L.Pool (I).Phase /= Free
              and then L.Pool (I).Stream_Id = Stream_Id
            then
               return I;
            end if;
         end loop;
         return 0;
      end Find_Slot;

      function Allocate_Slot (Stream_Id : Bit_Len) return Natural;
      function Allocate_Slot (Stream_Id : Bit_Len) return Natural is
      begin
         for I in L.Pool'Range loop
            if L.Pool (I).Phase = Free then
               L.Pool (I).Phase := Awaiting_Body;
               L.Pool (I).Stream_Id := Stream_Id;
               Headers_Last (I) := Headers (I)'First - 1;
               Body_Cursor (I) := Integer (Bodies (I)'First) - 1;
               Slot_Trailers_Last (I) := Slot_Trailers (I)'First - 1;
               FSM.Initialize
                 (Ctxs (I),
                  L.Pool (I).Inbound_Buf,
                  L.Pool (I).Outgoing_Buf);
               return I;
            end if;
         end loop;
         return 0;
      end Allocate_Slot;

      procedure Release_Slot (I : Positive);
      procedure Release_Slot (I : Positive) is
      begin
         if FSM.Initialized (Ctxs (I)) then
            FSM.Finalize
              (Ctxs (I),
               L.Pool (I).Inbound_Buf,
               L.Pool (I).Outgoing_Buf);
         end if;
         L.Pool (I).Phase := Free;
         L.Pool (I).Stream_Id := 0;
      end Release_Slot;

      procedure Send_Headers_Frame
        (Stream_Id  : Bit_Len;
         Headers_In : Hpack.Header_Block;
         End_Stream : Boolean);
      procedure Send_Headers_Frame
        (Stream_Id  : Bit_Len;
         Headers_In : Hpack.Header_Block;
         End_Stream : Boolean)
      is
         Frag_Out  : Hpack.Octet_Array
           (1 .. Hpack.Max_Header_Length * Hpack.Max_Headers);
         Frag_Last : Natural;
         Frag_OK   : Boolean;
         Frame_Last : RFLX.RFLX_Types.Index;
      begin
         Hpack.Encode
           (Headers     => Headers_In,
            Output      => Frag_Out,
            Output_Last => Frag_Last,
            Output_OK   => Frag_OK);
         if not Frag_OK then
            raise Mux_Server_Error with "HPACK encode failed";
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
      end Send_Headers_Frame;

      procedure Send_Data_Frame
        (Stream_Id  : Bit_Len;
         Payload    : RFLX.RFLX_Types.Bytes;
         End_Stream : Boolean);
      procedure Send_Data_Frame
        (Stream_Id  : Bit_Len;
         Payload    : RFLX.RFLX_Types.Bytes;
         End_Stream : Boolean)
      is
         Last : RFLX.RFLX_Types.Index;
      begin
         Wire.Encode_Data
           (Buffer => L.Buf, Last => Last,
            Stream_Id => Stream_Id, Payload => Payload,
            End_Stream => End_Stream);
         Transport.Send (Chan, L.Buf.all (L.Buf'First .. Last));
      end Send_Data_Frame;

      procedure Drain_Stream_App (I : Positive);
      procedure Drain_Stream_App (I : Positive) is
      begin
         loop
            FSM.Run (Ctxs (I));
            exit when not FSM.Has_Data (Ctxs (I), FSM.C_App_Pending);
            declare
               N : constant RFLX.RFLX_Types.Length :=
                 FSM.Read_Buffer_Size (Ctxs (I), FSM.C_App_Pending);
               View : RFLX.RFLX_Types.Bytes
                 (L.Buf'First ..
                    L.Buf'First + RFLX.RFLX_Types.Index (N) - 1);
               Hdr : Wire.Frame_Header;
               Hdr_Valid : Boolean;
            begin
               FSM.Read (Ctxs (I), FSM.C_App_Pending, View);
               Wire.Decode_Frame_Header
                 (Buffer => View (View'First .. View'First + 8),
                  Header => Hdr, Valid => Hdr_Valid);
               if Hdr_Valid then
                  case Hdr.Frame_Type_Value is
                     when RFLX.Http2_Parameters.HEADERS =>
                        declare
                           Frag_First : RFLX.RFLX_Types.Index :=
                             View'First + 9;
                           Frag_Last  : constant RFLX.RFLX_Types.Index :=
                             View'Last;
                           Decode_OK : Boolean;
                        begin
                           if (Hdr.Flags and Wire.Flag_PRIORITY) /= 0
                           then
                              Frag_First := Frag_First + 5;
                           end if;
                           declare
                              Frag : Hpack.Octet_Array
                                (1 ..
                                   Natural (Frag_Last - Frag_First) + 1);
                           begin
                              for K in Frag'Range loop
                                 Frag (K) :=
                                   Hpack.Octet
                                     (View
                                        (Frag_First
                                         + RFLX.RFLX_Types.Index (K)
                                         - 1));
                              end loop;
                              Hpack.Decode
                                (Input        => Frag,
                                 Headers      => Headers (I),
                                 Headers_Last => Headers_Last (I),
                                 Output_OK    => Decode_OK);
                              if not Decode_OK then
                                 raise Mux_Server_Error
                                   with "HPACK decode failed";
                              end if;
                           end;
                        end;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0
                        then
                           L.Pool (I).Phase := Body_Complete;
                        end if;

                     when RFLX.Http2_Parameters.DATA =>
                        if Hdr.Length > 0 then
                           declare
                              First : constant RFLX.RFLX_Types.Index :=
                                View'First + 9;
                              Lst   : constant RFLX.RFLX_Types.Index :=
                                First +
                                RFLX.RFLX_Types.Index (Hdr.Length) - 1;
                              Pay   : constant RFLX.RFLX_Types.Bytes :=
                                View (First .. Lst);
                           begin
                              if Body_Cursor (I)
                                + Pay'Length
                                <= Integer (Bodies (I)'Last)
                              then
                                 Bodies (I)
                                   (RFLX.RFLX_Types.Index
                                      (Body_Cursor (I) + 1)
                                    .. RFLX.RFLX_Types.Index
                                         (Body_Cursor (I) + Pay'Length)
                                   ) := Pay;
                                 Body_Cursor (I) :=
                                   Body_Cursor (I) + Pay'Length;
                              end if;
                           end;
                        end if;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0
                        then
                           L.Pool (I).Phase := Body_Complete;
                        end if;

                     when others => null;
                  end case;
               end if;
            end;
         end loop;
      end Drain_Stream_App;

      --  Variant-specific: Body_Complete → Setup_Response + send
      --  response HEADERS → flip to Streaming.
      procedure Begin_Stream (I : Positive);
      procedure Begin_Stream (I : Positive) is
         Resp_Hdrs : Hpack.Header_Block (1 .. 16);
         Resp_Hdrs_Last : Natural;
      begin
         Resp_Hdrs_Last := Resp_Hdrs'First - 1;
         Slot_Trailers_Last (I) := Slot_Trailers (I)'First - 1;
         Setup_Response
           (Slot                  => I,
            Request_Headers       => Headers (I),
            Request_Headers_Last  => Headers_Last (I),
            Request_Body          =>
              Bodies (I)
                (Bodies (I)'First ..
                   RFLX.RFLX_Types.Index (Body_Cursor (I))),
            Request_Body_Last     => Body_Cursor (I),
            Response_Headers      => Resp_Hdrs,
            Response_Headers_Last => Resp_Hdrs_Last,
            Trailers              => Slot_Trailers (I),
            Trailers_Last         => Slot_Trailers_Last (I));
         Send_Headers_Frame
           (L.Pool (I).Stream_Id,
            Resp_Hdrs (Resp_Hdrs'First .. Resp_Hdrs_Last),
            End_Stream => False);
         L.Pool (I).Phase := Streaming;
      end Begin_Stream;

      --  Variant-specific: Streaming → pull one Next_Reply per
      --  iteration. Returns True if it produced a reply. False
      --  means Next_Reply returned False; emit trailers + close.
      function Tick_Stream (I : Positive) return Boolean;
      function Tick_Stream (I : Positive) return Boolean is
         Msg_Buf  : RFLX.RFLX_Types.Bytes (1 .. 16384) :=
           (others => 0);
         Msg_Last : RFLX.RFLX_Types.Index;
         Has_Msg  : Boolean;
      begin
         Has_Msg := Next_Reply (I, Msg_Buf, Msg_Last);
         if Has_Msg then
            Send_Data_Frame
              (L.Pool (I).Stream_Id,
               Msg_Buf (Msg_Buf'First .. Msg_Last),
               End_Stream => False);
            return True;
         else
            Send_Headers_Frame
              (L.Pool (I).Stream_Id,
               Slot_Trailers (I)
                 (Slot_Trailers (I)'First .. Slot_Trailers_Last (I)),
               End_Stream => True);
            L.Pool (I).Phase := Closed;
            Last_Stream_Id := L.Pool (I).Stream_Id;
            return False;
         end if;
      end Tick_Stream;

      procedure Handle_Frame
        (Hdr  : Wire.Frame_Header;
         Last : RFLX.RFLX_Types.Index);
      procedure Handle_Frame
        (Hdr  : Wire.Frame_Header;
         Last : RFLX.RFLX_Types.Index)
      is
      begin
         if Hdr.Stream_Identifier = 0 then
            case Hdr.Frame_Type_Value is
               when RFLX.Http2_Parameters.PING =>
                  if (Hdr.Flags and Wire.Flag_ACK) = 0
                    and Hdr.Length = 8
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
                  end if;
               when RFLX.Http2_Parameters.SETTINGS =>
                  if (Hdr.Flags and Wire.Flag_ACK) = 0 then
                     declare
                        Ack_Last : RFLX.RFLX_Types.Index;
                     begin
                        Wire.Encode_Settings_Ack (L.Buf, Ack_Last);
                        Transport.Send
                          (Chan, L.Buf.all (L.Buf'First .. Ack_Last));
                     end;
                  end if;
               when RFLX.Http2_Parameters.GOAWAY =>
                  Goaway_Pending := True;
               when others => null;
            end case;
            return;
         end if;

         declare
            Slot : Natural := Find_Slot (Hdr.Stream_Identifier);
         begin
            if Slot = 0 then
               if Hdr.Frame_Type_Value =
                 RFLX.Http2_Parameters.HEADERS
               then
                  Slot := Allocate_Slot (Hdr.Stream_Identifier);
                  if Slot = 0 then
                     declare
                        RST_Last : RFLX.RFLX_Types.Index;
                     begin
                        Wire.Encode_Rst_Stream
                          (Buffer => L.Buf, Last => RST_Last,
                           Stream_Id => Hdr.Stream_Identifier,
                           Error_Code => 7);
                        Transport.Send
                          (Chan,
                           L.Buf.all (L.Buf'First .. RST_Last));
                     end;
                     return;
                  end if;
               else
                  return;
               end if;
            end if;

            if FSM.Needs_Data (Ctxs (Slot), FSM.C_Network) then
               FSM.Write
                 (Ctxs (Slot),
                  FSM.C_Network,
                  L.Buf.all (L.Buf'First .. Last));
            end if;
            Drain_Stream_App (Slot);
         end;
      end Handle_Frame;

      procedure Goodbye;
      procedure Goodbye is
         Goaway_Last : RFLX.RFLX_Types.Index;
         Empty : constant RFLX.RFLX_Types.Bytes (1 .. 0) :=
           (others => 0);
      begin
         Wire.Encode_Goaway
           (Buffer => L.Buf, Last => Goaway_Last,
            Last_Stream_Id => Last_Stream_Id,
            Error_Code => 0,
            Debug_Data => Empty);
         Transport.Send (Chan, L.Buf.all (L.Buf'First .. Goaway_Last));
      exception
         when others => null;
      end Goodbye;

   begin
      if L.Buf = null then
         raise Mux_Server_Error
           with "Http2_Core.Mux_Server.Attach_Buffer must be called first";
      end if;

      Transport.Accept_One (L.Trans, Chan);
      Receive_Preface;
      Send_Initial_Settings;

      Connection_Loop :
      loop
         exit Connection_Loop when Goaway_Pending;

         declare
            Made_Progress : Boolean := False;
         begin
            if Transport.Has_Pending (Chan) then
               declare
                  Frame_Hdr : Wire.Frame_Header;
                  Frame_Last : RFLX.RFLX_Types.Index;
                  OK : Boolean;
               begin
                  Read_Frame
                    (Chan, L.Buf, Frame_Hdr, Frame_Last, OK);
                  exit Connection_Loop when not OK;
                  Handle_Frame (Frame_Hdr, Frame_Last);
                  Made_Progress := True;
               end;
            end if;

            for I in L.Pool'Range loop
               case L.Pool (I).Phase is
                  when Body_Complete =>
                     Begin_Stream (I);
                     Made_Progress := True;
                  when Streaming =>
                     if Tick_Stream (I) then
                        Made_Progress := True;
                     end if;
                  when Closed =>
                     Release_Slot (I);
                     Made_Progress := True;
                  when others => null;
               end case;
            end loop;

            if not Made_Progress then
               delay 0.001;
            end if;
         end;
      end loop Connection_Loop;

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

      Goodbye;

      for I in L.Pool'Range loop
         if L.Pool (I).Phase /= Free then
            Release_Slot (I);
         end if;
      end loop;

      Transport.Close (Chan);
   end Accept_And_Serve_Multi_Server_Stream;

   procedure Accept_And_Serve_Multi_Client_Stream
     (L : in out Listener)
   is
      package FSM renames RFLX.Stream.Open.FSM;

      Chan : Transport.Channel;

      type Ctx_Pool is array (1 .. Max_Streams) of FSM.Context;
      Ctxs : Ctx_Pool;

      type Hdr_Pool is array (1 .. Max_Streams) of
        Hpack.Header_Block (1 .. 16);
      type Hdr_Last_Pool is array (1 .. Max_Streams) of Natural;

      Headers : Hdr_Pool := (others => (others => (Name_Last => 0,
                                                  Value_Last => 0,
                                                  Name => (others => ' '),
                                                  Value => (others => ' '))));
      Headers_Last : Hdr_Last_Pool := (others => 0);

      Goaway_Pending : Boolean := False;
      Last_Stream_Id : Bit_Len := 0;

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
                    View'First + 5
                    + RFLX.RFLX_Types.Index (Msg_Len) - 1);
            end;
         end;
      end Strip_Grpc_Frame;

      procedure Receive_Preface;
      procedure Receive_Preface is
         Pref_Bytes : RFLX.RFLX_Types.Bytes
           (RFLX.RFLX_Types.Index'First ..
              RFLX.RFLX_Types.Index'First +
              RFLX.RFLX_Types.Index (Wire.Preface'Length) - 1);
         Pref_OK : Boolean;
      begin
         Transport.Receive_Full (Chan, Pref_Bytes, Pref_OK);
         if not Pref_OK then
            raise Mux_Server_Error with "EOF before preface";
         end if;
         for I in Pref_Bytes'Range loop
            if Pref_Bytes (I) /=
              U8 (Character'Pos
                    (Wire.Preface
                       (Wire.Preface'First +
                          Integer (I - Pref_Bytes'First))))
            then
               raise Mux_Server_Error with "bad preface";
            end if;
         end loop;
      end Receive_Preface;

      procedure Send_Initial_Settings;
      procedure Send_Initial_Settings is
         Last : RFLX.RFLX_Types.Index;
         Params : constant Wire.Settings_List (1 .. 3) :=
           ((Identifier => RFLX.Http2_Parameters.HEADER_TABLE_SIZE,
             Value      => 0),
            (Identifier => RFLX.Http2_Parameters.ENABLE_PUSH,
             Value      => 0),
            (Identifier => RFLX.Http2_Parameters.MAX_CONCURRENT_STREAMS,
             Value      => Max_Streams));
      begin
         Wire.Encode_Settings (L.Buf, Last, Params);
         Transport.Send (Chan, L.Buf.all (L.Buf'First .. Last));
      end Send_Initial_Settings;

      function Find_Slot (Stream_Id : Bit_Len) return Natural;
      function Find_Slot (Stream_Id : Bit_Len) return Natural is
      begin
         for I in L.Pool'Range loop
            if L.Pool (I).Phase /= Free
              and then L.Pool (I).Stream_Id = Stream_Id
            then
               return I;
            end if;
         end loop;
         return 0;
      end Find_Slot;

      function Allocate_Slot (Stream_Id : Bit_Len) return Natural;
      function Allocate_Slot (Stream_Id : Bit_Len) return Natural is
      begin
         for I in L.Pool'Range loop
            if L.Pool (I).Phase = Free then
               L.Pool (I).Phase := Awaiting_Body;
               L.Pool (I).Stream_Id := Stream_Id;
               Headers_Last (I) := Headers (I)'First - 1;
               FSM.Initialize
                 (Ctxs (I),
                  L.Pool (I).Inbound_Buf,
                  L.Pool (I).Outgoing_Buf);
               return I;
            end if;
         end loop;
         return 0;
      end Allocate_Slot;

      procedure Release_Slot (I : Positive);
      procedure Release_Slot (I : Positive) is
      begin
         if FSM.Initialized (Ctxs (I)) then
            FSM.Finalize
              (Ctxs (I),
               L.Pool (I).Inbound_Buf,
               L.Pool (I).Outgoing_Buf);
         end if;
         L.Pool (I).Phase := Free;
         L.Pool (I).Stream_Id := 0;
      end Release_Slot;

      procedure Send_Headers_Frame
        (Stream_Id  : Bit_Len;
         Headers_In : Hpack.Header_Block;
         End_Stream : Boolean);
      procedure Send_Headers_Frame
        (Stream_Id  : Bit_Len;
         Headers_In : Hpack.Header_Block;
         End_Stream : Boolean)
      is
         Frag_Out  : Hpack.Octet_Array
           (1 .. Hpack.Max_Header_Length * Hpack.Max_Headers);
         Frag_Last : Natural;
         Frag_OK   : Boolean;
         Frame_Last : RFLX.RFLX_Types.Index;
      begin
         Hpack.Encode
           (Headers     => Headers_In,
            Output      => Frag_Out,
            Output_Last => Frag_Last,
            Output_OK   => Frag_OK);
         if not Frag_OK then
            raise Mux_Server_Error with "HPACK encode failed";
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
      end Send_Headers_Frame;

      procedure Send_Data_Frame
        (Stream_Id  : Bit_Len;
         Payload    : RFLX.RFLX_Types.Bytes;
         End_Stream : Boolean);
      procedure Send_Data_Frame
        (Stream_Id  : Bit_Len;
         Payload    : RFLX.RFLX_Types.Bytes;
         End_Stream : Boolean)
      is
         Last : RFLX.RFLX_Types.Index;
      begin
         Wire.Encode_Data
           (Buffer => L.Buf, Last => Last,
            Stream_Id => Stream_Id, Payload => Payload,
            End_Stream => End_Stream);
         Transport.Send (Chan, L.Buf.all (L.Buf'First .. Last));
      end Send_Data_Frame;

      --  Variant-specific Drain_Stream_App: deliver each inbound
      --  DATA payload as a single gRPC message via
      --  On_Request_Message (no body accumulation).
      procedure Drain_Stream_App (I : Positive);
      procedure Drain_Stream_App (I : Positive) is
      begin
         loop
            FSM.Run (Ctxs (I));
            exit when not FSM.Has_Data (Ctxs (I), FSM.C_App_Pending);
            declare
               N : constant RFLX.RFLX_Types.Length :=
                 FSM.Read_Buffer_Size (Ctxs (I), FSM.C_App_Pending);
               View : RFLX.RFLX_Types.Bytes
                 (L.Buf'First ..
                    L.Buf'First + RFLX.RFLX_Types.Index (N) - 1);
               Hdr : Wire.Frame_Header;
               Hdr_Valid : Boolean;
            begin
               FSM.Read (Ctxs (I), FSM.C_App_Pending, View);
               Wire.Decode_Frame_Header
                 (Buffer => View (View'First .. View'First + 8),
                  Header => Hdr, Valid => Hdr_Valid);
               if Hdr_Valid then
                  case Hdr.Frame_Type_Value is
                     when RFLX.Http2_Parameters.HEADERS =>
                        declare
                           Frag_First : RFLX.RFLX_Types.Index :=
                             View'First + 9;
                           Frag_Last  : constant RFLX.RFLX_Types.Index :=
                             View'Last;
                           Decode_OK : Boolean;
                        begin
                           if (Hdr.Flags and Wire.Flag_PRIORITY) /= 0
                           then
                              Frag_First := Frag_First + 5;
                           end if;
                           declare
                              Frag : Hpack.Octet_Array
                                (1 ..
                                   Natural (Frag_Last - Frag_First) + 1);
                           begin
                              for K in Frag'Range loop
                                 Frag (K) :=
                                   Hpack.Octet
                                     (View
                                        (Frag_First
                                         + RFLX.RFLX_Types.Index (K)
                                         - 1));
                              end loop;
                              Hpack.Decode
                                (Input        => Frag,
                                 Headers      => Headers (I),
                                 Headers_Last => Headers_Last (I),
                                 Output_OK    => Decode_OK);
                              if not Decode_OK then
                                 raise Mux_Server_Error
                                   with "HPACK decode failed";
                              end if;
                           end;
                        end;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0
                        then
                           L.Pool (I).Phase := Body_Complete;
                        end if;

                     when RFLX.Http2_Parameters.DATA =>
                        if Hdr.Length > 0 then
                           declare
                              First : constant RFLX.RFLX_Types.Index :=
                                View'First + 9;
                              Lst   : constant RFLX.RFLX_Types.Index :=
                                First +
                                RFLX.RFLX_Types.Index (Hdr.Length) - 1;
                              Pay   : constant RFLX.RFLX_Types.Bytes :=
                                View (First .. Lst);
                              Msg   : constant RFLX.RFLX_Types.Bytes :=
                                Strip_Grpc_Frame (Pay);
                           begin
                              if Msg'Length > 0 then
                                 On_Request_Message (I, Msg);
                              end if;
                           end;
                        end if;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0
                        then
                           L.Pool (I).Phase := Body_Complete;
                        end if;

                     when others => null;
                  end case;
               end if;
            end;
         end loop;
      end Drain_Stream_App;

      --  Body_Complete → call Build_Response, emit HEADERS+DATA+
      --  trailers in one shot, mark Closed.
      procedure Dispatch_Stream (I : Positive);
      procedure Dispatch_Stream (I : Positive) is
         Resp_Hdrs : Hpack.Header_Block (1 .. 16);
         Resp_Hdrs_Last : Natural;
         Resp_Body : RFLX.RFLX_Types.Bytes (1 .. 16384) :=
           (others => 0);
         Resp_Body_Last : Natural;
         Trailers : Hpack.Header_Block (1 .. 8);
         Trailers_Last : Natural;
      begin
         Resp_Hdrs_Last := Resp_Hdrs'First - 1;
         Trailers_Last := Trailers'First - 1;
         Resp_Body_Last := Integer (Resp_Body'First) - 1;

         Build_Response
           (Slot                  => I,
            Request_Headers       => Headers (I),
            Request_Headers_Last  => Headers_Last (I),
            Response_Headers      => Resp_Hdrs,
            Response_Headers_Last => Resp_Hdrs_Last,
            Response_Body         => Resp_Body,
            Response_Body_Last    => Resp_Body_Last,
            Trailers              => Trailers,
            Trailers_Last         => Trailers_Last);

         Send_Headers_Frame
           (L.Pool (I).Stream_Id,
            Resp_Hdrs (Resp_Hdrs'First .. Resp_Hdrs_Last),
            End_Stream => False);
         if Resp_Body_Last >= Integer (Resp_Body'First) then
            Send_Data_Frame
              (L.Pool (I).Stream_Id,
               Resp_Body
                 (Resp_Body'First ..
                    RFLX.RFLX_Types.Index (Resp_Body_Last)),
               End_Stream => False);
         end if;
         Send_Headers_Frame
           (L.Pool (I).Stream_Id,
            Trailers (Trailers'First .. Trailers_Last),
            End_Stream => True);

         L.Pool (I).Phase := Closed;
         Last_Stream_Id := L.Pool (I).Stream_Id;
      end Dispatch_Stream;

      procedure Handle_Frame
        (Hdr  : Wire.Frame_Header;
         Last : RFLX.RFLX_Types.Index);
      procedure Handle_Frame
        (Hdr  : Wire.Frame_Header;
         Last : RFLX.RFLX_Types.Index)
      is
      begin
         if Hdr.Stream_Identifier = 0 then
            case Hdr.Frame_Type_Value is
               when RFLX.Http2_Parameters.PING =>
                  if (Hdr.Flags and Wire.Flag_ACK) = 0
                    and Hdr.Length = 8
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
                  end if;
               when RFLX.Http2_Parameters.SETTINGS =>
                  if (Hdr.Flags and Wire.Flag_ACK) = 0 then
                     declare
                        Ack_Last : RFLX.RFLX_Types.Index;
                     begin
                        Wire.Encode_Settings_Ack (L.Buf, Ack_Last);
                        Transport.Send
                          (Chan, L.Buf.all (L.Buf'First .. Ack_Last));
                     end;
                  end if;
               when RFLX.Http2_Parameters.GOAWAY =>
                  Goaway_Pending := True;
               when others => null;
            end case;
            return;
         end if;

         declare
            Slot : Natural := Find_Slot (Hdr.Stream_Identifier);
         begin
            if Slot = 0 then
               if Hdr.Frame_Type_Value =
                 RFLX.Http2_Parameters.HEADERS
               then
                  Slot := Allocate_Slot (Hdr.Stream_Identifier);
                  if Slot = 0 then
                     declare
                        RST_Last : RFLX.RFLX_Types.Index;
                     begin
                        Wire.Encode_Rst_Stream
                          (Buffer => L.Buf, Last => RST_Last,
                           Stream_Id => Hdr.Stream_Identifier,
                           Error_Code => 7);
                        Transport.Send
                          (Chan,
                           L.Buf.all (L.Buf'First .. RST_Last));
                     end;
                     return;
                  end if;
               else
                  return;
               end if;
            end if;

            if FSM.Needs_Data (Ctxs (Slot), FSM.C_Network) then
               FSM.Write
                 (Ctxs (Slot),
                  FSM.C_Network,
                  L.Buf.all (L.Buf'First .. Last));
            end if;
            Drain_Stream_App (Slot);
         end;
      end Handle_Frame;

      procedure Goodbye;
      procedure Goodbye is
         Goaway_Last : RFLX.RFLX_Types.Index;
         Empty : constant RFLX.RFLX_Types.Bytes (1 .. 0) :=
           (others => 0);
      begin
         Wire.Encode_Goaway
           (Buffer => L.Buf, Last => Goaway_Last,
            Last_Stream_Id => Last_Stream_Id,
            Error_Code => 0,
            Debug_Data => Empty);
         Transport.Send (Chan, L.Buf.all (L.Buf'First .. Goaway_Last));
      exception
         when others => null;
      end Goodbye;

   begin
      if L.Buf = null then
         raise Mux_Server_Error
           with "Http2_Core.Mux_Server.Attach_Buffer must be called first";
      end if;

      Transport.Accept_One (L.Trans, Chan);
      Receive_Preface;
      Send_Initial_Settings;

      Connection_Loop :
      loop
         exit Connection_Loop when Goaway_Pending;

         declare
            Made_Progress : Boolean := False;
         begin
            if Transport.Has_Pending (Chan) then
               declare
                  Frame_Hdr : Wire.Frame_Header;
                  Frame_Last : RFLX.RFLX_Types.Index;
                  OK : Boolean;
               begin
                  Read_Frame
                    (Chan, L.Buf, Frame_Hdr, Frame_Last, OK);
                  exit Connection_Loop when not OK;
                  Handle_Frame (Frame_Hdr, Frame_Last);
                  Made_Progress := True;
               end;
            end if;

            for I in L.Pool'Range loop
               if L.Pool (I).Phase = Body_Complete then
                  Dispatch_Stream (I);
                  Release_Slot (I);
                  Made_Progress := True;
               elsif L.Pool (I).Phase = Closed then
                  Release_Slot (I);
                  Made_Progress := True;
               end if;
            end loop;

            if not Made_Progress then
               delay 0.001;
            end if;
         end;
      end loop Connection_Loop;

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

      Goodbye;

      for I in L.Pool'Range loop
         if L.Pool (I).Phase /= Free then
            Release_Slot (I);
         end if;
      end loop;

      Transport.Close (Chan);
   end Accept_And_Serve_Multi_Client_Stream;

   procedure Accept_And_Serve_Multi_Bidi_Stream
     (L : in out Listener)
   is
      package FSM renames RFLX.Stream.Open.FSM;

      Chan : Transport.Channel;

      type Ctx_Pool is array (1 .. Max_Streams) of FSM.Context;
      Ctxs : Ctx_Pool;

      type Hdr_Pool is array (1 .. Max_Streams) of
        Hpack.Header_Block (1 .. 16);
      type Hdr_Last_Pool is array (1 .. Max_Streams) of Natural;
      type Trailers_Pool is array (1 .. Max_Streams) of
        Hpack.Header_Block (1 .. 8);
      type Bool_Pool is array (1 .. Max_Streams) of Boolean;

      Headers : Hdr_Pool := (others => (others => (Name_Last => 0,
                                                  Value_Last => 0,
                                                  Name => (others => ' '),
                                                  Value => (others => ' '))));
      Headers_Last : Hdr_Last_Pool := (others => 0);
      Slot_Trailers      : Trailers_Pool :=
        (others => (others => (Name_Last => 0,
                               Value_Last => 0,
                               Name => (others => ' '),
                               Value => (others => ' '))));
      Slot_Trailers_Last : Hdr_Last_Pool := (others => 0);
      End_Of_Request : Bool_Pool := (others => False);

      Goaway_Pending : Boolean := False;
      Last_Stream_Id : Bit_Len := 0;

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
                    View'First + 5
                    + RFLX.RFLX_Types.Index (Msg_Len) - 1);
            end;
         end;
      end Strip_Grpc_Frame;

      procedure Receive_Preface;
      procedure Receive_Preface is
         Pref_Bytes : RFLX.RFLX_Types.Bytes
           (RFLX.RFLX_Types.Index'First ..
              RFLX.RFLX_Types.Index'First +
              RFLX.RFLX_Types.Index (Wire.Preface'Length) - 1);
         Pref_OK : Boolean;
      begin
         Transport.Receive_Full (Chan, Pref_Bytes, Pref_OK);
         if not Pref_OK then
            raise Mux_Server_Error with "EOF before preface";
         end if;
         for I in Pref_Bytes'Range loop
            if Pref_Bytes (I) /=
              U8 (Character'Pos
                    (Wire.Preface
                       (Wire.Preface'First +
                          Integer (I - Pref_Bytes'First))))
            then
               raise Mux_Server_Error with "bad preface";
            end if;
         end loop;
      end Receive_Preface;

      procedure Send_Initial_Settings;
      procedure Send_Initial_Settings is
         Last : RFLX.RFLX_Types.Index;
         Params : constant Wire.Settings_List (1 .. 3) :=
           ((Identifier => RFLX.Http2_Parameters.HEADER_TABLE_SIZE,
             Value      => 0),
            (Identifier => RFLX.Http2_Parameters.ENABLE_PUSH,
             Value      => 0),
            (Identifier => RFLX.Http2_Parameters.MAX_CONCURRENT_STREAMS,
             Value      => Max_Streams));
      begin
         Wire.Encode_Settings (L.Buf, Last, Params);
         Transport.Send (Chan, L.Buf.all (L.Buf'First .. Last));
      end Send_Initial_Settings;

      function Find_Slot (Stream_Id : Bit_Len) return Natural;
      function Find_Slot (Stream_Id : Bit_Len) return Natural is
      begin
         for I in L.Pool'Range loop
            if L.Pool (I).Phase /= Free
              and then L.Pool (I).Stream_Id = Stream_Id
            then
               return I;
            end if;
         end loop;
         return 0;
      end Find_Slot;

      function Allocate_Slot (Stream_Id : Bit_Len) return Natural;
      function Allocate_Slot (Stream_Id : Bit_Len) return Natural is
      begin
         for I in L.Pool'Range loop
            if L.Pool (I).Phase = Free then
               L.Pool (I).Phase := Awaiting_Body;
               L.Pool (I).Stream_Id := Stream_Id;
               Headers_Last (I) := Headers (I)'First - 1;
               Slot_Trailers_Last (I) := Slot_Trailers (I)'First - 1;
               End_Of_Request (I) := False;
               FSM.Initialize
                 (Ctxs (I),
                  L.Pool (I).Inbound_Buf,
                  L.Pool (I).Outgoing_Buf);
               return I;
            end if;
         end loop;
         return 0;
      end Allocate_Slot;

      procedure Release_Slot (I : Positive);
      procedure Release_Slot (I : Positive) is
      begin
         if FSM.Initialized (Ctxs (I)) then
            FSM.Finalize
              (Ctxs (I),
               L.Pool (I).Inbound_Buf,
               L.Pool (I).Outgoing_Buf);
         end if;
         L.Pool (I).Phase := Free;
         L.Pool (I).Stream_Id := 0;
      end Release_Slot;

      procedure Send_Headers_Frame
        (Stream_Id  : Bit_Len;
         Headers_In : Hpack.Header_Block;
         End_Stream : Boolean);
      procedure Send_Headers_Frame
        (Stream_Id  : Bit_Len;
         Headers_In : Hpack.Header_Block;
         End_Stream : Boolean)
      is
         Frag_Out  : Hpack.Octet_Array
           (1 .. Hpack.Max_Header_Length * Hpack.Max_Headers);
         Frag_Last : Natural;
         Frag_OK   : Boolean;
         Frame_Last : RFLX.RFLX_Types.Index;
      begin
         Hpack.Encode
           (Headers     => Headers_In,
            Output      => Frag_Out,
            Output_Last => Frag_Last,
            Output_OK   => Frag_OK);
         if not Frag_OK then
            raise Mux_Server_Error with "HPACK encode failed";
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
      end Send_Headers_Frame;

      procedure Send_Data_Frame
        (Stream_Id  : Bit_Len;
         Payload    : RFLX.RFLX_Types.Bytes;
         End_Stream : Boolean);
      procedure Send_Data_Frame
        (Stream_Id  : Bit_Len;
         Payload    : RFLX.RFLX_Types.Bytes;
         End_Stream : Boolean)
      is
         Last : RFLX.RFLX_Types.Index;
      begin
         Wire.Encode_Data
           (Buffer => L.Buf, Last => Last,
            Stream_Id => Stream_Id, Payload => Payload,
            End_Stream => End_Stream);
         Transport.Send (Chan, L.Buf.all (L.Buf'First .. Last));
      end Send_Data_Frame;

      --  Variant-specific: HEADERS parse → Phase := Headers_Complete
      --  (the bidi connection loop will then fire Setup_Response).
      --  DATA → deliver via On_Request_Message; track END_STREAM in
      --  End_Of_Request rather than flipping phase to Body_Complete
      --  (Body_Complete is unused here — replies are independent of
      --  request termination).
      procedure Drain_Stream_App (I : Positive);
      procedure Drain_Stream_App (I : Positive) is
      begin
         loop
            FSM.Run (Ctxs (I));
            exit when not FSM.Has_Data (Ctxs (I), FSM.C_App_Pending);
            declare
               N : constant RFLX.RFLX_Types.Length :=
                 FSM.Read_Buffer_Size (Ctxs (I), FSM.C_App_Pending);
               View : RFLX.RFLX_Types.Bytes
                 (L.Buf'First ..
                    L.Buf'First + RFLX.RFLX_Types.Index (N) - 1);
               Hdr : Wire.Frame_Header;
               Hdr_Valid : Boolean;
            begin
               FSM.Read (Ctxs (I), FSM.C_App_Pending, View);
               Wire.Decode_Frame_Header
                 (Buffer => View (View'First .. View'First + 8),
                  Header => Hdr, Valid => Hdr_Valid);
               if Hdr_Valid then
                  case Hdr.Frame_Type_Value is
                     when RFLX.Http2_Parameters.HEADERS =>
                        declare
                           Frag_First : RFLX.RFLX_Types.Index :=
                             View'First + 9;
                           Frag_Last  : constant RFLX.RFLX_Types.Index :=
                             View'Last;
                           Decode_OK : Boolean;
                        begin
                           if (Hdr.Flags and Wire.Flag_PRIORITY) /= 0
                           then
                              Frag_First := Frag_First + 5;
                           end if;
                           declare
                              Frag : Hpack.Octet_Array
                                (1 ..
                                   Natural (Frag_Last - Frag_First) + 1);
                           begin
                              for K in Frag'Range loop
                                 Frag (K) :=
                                   Hpack.Octet
                                     (View
                                        (Frag_First
                                         + RFLX.RFLX_Types.Index (K)
                                         - 1));
                              end loop;
                              Hpack.Decode
                                (Input        => Frag,
                                 Headers      => Headers (I),
                                 Headers_Last => Headers_Last (I),
                                 Output_OK    => Decode_OK);
                              if not Decode_OK then
                                 raise Mux_Server_Error
                                   with "HPACK decode failed";
                              end if;
                           end;
                        end;
                        --  Bidi: kick Setup_Response from the
                        --  conn loop on Headers_Complete. Note
                        --  END_STREAM on HEADERS (no body) is
                        --  legal.
                        L.Pool (I).Phase := Headers_Complete;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0
                        then
                           End_Of_Request (I) := True;
                        end if;

                     when RFLX.Http2_Parameters.DATA =>
                        if Hdr.Length > 0 then
                           declare
                              First : constant RFLX.RFLX_Types.Index :=
                                View'First + 9;
                              Lst   : constant RFLX.RFLX_Types.Index :=
                                First +
                                RFLX.RFLX_Types.Index (Hdr.Length) - 1;
                              Pay   : constant RFLX.RFLX_Types.Bytes :=
                                View (First .. Lst);
                              Msg   : constant RFLX.RFLX_Types.Bytes :=
                                Strip_Grpc_Frame (Pay);
                           begin
                              if Msg'Length > 0 then
                                 On_Request_Message (I, Msg);
                              end if;
                           end;
                        end if;
                        if (Hdr.Flags and Wire.Flag_END_STREAM) /= 0
                        then
                           End_Of_Request (I) := True;
                        end if;

                     when others => null;
                  end case;
               end if;
            end;
         end loop;
      end Drain_Stream_App;

      --  Headers_Complete → Setup_Response, send response HEADERS,
      --  flip to Streaming.
      procedure Begin_Stream (I : Positive);
      procedure Begin_Stream (I : Positive) is
         Resp_Hdrs : Hpack.Header_Block (1 .. 16);
         Resp_Hdrs_Last : Natural;
      begin
         Resp_Hdrs_Last := Resp_Hdrs'First - 1;
         Slot_Trailers_Last (I) := Slot_Trailers (I)'First - 1;
         Setup_Response
           (Slot                  => I,
            Request_Headers       => Headers (I),
            Request_Headers_Last  => Headers_Last (I),
            Response_Headers      => Resp_Hdrs,
            Response_Headers_Last => Resp_Hdrs_Last,
            Trailers              => Slot_Trailers (I),
            Trailers_Last         => Slot_Trailers_Last (I));
         Send_Headers_Frame
           (L.Pool (I).Stream_Id,
            Resp_Hdrs (Resp_Hdrs'First .. Resp_Hdrs_Last),
            End_Stream => False);
         L.Pool (I).Phase := Streaming;
      end Begin_Stream;

      --  Streaming tick: pull one Next_Reply. True if a reply was
      --  emitted. False if Next_Reply returned False.
      function Tick_Stream (I : Positive) return Boolean;
      function Tick_Stream (I : Positive) return Boolean is
         Msg_Buf  : RFLX.RFLX_Types.Bytes (1 .. 16384) :=
           (others => 0);
         Msg_Last : RFLX.RFLX_Types.Index;
         Has_Msg  : Boolean;
      begin
         Has_Msg := Next_Reply (I, Msg_Buf, Msg_Last);
         if Has_Msg then
            Send_Data_Frame
              (L.Pool (I).Stream_Id,
               Msg_Buf (Msg_Buf'First .. Msg_Last),
               End_Stream => False);
            return True;
         end if;
         --  No reply right now. If the request side has ended,
         --  close the stream; otherwise stay in Streaming and try
         --  again next iteration (peer might still send messages
         --  that produce more replies).
         if End_Of_Request (I) then
            Send_Headers_Frame
              (L.Pool (I).Stream_Id,
               Slot_Trailers (I)
                 (Slot_Trailers (I)'First .. Slot_Trailers_Last (I)),
               End_Stream => True);
            L.Pool (I).Phase := Closed;
            Last_Stream_Id := L.Pool (I).Stream_Id;
         end if;
         return False;
      end Tick_Stream;

      procedure Handle_Frame
        (Hdr  : Wire.Frame_Header;
         Last : RFLX.RFLX_Types.Index);
      procedure Handle_Frame
        (Hdr  : Wire.Frame_Header;
         Last : RFLX.RFLX_Types.Index)
      is
      begin
         if Hdr.Stream_Identifier = 0 then
            case Hdr.Frame_Type_Value is
               when RFLX.Http2_Parameters.PING =>
                  if (Hdr.Flags and Wire.Flag_ACK) = 0
                    and Hdr.Length = 8
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
                  end if;
               when RFLX.Http2_Parameters.SETTINGS =>
                  if (Hdr.Flags and Wire.Flag_ACK) = 0 then
                     declare
                        Ack_Last : RFLX.RFLX_Types.Index;
                     begin
                        Wire.Encode_Settings_Ack (L.Buf, Ack_Last);
                        Transport.Send
                          (Chan, L.Buf.all (L.Buf'First .. Ack_Last));
                     end;
                  end if;
               when RFLX.Http2_Parameters.GOAWAY =>
                  Goaway_Pending := True;
               when others => null;
            end case;
            return;
         end if;

         declare
            Slot : Natural := Find_Slot (Hdr.Stream_Identifier);
         begin
            if Slot = 0 then
               if Hdr.Frame_Type_Value =
                 RFLX.Http2_Parameters.HEADERS
               then
                  Slot := Allocate_Slot (Hdr.Stream_Identifier);
                  if Slot = 0 then
                     declare
                        RST_Last : RFLX.RFLX_Types.Index;
                     begin
                        Wire.Encode_Rst_Stream
                          (Buffer => L.Buf, Last => RST_Last,
                           Stream_Id => Hdr.Stream_Identifier,
                           Error_Code => 7);
                        Transport.Send
                          (Chan,
                           L.Buf.all (L.Buf'First .. RST_Last));
                     end;
                     return;
                  end if;
               else
                  return;
               end if;
            end if;

            if FSM.Needs_Data (Ctxs (Slot), FSM.C_Network) then
               FSM.Write
                 (Ctxs (Slot),
                  FSM.C_Network,
                  L.Buf.all (L.Buf'First .. Last));
            end if;
            Drain_Stream_App (Slot);
         end;
      end Handle_Frame;

      procedure Goodbye;
      procedure Goodbye is
         Goaway_Last : RFLX.RFLX_Types.Index;
         Empty : constant RFLX.RFLX_Types.Bytes (1 .. 0) :=
           (others => 0);
      begin
         Wire.Encode_Goaway
           (Buffer => L.Buf, Last => Goaway_Last,
            Last_Stream_Id => Last_Stream_Id,
            Error_Code => 0,
            Debug_Data => Empty);
         Transport.Send (Chan, L.Buf.all (L.Buf'First .. Goaway_Last));
      exception
         when others => null;
      end Goodbye;

   begin
      if L.Buf = null then
         raise Mux_Server_Error
           with "Http2_Core.Mux_Server.Attach_Buffer must be called first";
      end if;

      Transport.Accept_One (L.Trans, Chan);
      Receive_Preface;
      Send_Initial_Settings;

      Connection_Loop :
      loop
         exit Connection_Loop when Goaway_Pending;

         declare
            Made_Progress : Boolean := False;
         begin
            if Transport.Has_Pending (Chan) then
               declare
                  Frame_Hdr : Wire.Frame_Header;
                  Frame_Last : RFLX.RFLX_Types.Index;
                  OK : Boolean;
               begin
                  Read_Frame
                    (Chan, L.Buf, Frame_Hdr, Frame_Last, OK);
                  exit Connection_Loop when not OK;
                  Handle_Frame (Frame_Hdr, Frame_Last);
                  Made_Progress := True;
               end;
            end if;

            for I in L.Pool'Range loop
               case L.Pool (I).Phase is
                  when Headers_Complete =>
                     Begin_Stream (I);
                     Made_Progress := True;
                  when Streaming =>
                     if Tick_Stream (I) then
                        Made_Progress := True;
                     end if;
                  when Closed =>
                     Release_Slot (I);
                     Made_Progress := True;
                  when others => null;
               end case;
            end loop;

            if not Made_Progress then
               delay 0.001;
            end if;
         end;
      end loop Connection_Loop;

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

      Goodbye;

      for I in L.Pool'Range loop
         if L.Pool (I).Phase /= Free then
            Release_Slot (I);
         end if;
      end loop;

      Transport.Close (Chan);
   end Accept_And_Serve_Multi_Bidi_Stream;

end Http2_Core.Mux_Server;
