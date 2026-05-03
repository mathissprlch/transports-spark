--  greeter_streaming_demo — exercise all 4 gRPC stream types over
--  the v0.2 SPARK stack against the Python helloworld.Greeter server:
--
--    Unary             SayHello          → existing greeter_client_v02
--    Server-streaming  LotsOfReplies     → 1 req, 5 replies
--    Client-streaming  LotsOfGreetings   → 3 reqs, 1 combined reply
--    Bidi-streaming    BidiHello         → 3 reqs, 3 interleaved replies
--
--  Each branch prints the on-the-wire protobuf bytes then decodes
--  the HelloReply.message field via Protobuf_Core.Wire.

with Ada.Text_IO;
with Ada.Command_Line;

with RFLX.RFLX_Types;

with Http2_Core.Hpack;
with Http2_Core.Connection;
with Protobuf_Core.Wire;

procedure Greeter_Streaming_Demo is
   use Ada.Text_IO;
   use type RFLX.RFLX_Types.Index;

   Default_Host : constant String := "127.0.0.1";
   Default_Port : constant Natural := 50_051;

   Host : String (1 .. 64) := (others => ' ');
   Host_Last : Natural := 0;
   Port : Natural := Default_Port;

   procedure Set_Host (Spec : String);
   procedure Set_Host (Spec : String) is
      Colon_At : Natural := 0;
   begin
      for I in Spec'Range loop
         if Spec (I) = ':' then Colon_At := I; exit; end if;
      end loop;
      if Colon_At = 0 then
         Host (1 .. Spec'Length) := Spec;
         Host_Last := Spec'Length;
      else
         declare
            H_Len : constant Natural := Colon_At - Spec'First;
         begin
            Host (1 .. H_Len) := Spec (Spec'First .. Colon_At - 1);
            Host_Last := H_Len;
            Port := Natural'Value (Spec (Colon_At + 1 .. Spec'Last));
         end;
      end if;
   end Set_Host;

   --  Global state for callbacks (Ada doesn't have closures over
   --  access-to-subprogram). Per-mode message counter / source.

   --  --- Server-streaming sink: print each reply.
   procedure SS_On_Message (Msg : RFLX.RFLX_Types.Bytes);
   procedure SS_On_Message (Msg : RFLX.RFLX_Types.Bytes) is
      Reply : String (1 .. 256) := (others => ' ');
      Reply_Last : Natural;
      Tag_Last : RFLX.RFLX_Types.Index;
      Tag_OK : Boolean;
      Field_Num, Wire_Tp : Natural;
      Str_End : RFLX.RFLX_Types.Index;
      Str_OK : Boolean;
   begin
      if Msg'Length < 2 then
         Put_Line ("    [empty]");
         return;
      end if;
      Protobuf_Core.Wire.Decode_Tag
        (Msg, Msg'First, Field_Num, Wire_Tp, Tag_Last, Tag_OK);
      if not Tag_OK or else Field_Num /= 1 then
         Put_Line ("    [tag decode failed]");
         return;
      end if;
      Protobuf_Core.Wire.Decode_String_Value
        (Msg, Tag_Last + 1, Reply, Reply_Last, Str_End, Str_OK);
      if Str_OK then
         Put_Line ("    " & Reply (1 .. Reply_Last));
      else
         Put_Line ("    [string decode failed]");
      end if;
   end SS_On_Message;

   --  --- Client-streaming source: emit "Alice", "Bob", "Carol".
   CS_Names : constant array (1 .. 3) of access constant String :=
     (new String'("Alice"), new String'("Bob"), new String'("Carol"));
   CS_Idx : Natural := 0;

   function CS_Next
     (Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out RFLX.RFLX_Types.Index)
      return Boolean;

   function CS_Next
     (Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out RFLX.RFLX_Types.Index)
      return Boolean
   is
      OK : Boolean;
   begin
      Out_Last := Out_Buf'First;
      CS_Idx := CS_Idx + 1;
      if CS_Idx > CS_Names'Last then
         return False;
      end if;
      Protobuf_Core.Wire.Encode_String_Field
        (Out_Buf, Out_Buf'First, 1, CS_Names (CS_Idx).all, Out_Last, OK);
      return OK;
   end CS_Next;

   --  --- Bidi: emit "ping1/2/3", expect 3 replies.
   Bidi_Names : constant array (1 .. 3) of access constant String :=
     (new String'("ping1"), new String'("ping2"), new String'("ping3"));
   Bidi_Idx : Natural := 0;

   function Bidi_Next_Out
     (Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out RFLX.RFLX_Types.Index)
      return Boolean;

   function Bidi_Next_Out
     (Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out RFLX.RFLX_Types.Index)
      return Boolean
   is
      OK : Boolean;
   begin
      Out_Last := Out_Buf'First;
      Bidi_Idx := Bidi_Idx + 1;
      if Bidi_Idx > Bidi_Names'Last then
         return False;
      end if;
      Protobuf_Core.Wire.Encode_String_Field
        (Out_Buf, Out_Buf'First, 1,
         Bidi_Names (Bidi_Idx).all, Out_Last, OK);
      return OK;
   end Bidi_Next_Out;

   procedure Bidi_On_In (Msg : RFLX.RFLX_Types.Bytes);
   procedure Bidi_On_In (Msg : RFLX.RFLX_Types.Bytes) renames
     SS_On_Message;

   procedure Run_Server_Stream
     (C : in out Http2_Core.Connection.Connection);
   procedure Run_Server_Stream
     (C : in out Http2_Core.Connection.Connection)
   is
      Req_Buf  : RFLX.RFLX_Types.Bytes (1 .. 256) := (others => 0);
      Req_Last : RFLX.RFLX_Types.Index;
      Req_OK   : Boolean;

      Headers : constant Http2_Core.Hpack.Header_Block (1 .. 7) :=
        (Http2_Core.Hpack.Make_Header (":method", "POST"),
         Http2_Core.Hpack.Make_Header (":scheme", "http"),
         Http2_Core.Hpack.Make_Header
           (":path", "/helloworld.Greeter/LotsOfReplies"),
         Http2_Core.Hpack.Make_Header
           (":authority", Host (1 .. Host_Last)),
         Http2_Core.Hpack.Make_Header
           ("content-type", "application/grpc"),
         Http2_Core.Hpack.Make_Header ("te", "trailers"),
         Http2_Core.Hpack.Make_Header
           ("user-agent", "grpc-ada-v0.2"));
      Resp_Hdrs : Http2_Core.Hpack.Header_Block (1 .. 16);
      Hdrs_Last : Natural;

      --  Compose gRPC-framed request: 5-byte prefix + protobuf.
      PB_Buf : RFLX.RFLX_Types.Bytes (1 .. 256) := (others => 0);
      PB_Last : RFLX.RFLX_Types.Index;
   begin
      Put_Line ("=== Server-streaming: LotsOfReplies(name=Streaming) ===");
      Protobuf_Core.Wire.Encode_String_Field
        (PB_Buf, PB_Buf'First, 1, "Streaming", PB_Last, Req_OK);

      --  gRPC framing: 1B compression flag + 4B BE length + payload.
      declare
         Len : constant Natural := Natural (PB_Last);
      begin
         Req_Buf (1) := 0;
         Req_Buf (2) := RFLX.RFLX_Types.Byte ((Len / 16777216) mod 256);
         Req_Buf (3) := RFLX.RFLX_Types.Byte ((Len / 65536) mod 256);
         Req_Buf (4) := RFLX.RFLX_Types.Byte ((Len / 256) mod 256);
         Req_Buf (5) := RFLX.RFLX_Types.Byte (Len mod 256);
         for I in 1 .. Len loop
            Req_Buf (5 + RFLX.RFLX_Types.Index (I)) :=
              PB_Buf (RFLX.RFLX_Types.Index (I));
         end loop;
         Req_Last := 5 + RFLX.RFLX_Types.Index (Len);
      end;

      declare
         procedure SS_Run is new Http2_Core.Connection.Server_Stream
           (On_Message => SS_On_Message);
      begin
         SS_Run (C, Headers, Req_Buf (Req_Buf'First .. Req_Last),
                 Resp_Hdrs, Hdrs_Last);
      end;
      Put_Line ("  [server-stream done]");
      New_Line;
   end Run_Server_Stream;

   procedure Run_Client_Stream
     (C : in out Http2_Core.Connection.Connection);
   procedure Run_Client_Stream
     (C : in out Http2_Core.Connection.Connection)
   is
      Headers : constant Http2_Core.Hpack.Header_Block (1 .. 7) :=
        (Http2_Core.Hpack.Make_Header (":method", "POST"),
         Http2_Core.Hpack.Make_Header (":scheme", "http"),
         Http2_Core.Hpack.Make_Header
           (":path", "/helloworld.Greeter/LotsOfGreetings"),
         Http2_Core.Hpack.Make_Header
           (":authority", Host (1 .. Host_Last)),
         Http2_Core.Hpack.Make_Header
           ("content-type", "application/grpc"),
         Http2_Core.Hpack.Make_Header ("te", "trailers"),
         Http2_Core.Hpack.Make_Header
           ("user-agent", "grpc-ada-v0.2"));
      Resp_Hdrs : Http2_Core.Hpack.Header_Block (1 .. 16);
      Hdrs_Last : Natural;
      Resp_Body : RFLX.RFLX_Types.Bytes (1 .. 4096) := (others => 0);
      Body_Last : Natural;
   begin
      Put_Line ("=== Client-streaming: LotsOfGreetings([Alice,Bob,Carol]) ===");
      CS_Idx := 0;
      declare
         procedure CS_Run is new Http2_Core.Connection.Client_Stream
           (Next_Message => CS_Next);
      begin
         CS_Run (C, Headers, Resp_Hdrs, Hdrs_Last,
                 Resp_Body, Body_Last);
      end;
      --  Response body = 5-byte gRPC prefix + protobuf HelloReply.
      if Body_Last >= Integer (Resp_Body'First) + 6 then
         declare
            PB_Start : constant RFLX.RFLX_Types.Index :=
              Resp_Body'First + 5;
            PB_End : constant RFLX.RFLX_Types.Index :=
              RFLX.RFLX_Types.Index (Body_Last);
         begin
            SS_On_Message (Resp_Body (PB_Start .. PB_End));
         end;
      end if;
      New_Line;
   end Run_Client_Stream;

   procedure Run_Bidi_Stream
     (C : in out Http2_Core.Connection.Connection);
   procedure Run_Bidi_Stream
     (C : in out Http2_Core.Connection.Connection)
   is
      Headers : constant Http2_Core.Hpack.Header_Block (1 .. 7) :=
        (Http2_Core.Hpack.Make_Header (":method", "POST"),
         Http2_Core.Hpack.Make_Header (":scheme", "http"),
         Http2_Core.Hpack.Make_Header
           (":path", "/helloworld.Greeter/BidiHello"),
         Http2_Core.Hpack.Make_Header
           (":authority", Host (1 .. Host_Last)),
         Http2_Core.Hpack.Make_Header
           ("content-type", "application/grpc"),
         Http2_Core.Hpack.Make_Header ("te", "trailers"),
         Http2_Core.Hpack.Make_Header
           ("user-agent", "grpc-ada-v0.2"));
      Resp_Hdrs : Http2_Core.Hpack.Header_Block (1 .. 16);
      Hdrs_Last : Natural;
   begin
      Put_Line ("=== Bidi-streaming: BidiHello(ping1/2/3) ===");
      Bidi_Idx := 0;
      declare
         procedure Bidi_Run is new Http2_Core.Connection.Bidi_Stream
           (Next_Outbound => Bidi_Next_Out,
            On_Inbound    => Bidi_On_In);
      begin
         Bidi_Run (C, Headers, Resp_Hdrs, Hdrs_Last);
      end;
      Put_Line ("  [bidi done]");
      New_Line;
   end Run_Bidi_Stream;

begin
   if Ada.Command_Line.Argument_Count >= 1 then
      Set_Host (Ada.Command_Line.Argument (1));
   else
      Host (1 .. Default_Host'Length) := Default_Host;
      Host_Last := Default_Host'Length;
   end if;

   Put_Line ("greeter_streaming_demo: target=" & Host (1 .. Host_Last)
             & ":" & Port'Image);
   New_Line;

   --  Each stream type uses its own connection (single-stream per
   --  Connection in v0.2 — multiplexing is v0.5 work).

   for Mode in 1 .. 3 loop
      declare
         C : Http2_Core.Connection.Connection;
         Conn_Buf : RFLX.RFLX_Types.Bytes_Ptr :=
           new RFLX.RFLX_Types.Bytes'(1 .. 16 * 1024 + 64 => 0);
         Inbound_Buf : RFLX.RFLX_Types.Bytes_Ptr :=
           new RFLX.RFLX_Types.Bytes'(1 .. 16 * 1024 + 64 => 0);
         Outgoing_Buf : RFLX.RFLX_Types.Bytes_Ptr :=
           new RFLX.RFLX_Types.Bytes'(1 .. 16 * 1024 + 64 => 0);
      begin
         Http2_Core.Connection.Attach_Buffers
           (C, Conn_Buf, Inbound_Buf, Outgoing_Buf);
         Http2_Core.Connection.Open
           (C, Host (1 .. Host_Last), Port);
         case Mode is
            when 1 => Run_Server_Stream (C);
            when 2 => Run_Client_Stream (C);
            when 3 => Run_Bidi_Stream (C);
            when others => null;
         end case;
         Http2_Core.Connection.Close (C);
         Http2_Core.Connection.Detach_Buffers
           (C, Conn_Buf, Inbound_Buf, Outgoing_Buf);
         RFLX.RFLX_Types.Free (Conn_Buf);
         RFLX.RFLX_Types.Free (Inbound_Buf);
         RFLX.RFLX_Types.Free (Outgoing_Buf);
      end;
   end loop;
   Put_Line ("greeter_streaming_demo: SUCCESS");
end Greeter_Streaming_Demo;
