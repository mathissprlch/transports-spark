--  greeter_streaming_server — Ada gRPC server for all four
--  helloworld.Greeter RPC types. Mode picked by argv[1]:
--    unary           SayHello
--    server-stream   LotsOfReplies     (default)
--    client-stream   LotsOfGreetings
--    bidi            BidiHello
--  Port via argv[2] (default 50051).
--
--  Run:
--    ./bin/greeter_streaming_server server-stream 50051
--    grpcurl -plaintext -d '{"name":"X"}' \
--      -import-path crates/examples/proto -proto helloworld.proto \
--      127.0.0.1:50051 helloworld.Greeter/LotsOfReplies

with Ada.Text_IO;
with Ada.Command_Line;
with Ada.Strings.Fixed;

with RFLX.RFLX_Types;

with Http2_Core.Hpack;
with Http2_Core.Server;
with Protobuf_Core.Wire;

procedure Greeter_Streaming_Server is
   use Ada.Text_IO;
   use type RFLX.RFLX_Types.Index;

   ----------------------------------------------------------------
   --  Helpers shared across modes.
   ----------------------------------------------------------------

   --  Decode HelloRequest.name from a body (or from a stripped
   --  protobuf message buffer).
   procedure Decode_Name_PB
     (PB_View    : RFLX.RFLX_Types.Bytes;
      Name_Buf   : out String;
      Name_Last  : out Natural;
      OK         : out Boolean);

   procedure Decode_Name_PB
     (PB_View    : RFLX.RFLX_Types.Bytes;
      Name_Buf   : out String;
      Name_Last  : out Natural;
      OK         : out Boolean)
   is
      Field_Num : Natural;
      Wire_Tp   : Natural;
      Tag_Last  : RFLX.RFLX_Types.Index;
      Tag_OK    : Boolean;
      Str_End   : RFLX.RFLX_Types.Index;
   begin
      Name_Buf := (others => ' ');
      Name_Last := 0;
      OK := False;
      if PB_View'Length < 2 then return; end if;
      Protobuf_Core.Wire.Decode_Tag
        (PB_View, PB_View'First, Field_Num, Wire_Tp, Tag_Last, Tag_OK);
      if not Tag_OK or else Field_Num /= 1
        or else Wire_Tp /= Protobuf_Core.Wire.Wire_Length_Delim
      then return; end if;
      Protobuf_Core.Wire.Decode_String_Value
        (PB_View, Tag_Last + 1, Name_Buf, Name_Last, Str_End, OK);
   end Decode_Name_PB;

   --  Decode from full body (5-byte gRPC prefix + protobuf).
   procedure Decode_Name_Body
     (Body_Bytes : RFLX.RFLX_Types.Bytes;
      Name_Buf   : out String;
      Name_Last  : out Natural;
      OK         : out Boolean);

   procedure Decode_Name_Body
     (Body_Bytes : RFLX.RFLX_Types.Bytes;
      Name_Buf   : out String;
      Name_Last  : out Natural;
      OK         : out Boolean) is
   begin
      if Body_Bytes'Length < 6 then
         Name_Buf := (others => ' ');
         Name_Last := 0;
         OK := False;
         return;
      end if;
      Decode_Name_PB
        (Body_Bytes (Body_Bytes'First + 5 .. Body_Bytes'Last),
         Name_Buf, Name_Last, OK);
   end Decode_Name_Body;

   --  Encode "Hello, <text>!" as gRPC-framed HelloReply.
   procedure Encode_Reply
     (Text     : String;
      Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out RFLX.RFLX_Types.Index;
      OK       : out Boolean);

   procedure Encode_Reply
     (Text     : String;
      Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out RFLX.RFLX_Types.Index;
      OK       : out Boolean)
   is
      PB_Buf  : RFLX.RFLX_Types.Bytes (1 .. 1024) := (others => 0);
      PB_Last : RFLX.RFLX_Types.Index;
   begin
      Out_Last := Out_Buf'First;
      Protobuf_Core.Wire.Encode_String_Field
        (PB_Buf, PB_Buf'First, 1, Text, PB_Last, OK);
      if not OK then return; end if;
      declare
         Len : constant Natural := Natural (PB_Last);
      begin
         Out_Buf (Out_Buf'First) := 0;
         Out_Buf (Out_Buf'First + 1) :=
           RFLX.RFLX_Types.Byte ((Len / 16777216) mod 256);
         Out_Buf (Out_Buf'First + 2) :=
           RFLX.RFLX_Types.Byte ((Len / 65536) mod 256);
         Out_Buf (Out_Buf'First + 3) :=
           RFLX.RFLX_Types.Byte ((Len / 256) mod 256);
         Out_Buf (Out_Buf'First + 4) :=
           RFLX.RFLX_Types.Byte (Len mod 256);
         for I in 1 .. Len loop
            Out_Buf (Out_Buf'First + 4 + RFLX.RFLX_Types.Index (I)) :=
              PB_Buf (PB_Buf'First + RFLX.RFLX_Types.Index (I) - 1);
         end loop;
         Out_Last := Out_Buf'First + 4 + RFLX.RFLX_Types.Index (Len);
      end;
   end Encode_Reply;

   procedure Set_Headers_And_Trailers
     (Resp_Hdrs       : in out Http2_Core.Hpack.Header_Block;
      Resp_Hdrs_Last  : out Natural;
      Trailers        : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last   : out Natural);

   procedure Set_Headers_And_Trailers
     (Resp_Hdrs       : in out Http2_Core.Hpack.Header_Block;
      Resp_Hdrs_Last  : out Natural;
      Trailers        : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last   : out Natural) is
   begin
      Resp_Hdrs (Resp_Hdrs'First) :=
        Http2_Core.Hpack.Make_Header (":status", "200");
      Resp_Hdrs (Resp_Hdrs'First + 1) :=
        Http2_Core.Hpack.Make_Header ("content-type", "application/grpc");
      Resp_Hdrs_Last := Resp_Hdrs'First + 1;
      Trailers (Trailers'First) :=
        Http2_Core.Hpack.Make_Header ("grpc-status", "0");
      Trailers_Last := Trailers'First;
   end Set_Headers_And_Trailers;

   ----------------------------------------------------------------
   --  Server-streaming: LotsOfReplies (one request → 5 replies).
   ----------------------------------------------------------------

   Total_Replies : constant := 5;
   Reply_Counter : Natural := 0;
   Cached_Name : String (1 .. 256) := (others => ' ');
   Cached_Name_Last : Natural := 0;

   procedure SS_Setup
     (Request_Headers       : Http2_Core.Hpack.Header_Block;
      Request_Headers_Last  : Natural;
      Request_Body          : RFLX.RFLX_Types.Bytes;
      Request_Body_Last     : Natural;
      Response_Headers      : in out Http2_Core.Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Trailers              : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last         : out Natural);

   procedure SS_Setup
     (Request_Headers       : Http2_Core.Hpack.Header_Block;
      Request_Headers_Last  : Natural;
      Request_Body          : RFLX.RFLX_Types.Bytes;
      Request_Body_Last     : Natural;
      Response_Headers      : in out Http2_Core.Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Trailers              : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last         : out Natural)
   is
      pragma Unreferenced (Request_Headers);
      pragma Unreferenced (Request_Headers_Last);
      pragma Unreferenced (Request_Body_Last);
      OK : Boolean;
   begin
      Decode_Name_Body
        (Request_Body, Cached_Name, Cached_Name_Last, OK);
      if not OK then
         Cached_Name (1 .. 7) := "Unknown"; Cached_Name_Last := 7;
      end if;
      Reply_Counter := 0;
      Set_Headers_And_Trailers
        (Response_Headers, Response_Headers_Last,
         Trailers, Trailers_Last);
   end SS_Setup;

   function SS_Next
     (Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out RFLX.RFLX_Types.Index)
      return Boolean;

   function SS_Next
     (Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out RFLX.RFLX_Types.Index)
      return Boolean
   is
      use Ada.Strings.Fixed;
      OK : Boolean;
   begin
      Out_Last := Out_Buf'First;
      if Reply_Counter >= Total_Replies then return False; end if;
      Reply_Counter := Reply_Counter + 1;
      Encode_Reply
        ("Hello, " & Cached_Name (1 .. Cached_Name_Last)
         & "! [" & Trim (Reply_Counter'Image, Ada.Strings.Both)
         & "/" & Trim (Total_Replies'Image, Ada.Strings.Both) & "]",
         Out_Buf, Out_Last, OK);
      Put_Line ("  → reply" & Reply_Counter'Image);
      return OK;
   end SS_Next;

   ----------------------------------------------------------------
   --  Client-streaming: LotsOfGreetings (N requests → 1 reply).
   ----------------------------------------------------------------

   Names_Buf : String (1 .. 4096) := (others => ' ');
   Names_Last : Natural := 0;

   procedure CS_On_Request_Message (Message : RFLX.RFLX_Types.Bytes);
   procedure CS_On_Request_Message (Message : RFLX.RFLX_Types.Bytes) is
      Name_Buf : String (1 .. 256);
      Name_Last : Natural;
      OK : Boolean;
   begin
      Decode_Name_PB (Message, Name_Buf, Name_Last, OK);
      if OK and then Name_Last > 0 then
         if Names_Last > 0 then
            Names_Buf (Names_Last + 1 .. Names_Last + 2) := ", ";
            Names_Last := Names_Last + 2;
         end if;
         Names_Buf (Names_Last + 1 .. Names_Last + Name_Last) :=
           Name_Buf (1 .. Name_Last);
         Names_Last := Names_Last + Name_Last;
         Put_Line ("  ← request " & Name_Buf (1 .. Name_Last));
      end if;
   end CS_On_Request_Message;

   procedure CS_Build_Response
     (Request_Headers       : Http2_Core.Hpack.Header_Block;
      Request_Headers_Last  : Natural;
      Response_Headers      : in out Http2_Core.Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Response_Body         : in out RFLX.RFLX_Types.Bytes;
      Response_Body_Last    : out Natural;
      Trailers              : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last         : out Natural);

   procedure CS_Build_Response
     (Request_Headers       : Http2_Core.Hpack.Header_Block;
      Request_Headers_Last  : Natural;
      Response_Headers      : in out Http2_Core.Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Response_Body         : in out RFLX.RFLX_Types.Bytes;
      Response_Body_Last    : out Natural;
      Trailers              : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last         : out Natural)
   is
      pragma Unreferenced (Request_Headers);
      pragma Unreferenced (Request_Headers_Last);
      OK : Boolean;
      Out_Last : RFLX.RFLX_Types.Index;
   begin
      Set_Headers_And_Trailers
        (Response_Headers, Response_Headers_Last,
         Trailers, Trailers_Last);

      declare
         Greeting : constant String :=
           "Hello to all: " & Names_Buf (1 .. Names_Last) & "!";
      begin
         Encode_Reply (Greeting, Response_Body, Out_Last, OK);
         Response_Body_Last :=
           (if OK then Natural (Out_Last) else
              Integer (Response_Body'First) - 1);
         Put_Line ("  → " & Greeting);
      end;

      Names_Last := 0;  --  reset for next RPC
   end CS_Build_Response;

   ----------------------------------------------------------------
   --  Bidi: BidiHello (each ping → one pong).
   ----------------------------------------------------------------

   --  Single-element queue for "received name; ready to reply".
   Bidi_Pending_Name : String (1 .. 256) := (others => ' ');
   Bidi_Pending_Last : Natural := 0;

   procedure Bidi_Setup
     (Request_Headers       : Http2_Core.Hpack.Header_Block;
      Request_Headers_Last  : Natural;
      Response_Headers      : in out Http2_Core.Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Trailers              : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last         : out Natural);

   procedure Bidi_Setup
     (Request_Headers       : Http2_Core.Hpack.Header_Block;
      Request_Headers_Last  : Natural;
      Response_Headers      : in out Http2_Core.Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Trailers              : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last         : out Natural)
   is
      pragma Unreferenced (Request_Headers);
      pragma Unreferenced (Request_Headers_Last);
   begin
      Bidi_Pending_Last := 0;
      Set_Headers_And_Trailers
        (Response_Headers, Response_Headers_Last,
         Trailers, Trailers_Last);
   end Bidi_Setup;

   procedure Bidi_On_Msg (Message : RFLX.RFLX_Types.Bytes);
   procedure Bidi_On_Msg (Message : RFLX.RFLX_Types.Bytes) is
      OK : Boolean;
   begin
      Decode_Name_PB
        (Message, Bidi_Pending_Name, Bidi_Pending_Last, OK);
      if OK then
         Put_Line ("  ← " & Bidi_Pending_Name (1 .. Bidi_Pending_Last));
      else
         Bidi_Pending_Last := 0;
      end if;
   end Bidi_On_Msg;

   function Bidi_Next
     (Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out RFLX.RFLX_Types.Index)
      return Boolean;

   function Bidi_Next
     (Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out RFLX.RFLX_Types.Index)
      return Boolean
   is
      OK : Boolean;
   begin
      Out_Last := Out_Buf'First;
      if Bidi_Pending_Last = 0 then
         return False;  --  nothing pending; v0.2 caller alternates
      end if;
      Encode_Reply
        ("Hi, " & Bidi_Pending_Name (1 .. Bidi_Pending_Last) & "!",
         Out_Buf, Out_Last, OK);
      Put_Line ("  → Hi, "
                & Bidi_Pending_Name (1 .. Bidi_Pending_Last) & "!");
      Bidi_Pending_Last := 0;
      return OK;
   end Bidi_Next;

   ----------------------------------------------------------------

   procedure SS_Run is new
     Http2_Core.Server.Accept_And_Serve_Server_Stream
       (Setup_Response => SS_Setup,
        Next_Reply     => SS_Next);

   procedure CS_Run is new
     Http2_Core.Server.Accept_And_Serve_Client_Stream
       (On_Request_Message => CS_On_Request_Message,
        Build_Response     => CS_Build_Response);

   procedure Bidi_Run is new
     Http2_Core.Server.Accept_And_Serve_Bidi_Stream
       (Setup_Response     => Bidi_Setup,
        On_Request_Message => Bidi_On_Msg,
        Next_Reply         => Bidi_Next);

   Mode : String (1 .. 32) := (others => ' ');
   Mode_Last : Natural := 13;
   Port : Natural := 50_051;
begin
   Mode (1 .. 13) := "server-stream";
   if Ada.Command_Line.Argument_Count >= 1 then
      declare
         A : constant String := Ada.Command_Line.Argument (1);
      begin
         Mode := (others => ' ');
         Mode (1 .. A'Length) := A;
         Mode_Last := A'Length;
      end;
   end if;
   if Ada.Command_Line.Argument_Count >= 2 then
      Port := Natural'Value (Ada.Command_Line.Argument (2));
   end if;

   declare
      L : Http2_Core.Server.Listener;
      Buf : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. 16 * 1024 + 64 => 0);
      Inbound_Buf : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. 16 * 1024 + 64 => 0);
      Outgoing_Buf : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. 16 * 1024 + 64 => 0);
   begin
      Http2_Core.Server.Attach_Buffers
        (L, Buf, Inbound_Buf, Outgoing_Buf);
      Http2_Core.Server.Listen (L, "0.0.0.0", Port);
      Put_Line ("greeter_streaming_server: mode="
                & Mode (1 .. Mode_Last)
                & " port=" & Port'Image);

      loop
         Put_Line ("greeter_streaming_server: awaiting client...");
         if Mode (1 .. Mode_Last) = "server-stream" then
            SS_Run (L);
         elsif Mode (1 .. Mode_Last) = "client-stream" then
            CS_Run (L);
         elsif Mode (1 .. Mode_Last) = "bidi" then
            Bidi_Run (L);
         else
            Put_Line ("unknown mode: " & Mode (1 .. Mode_Last));
            exit;
         end if;
         Put_Line ("greeter_streaming_server: served one RPC");
      end loop;
   end;
end Greeter_Streaming_Server;
