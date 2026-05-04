--  greeter_mux_server — multi-stream HTTP/2 server.
--
--  v0.3 demo: a single connection accepts up to Max_Streams (16)
--  concurrent unary SayHello RPCs. Frames are demuxed by stream-id
--  into per-stream Stream::Open FSM contexts; handlers run inline
--  as soon as a stream's request body completes.
--
--  Run:
--    ./bin/greeter_mux_server [port]   # default 50051
--
--  Test (single):
--    grpcurl -plaintext -d '{"name":"X"}' \
--      -import-path crates/examples/proto -proto helloworld.proto \
--      127.0.0.1:50051 helloworld.Greeter/SayHello
--
--  Test (concurrent, requires Python grpcio):
--    python3 crates/examples/scripts/mux_client.py
--    — see scripts/mux_client.py for the concurrent-call demo.

with Ada.Text_IO;
with Ada.Command_Line;

with RFLX.RFLX_Types;

with Http2_Core.Hpack;
with Http2_Core.Mux_Server;
with Protobuf_Core.Wire;

procedure Greeter_Mux_Server is
   use Ada.Text_IO;
   use type RFLX.RFLX_Types.Index;

   --  Decode HelloRequest.name from a body (5-byte gRPC prefix +
   --  protobuf message).
   procedure Decode_Name
     (Body_Bytes : RFLX.RFLX_Types.Bytes;
      Name_Buf   : out String;
      Name_Last  : out Natural;
      OK         : out Boolean);

   procedure Decode_Name
     (Body_Bytes : RFLX.RFLX_Types.Bytes;
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
      if Body_Bytes'Length < 7 then return; end if;
      declare
         PB : constant RFLX.RFLX_Types.Bytes :=
           Body_Bytes (Body_Bytes'First + 5 .. Body_Bytes'Last);
      begin
         Protobuf_Core.Wire.Decode_Tag
           (PB, PB'First, Field_Num, Wire_Tp, Tag_Last, Tag_OK);
         if not Tag_OK or else Field_Num /= 1
           or else Wire_Tp /= Protobuf_Core.Wire.Wire_Length_Delim
         then return; end if;
         Protobuf_Core.Wire.Decode_String_Value
           (PB, Tag_Last + 1, Name_Buf, Name_Last, Str_End, OK);
      end;
   end Decode_Name;

   procedure Encode_Reply
     (Text     : String;
      Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out Natural;
      OK       : out Boolean);

   procedure Encode_Reply
     (Text     : String;
      Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out Natural;
      OK       : out Boolean)
   is
      PB_Buf  : RFLX.RFLX_Types.Bytes (1 .. 1024) := (others => 0);
      PB_Last : RFLX.RFLX_Types.Index;
   begin
      Out_Last := Integer (Out_Buf'First) - 1;
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
         Out_Last := Integer (Out_Buf'First) + 4 + Len;
      end;
   end Encode_Reply;

   ----------------------------------------------------------------
   --  Handler: one SayHello call.
   ----------------------------------------------------------------

   Call_Counter : Natural := 0;

   procedure Handle_SayHello
     (Request_Headers       : Http2_Core.Hpack.Header_Block;
      Request_Headers_Last  : Natural;
      Request_Body          : RFLX.RFLX_Types.Bytes;
      Request_Body_Last     : Natural;
      Response_Headers      : in out Http2_Core.Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Response_Body         : in out RFLX.RFLX_Types.Bytes;
      Response_Body_Last    : out Natural;
      Trailers              : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last         : out Natural);

   procedure Handle_SayHello
     (Request_Headers       : Http2_Core.Hpack.Header_Block;
      Request_Headers_Last  : Natural;
      Request_Body          : RFLX.RFLX_Types.Bytes;
      Request_Body_Last     : Natural;
      Response_Headers      : in out Http2_Core.Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Response_Body         : in out RFLX.RFLX_Types.Bytes;
      Response_Body_Last    : out Natural;
      Trailers              : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last         : out Natural)
   is
      pragma Unreferenced (Request_Headers);
      pragma Unreferenced (Request_Headers_Last);
      pragma Unreferenced (Request_Body_Last);
      Name : String (1 .. 256);
      Name_Last : Natural;
      OK : Boolean;
   begin
      Decode_Name (Request_Body, Name, Name_Last, OK);
      if not OK then
         Name (1 .. 7) := "Unknown"; Name_Last := 7;
      end if;
      Call_Counter := Call_Counter + 1;
      Put_Line ("  ← call#" & Call_Counter'Image
                & " name=" & Name (1 .. Name_Last));

      Encode_Reply
        (Text     => "Hello, " & Name (1 .. Name_Last) & "!",
         Out_Buf  => Response_Body,
         Out_Last => Response_Body_Last,
         OK       => OK);

      Response_Headers (Response_Headers'First) :=
        Http2_Core.Hpack.Make_Header (":status", "200");
      Response_Headers (Response_Headers'First + 1) :=
        Http2_Core.Hpack.Make_Header
          ("content-type", "application/grpc");
      Response_Headers_Last := Response_Headers'First + 1;
      Trailers (Trailers'First) :=
        Http2_Core.Hpack.Make_Header ("grpc-status", "0");
      Trailers_Last := Trailers'First;
   end Handle_SayHello;

   procedure Mux_Run is new Http2_Core.Mux_Server.Accept_And_Serve_Multi
     (Handle_Request => Handle_SayHello);

   ----------------------------------------------------------------

   L : Http2_Core.Mux_Server.Listener;

   Buffer_Size : constant := 16384;
   Conn_Buf : RFLX.RFLX_Types.Bytes_Ptr :=
     new RFLX.RFLX_Types.Bytes'(1 .. Buffer_Size => 0);

   Port : Natural := 50051;
begin
   if Ada.Command_Line.Argument_Count >= 1 then
      Port := Natural'Value (Ada.Command_Line.Argument (1));
   end if;

   Http2_Core.Mux_Server.Listen (L, "0.0.0.0", Port);
   Http2_Core.Mux_Server.Attach_Buffer (L, Conn_Buf);

   Put_Line ("greeter_mux_server: listening on 0.0.0.0:"
             & Port'Image & " (max"
             & Http2_Core.Mux_Server.Max_Streams'Image
             & " concurrent streams per connection)");

   loop
      Put_Line ("greeter_mux_server: awaiting client...");
      begin
         Mux_Run (L);
         Put_Line ("greeter_mux_server: connection closed (served"
                   & Call_Counter'Image & " RPCs total)");
      exception
         when others =>
            Put_Line ("greeter_mux_server: connection error, retrying");
      end;
   end loop;
end Greeter_Mux_Server;
