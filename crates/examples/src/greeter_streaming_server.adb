--  greeter_streaming_server — Ada gRPC server-streaming demo.
--
--  Implements helloworld.Greeter/LotsOfReplies: server takes one
--  HelloRequest, streams 5 HelloReply messages back, then trailers
--  with grpc-status=0.
--
--  Run:
--    ./bin/greeter_streaming_server [port]    # default 50051
--
--  Test:
--    grpcurl -plaintext -d '{"name":"X"}' \
--      -import-path crates/examples/proto -proto helloworld.proto \
--      127.0.0.1:50051 helloworld.Greeter/LotsOfReplies
--
--  v0.2 server-streaming uses Http2_Core.Server.Accept_And_Serve_Server_Stream.

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

   Total_Replies : constant := 5;
   Reply_Counter : Natural := 0;
   Cached_Name   : String (1 .. 256) := (others => ' ');
   Cached_Name_Last : Natural := 0;

   --  Decode HelloRequest.name from request body.
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
      if Body_Bytes'Length < 6 then return; end if;
      declare
         PB_View : constant RFLX.RFLX_Types.Bytes :=
           Body_Bytes (Body_Bytes'First + 5 .. Body_Bytes'Last);
      begin
         Protobuf_Core.Wire.Decode_Tag
           (PB_View, PB_View'First, Field_Num, Wire_Tp, Tag_Last, Tag_OK);
         if not Tag_OK or else Field_Num /= 1
           or else Wire_Tp /= Protobuf_Core.Wire.Wire_Length_Delim
         then return; end if;
         Protobuf_Core.Wire.Decode_String_Value
           (PB_View, Tag_Last + 1, Name_Buf, Name_Last, Str_End, OK);
      end;
   end Decode_Name;

   --  Encode "Hello, <name>! [N/Total]" as gRPC-framed HelloReply.
   procedure Encode_Reply
     (Idx        : Natural;
      Out_Buf    : in out RFLX.RFLX_Types.Bytes;
      Out_Last   : out RFLX.RFLX_Types.Index;
      OK         : out Boolean);

   procedure Encode_Reply
     (Idx        : Natural;
      Out_Buf    : in out RFLX.RFLX_Types.Bytes;
      Out_Last   : out RFLX.RFLX_Types.Index;
      OK         : out Boolean)
   is
      use Ada.Strings.Fixed;
      Idx_Str   : constant String := Trim (Idx'Image, Ada.Strings.Both);
      Total_Str : constant String :=
        Trim (Total_Replies'Image, Ada.Strings.Both);
      Reply_Msg : constant String :=
        "Hello, "
        & Cached_Name (1 .. Cached_Name_Last)
        & "! [" & Idx_Str & "/" & Total_Str & "]";

      PB_Buf  : RFLX.RFLX_Types.Bytes (1 .. 1024) := (others => 0);
      PB_Last : RFLX.RFLX_Types.Index;
   begin
      Out_Last := Out_Buf'First;
      Protobuf_Core.Wire.Encode_String_Field
        (PB_Buf, PB_Buf'First, 1, Reply_Msg, PB_Last, OK);
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

   procedure Setup_Response
     (Request_Headers       : Http2_Core.Hpack.Header_Block;
      Request_Headers_Last  : Natural;
      Request_Body          : RFLX.RFLX_Types.Bytes;
      Request_Body_Last     : Natural;
      Response_Headers      : in out Http2_Core.Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Trailers              : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last         : out Natural);

   procedure Setup_Response
     (Request_Headers       : Http2_Core.Hpack.Header_Block;
      Request_Headers_Last  : Natural;
      Request_Body          : RFLX.RFLX_Types.Bytes;
      Request_Body_Last     : Natural;
      Response_Headers      : in out Http2_Core.Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Trailers              : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last         : out Natural)
   is
      pragma Unreferenced (Request_Body_Last);
      Path : String (1 .. 256) := (others => ' ');
      Path_Len : Natural := 0;
      OK : Boolean;
   begin
      for I in Request_Headers'First .. Request_Headers_Last loop
         declare
            H : Http2_Core.Hpack.Header_Field renames Request_Headers (I);
         begin
            if H.Name (1 .. H.Name_Last) = ":path" then
               Path (1 .. H.Value_Last) := H.Value (1 .. H.Value_Last);
               Path_Len := H.Value_Last;
            end if;
         end;
      end loop;
      Put_Line ("  request path: " & Path (1 .. Path_Len));

      Decode_Name
        (Request_Body, Cached_Name, Cached_Name_Last, OK);
      if not OK then
         Cached_Name (1 .. 7) := "Unknown";
         Cached_Name_Last := 7;
      end if;
      Put_Line ("  decoded name: "
                & Cached_Name (1 .. Cached_Name_Last)
                & " (will stream "
                & Total_Replies'Image
                & " replies)");

      Reply_Counter := 0;

      Response_Headers (Response_Headers'First) :=
        Http2_Core.Hpack.Make_Header (":status", "200");
      Response_Headers (Response_Headers'First + 1) :=
        Http2_Core.Hpack.Make_Header ("content-type", "application/grpc");
      Response_Headers_Last := Response_Headers'First + 1;

      Trailers (Trailers'First) :=
        Http2_Core.Hpack.Make_Header ("grpc-status", "0");
      Trailers_Last := Trailers'First;
   end Setup_Response;

   function Next_Reply
     (Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out RFLX.RFLX_Types.Index)
      return Boolean;

   function Next_Reply
     (Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out RFLX.RFLX_Types.Index)
      return Boolean
   is
      OK : Boolean;
   begin
      Out_Last := Out_Buf'First;
      if Reply_Counter >= Total_Replies then
         return False;
      end if;
      Reply_Counter := Reply_Counter + 1;
      Encode_Reply (Reply_Counter, Out_Buf, Out_Last, OK);
      Put_Line ("  → reply" & Reply_Counter'Image);
      return OK;
   end Next_Reply;

   procedure Serve is new
     Http2_Core.Server.Accept_And_Serve_Server_Stream
       (Setup_Response => Setup_Response,
        Next_Reply     => Next_Reply);

begin
   declare
      Port : Natural := 50_051;
      L : Http2_Core.Server.Listener;
      Buf : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. 16 * 1024 + 64 => 0);
      Inbound_Buf : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. 16 * 1024 + 64 => 0);
      Outgoing_Buf : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. 16 * 1024 + 64 => 0);
   begin
      if Ada.Command_Line.Argument_Count >= 1 then
         Port := Natural'Value (Ada.Command_Line.Argument (1));
      end if;

      Http2_Core.Server.Attach_Buffers
        (L, Buf, Inbound_Buf, Outgoing_Buf);
      Http2_Core.Server.Listen (L, "0.0.0.0", Port);
      Put_Line ("greeter_streaming_server: listening on 0.0.0.0:"
                & Port'Image);
      loop
         Put_Line ("greeter_streaming_server: awaiting client...");
         Serve (L);
         Put_Line ("greeter_streaming_server: served one streaming RPC");
      end loop;
   end;
end Greeter_Streaming_Server;
