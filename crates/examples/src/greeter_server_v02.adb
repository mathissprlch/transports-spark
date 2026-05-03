--  greeter_server_v02 — first Ada-implemented gRPC server in the
--  v0.2 SPARK stack. Serves helloworld.Greeter/SayHello, returns
--  one HelloReply per request, then closes the stream.
--
--  Single-stream, single-client at a time (v0.2 limit). Hosted only;
--  uses GNAT.Sockets via Http2_Core.Transport.
--
--  Verified against:
--    * grpcurl -plaintext localhost:50051 helloworld.Greeter/SayHello
--      -d '{"name":"X"}'
--    * Python helloworld_pb2_grpc client

with Ada.Text_IO;
with Ada.Command_Line;

with RFLX.RFLX_Types;

with Http2_Core.Hpack;
with Http2_Core.Server;
with Protobuf_Core.Wire;

procedure Greeter_Server_V02 is
   use Ada.Text_IO;
   use type RFLX.RFLX_Types.Index;

   --  Strip the 5-byte gRPC framing prefix and decode the
   --  HelloRequest's string field 1 → Name.
   procedure Decode_Hello_Request
     (Body_Bytes : RFLX.RFLX_Types.Bytes;
      Name_Buf   : out String;
      Name_Last  : out Natural;
      OK         : out Boolean);

   procedure Decode_Hello_Request
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
      if Body_Bytes'Length < 6 then
         return;  --  must have 5-byte gRPC prefix + at least 1 protobuf byte
      end if;
      --  Skip 5-byte gRPC prefix (1B compression + 4B BE length).
      declare
         PB_View : constant RFLX.RFLX_Types.Bytes :=
           Body_Bytes (Body_Bytes'First + 5 .. Body_Bytes'Last);
      begin
         if PB_View'Length = 0 then
            return;
         end if;
         Protobuf_Core.Wire.Decode_Tag
           (PB_View, PB_View'First, Field_Num, Wire_Tp, Tag_Last, Tag_OK);
         if not Tag_OK or else Field_Num /= 1
            or else Wire_Tp /= Protobuf_Core.Wire.Wire_Length_Delim
         then
            return;
         end if;
         Protobuf_Core.Wire.Decode_String_Value
           (PB_View, Tag_Last + 1, Name_Buf, Name_Last,
            Str_End, OK);
      end;
   end Decode_Hello_Request;

   --  Encode HelloReply{message=...} into a gRPC-framed body.
   procedure Encode_Hello_Reply
     (Message    : String;
      Out_Buf    : in out RFLX.RFLX_Types.Bytes;
      Out_Last   : out Natural;
      OK         : out Boolean);

   procedure Encode_Hello_Reply
     (Message    : String;
      Out_Buf    : in out RFLX.RFLX_Types.Bytes;
      Out_Last   : out Natural;
      OK         : out Boolean)
   is
      PB_Buf  : RFLX.RFLX_Types.Bytes (1 .. 1024) := (others => 0);
      PB_Last : RFLX.RFLX_Types.Index;
   begin
      Out_Last := Integer (Out_Buf'First) - 1;
      Protobuf_Core.Wire.Encode_String_Field
        (PB_Buf, PB_Buf'First, 1, Message, PB_Last, OK);
      if not OK then return; end if;
      declare
         Len : constant Natural := Natural (PB_Last);
      begin
         Out_Buf (Out_Buf'First) := 0;  --  compression flag
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
   end Encode_Hello_Reply;

   --  Handler: dispatch by :path (only SayHello supported in v0.2).
   procedure Handle_Request
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

   procedure Handle_Request
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
      pragma Unreferenced (Request_Body_Last);
      Path : String (1 .. 256) := (others => ' ');
      Path_Len : Natural := 0;
      Name_Buf : String (1 .. 256) := (others => ' ');
      Name_Last : Natural := 0;
      Decode_OK : Boolean;
      Reply_OK  : Boolean;
   begin
      --  Find :path header.
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

      --  Decode HelloRequest from the body.
      Decode_Hello_Request
        (Request_Body, Name_Buf, Name_Last, Decode_OK);
      if not Decode_OK then
         Put_Line ("  decode HelloRequest failed");
         Name_Buf (1 .. 7) := "Unknown";
         Name_Last := 7;
      else
         Put_Line ("  decoded name: " & Name_Buf (1 .. Name_Last));
      end if;

      Response_Headers (Response_Headers'First) :=
        Http2_Core.Hpack.Make_Header (":status", "200");
      Response_Headers (Response_Headers'First + 1) :=
        Http2_Core.Hpack.Make_Header ("content-type", "application/grpc");
      Response_Headers_Last := Response_Headers'First + 1;

      --  Build response body: "Hello, <Name>!"
      declare
         Reply_Msg : String (1 .. 256) := (others => ' ');
         Reply_Msg_Last : Natural;
         Prefix : constant String := "Hello, ";
         Suffix : constant String := "!";
      begin
         Reply_Msg (1 .. Prefix'Length) := Prefix;
         Reply_Msg (Prefix'Length + 1 ..
                      Prefix'Length + Name_Last) :=
           Name_Buf (1 .. Name_Last);
         Reply_Msg (Prefix'Length + Name_Last + 1 ..
                      Prefix'Length + Name_Last + Suffix'Length) :=
           Suffix;
         Reply_Msg_Last := Prefix'Length + Name_Last + Suffix'Length;
         Encode_Hello_Reply
           (Reply_Msg (1 .. Reply_Msg_Last),
            Response_Body, Response_Body_Last, Reply_OK);
         if not Reply_OK then
            Put_Line ("  encode HelloReply failed");
         else
            Put_Line ("  reply: " & Reply_Msg (1 .. Reply_Msg_Last));
         end if;
      end;

      --  Trailers: grpc-status = 0 (OK).
      Trailers (Trailers'First) :=
        Http2_Core.Hpack.Make_Header ("grpc-status", "0");
      Trailers_Last := Trailers'First;
   end Handle_Request;

begin
   declare
      L : Http2_Core.Server.Listener;
      Buf : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. 16 * 1024 + 64 => 0);
      Inbound_Buf : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. 16 * 1024 + 64 => 0);
      Outgoing_Buf : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. 16 * 1024 + 64 => 0);

      procedure Serve_One is new Http2_Core.Server.Accept_And_Serve
        (Handle_Request => Handle_Request);

      Port : Natural := 50_051;
   begin
      if Ada.Command_Line.Argument_Count >= 1 then
         Port := Natural'Value (Ada.Command_Line.Argument (1));
      end if;

      Http2_Core.Server.Attach_Buffers
        (L, Buf, Inbound_Buf, Outgoing_Buf);
      Http2_Core.Server.Listen (L, "0.0.0.0", Port);
      Put_Line ("greeter_server_v02: listening on 0.0.0.0:" & Port'Image);

      loop
         Put_Line ("greeter_server_v02: awaiting client...");
         Serve_One (L);
         Put_Line ("greeter_server_v02: served one RPC");
      end loop;
   end;
end Greeter_Server_V02;
