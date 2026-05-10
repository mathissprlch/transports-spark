--  greeter_server_tls -- gRPC SayHello served over TLS 1.3.
--
--  Same logic as greeter_server_v02, but the transport layer is our
--  pure-Ada/SPARK TLS 1.3. Build with -XTRANSPORT=tls.
--
--  Verified against:
--    grpcurl -insecure localhost:50051 helloworld.Greeter/SayHello \
--      -d '{"name":"TLS"}'

with Ada.Text_IO;
with Ada.Command_Line;
with Ada.Directories;
with Ada.Streams.Stream_IO;

with RFLX.RFLX_Types;

with Http2_Core.Hpack;
with Http2_Core.Server;
with Http2_Core.Transport;
with Protobuf_Core.Wire;

procedure Greeter_Server_Tls is
   use Ada.Text_IO;
   use type RFLX.RFLX_Types.Index;

   Cert_Path : constant String :=
     "../tls_core/tests/fixtures/interop/ec/leaf.der";
   Key_Path  : constant String :=
     "../tls_core/tests/fixtures/interop/ec/leaf.priv";
   Root_Path : constant String :=
     "../tls_core/tests/fixtures/interop/ec/root.der";

   function Load_File (Path : String) return RFLX.RFLX_Types.Bytes;
   function Load_File (Path : String) return RFLX.RFLX_Types.Bytes is
      use Ada.Streams;
      F     : Ada.Streams.Stream_IO.File_Type;
      Sz    : constant Natural :=
        Natural (Ada.Directories.Size (Path));
      Buf   : Stream_Element_Array (1 .. Stream_Element_Offset (Sz));
      Last  : Stream_Element_Offset;
      Result : RFLX.RFLX_Types.Bytes (1 .. RFLX.RFLX_Types.Index (Sz));
   begin
      Ada.Streams.Stream_IO.Open (F, Ada.Streams.Stream_IO.In_File, Path);
      Ada.Streams.Read (Ada.Streams.Stream_IO.Stream (F).all, Buf, Last);
      Ada.Streams.Stream_IO.Close (F);
      for I in Result'Range loop
         Result (I) := RFLX.RFLX_Types.Byte (
           Buf (Stream_Element_Offset (I)));
      end loop;
      return Result;
   end Load_File;

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
      if Body_Bytes'Length < 6 then return; end if;
      declare
         PB_View : constant RFLX.RFLX_Types.Bytes :=
           Body_Bytes (Body_Bytes'First + 5 .. Body_Bytes'Last);
      begin
         if PB_View'Length = 0 then return; end if;
         Protobuf_Core.Wire.Decode_Tag
           (PB_View, PB_View'First, Field_Num, Wire_Tp, Tag_Last, Tag_OK);
         if not Tag_OK or else Field_Num /= 1
            or else Wire_Tp /= Protobuf_Core.Wire.Wire_Length_Delim
         then return; end if;
         Protobuf_Core.Wire.Decode_String_Value
           (PB_View, Tag_Last + 1, Name_Buf, Name_Last, Str_End, OK);
      end;
   end Decode_Hello_Request;

   procedure Encode_Hello_Reply
     (Message  : String;
      Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out Natural;
      OK       : out Boolean);
   procedure Encode_Hello_Reply
     (Message  : String;
      Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out Natural;
      OK       : out Boolean)
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
   end Encode_Hello_Reply;

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
      pragma Unreferenced (Request_Headers_Last, Request_Body_Last);
      Name_Buf  : String (1 .. 256) := (others => ' ');
      Name_Last : Natural := 0;
      Decode_OK : Boolean;
      Reply_OK  : Boolean;
   begin
      Decode_Hello_Request (Request_Body, Name_Buf, Name_Last, Decode_OK);
      if not Decode_OK then
         Name_Buf (1 .. 7) := "Unknown";
         Name_Last := 7;
      end if;
      Put_Line ("  request name: " & Name_Buf (1 .. Name_Last));

      Response_Headers (Response_Headers'First) :=
        Http2_Core.Hpack.Make_Header (":status", "200");
      Response_Headers (Response_Headers'First + 1) :=
        Http2_Core.Hpack.Make_Header ("content-type", "application/grpc");
      Response_Headers_Last := Response_Headers'First + 1;

      declare
         Msg : constant String :=
           "Hello, " & Name_Buf (1 .. Name_Last) & "!";
      begin
         Encode_Hello_Reply (Msg, Response_Body, Response_Body_Last, Reply_OK);
         if Reply_OK then
            Put_Line ("  reply: " & Msg);
         end if;
      end;

      Trailers (Trailers'First) :=
        Http2_Core.Hpack.Make_Header ("grpc-status", "0");
      Trailers_Last := Trailers'First;
   end Handle_Request;

begin
   declare
      L   : aliased Http2_Core.Server.Listener;
      Buf : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. 16 * 1024 + 64 => 0);
      Inbound_Buf : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. 16 * 1024 + 64 => 0);
      Outgoing_Buf : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. 16 * 1024 + 64 => 0);

      procedure Serve_One is new Http2_Core.Server.Accept_And_Serve
        (Handle_Request => Handle_Request);

      Port : Natural := 50_051;

      Cert_Der : constant RFLX.RFLX_Types.Bytes := Load_File (Cert_Path);
      Key_Raw  : constant RFLX.RFLX_Types.Bytes := Load_File (Key_Path);
   begin
      if Ada.Command_Line.Argument_Count >= 1 then
         Port := Natural'Value (Ada.Command_Line.Argument (1));
      end if;

      Http2_Core.Transport.Set_Server_Identity
        (Http2_Core.Server.Get_Transport (L).all,
         Cert_Der, Key_Raw);

      Http2_Core.Server.Attach_Buffers (L, Buf, Inbound_Buf, Outgoing_Buf);
      Http2_Core.Server.Listen (L, "0.0.0.0", Port);
      Put_Line ("greeter_server_tls: listening on :" & Port'Image & " (TLS 1.3)");

      loop
         Put_Line ("greeter_server_tls: awaiting client...");
         Serve_One (L);
         Put_Line ("greeter_server_tls: served one RPC");
      end loop;
   end;
end Greeter_Server_Tls;
