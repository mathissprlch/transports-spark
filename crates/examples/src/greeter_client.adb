--  Hello-world gRPC client.
--
--  Hand-rolled stub today (codegen for the per-method stub lands next
--  phase). Issues an HTTP/2 POST to /helloworld.Greeter/SayHello with
--  the gRPC-framed request body, then unwraps the framed response.

with Ada.Streams;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO;

with AWS;
with AWS.Client;
with AWS.Headers;
with AWS.Response;

with GRPC.Channel;
with GRPC.Framing;

with Helloworld.Greeter;
with Helloworld.Hello_Reply;
with Helloworld.Hello_Request;

with Interfaces;
with Protobuf.IO;

procedure Greeter_Client is
   use Ada.Streams;
   use type Stream_Element_Offset;

   Channel : GRPC.Channel.Instance;
   Request : Helloworld.Hello_Request.T;
   Reply   : Helloworld.Hello_Reply.T;

   Max_Buffer : constant := 64 * 1024;

begin
   GRPC.Channel.Initialize (Channel, "localhost", 50_051);
   Request.Name := To_Unbounded_String ("World");

   --  Encode request -> protobuf -> gRPC frame.
   declare
      Payload : Protobuf.IO.Octet_Array (1 .. Max_Buffer);
      Cursor  : Protobuf.IO.Write_Cursor;
   begin
      Helloworld.Hello_Request.Encode (Request, Payload, Cursor);

      declare
         Frame  : Protobuf.IO.Octet_Array (1 .. Cursor.Position
                                              + Stream_Element_Offset
                                                  (GRPC.Framing.Header_Size));
         Header_Cursor : Protobuf.IO.Write_Cursor;
         URL    : constant String :=
           "http://" & To_String (Channel.Host) & ":"
           & Channel.Port'Image (Channel.Port'Image'First + 1
                                 .. Channel.Port'Image'Last)
           & Helloworld.Greeter.Path_Say_Hello;

         H : AWS.Headers.List := AWS.Client.Empty_Header_List;
         R : AWS.Response.Data;
      begin
         GRPC.Framing.Encode_Header
           (Buffer => Frame,
            Cursor => Header_Cursor,
            Length => Interfaces.Unsigned_32 (Cursor.Position),
            Flag   => 0);
         Frame
           (Frame'First + Stream_Element_Offset (GRPC.Framing.Header_Size)
            .. Frame'Last) := Payload (1 .. Cursor.Position);

         AWS.Headers.Add (H, "te", "trailers");
         AWS.Headers.Add (H, "grpc-encoding", "identity");

         R := AWS.Client.Post
           (URL          => URL,
            Data         => Frame,
            Content_Type => "application/grpc+proto",
            Headers      => H,
            HTTP_Version => AWS.HTTPv2);

         declare
            Body_Bytes : constant Stream_Element_Array :=
              AWS.Response.Message_Body (R);
            Read_Cursor : Protobuf.IO.Read_Cursor;
            Length      : Interfaces.Unsigned_32;
            Flag        : GRPC.Framing.Compression_Flag;
         begin
            if Body_Bytes'Length < GRPC.Framing.Header_Size then
               raise Program_Error with "response too short for gRPC frame";
            end if;

            GRPC.Framing.Decode_Header
              (Buffer => Body_Bytes,
               Cursor => Read_Cursor,
               Length => Length,
               Flag   => Flag);

            Helloworld.Hello_Reply.Decode
              (Body_Bytes
                 (Body_Bytes'First + Read_Cursor.Position
                  .. Body_Bytes'First + Read_Cursor.Position
                     + Stream_Element_Offset (Length) - 1),
               Reply);
         end;
      end;
   end;

   Ada.Text_IO.Put_Line ("Request:  " & To_String (Request.Name));
   Ada.Text_IO.Put_Line ("Reply:    " & To_String (Reply.Message));
end Greeter_Client;
