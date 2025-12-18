--  GRPC.Transport.HTTP2
--
--  Concrete transport over the patched AWS HTTP/2 server. Each AWS
--  callback invocation produces one Stream instance bound to that
--  request; the gRPC dispatcher reads the request body via Receive_*
--  and writes the response via Send_*. The trailer HEADERS frame is
--  produced by AWS once Send_Trailers is called and the AWS callback
--  returns the response.
--
--  v0.1 supports unary RPCs end-to-end. Streaming methods plug in at
--  the Send_Message / Receive_Message boundary in a later phase.

with Ada.Strings.Unbounded;
with Ada.Streams;
with GRPC.Metadata;
with GRPC.Server;
with Protobuf.IO;

package GRPC.Transport.HTTP2 is

   type Server_Stream is limited new GRPC.Transport.Stream with private;

   --  Run an HTTP/2 server using the registered handlers in S until
   --  Stop is called. Blocks the caller. AWS owns the listen socket;
   --  per-stream tasks are spawned by AWS and bridged into our
   --  Server.Method_Handler dispatch.
   procedure Run
     (S : in out GRPC.Server.Instance);

   procedure Stop
     (S : in out GRPC.Server.Instance);

private

   type Octet_Array_Access is access Ada.Streams.Stream_Element_Array;

   type Server_Stream is limited new GRPC.Transport.Stream with record
      Path              : Ada.Strings.Unbounded.Unbounded_String;

      --  Inbound (set up by the AWS callback before dispatch):
      Request_Headers   : GRPC.Metadata.Headers;
      Request_Body      : Octet_Array_Access;
      Request_Consumed  : Boolean := False;

      --  Outbound (populated by the handler, harvested after it returns):
      Response_Headers  : GRPC.Metadata.Headers;
      Response_Body     : Octet_Array_Access;
      Response_Length   : Ada.Streams.Stream_Element_Count := 0;
      Response_Trailers : GRPC.Metadata.Headers;

      Headers_Sent      : Boolean := False;
      Trailers_Sent     : Boolean := False;
   end record;

   overriding procedure Send_Initial_Headers
     (S          : in out Server_Stream;
      Headers    : GRPC.Metadata.Headers;
      End_Stream : Boolean);

   overriding procedure Send_Message
     (S          : in out Server_Stream;
      Payload    : Protobuf.IO.Octet_Array;
      End_Stream : Boolean);

   overriding procedure Send_Trailers
     (S        : in out Server_Stream;
      Trailers : GRPC.Metadata.Headers);

   overriding procedure Receive_Initial_Headers
     (S       : in out Server_Stream;
      Headers : out GRPC.Metadata.Headers;
      Got     : out Boolean);

   overriding procedure Receive_Message
     (S       : in out Server_Stream;
      Payload : out Protobuf.IO.Octet_Array;
      Last    : out Protobuf.IO.Octet_Count;
      Got     : out Boolean);

   overriding procedure Receive_Trailers
     (S        : in out Server_Stream;
      Trailers : out GRPC.Metadata.Headers;
      Got      : out Boolean);

end GRPC.Transport.HTTP2;
