--  GRPC.Transport.HTTP2
--
--  Concrete transport over the patched AWS HTTP/2 server. Each AWS
--  callback invocation produces one Stream instance bound to that
--  request; the gRPC dispatcher reads the request body via Receive_*
--  and writes the response via Send_*. The trailer HEADERS frame is
--  produced by AWS once Send_Trailers is called and the AWS callback
--  returns the response.
--
--  Body is currently a stub — wiring lands when the AWS build
--  environment is unblocked (see docs/aws-integration.md). Higher
--  layers (Server, Channel, generated code) are unaffected: they
--  speak only to GRPC.Transport.Stream'Class.

with Ada.Strings.Unbounded;
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

   type Server_Stream is limited new GRPC.Transport.Stream with record
      Path             : Ada.Strings.Unbounded.Unbounded_String;
      --  Inbound + outbound message queues, AWS request/response handles,
      --  and flow-control state attach here once the body is written.
      Headers_Sent     : Boolean := False;
      Trailers_Sent    : Boolean := False;
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
     (S          : in out Server_Stream;
      Trailers   : GRPC.Metadata.Headers);

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
