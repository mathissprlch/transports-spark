--  GRPC.Transport
--
--  Abstract bidirectional stream over which gRPC frames flow. Each
--  active RPC owns one stream. Concrete implementations live in child
--  packages: GRPC.Transport.HTTP2 (over patched AWS), GRPC.Transport.Loopback
--  (in-process, used by tests).
--
--  Frame primitives are oriented at the gRPC layer, not HTTP/2 — the
--  transport hides framing details, including trailers.

with GRPC.Metadata;
with Protobuf.IO;

package GRPC.Transport is

   type Stream is limited interface;

   --  Server: send the initial response headers (`:status = 200`,
   --  `content-type`, custom). On the client this is implemented by the
   --  request initiator.
   procedure Send_Initial_Headers
     (S          : in out Stream;
      Headers    : GRPC.Metadata.Headers;
      End_Stream : Boolean) is abstract;

   --  Send a length-prefixed message payload. The transport handles the
   --  5-byte gRPC framing internally.
   procedure Send_Message
     (S          : in out Stream;
      Payload    : Protobuf.IO.Octet_Array;
      End_Stream : Boolean) is abstract;

   --  Send the final trailers and close the stream. On the wire this
   --  becomes an HTTP/2 trailer-HEADERS frame; on the loopback it's
   --  recorded into the peer's queue.
   procedure Send_Trailers
     (S          : in out Stream;
      Trailers   : GRPC.Metadata.Headers) is abstract;

   --  Receive APIs. Block until a frame is available; return False on
   --  end-of-stream.

   procedure Receive_Initial_Headers
     (S       : in out Stream;
      Headers : out GRPC.Metadata.Headers;
      Got     : out Boolean) is abstract;

   procedure Receive_Message
     (S       : in out Stream;
      Payload : out Protobuf.IO.Octet_Array;
      Last    : out Protobuf.IO.Octet_Count;
      Got     : out Boolean) is abstract;

   procedure Receive_Trailers
     (S        : in out Stream;
      Trailers : out GRPC.Metadata.Headers;
      Got      : out Boolean) is abstract;

end GRPC.Transport;
