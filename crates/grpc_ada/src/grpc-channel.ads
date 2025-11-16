--  GRPC.Channel
--
--  Client-side connection to a single gRPC endpoint. Thin wrapper that
--  records the target host/port and serves as the parent for stubs.
--  Connection lifetime + transport selection live in the concrete
--  GRPC.Transport.HTTP2.Channel implementation; this is the API.

with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;

package GRPC.Channel is

   type Scheme_Type is (HTTP, HTTPS);

   type Instance is tagged limited record
      Host       : Unbounded_String;
      Port       : Positive := 80;
      Scheme     : Scheme_Type := HTTP;
      Authority  : Unbounded_String;   --  host:port, used in :authority
   end record;

   procedure Initialize
     (C       : in out Instance;
      Host    : String;
      Port    : Positive;
      Scheme  : Scheme_Type := HTTP);

end GRPC.Channel;
