--  Http1_Core.Server — single-connection HTTP/1.1 server.
--
--  v0.3 scope: accept one client, read one request, dispatch via
--  Handle_Request, send one response, Connection: close, repeat.
--  Multi-client and keep-alive are v0.4 work.
--
--  Lifecycle:
--    1. Listen — bind + listen on host:port.
--    2. Accept_And_Serve — block until a client connects, read
--       one request, dispatch, write the response, close the
--       socket.
--    3. Stop — close listening socket.

with Http1_Core.Transport;
with Http1_Core.Wire;

package Http1_Core.Server is

   type Listener is limited private;

   procedure Listen
     (L    : in out Listener;
      Host : String;
      Port : Natural);

   --  Generic handler: invoked once per accepted connection. Receives
   --  the parsed request and fills response status / headers / body.
   --  Status default of 200 OK, content-type plain text. Caller may
   --  override.
   generic
      with procedure Handle_Request
        (Request           : Wire.Request;
         Request_Body      : Wire.Octet_Array;
         Response_Status   : out Natural;
         Response_Reason   : in out String;
         Reason_Last       : out Natural;
         Response_Headers      : in out Wire.Header_Block;
         Response_Headers_Last : out Natural;
         Response_Body         : in out Wire.Octet_Array;
         Response_Body_Last    : out Wire.Octet_Offset);
   procedure Accept_And_Serve (L : in out Listener);

   procedure Stop (L : in out Listener);

   Server_Error : exception;

private

   type Listener is limited record
      Trans : Transport.Listener;
   end record;

end Http1_Core.Server;
