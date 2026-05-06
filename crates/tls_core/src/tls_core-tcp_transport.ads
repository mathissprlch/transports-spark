--  Tls_Core.Tcp_Transport — blocking TCP socket adapter for TLS records.
--
--  Wraps GNAT.Sockets behind an `Octet_Array`-shaped API so the rest
--  of tls_core never sees Stream_Element_Array. Single-connection by
--  design: matches what the in-process Tls_Core.Transport.Pipe does
--  for the loopback test, but the bytes go through a real localhost
--  TCP socket instead of an in-memory queue.
--
--  Style mirrored from Http2_Core.Transport (transport_tcp/) — same
--  Channel + Listener split, same Connect / Listen / Accept_One /
--  Send_All / Recv_All / Close shape. Dropped the bells and whistles
--  (Has_Pending, Wait_For_Data) since the loopback test has no use
--  for non-blocking polling.
--
--  Read framing helpers: TCP is a byte stream; the TLS handshake
--  messages have a 4-byte header (1 byte type + 3 bytes u24 length)
--  and TLSCiphertext records have a 5-byte header. Recv_All loops
--  on Receive_Socket until exactly Length bytes are delivered, so
--  the caller can read a header first, then the body.
--
--  SPARK_Mode => Off — GNAT.Sockets is not in SPARK; the wrapper
--  itself is consumed from SPARK-friendly code but its body lives
--  outside the verified perimeter (same arrangement as Channel).

private with GNAT.Sockets;

package Tls_Core.Tcp_Transport
with SPARK_Mode => Off
is

   --  A connected TCP endpoint (either side of an established link).
   type Channel is limited private;

   --  Open a blocking TCP connection to `Host:Port`. Raises
   --  Connect_Error on DNS, refused, or unreachable failures.
   procedure Connect
     (Chan : in out Channel;
      Host : String;
      Port : Natural);

   function Is_Open (Chan : Channel) return Boolean;

   --  Send all of `Data` synchronously. Raises Send_Error on
   --  short-write or socket error.
   procedure Send_All
     (Chan : Channel;
      Data : Octet_Array)
   with Pre => Is_Open (Chan);

   --  Read exactly `Buffer'Length` bytes (loops over Receive_Socket
   --  until the buffer fills or the peer closes). Sets
   --  Success := False on EOF before the buffer was filled or any
   --  socket error.
   procedure Recv_All
     (Chan    : Channel;
      Buffer  : out Octet_Array;
      Success : out Boolean)
   with Pre => Is_Open (Chan);

   procedure Close (Chan : in out Channel)
   with
     Pre  => Is_Open (Chan),
     Post => not Is_Open (Chan);

   --  Server side: a Listener owns a bound + listening TCP socket.
   --  Listen on `Host:Port`. Use Port = 0 to let the OS pick a free
   --  port; query the chosen port back via Bound_Port. Accept_One
   --  blocks until a client connects and fills `Chan` with the
   --  accepted connection.
   type Listener is limited private;

   procedure Listen
     (L    : in out Listener;
      Host : String;
      Port : Natural);

   function Is_Listening (L : Listener) return Boolean;

   --  After Listen, return the actual port number the kernel bound
   --  the listening socket to. Useful when Listen was called with
   --  Port = 0 (ephemeral / OS-assigned port).
   function Bound_Port (L : Listener) return Natural
   with Pre => Is_Listening (L);

   procedure Accept_One
     (L    : in out Listener;
      Chan : in out Channel)
   with
     Pre  => Is_Listening (L),
     Post => Is_Open (Chan);

   procedure Stop (L : in out Listener)
   with
     Pre  => Is_Listening (L),
     Post => not Is_Listening (L);

   Connect_Error : exception;
   Send_Error    : exception;
   Recv_Error    : exception;

private

   type Channel is limited record
      Socket : GNAT.Sockets.Socket_Type;
      Open   : Boolean := False;
   end record;

   type Listener is limited record
      Socket    : GNAT.Sockets.Socket_Type;
      Port      : Natural := 0;
      Listening : Boolean := False;
   end record;

end Tls_Core.Tcp_Transport;
