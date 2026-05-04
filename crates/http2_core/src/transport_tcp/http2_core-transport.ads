--  Http2_Core.Transport — blocking TCP socket adapter.
--
--  Wraps GNAT.Sockets behind an `RFLX_Types.Bytes`-shaped API so the
--  rest of http2_core never sees Stream_Element_Array. Single-connection
--  by design; the v0.2 client uses one TCP socket per session.
--
--  TLS is out of scope (per docs/scope) — production deployments put a
--  TLS-terminating gateway in front of the broker, or use mbedTLS as
--  a black box on bare metal.

with RFLX.RFLX_Types;
private with GNAT.Sockets;

package Http2_Core.Transport is

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
   procedure Send
     (Chan : Channel;
      Data : RFLX.RFLX_Types.Bytes)
   with Pre => Is_Open (Chan);

   --  Read up to `Buffer'Length` bytes; `Last` is the index of the
   --  last byte filled (Buffer'First - 1 if zero bytes were read).
   --  Sets Success := False on EOF / socket error.
   procedure Receive
     (Chan    : Channel;
      Buffer  : out RFLX.RFLX_Types.Bytes;
      Last    : out RFLX.RFLX_Types.Index;
      Success : out Boolean)
   with Pre => Is_Open (Chan);

   --  Non-blocking poll: returns True iff a subsequent Receive would
   --  not block (either bytes are queued or the peer has FIN'd).
   --  Backed by a persistent Selector created in Connect/Accept_One;
   --  no per-call file-descriptor churn.
   function Has_Pending (Chan : Channel) return Boolean
   with Pre => Is_Open (Chan);

   --  Block (up to Timeout seconds) waiting for the channel to
   --  become readable. Sets Got_Data := True if data is now
   --  pending, False if the timeout fired. Used by the connection
   --  driver to sleep efficiently between RPCs without
   --  busy-looping. Timeout 0.0 is a non-blocking poll (same
   --  semantics as Has_Pending).
   procedure Wait_For_Data
     (Chan     : Channel;
      Timeout  : Duration;
      Got_Data : out Boolean)
   with Pre => Is_Open (Chan);

   --  Read exactly `Buffer'Length` bytes (loops over Receive).
   --  Sets Success := False if EOF arrives before the buffer fills.
   procedure Receive_Full
     (Chan    : Channel;
      Buffer  : out RFLX.RFLX_Types.Bytes;
      Success : out Boolean)
   with Pre => Is_Open (Chan);

   procedure Close (Chan : in out Channel)
   with
     Pre  => Is_Open (Chan),
     Post => not Is_Open (Chan);

   --  Server side: a Listener owns a bound + listening TCP socket.
   --  Accept_One blocks until a client connects, then fills `Chan`
   --  with the accepted connection. Single-stream-per-connection in
   --  v0.2; a real server would loop and spawn handlers.
   type Listener is limited private;

   procedure Listen
     (L    : in out Listener;
      Host : String;
      Port : Natural);

   function Is_Listening (L : Listener) return Boolean;

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

private

   type Channel is limited record
      Socket    : GNAT.Sockets.Socket_Type;
      Selector  : GNAT.Sockets.Selector_Type;
      Sel_Open  : Boolean := False;
      Open      : Boolean := False;
   end record;

   type Listener is limited record
      Socket    : GNAT.Sockets.Socket_Type;
      Listening : Boolean := False;
   end record;

end Http2_Core.Transport;
