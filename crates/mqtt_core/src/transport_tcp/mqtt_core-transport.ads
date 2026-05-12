--  Mqtt_Core.Transport — blocking TCP socket adapter.
--
--  Wraps GNAT.Sockets behind an `RFLX_Types.Bytes`-shaped API so the
--  rest of mqtt_core never sees Stream_Element_Array. Single-connection
--  by design; the v0.2 client uses one TCP socket per session.
--
--  TLS is out of scope (per docs/scope) — production deployments put a
--  TLS-terminating gateway in front of the broker, or use mbedTLS as
--  a black box on bare metal.

with RFLX.RFLX_Types;
with GNAT.Sockets;

package Mqtt_Core.Transport is

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

   --  Server-side: same API shape as Http2_Core.Transport. Listener
   --  binds + listens; Accept_One blocks for the next client TCP
   --  connection.
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

   --  Hosted-only escape hatch — broker uses GNAT.Sockets.Selector
   --  directly across multiple sockets, so it needs the underlying
   --  socket handle. Bare-metal Transport returns a sentinel.
   function Native_Socket (L : Listener) return GNAT.Sockets.Socket_Type;
   function Native_Socket (Chan : Channel) return GNAT.Sockets.Socket_Type;

   --  TLS config no-ops — present so Client.Configure_Tls compiles
   --  for all TRANSPORT variants. Only the tls variant does real work.
   procedure Set_Trust_Anchor
     (Chan : in out Channel;
      Der  : RFLX.RFLX_Types.Bytes);
   procedure Set_Server_Identity
     (Chan     : in out Channel;
      Cert_Der : RFLX.RFLX_Types.Bytes;
      Key_Raw  : RFLX.RFLX_Types.Bytes);

   Connect_Error : exception;
   Send_Error    : exception;

private

   type Channel is limited record
      Socket : GNAT.Sockets.Socket_Type;
      Open   : Boolean := False;
   end record;

   type Listener is limited record
      Socket    : GNAT.Sockets.Socket_Type;
      Listening : Boolean := False;
   end record;

end Mqtt_Core.Transport;
