--  Mqtt_Core.Transport — bare-metal memory-loopback.
--
--  Same API surface as the TCP variant in `../transport_tcp/`, but
--  the body uses a fixed-size in-image FIFO instead of GNAT.Sockets.
--  Bare-metal-clean: no hosted-OS dependency.
--
--    Send (Chan, Bytes)        →  pushes Bytes into a static FIFO
--    Receive (Chan, Buffer, …) →  pops bytes from the same FIFO
--
--  Single shared FIFO at package-body scope; bare-metal targets
--  are single-threaded under the light-* runtime so contention is
--  a non-issue. All Channels read the same queue — a Channel
--  sending bytes and the same (or another) Channel reading them
--  back is the round-trip topology this Transport supports.
--
--  Useful for: exercising Wire encoders+decoders on bare-metal
--  ("encode CONNECT, push to queue, pop, decode → assert equal"),
--  or seeding fixed broker-response bytes with `Inject_Inbound`
--  before driving a Client request.
--
--  NOT useful for: a real two-peer protocol exchange where the
--  responder must compute its reply from the inbound message —
--  that needs a co-routine scheduler or real I/O hardware (UART,
--  Ethernet PHY+LWIP). Those are tracked separately on the
--  bare-metal roadmap.
--
--  Build selection: `mqtt_core.gpr` has scenario variable
--  TRANSPORT={tcp|bare} picking which `src/` subdirectory compiles.

with RFLX.RFLX_Types;

package Mqtt_Core.Transport is

   type Channel is limited private;

   procedure Connect
     (Chan : in out Channel;
      Host : String;
      Port : Natural);

   function Is_Open (Chan : Channel) return Boolean;

   procedure Send
     (Chan : Channel;
      Data : RFLX.RFLX_Types.Bytes)
   with Pre => Is_Open (Chan);

   procedure Receive
     (Chan    : Channel;
      Buffer  : out RFLX.RFLX_Types.Bytes;
      Last    : out RFLX.RFLX_Types.Index;
      Success : out Boolean)
   with Pre => Is_Open (Chan);

   procedure Receive_Full
     (Chan    : Channel;
      Buffer  : out RFLX.RFLX_Types.Bytes;
      Success : out Boolean)
   with Pre => Is_Open (Chan);

   procedure Close (Chan : in out Channel)
   with
     Pre  => Is_Open (Chan),
     Post => not Is_Open (Chan);

   --  Queued-byte count helpers — useful for tests that want to
   --  assert "queue is empty after the round trip" or seed inbound
   --  bytes for a request the FSM is about to make.
   function Queued_Bytes return Natural;
   procedure Inject_Inbound (Data : RFLX.RFLX_Types.Bytes);
   procedure Reset_Queue;

   --  Server-side stubs (no-op on bare metal).
   type Listener is limited private;
   procedure Listen
     (L : in out Listener; Host : String; Port : Natural);
   function Is_Listening (L : Listener) return Boolean;
   procedure Accept_One (L : in out Listener; Chan : in out Channel)
   with Pre  => Is_Listening (L), Post => Is_Open (Chan);
   procedure Stop (L : in out Listener)
   with Pre  => Is_Listening (L), Post => not Is_Listening (L);

   --  Bare-metal: no GNAT.Sockets, no native socket. Function
   --  exists only to satisfy the API surface the hosted broker
   --  uses; calling it on bare-metal raises Send_Error. Broker
   --  itself doesn't run on bare-metal in v0.2.
   type Native_Socket_Stub is null record;
   function Native_Socket (L : Listener) return Native_Socket_Stub
   is ((null record));
   function Native_Socket (Chan : Channel) return Native_Socket_Stub
   is ((null record));

   Connect_Error : exception;
   Send_Error    : exception;

private

   type Channel is limited record
      Open : Boolean := False;
   end record;

   type Listener is limited record
      Listening : Boolean := False;
   end record;

end Mqtt_Core.Transport;
