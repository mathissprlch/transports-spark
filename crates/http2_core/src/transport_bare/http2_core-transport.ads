--  Http2_Core.Transport — bare-metal memory-loopback.
--  Mirror of Mqtt_Core.Transport's bare variant; same rationale.
--  In-image FIFO so http2_core can do byte round-trips on a
--  Cortex-M / Cortex-R target without GNAT.Sockets.

with RFLX.RFLX_Types;

package Http2_Core.Transport is

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

   --  Bare metal: the loopback FIFO is synchronous, so any pending
   --  bytes are immediately visible. Returns True iff Queued_Bytes > 0.
   function Has_Pending (Chan : Channel) return Boolean
   with Pre => Is_Open (Chan);

   procedure Close (Chan : in out Channel)
   with
     Pre  => Is_Open (Chan),
     Post => not Is_Open (Chan);

   --  Test helpers — same shape as Mqtt_Core.Transport's.
   function Queued_Bytes return Natural;
   procedure Inject_Inbound (Data : RFLX.RFLX_Types.Bytes);
   procedure Reset_Queue;

   --  Server-side stubs (no-op on bare metal — listening sockets
   --  don't exist on Cortex-M targets without an IP stack).
   type Listener is limited private;
   procedure Listen
     (L : in out Listener; Host : String; Port : Natural);
   function Is_Listening (L : Listener) return Boolean;
   procedure Accept_One (L : in out Listener; Chan : in out Channel)
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
      Open : Boolean := False;
   end record;

   type Listener is limited record
      Listening : Boolean := False;
   end record;

end Http2_Core.Transport;
