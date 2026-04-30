--  Http2_Core.Transport — bare-metal stub.
--  Mirror of Mqtt_Core.Transport's bare variant; same rationale.
--  Operations all return errors so the rest of http2_core can
--  build for a Cortex-M / Cortex-R target without GNAT.Sockets.

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

   procedure Close (Chan : in out Channel)
   with
     Pre  => Is_Open (Chan),
     Post => not Is_Open (Chan);

   Connect_Error : exception;
   Send_Error    : exception;

private

   type Channel is limited record
      Open : Boolean := False;
   end record;

end Http2_Core.Transport;
