--  Http2_Core.Transport (bare-metal stub) — every I/O op raises
--  Connect_Error / Send_Error. Replaced by real bare-metal
--  Transport bodies (UART, LWIP, etc.) for actual targets.

package body Http2_Core.Transport is

   function Is_Open (Chan : Channel) return Boolean is (Chan.Open);

   procedure Connect
     (Chan : in out Channel;
      Host : String;
      Port : Natural)
   is
      pragma Unreferenced (Host);
      pragma Unreferenced (Port);
   begin
      Chan.Open := False;
      raise Connect_Error
        with "bare-metal Transport stub — no I/O backend wired";
   end Connect;

   procedure Send
     (Chan : Channel;
      Data : RFLX.RFLX_Types.Bytes)
   is
      pragma Unreferenced (Chan);
      pragma Unreferenced (Data);
   begin
      raise Send_Error
        with "bare-metal Transport stub — no I/O backend wired";
   end Send;

   procedure Receive
     (Chan    : Channel;
      Buffer  : out RFLX.RFLX_Types.Bytes;
      Last    : out RFLX.RFLX_Types.Index;
      Success : out Boolean)
   is
      pragma Unreferenced (Chan);
   begin
      Buffer  := (others => 0);
      Last    := Buffer'First;
      Success := False;
   end Receive;

   procedure Receive_Full
     (Chan    : Channel;
      Buffer  : out RFLX.RFLX_Types.Bytes;
      Success : out Boolean)
   is
      pragma Unreferenced (Chan);
   begin
      Buffer  := (others => 0);
      Success := False;
   end Receive_Full;

   procedure Close (Chan : in out Channel) is
   begin
      Chan.Open := False;
   end Close;

end Http2_Core.Transport;
