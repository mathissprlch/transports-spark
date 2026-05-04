--  Http2_Core.Transport (bare-metal) — in-image memory loopback.
--  Same shape as Mqtt_Core.Transport's bare body.

package body Http2_Core.Transport is

   use type RFLX.RFLX_Types.Index;

   subtype U8 is RFLX.RFLX_Types.Byte;

   FIFO_Capacity : constant := 4096;

   FIFO : array (1 .. FIFO_Capacity) of U8 := (others => 0);
   Head : Natural := 0;
   Tail : Natural := 0;

   ----------------------------------------------------------------

   function Is_Open (Chan : Channel) return Boolean is (Chan.Open);

   procedure Connect
     (Chan : in out Channel;
      Host : String;
      Port : Natural)
   is
      pragma Unreferenced (Host);
      pragma Unreferenced (Port);
   begin
      Chan.Open := True;
   end Connect;

   procedure Send
     (Chan : Channel;
      Data : RFLX.RFLX_Types.Bytes)
   is
      pragma Unreferenced (Chan);
      Avail : constant Natural := FIFO_Capacity - Tail;
   begin
      if Data'Length = 0 then
         return;
      end if;
      if Data'Length > Avail then
         raise Send_Error with "loopback FIFO full";
      end if;
      for I in 1 .. Data'Length loop
         FIFO (Tail + I) :=
           Data (Data'First + RFLX.RFLX_Types.Index'Base (I) - 1);
      end loop;
      if Head = 0 then
         Head := 1;
      end if;
      Tail := Tail + Data'Length;
   end Send;

   function Pop_Into
     (Buffer : in out RFLX.RFLX_Types.Bytes;
      N      : Natural) return Natural;

   function Pop_Into
     (Buffer : in out RFLX.RFLX_Types.Bytes;
      N      : Natural) return Natural
   is
      Copied : Natural := 0;
   begin
      if N = 0 or else Head = 0 then
         return 0;
      end if;
      while Copied < N and then Head + Copied <= Tail loop
         Buffer (Buffer'First +
                   RFLX.RFLX_Types.Index'Base (Copied)) :=
           FIFO (Head + Copied);
         Copied := Copied + 1;
      end loop;
      Head := Head + Copied;
      if Head > Tail then
         Head := 0;
         Tail := 0;
      end if;
      return Copied;
   end Pop_Into;

   procedure Receive
     (Chan    : Channel;
      Buffer  : out RFLX.RFLX_Types.Bytes;
      Last    : out RFLX.RFLX_Types.Index;
      Success : out Boolean)
   is
      pragma Unreferenced (Chan);
      Want : constant Natural := Buffer'Length;
      Got  : Natural;
   begin
      Buffer  := (others => 0);
      Last    := Buffer'First;
      Success := False;
      if Want = 0 or else Head = 0 then
         return;
      end if;
      Got := Pop_Into (Buffer, Want);
      if Got = 0 then
         return;
      end if;
      Last    := Buffer'First + RFLX.RFLX_Types.Index'Base (Got) - 1;
      Success := True;
   end Receive;

   procedure Receive_Full
     (Chan    : Channel;
      Buffer  : out RFLX.RFLX_Types.Bytes;
      Success : out Boolean)
   is
      pragma Unreferenced (Chan);
      Want : constant Natural := Buffer'Length;
      Got  : Natural;
   begin
      Buffer  := (others => 0);
      Success := False;
      if Want = 0 then
         Success := True;
         return;
      end if;
      if Head = 0 or else Tail - Head + 1 < Want then
         return;
      end if;
      Got := Pop_Into (Buffer, Want);
      Success := Got = Want;
   end Receive_Full;

   procedure Close (Chan : in out Channel) is
   begin
      Chan.Open := False;
   end Close;

   function Has_Pending (Chan : Channel) return Boolean is
      pragma Unreferenced (Chan);
   begin
      return Queued_Bytes > 0;
   end Has_Pending;

   procedure Wait_For_Data
     (Chan     : Channel;
      Timeout  : Duration;
      Got_Data : out Boolean)
   is
      pragma Unreferenced (Chan, Timeout);
   begin
      Got_Data := Queued_Bytes > 0;
   end Wait_For_Data;

   function Queued_Bytes return Natural is
   begin
      if Head = 0 then
         return 0;
      end if;
      return Tail - Head + 1;
   end Queued_Bytes;

   procedure Inject_Inbound (Data : RFLX.RFLX_Types.Bytes) is
      Avail : constant Natural := FIFO_Capacity - Tail;
   begin
      if Data'Length = 0 then
         return;
      end if;
      if Data'Length > Avail then
         raise Send_Error with "loopback FIFO full (inject)";
      end if;
      for I in 1 .. Data'Length loop
         FIFO (Tail + I) :=
           Data (Data'First + RFLX.RFLX_Types.Index'Base (I) - 1);
      end loop;
      if Head = 0 then
         Head := 1;
      end if;
      Tail := Tail + Data'Length;
   end Inject_Inbound;

   procedure Reset_Queue is
   begin
      Head := 0;
      Tail := 0;
      FIFO := (others => 0);
   end Reset_Queue;

   ----------------------------------------------------------------
   --  Listener stubs — bare-metal has no listening sockets; the
   --  loopback Transport's single shared FIFO already handles the
   --  in-image case. These exist only to keep the API surface
   --  uniform between hosted and bare builds.
   ----------------------------------------------------------------

   function Is_Listening (L : Listener) return Boolean is
     (L.Listening);

   procedure Listen
     (L : in out Listener; Host : String; Port : Natural)
   is
      pragma Unreferenced (Host);
      pragma Unreferenced (Port);
   begin
      L.Listening := True;
   end Listen;

   procedure Accept_One
     (L : in out Listener; Chan : in out Channel) is
      pragma Unreferenced (L);
   begin
      Chan.Open := True;
   end Accept_One;

   procedure Stop (L : in out Listener) is
   begin
      L.Listening := False;
   end Stop;

end Http2_Core.Transport;
