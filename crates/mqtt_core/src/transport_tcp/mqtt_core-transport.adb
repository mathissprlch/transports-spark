with Ada.Streams;

package body Mqtt_Core.Transport is

   --  GNAT.Sockets is not SPARK; the wrapper API is consumed from
   --  SPARK-friendly code but its implementation lives outside the
   --  verified perimeter, like the DCCP example does for the
   --  RecordFlux apps.

   use type RFLX.RFLX_Types.Index;
   use type Ada.Streams.Stream_Element_Offset;

   ---------------------------------------------------------------------
   --  Is_Open
   ---------------------------------------------------------------------

   function Is_Open (Chan : Channel) return Boolean is (Chan.Open);

   ---------------------------------------------------------------------
   --  Connect
   ---------------------------------------------------------------------

   procedure Connect
     (Chan : in out Channel;
      Host : String;
      Port : Natural)
   is
      use GNAT.Sockets;
      Address : constant Sock_Addr_Type :=
        (Family => Family_Inet,
         Addr   => Inet_Addr (Host),
         Port   => Port_Type (Port));
   begin
      Create_Socket (Chan.Socket, Family_Inet, Socket_Stream);
      Connect_Socket (Chan.Socket, Address);
      Chan.Open := True;
   exception
      when others =>
         begin
            Close_Socket (Chan.Socket);
         exception
            when others => null;
         end;
         Chan.Open := False;
         raise Connect_Error;
   end Connect;

   ---------------------------------------------------------------------
   --  Send
   ---------------------------------------------------------------------

   procedure Send
     (Chan : Channel;
      Data : RFLX.RFLX_Types.Bytes)
   is
      use Ada.Streams;
      Buf  : Stream_Element_Array (1 .. Stream_Element_Offset (Data'Length));
      Last : Stream_Element_Offset;
   begin
      for I in Data'Range loop
         Buf (Stream_Element_Offset (I - Data'First) + Buf'First) :=
           Stream_Element (Data (I));
      end loop;
      GNAT.Sockets.Send_Socket (Chan.Socket, Buf, Last);
      if Last /= Buf'Last then
         raise Send_Error;
      end if;
   end Send;

   ---------------------------------------------------------------------
   --  Receive
   ---------------------------------------------------------------------

   procedure Receive
     (Chan    : Channel;
      Buffer  : out RFLX.RFLX_Types.Bytes;
      Last    : out RFLX.RFLX_Types.Index;
      Success : out Boolean)
   is
      use Ada.Streams;
      Buf      : Stream_Element_Array
        (1 .. Stream_Element_Offset (Buffer'Length));
      Recv_Last : Stream_Element_Offset;
   begin
      Buffer  := (others => 0);
      Last    := Buffer'First;  --  not meaningful unless Success = True
      Success := False;
      GNAT.Sockets.Receive_Socket (Chan.Socket, Buf, Recv_Last);
      if Recv_Last < Buf'First then
         --  EOF or zero-length read.
         return;
      end if;
      --  Copy in lockstep; we cannot convert 0 → RFLX_Types.Index since
      --  Index starts at 1, so use parallel indices instead of an offset.
      declare
         Src : Stream_Element_Offset := Buf'First;
         Dst : RFLX.RFLX_Types.Index := Buffer'First;
      begin
         while Src <= Recv_Last loop
            Buffer (Dst) := RFLX.RFLX_Types.Byte (Buf (Src));
            Src := Src + 1;
            exit when Src > Recv_Last;
            Dst := Dst + 1;
         end loop;
         Last := Dst;
      end;
      Success := True;
   exception
      when others =>
         Success := False;
   end Receive;

   ---------------------------------------------------------------------
   --  Receive_Full — loops until the whole buffer is filled or EOF.
   ---------------------------------------------------------------------

   procedure Receive_Full
     (Chan    : Channel;
      Buffer  : out RFLX.RFLX_Types.Bytes;
      Success : out Boolean)
   is
      Cursor    : RFLX.RFLX_Types.Index := Buffer'First;
      Sub_Last  : RFLX.RFLX_Types.Index;
      Sub_Ok    : Boolean;
   begin
      Buffer  := (others => 0);
      Success := False;
      while Cursor <= Buffer'Last loop
         declare
            Tail : RFLX.RFLX_Types.Bytes (Cursor .. Buffer'Last);
         begin
            Receive (Chan, Tail, Sub_Last, Sub_Ok);
            if not Sub_Ok or Sub_Last < Cursor then
               return;
            end if;
            Buffer (Cursor .. Sub_Last) := Tail (Cursor .. Sub_Last);
            Cursor := Sub_Last + 1;
         end;
      end loop;
      Success := True;
   end Receive_Full;

   ---------------------------------------------------------------------
   --  Close
   ---------------------------------------------------------------------

   procedure Close (Chan : in out Channel) is
   begin
      begin
         GNAT.Sockets.Close_Socket (Chan.Socket);
      exception
         when others => null;
      end;
      Chan.Open := False;
   end Close;

   ---------------------------------------------------------------------
   --  Listener (server side)
   ---------------------------------------------------------------------

   function Is_Listening (L : Listener) return Boolean is (L.Listening);

   procedure Listen
     (L    : in out Listener;
      Host : String;
      Port : Natural)
   is
      use GNAT.Sockets;
      Address : constant Sock_Addr_Type :=
        (Family => Family_Inet,
         Addr   => (if Host = "0.0.0.0" then Any_Inet_Addr
                    else Inet_Addr (Host)),
         Port   => Port_Type (Port));
   begin
      Create_Socket (L.Socket, Family_Inet, Socket_Stream);
      Set_Socket_Option
        (L.Socket, Socket_Level, (Reuse_Address, True));
      Bind_Socket (L.Socket, Address);
      Listen_Socket (L.Socket, 8);
      L.Listening := True;
   exception
      when others =>
         begin
            Close_Socket (L.Socket);
         exception
            when others => null;
         end;
         L.Listening := False;
         raise Connect_Error;
   end Listen;

   procedure Accept_One
     (L    : in out Listener;
      Chan : in out Channel)
   is
      use GNAT.Sockets;
      Peer : Sock_Addr_Type;
   begin
      Accept_Socket (L.Socket, Chan.Socket, Peer);
      Chan.Open := True;
   exception
      when others =>
         Chan.Open := False;
         raise Connect_Error;
   end Accept_One;

   procedure Stop (L : in out Listener) is
   begin
      begin
         GNAT.Sockets.Close_Socket (L.Socket);
      exception
         when others => null;
      end;
      L.Listening := False;
   end Stop;

   function Native_Socket (L : Listener) return GNAT.Sockets.Socket_Type is
     (L.Socket);

   function Native_Socket (Chan : Channel) return GNAT.Sockets.Socket_Type is
     (Chan.Socket);

   procedure Set_Trust_Anchor
     (Chan : in out Channel;
      Der  : RFLX.RFLX_Types.Bytes) is
      pragma Unreferenced (Chan, Der);
   begin null; end Set_Trust_Anchor;

   procedure Set_Server_Identity
     (Chan     : in out Channel;
      Cert_Der : RFLX.RFLX_Types.Bytes;
      Key_Raw  : RFLX.RFLX_Types.Bytes) is
      pragma Unreferenced (Chan, Cert_Der, Key_Raw);
   begin null; end Set_Server_Identity;

end Mqtt_Core.Transport;
