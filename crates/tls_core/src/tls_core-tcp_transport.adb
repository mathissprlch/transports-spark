with Ada.Streams;

package body Tls_Core.Tcp_Transport
with SPARK_Mode => Off
is

   --  GNAT.Sockets is not SPARK; the wrapper API is consumed from
   --  SPARK-friendly code but its implementation lives outside the
   --  verified perimeter, mirroring Http2_Core.Transport.

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
   --  Send_All — write the whole buffer or raise Send_Error.
   ---------------------------------------------------------------------

   procedure Send_All
     (Chan : Channel;
      Data : Octet_Array)
   is
      use Ada.Streams;
      Buf  : Stream_Element_Array
        (1 .. Stream_Element_Offset (Data'Length));
      Last : Stream_Element_Offset;
      Cursor : Stream_Element_Offset := Buf'First;
   begin
      if Data'Length = 0 then
         return;
      end if;
      for I in Data'Range loop
         Buf (Stream_Element_Offset (I - Data'First) + Buf'First) :=
           Stream_Element (Data (I));
      end loop;
      --  Loop over Send_Socket until the entire buffer is delivered;
      --  on short writes we simply continue from where we stopped.
      while Cursor <= Buf'Last loop
         GNAT.Sockets.Send_Socket
           (Chan.Socket, Buf (Cursor .. Buf'Last), Last);
         if Last < Cursor then
            raise Send_Error;
         end if;
         Cursor := Last + 1;
      end loop;
   exception
      when Send_Error =>
         raise;
      when others =>
         raise Send_Error;
   end Send_All;

   ---------------------------------------------------------------------
   --  Recv_All — block until exactly Buffer'Length bytes have been
   --  received, or the peer FIN'd / errored before the buffer filled.
   ---------------------------------------------------------------------

   procedure Recv_All
     (Chan    : Channel;
      Buffer  : out Octet_Array;
      Success : out Boolean)
   is
      use Ada.Streams;
      Total  : constant Stream_Element_Offset :=
        Stream_Element_Offset (Buffer'Length);
      Buf    : Stream_Element_Array (1 .. Total);
      Cursor : Stream_Element_Offset := Buf'First;
      Last   : Stream_Element_Offset;
   begin
      Buffer  := (others => 0);
      Success := False;
      if Buffer'Length = 0 then
         Success := True;
         return;
      end if;
      while Cursor <= Buf'Last loop
         GNAT.Sockets.Receive_Socket
           (Chan.Socket, Buf (Cursor .. Buf'Last), Last);
         if Last < Cursor then
            --  Peer closed (or zero-length read); we got fewer bytes
            --  than requested → buffer didn't fill, fail.
            return;
         end if;
         Cursor := Last + 1;
      end loop;
      --  Copy back into the Octet_Array result.
      declare
         Src : Stream_Element_Offset := Buf'First;
      begin
         for I in Buffer'Range loop
            Buffer (I) := Octet (Buf (Src));
            Src := Src + 1;
         end loop;
      end;
      Success := True;
   exception
      when others =>
         Success := False;
   end Recv_All;

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
   --  Listener side
   ---------------------------------------------------------------------

   function Is_Listening (L : Listener) return Boolean is (L.Listening);

   function Bound_Port (L : Listener) return Natural is (L.Port);

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
      --  Read back the actual bound port — Get_Socket_Name reflects
      --  the kernel-assigned port when caller passed Port = 0.
      declare
         Bound : constant Sock_Addr_Type :=
           Get_Socket_Name (L.Socket);
      begin
         L.Port := Natural (Bound.Port);
      end;
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

   function Native_Socket (Chan : Channel) return GNAT.Sockets.Socket_Type is
     (Chan.Socket);

end Tls_Core.Tcp_Transport;
