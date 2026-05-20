package body Http1_Core.Transport is

   use type Octet_Offset;

   function Is_Open (Chan : Channel) return Boolean
   is (Chan.Open);

   procedure Send (Chan : Channel; Data : Octet_Array) is
      Last : Octet_Offset;
   begin
      GNAT.Sockets.Send_Socket (Chan.Socket, Data, Last);
   end Send;

   procedure Receive
     (Chan    : Channel;
      Buffer  : out Octet_Array;
      Last    : out Octet_Offset;
      Success : out Boolean) is
   begin
      Buffer := [others => 0];
      Last := Buffer'First - 1;
      Success := False;
      GNAT.Sockets.Receive_Socket (Chan.Socket, Buffer, Last);
      Success := Last >= Buffer'First;
   exception
      when others =>
         Success := False;
   end Receive;

   procedure Close (Chan : in out Channel) is
   begin
      begin
         GNAT.Sockets.Close_Socket (Chan.Socket);
      exception
         when others =>
            null;
      end;
      Chan.Open := False;
   end Close;

   function Is_Listening (L : Listener) return Boolean
   is (L.Listening);

   procedure Listen (L : in out Listener; Host : String; Port : Natural) is
      use GNAT.Sockets;
      Address : constant Sock_Addr_Type :=
        (Family => Family_Inet,
         Addr   =>
           (if Host = "0.0.0.0" then Any_Inet_Addr else Inet_Addr (Host)),
         Port   => Port_Type (Port));
   begin
      Create_Socket (L.Socket, Family_Inet, Socket_Stream);
      Set_Socket_Option (L.Socket, Socket_Level, (Reuse_Address, True));
      Bind_Socket (L.Socket, Address);
      Listen_Socket (L.Socket, 8);
      L.Listening := True;
   exception
      when others =>
         begin
            Close_Socket (L.Socket);
         exception
            when others =>
               null;
         end;
         L.Listening := False;
         raise Connect_Error;
   end Listen;

   procedure Accept_One (L : in out Listener; Chan : in out Channel) is
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
         when others =>
            null;
      end;
      L.Listening := False;
   end Stop;

end Http1_Core.Transport;
