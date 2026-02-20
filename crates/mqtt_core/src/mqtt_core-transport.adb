with Ada.Streams;

package body Mqtt_Core.Transport is

   --  GNAT.Sockets is not SPARK; the wrapper API is consumed from
   --  SPARK-friendly code but its implementation lives outside the
   --  verified perimeter, like the DCCP example does for the
   --  RecordFlux apps.

   use type RFLX.RFLX_Types.Index;
   use type RFLX.RFLX_Types.Length;
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
      Last    := Buffer'First - 1;
      Success := False;
      GNAT.Sockets.Receive_Socket (Chan.Socket, Buf, Recv_Last);
      if Recv_Last < Buf'First then
         --  EOF or zero-length read.
         return;
      end if;
      for I in Buf'First .. Recv_Last loop
         Buffer (Buffer'First + RFLX.RFLX_Types.Index (I - Buf'First)) :=
           RFLX.RFLX_Types.Byte (Buf (I));
      end loop;
      Last := Buffer'First + RFLX.RFLX_Types.Index (Recv_Last - Buf'First);
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

end Mqtt_Core.Transport;
