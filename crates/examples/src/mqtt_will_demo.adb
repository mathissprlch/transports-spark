--  mqtt_will_demo — verifies §3.1.2.5 Will/Testament publishing.
--
--  Sequence:
--    1. publisher CONNECT with Will_Topic=ada/will, Will_Message="rip"
--    2. subscriber CONNECT, SUBSCRIBE ada/will
--    3. publisher slams the socket shut WITHOUT DISCONNECT (Drop)
--    4. subscriber expects to receive "rip" on ada/will from the
--       broker, since the publisher's last words must be replayed
--       per §3.1.2.5.

with Ada.Text_IO;
with Ada.Command_Line;
with RFLX.RFLX_Types; use type RFLX.RFLX_Types.Index;
with RFLX.Control_Packet;
with Mqtt_Core.Client;

procedure Mqtt_Will_Demo is
   use Ada.Text_IO;

   Host : constant String := "127.0.0.1";
   Port : Natural := 1883;

   function To_Bytes (S : String) return RFLX.RFLX_Types.Bytes is
      Out_Bytes : RFLX.RFLX_Types.Bytes (1 .. S'Length);
      Dst : RFLX.RFLX_Types.Index := Out_Bytes'First;
   begin
      for Src in S'Range loop
         Out_Bytes (Dst) :=
           RFLX.RFLX_Types.Byte (Character'Pos (S (Src)));
         exit when Src = S'Last;
         Dst := Dst + 1;
      end loop;
      return Out_Bytes;
   end To_Bytes;

   function To_String
     (B : RFLX.RFLX_Types.Bytes; Last : RFLX.RFLX_Types.Length)
      return String
   is
      R : String (1 .. Natural (Last));
      Src : RFLX.RFLX_Types.Index := B'First;
   begin
      for Dst in R'Range loop
         R (Dst) := Character'Val (Natural (B (Src)));
         exit when Dst = R'Last;
         Src := Src + 1;
      end loop;
      return R;
   end To_String;

   Pub : Mqtt_Core.Client.Client;
   Sub : Mqtt_Core.Client.Client;

   Buffer_Capacity : constant := 256;
   Pub_Buf      : RFLX.RFLX_Types.Bytes_Ptr :=
     new RFLX.RFLX_Types.Bytes'(1 .. Buffer_Capacity => 0);
   Pub_Inbound  : RFLX.RFLX_Types.Bytes_Ptr :=
     new RFLX.RFLX_Types.Bytes'(1 .. Buffer_Capacity => 0);
   Pub_Outgoing : RFLX.RFLX_Types.Bytes_Ptr :=
     new RFLX.RFLX_Types.Bytes'(1 .. Buffer_Capacity => 0);
   Sub_Buf      : RFLX.RFLX_Types.Bytes_Ptr :=
     new RFLX.RFLX_Types.Bytes'(1 .. Buffer_Capacity => 0);
   Sub_Inbound  : RFLX.RFLX_Types.Bytes_Ptr :=
     new RFLX.RFLX_Types.Bytes'(1 .. Buffer_Capacity => 0);
   Sub_Outgoing : RFLX.RFLX_Types.Bytes_Ptr :=
     new RFLX.RFLX_Types.Bytes'(1 .. Buffer_Capacity => 0);

   Will_Topic   : constant String := "ada/will";
   Will_Message : constant String := "rip";
   Failures     : Natural := 0;
begin
   if Ada.Command_Line.Argument_Count >= 1 then
      Port := Natural'Value (Ada.Command_Line.Argument (1));
   end if;

   Mqtt_Core.Client.Attach_Buffers
     (Pub, Pub_Buf, Pub_Inbound, Pub_Outgoing);
   Mqtt_Core.Client.Attach_Buffers
     (Sub, Sub_Buf, Sub_Inbound, Sub_Outgoing);

   --  Subscribe first so the will publication finds the subscriber.
   Mqtt_Core.Client.Open
     (Sub, Host, Port,
      Client_Id => "will-sub",
      Clean_Session => True);
   Mqtt_Core.Client.Subscribe (Sub, Will_Topic);
   Put_Line ("will-sub: subscribed to " & Will_Topic);

   --  Publisher connects WITH a Will, then drops the socket.
   Mqtt_Core.Client.Open
     (Pub, Host, Port,
      Client_Id    => "will-pub",
      Clean_Session => True,
      Will_Topic   => Will_Topic,
      Will_Message => To_Bytes (Will_Message),
      Will_QoS     => RFLX.Control_Packet.QOS_0,
      Will_Retain  => False);
   Put_Line ("will-pub: connected with Will=" & Will_Message
             & " on " & Will_Topic & "; dropping socket");
   Mqtt_Core.Client.Drop (Pub);

   --  Broker should now publish the Will to all matching subscribers.
   declare
      Got_Topic   : String (1 .. 256);
      Got_T_Last  : Natural;
      Got_Pl      : RFLX.RFLX_Types.Bytes (1 .. 1024);
      Got_Pl_Last : RFLX.RFLX_Types.Length;
   begin
      Mqtt_Core.Client.Receive_Publish
        (Sub, Got_Topic, Got_T_Last, Got_Pl, Got_Pl_Last);
      declare
         T : constant String := Got_Topic (1 .. Got_T_Last);
         P : constant String := To_String (Got_Pl, Got_Pl_Last);
      begin
         if T /= Will_Topic or else P /= Will_Message then
            Put_Line ("FAIL: expected (" & Will_Topic & ", "
                      & Will_Message & "), got (" & T & ", "
                      & P & ")");
            Failures := Failures + 1;
         else
            Put_Line ("will-sub: got Will publication: """ & P
                      & """ on " & T);
         end if;
      end;
   end;

   Mqtt_Core.Client.Close (Sub);

   if Failures = 0 then
      Put_Line ("mqtt_will_demo: SUCCESS");
   else
      Put_Line ("mqtt_will_demo: FAILED");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Mqtt_Will_Demo;
