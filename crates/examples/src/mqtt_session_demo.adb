--  mqtt_session_demo — verifies §3.1.2.4 persistent sessions
--  (Clean_Session=False) for subscription preservation across
--  reconnect.
--
--  Sequence:
--    1. client A connects with Client_Id=session-a, Clean_Session=False
--    2. SUBSCRIBE ada/persist
--    3. clean DISCONNECT (broker snapshots subs)
--    4. client A reconnects with same Client_Id, Clean_Session=False
--    5. publisher publishes to ada/persist
--    6. client A receives the publish — proving the subscription
--       was preserved across the reconnect.

with Ada.Text_IO;
with Ada.Command_Line;
with RFLX.RFLX_Types; use type RFLX.RFLX_Types.Index;
with RFLX.Control_Packet;
with Mqtt_Core.Client;

procedure Mqtt_Session_Demo is
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

   Topic   : constant String := "ada/persist";
   Payload : constant String := "after-resume";
   Failures : Natural := 0;
begin
   if Ada.Command_Line.Argument_Count >= 1 then
      Port := Natural'Value (Ada.Command_Line.Argument (1));
   end if;

   Mqtt_Core.Client.Attach_Buffers
     (Sub, Sub_Buf, Sub_Inbound, Sub_Outgoing);
   Mqtt_Core.Client.Attach_Buffers
     (Pub, Pub_Buf, Pub_Inbound, Pub_Outgoing);

   --  First session: subscribe + clean disconnect.
   Mqtt_Core.Client.Open
     (Sub, Host, Port,
      Client_Id     => "session-sub",
      Clean_Session => False);
   Put_Line ("session-sub: connected (Clean_Session=False)");
   Mqtt_Core.Client.Subscribe (Sub, Topic);
   Put_Line ("session-sub: subscribed to " & Topic);
   Mqtt_Core.Client.Close (Sub);
   Put_Line ("session-sub: clean disconnect");

   --  Second session: same Client_Id, no SUBSCRIBE — broker MUST
   --  resume the subscription.
   Mqtt_Core.Client.Open
     (Sub, Host, Port,
      Client_Id     => "session-sub",
      Clean_Session => False);
   Put_Line ("session-sub: reconnected; broker should have resumed sub");

   --  Publisher fires a message that the broker can route only if
   --  the subscription survived.
   Mqtt_Core.Client.Open
     (Pub, Host, Port,
      Client_Id     => "session-pub",
      Clean_Session => True);
   Mqtt_Core.Client.Publish (Pub, Topic, To_Bytes (Payload));
   Mqtt_Core.Client.Close (Pub);

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
         if T /= Topic or else P /= Payload then
            Put_Line ("FAIL: expected (" & Topic & ", " & Payload
                      & "), got (" & T & ", " & P & ")");
            Failures := Failures + 1;
         else
            Put_Line ("session-sub: got post-resume publish: """
                      & P & """ on " & T);
         end if;
      end;
   end;

   Mqtt_Core.Client.Close (Sub);

   if Failures = 0 then
      Put_Line ("mqtt_session_demo: SUCCESS");
   else
      Put_Line ("mqtt_session_demo: FAILED");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Mqtt_Session_Demo;
