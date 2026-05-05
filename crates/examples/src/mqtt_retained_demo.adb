--  mqtt_retained_demo — verifies §3.3.1.3 retained-message replay.
--
--  Run a broker on 127.0.0.1:1883 first (e.g. mqtt_broker_demo), then:
--    ./bin/mqtt_retained_demo
--
--  Sequence:
--    1. publisher CONNECT
--    2. PUBLISH (retain=True) to ada/retained
--    3. publisher DISCONNECT
--    4. subscriber CONNECT (different client-id)
--    5. SUBSCRIBE ada/retained
--    6. Receive_Publish — expect the retained payload, even though
--       no publish has happened during this session.

with Ada.Text_IO;
with Ada.Command_Line;
with RFLX.RFLX_Types; use type RFLX.RFLX_Types.Index;
with RFLX.Control_Packet;
with Mqtt_Core.Client;

procedure Mqtt_Retained_Demo is
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

   Topic   : constant String := "ada/retained";
   Payload : constant String := "stored-at-broker";
   Failures : Natural := 0;
begin
   if Ada.Command_Line.Argument_Count >= 1 then
      Port := Natural'Value (Ada.Command_Line.Argument (1));
   end if;

   Mqtt_Core.Client.Attach_Buffers
     (Pub, Pub_Buf, Pub_Inbound, Pub_Outgoing);
   Mqtt_Core.Client.Attach_Buffers
     (Sub, Sub_Buf, Sub_Inbound, Sub_Outgoing);

   --  Step 1-3: publish-with-retain, then go away.
   Mqtt_Core.Client.Open
     (Pub, Host, Port,
      Client_Id => "retained-pub",
      Clean_Session => True);
   Put_Line ("retained-pub: connected; publishing RETAIN=1");
   Mqtt_Core.Client.Publish
     (Pub, Topic, To_Bytes (Payload), Retain => True);
   Mqtt_Core.Client.Close (Pub);

   --  Step 4-6: a fresh client subscribes; the broker MUST replay
   --  the stored value as the initial payload.
   Mqtt_Core.Client.Open
     (Sub, Host, Port,
      Client_Id => "retained-sub",
      Clean_Session => True);
   Put_Line ("retained-sub: connected; subscribing to " & Topic);
   Mqtt_Core.Client.Subscribe (Sub, Topic);

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
            Put_Line ("retained-sub: replay OK — got """ & P
                      & """ on " & T);
         end if;
      end;
   end;

   Mqtt_Core.Client.Close (Sub);

   if Failures = 0 then
      Put_Line ("mqtt_retained_demo: SUCCESS");
   else
      Put_Line ("mqtt_retained_demo: FAILED");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Mqtt_Retained_Demo;
