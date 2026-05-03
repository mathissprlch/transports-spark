--  Mqtt_Core.Broker — multi-client event-loop body. Hosted only;
--  uses GNAT.Sockets selector primitives directly.

with RFLX.RFLX_Types; use type RFLX.RFLX_Types.Index;
with RFLX.RFLX_Builtin_Types;
with RFLX.Suback;
with RFLX.Session.Broker_Reading.FSM;

with Ada.Streams;
with Ada.Unchecked_Deallocation;
with GNAT.Sockets;

with Mqtt_Core.Wire;
with Mqtt_Core.Topics;

package body Mqtt_Core.Broker is

   use type RFLX.RFLX_Builtin_Types.Bytes_Ptr;
   use type RFLX.RFLX_Types.Length;
   use type RFLX.Control_Packet.Packet_Type;
   use type RFLX.Control_Packet.QoS_Level;
   use type Ada.Streams.Stream_Element_Offset;
   use type GNAT.Sockets.Socket_Type;
   use type GNAT.Sockets.Selector_Status;

   Client_Buffer_Size : constant := 4096;

   procedure Free is new Ada.Unchecked_Deallocation
     (RFLX.RFLX_Types.Bytes, RFLX.RFLX_Types.Bytes_Ptr);

   ----------------------------------------------------------------
   --  Per-client state
   ----------------------------------------------------------------

   package FSM renames RFLX.Session.Broker_Reading.FSM;

   type Client_Index is range 0 .. Max_Clients;
   subtype Active_Client is Client_Index range 1 .. Max_Clients;

   type Client_State is record
      In_Use      : Boolean := False;
      Sock        : GNAT.Sockets.Socket_Type :=
        GNAT.Sockets.No_Socket;
      Client_Id   : String (1 .. 64) := (others => ' ');
      Cid_Last    : Natural := 0;
      Inbound_Buf : RFLX.RFLX_Types.Bytes_Ptr := null;
      Working_Buf : RFLX.RFLX_Types.Bytes_Ptr := null;
      Ctx         : FSM.Context;
      Connected   : Boolean := False;  --  CONNACK already sent?
   end record;

   type Client_Array is array (Active_Client) of Client_State;

   ----------------------------------------------------------------
   --  Subscription registry
   ----------------------------------------------------------------

   type Subscription_State is record
      In_Use       : Boolean := False;
      Owner        : Active_Client := 1;
      Topic_Filter : String (1 .. 256) := (others => ' ');
      Filter_Last  : Natural := 0;
      QoS          : RFLX.Control_Packet.QoS_Level :=
        RFLX.Control_Packet.QOS_0;
   end record;

   subtype Subscription_Index is Natural range 1 .. Max_Subscriptions;
   type Subscription_Array is array (Subscription_Index) of
     Subscription_State;

   ----------------------------------------------------------------
   --  Listen / Stop
   ----------------------------------------------------------------

   procedure Listen
     (L    : in out Listener;
      Host : String;
      Port : Natural := 1883)
   is
   begin
      Transport.Listen (L.Trans, Host, Port);
   end Listen;

   procedure Stop (L : in out Listener) is
   begin
      L.Stopping := True;
      if Transport.Is_Listening (L.Trans) then
         Transport.Stop (L.Trans);
      end if;
   end Stop;

   ----------------------------------------------------------------
   --  Helpers
   ----------------------------------------------------------------

   procedure Send_All
     (Sock : GNAT.Sockets.Socket_Type;
      Data : RFLX.RFLX_Types.Bytes);

   procedure Send_All
     (Sock : GNAT.Sockets.Socket_Type;
      Data : RFLX.RFLX_Types.Bytes)
   is
      use Ada.Streams;
      Buf  : Stream_Element_Array
        (1 .. Stream_Element_Offset (Data'Length));
      Last : Stream_Element_Offset;
   begin
      for I in Data'Range loop
         Buf (Stream_Element_Offset (I - Data'First) + Buf'First) :=
           Stream_Element (Data (I));
      end loop;
      GNAT.Sockets.Send_Socket (Sock, Buf, Last);
   exception
      when others => null;
   end Send_All;

   --  Read exactly N bytes from socket into Buf starting at Buf'First.
   --  Returns False on EOF / error.
   procedure Recv_Exact
     (Sock : GNAT.Sockets.Socket_Type;
      Buf  : in out RFLX.RFLX_Types.Bytes;
      N    : Natural;
      OK   : out Boolean);

   procedure Recv_Exact
     (Sock : GNAT.Sockets.Socket_Type;
      Buf  : in out RFLX.RFLX_Types.Bytes;
      N    : Natural;
      OK   : out Boolean)
   is
      use Ada.Streams;
      Got : Stream_Element_Offset := 0;
   begin
      OK := False;
      if N = 0 then
         OK := True; return;
      end if;
      while Got < Stream_Element_Offset (N) loop
         declare
            Want : constant Stream_Element_Offset :=
              Stream_Element_Offset (N) - Got;
            Tmp  : Stream_Element_Array (1 .. Want);
            Last : Stream_Element_Offset;
         begin
            GNAT.Sockets.Receive_Socket (Sock, Tmp, Last);
            if Last < Tmp'First then
               return;  --  EOF
            end if;
            for I in Tmp'First .. Last loop
               Buf (Buf'First + RFLX.RFLX_Types.Index'Base
                                  (Got + (I - Tmp'First))) :=
                 RFLX.RFLX_Types.Byte (Tmp (I));
            end loop;
            Got := Got + (Last - Tmp'First + 1);
         end;
      end loop;
      OK := True;
   exception
      when others => OK := False;
   end Recv_Exact;

   --  Read one full MQTT control packet. v0.2 single-byte
   --  Remaining-Length only.
   procedure Read_Full_Packet
     (Sock    : GNAT.Sockets.Socket_Type;
      Buf     : RFLX.RFLX_Types.Bytes_Ptr;
      Last    : out RFLX.RFLX_Types.Index;
      Success : out Boolean);

   procedure Read_Full_Packet
     (Sock    : GNAT.Sockets.Socket_Type;
      Buf     : RFLX.RFLX_Types.Bytes_Ptr;
      Last    : out RFLX.RFLX_Types.Index;
      Success : out Boolean)
   is
      Hdr_OK : Boolean;
   begin
      Last := Buf'First;
      Success := False;
      Recv_Exact (Sock, Buf.all, 2, Hdr_OK);
      if not Hdr_OK then return; end if;
      declare
         RL : constant Natural := Natural (Buf.all (Buf'First + 1));
      begin
         if RL = 0 then
            Last := Buf'First + 1;
            Success := True;
            return;
         end if;
         declare
            Body_Slice : RFLX.RFLX_Types.Bytes
              (Buf'First + 2 ..
                 Buf'First + 1 + RFLX.RFLX_Types.Index (RL));
            Body_OK : Boolean;
         begin
            Recv_Exact (Sock, Body_Slice, RL, Body_OK);
            if not Body_OK then return; end if;
            Buf.all (Body_Slice'Range) := Body_Slice;
            Last := Body_Slice'Last;
            Success := True;
         end;
      end;
   end Read_Full_Packet;

   ----------------------------------------------------------------
   --  Run — main event loop. Generic over On_Event.
   ----------------------------------------------------------------

   procedure Run (L : in out Listener) is
      Clients   : Client_Array;
      Subs      : Subscription_Array;
      Selector  : GNAT.Sockets.Selector_Type;
      Read_Set  : GNAT.Sockets.Socket_Set_Type;
      W_Set     : GNAT.Sockets.Socket_Set_Type;
      Status    : GNAT.Sockets.Selector_Status;

      Listening_Sock : GNAT.Sockets.Socket_Type;

      ---------------------------------------------------------------
      --  Inner helpers
      ---------------------------------------------------------------

      function Find_Free_Client return Client_Index;
      function Find_Free_Client return Client_Index is
      begin
         for I in Clients'Range loop
            if not Clients (I).In_Use then return I; end if;
         end loop;
         return 0;
      end Find_Free_Client;

      function Find_Free_Sub return Natural;
      function Find_Free_Sub return Natural is
      begin
         for I in Subs'Range loop
            if not Subs (I).In_Use then return I; end if;
         end loop;
         return 0;
      end Find_Free_Sub;

      procedure Disconnect_Client (CI : Active_Client);
      procedure Disconnect_Client (CI : Active_Client) is
      begin
         --  Drop subscriptions for this client.
         for I in Subs'Range loop
            if Subs (I).In_Use and then Subs (I).Owner = CI then
               Subs (I).In_Use := False;
            end if;
         end loop;

         --  Finalize FSM.
         if FSM.Initialized (Clients (CI).Ctx) then
            FSM.Finalize
              (Clients (CI).Ctx, Clients (CI).Inbound_Buf);
         end if;
         if Clients (CI).Inbound_Buf /= null then
            Free (Clients (CI).Inbound_Buf);
         end if;
         if Clients (CI).Working_Buf /= null then
            Free (Clients (CI).Working_Buf);
         end if;
         begin
            GNAT.Sockets.Close_Socket (Clients (CI).Sock);
         exception when others => null;
         end;
         Clients (CI).In_Use      := False;
         Clients (CI).Sock        := GNAT.Sockets.No_Socket;
         Clients (CI).Client_Id   := (others => ' ');
         Clients (CI).Cid_Last    := 0;
         Clients (CI).Inbound_Buf := null;
         Clients (CI).Working_Buf := null;
         Clients (CI).Connected   := False;
      end Disconnect_Client;

      ---------------------------------------------------------------
      --  Route a published message to all matching subscribers.
      --  Outbound QoS = min(publish_qos, subscriber_granted_qos).
      --  v0.2 caps at QoS 1 (no PUBREC/PUBREL outbound flow).
      ---------------------------------------------------------------

      procedure Route_Publish
        (Topic   : String;
         Payload : RFLX.RFLX_Types.Bytes;
         Pub_QoS : RFLX.Control_Packet.QoS_Level;
         Sub_Count : out Natural);

      procedure Route_Publish
        (Topic   : String;
         Payload : RFLX.RFLX_Types.Bytes;
         Pub_QoS : RFLX.Control_Packet.QoS_Level;
         Sub_Count : out Natural)
      is
         Pid_Counter : RFLX.RFLX_Builtin_Types.Bit_Length := 1;
         pragma Unreferenced (Pid_Counter);
         Out_Last : RFLX.RFLX_Types.Index;
      begin
         Sub_Count := 0;
         for I in Subs'Range loop
            if Subs (I).In_Use
              and then Topics.Matches
                         (Topic,
                          Subs (I).Topic_Filter
                            (1 .. Subs (I).Filter_Last))
            then
               declare
                  Owner : constant Active_Client := Subs (I).Owner;
                  Effective_QoS : constant
                    RFLX.Control_Packet.QoS_Level :=
                      (if Pub_QoS = RFLX.Control_Packet.QOS_0
                         or else Subs (I).QoS = RFLX.Control_Packet.QOS_0
                       then RFLX.Control_Packet.QOS_0
                       else RFLX.Control_Packet.QOS_1);
               begin
                  if Clients (Owner).In_Use
                    and then Clients (Owner).Connected
                  then
                     case Effective_QoS is
                        when RFLX.Control_Packet.QOS_0 =>
                           Wire.Encode_Publish_Qos0
                             (Clients (Owner).Working_Buf,
                              Out_Last,
                              Topic, Payload);
                        when RFLX.Control_Packet.QOS_1 =>
                           --  v0.2 doesn't track outbound q1 PUBACKs,
                           --  so the packet id is informational.
                           Wire.Encode_Publish_Qos1
                             (Buffer    => Clients (Owner).Working_Buf,
                              Last      => Out_Last,
                              Packet_Id => 1,
                              Topic     => Topic,
                              Payload   => Payload);
                        when others =>
                           Wire.Encode_Publish_Qos0
                             (Clients (Owner).Working_Buf,
                              Out_Last,
                              Topic, Payload);
                     end case;
                     Send_All
                       (Clients (Owner).Sock,
                        Clients (Owner).Working_Buf.all
                          (Clients (Owner).Working_Buf'First .. Out_Last));
                     Sub_Count := Sub_Count + 1;
                  end if;
               end;
            end if;
         end loop;
      end Route_Publish;

      ---------------------------------------------------------------
      --  Process one packet from a client.
      ---------------------------------------------------------------

      procedure Handle_Packet
        (CI : Active_Client; Pkt_Last : RFLX.RFLX_Types.Index);

      procedure Handle_Packet
        (CI : Active_Client; Pkt_Last : RFLX.RFLX_Types.Index)
      is
         Buf : RFLX.RFLX_Types.Bytes_Ptr renames
           Clients (CI).Working_Buf;
         Out_Last : RFLX.RFLX_Types.Index;
         View : constant RFLX.RFLX_Types.Bytes :=
           Buf.all (Buf'First .. Pkt_Last);
         use type RFLX.RFLX_Types.Length;
         Empty : constant RFLX.RFLX_Types.Bytes (1 .. 0) :=
           (others => 0);
      begin
         case Wire.Peek_Packet_Type (View) is
            when RFLX.Control_Packet.CONNECT =>
               declare
                  Valid : Boolean;
               begin
                  Wire.Decode_Connect
                    (Buf, Pkt_Last, Valid,
                     Clients (CI).Client_Id,
                     Clients (CI).Cid_Last);
                  if not Valid then
                     Disconnect_Client (CI);
                     return;
                  end if;
               end;
               Wire.Encode_Connack (Buf, Out_Last);
               Send_All
                 (Clients (CI).Sock,
                  Buf.all (Buf'First .. Out_Last));
               Clients (CI).Connected := True;
               On_Event
                 (Kind     => Client_Connected,
                  Client_Id =>
                    Clients (CI).Client_Id (1 .. Clients (CI).Cid_Last),
                  Topic    => "",
                  Payload  => Empty,
                  QoS      => RFLX.Control_Packet.QOS_0,
                  Subscriber_Count => 0);

            when RFLX.Control_Packet.SUBSCRIBE =>
               declare
                  Valid : Boolean;
                  Pid   : Wire.Packet_Identifier;
                  Topic : String (1 .. 256);
                  Topic_Last : Natural;
                  Req_QoS : RFLX.Control_Packet.QoS_Level;
                  Slot : Natural;
               begin
                  Wire.Decode_Subscribe
                    (Buf, Pkt_Last, Valid, Pid,
                     Topic, Topic_Last, Req_QoS);
                  if not Valid then
                     Disconnect_Client (CI);
                     return;
                  end if;

                  Slot := Find_Free_Sub;
                  if Slot = 0 then
                     Disconnect_Client (CI);
                     return;
                  end if;
                  Subs (Slot) :=
                    (In_Use      => True,
                     Owner       => CI,
                     Topic_Filter =>
                       (others => ' '),
                     Filter_Last => Topic_Last,
                     QoS         => Req_QoS);
                  Subs (Slot).Topic_Filter (1 .. Topic_Last) :=
                    Topic (1 .. Topic_Last);

                  Wire.Encode_Suback_Single
                    (Buf, Out_Last, Pid,
                     Granted_QoS =>
                       (case Req_QoS is
                          when RFLX.Control_Packet.QOS_0 =>
                            RFLX.Suback.SUCCESS_QOS_0,
                          when RFLX.Control_Packet.QOS_1 =>
                            RFLX.Suback.SUCCESS_QOS_1,
                          when RFLX.Control_Packet.QOS_2 =>
                            RFLX.Suback.SUCCESS_QOS_2));
                  Send_All
                    (Clients (CI).Sock,
                     Buf.all (Buf'First .. Out_Last));
                  On_Event
                    (Kind     => Client_Subscribed,
                     Client_Id =>
                       Clients (CI).Client_Id (1 .. Clients (CI).Cid_Last),
                     Topic    => Topic (1 .. Topic_Last),
                     Payload  => Empty,
                     QoS      => Req_QoS,
                     Subscriber_Count => 0);
               end;

            when RFLX.Control_Packet.PUBLISH =>
               declare
                  Topic : String (1 .. 256);
                  Topic_Last : Natural;
                  Payload : RFLX.RFLX_Types.Bytes (1 .. 1024);
                  Payload_Last : RFLX.RFLX_Types.Length;
                  QoS : RFLX.Control_Packet.QoS_Level;
                  Pid : Wire.Packet_Identifier;
                  Decode_OK : Boolean;
                  Sub_Count : Natural := 0;
               begin
                  Wire.Decode_Publish
                    (Buf, Pkt_Last, Decode_OK,
                     QoS, Pid, Topic, Topic_Last,
                     Payload, Payload_Last);
                  if not Decode_OK then
                     Disconnect_Client (CI);
                     return;
                  end if;
                  if QoS = RFLX.Control_Packet.QOS_1 then
                     Wire.Encode_Puback (Buf, Out_Last, Pid);
                     Send_All
                       (Clients (CI).Sock,
                        Buf.all (Buf'First .. Out_Last));
                  end if;
                  --  Route to subscribers.
                  if Payload_Last > 0 then
                     Route_Publish
                       (Topic (1 .. Topic_Last),
                        Payload
                          (Payload'First ..
                             Payload'First +
                                RFLX.RFLX_Types.Index (Payload_Last) - 1),
                        QoS, Sub_Count);
                  else
                     Route_Publish
                       (Topic (1 .. Topic_Last),
                        Empty, QoS, Sub_Count);
                  end if;
                  On_Event
                    (Kind     => Publish_Received,
                     Client_Id =>
                       Clients (CI).Client_Id (1 .. Clients (CI).Cid_Last),
                     Topic    => Topic (1 .. Topic_Last),
                     Payload  =>
                       (if Payload_Last > 0
                        then Payload
                          (Payload'First ..
                             Payload'First +
                                RFLX.RFLX_Types.Index (Payload_Last) - 1)
                        else Empty),
                     QoS      => QoS,
                     Subscriber_Count => Sub_Count);
               end;

            when RFLX.Control_Packet.PINGREQ =>
               Wire.Encode_Pingresp (Buf, Out_Last);
               Send_All
                 (Clients (CI).Sock,
                  Buf.all (Buf'First .. Out_Last));
               On_Event
                 (Kind     => Pingreq_Received,
                  Client_Id =>
                    Clients (CI).Client_Id (1 .. Clients (CI).Cid_Last),
                  Topic    => "",
                  Payload  => Empty,
                  QoS      => RFLX.Control_Packet.QOS_0,
                  Subscriber_Count => 0);

            when RFLX.Control_Packet.DISCONNECT =>
               On_Event
                 (Kind     => Client_Disconnected,
                  Client_Id =>
                    Clients (CI).Client_Id (1 .. Clients (CI).Cid_Last),
                  Topic    => "",
                  Payload  => Empty,
                  QoS      => RFLX.Control_Packet.QOS_0,
                  Subscriber_Count => 0);
               Disconnect_Client (CI);

            when RFLX.Control_Packet.UNSUBSCRIBE =>
               declare
                  Valid : Boolean;
                  Pid   : Wire.Packet_Identifier;
               begin
                  Wire.Decode_Unsubscribe_Pid
                    (Buf, Pkt_Last, Valid, Pid);
                  if Valid then
                     --  v0.2: drop ALL subscriptions for this client
                     --  on UNSUBSCRIBE. The proper per-filter walk
                     --  is v0.3 work; for now MQTT clients that
                     --  unsubscribe usually unsubscribe everything
                     --  before disconnect anyway.
                     for I in Subs'Range loop
                        if Subs (I).In_Use
                          and then Subs (I).Owner = CI
                        then
                           Subs (I).In_Use := False;
                        end if;
                     end loop;
                     Wire.Encode_Unsuback (Buf, Out_Last, Pid);
                     Send_All
                       (Clients (CI).Sock,
                        Buf.all (Buf'First .. Out_Last));
                     On_Event
                       (Kind     => Client_Unsubscribed,
                        Client_Id =>
                          Clients (CI).Client_Id
                            (1 .. Clients (CI).Cid_Last),
                        Topic    => "",
                        Payload  => Empty,
                        QoS      => RFLX.Control_Packet.QOS_0,
                        Subscriber_Count => 0);
                  end if;
               end;

            when others =>
               --  PUBACK / PUBREC / PUBREL / PUBCOMP — v0.2 broker
               --  doesn't track outbound q1/q2 publishes, so these
               --  ack receipts have no pending request to ack.
               null;
         end case;
      end Handle_Packet;

      ---------------------------------------------------------------
      --  Drive one client through one or more FSM iterations after
      --  a frame has been Network'Written into its FSM.
      ---------------------------------------------------------------

      procedure Drive_Client (CI : Active_Client);

      procedure Drive_Client (CI : Active_Client) is
      begin
         loop
            FSM.Run (Clients (CI).Ctx);
            exit when not FSM.Active (Clients (CI).Ctx);

            if FSM.Has_Data (Clients (CI).Ctx, FSM.C_App_Pending)
            then
               declare
                  N : constant RFLX.RFLX_Types.Length :=
                    FSM.Read_Buffer_Size
                      (Clients (CI).Ctx, FSM.C_App_Pending);
                  Buf : RFLX.RFLX_Types.Bytes_Ptr renames
                    Clients (CI).Working_Buf;
                  View : RFLX.RFLX_Types.Bytes
                    (Buf'First ..
                       Buf'First + RFLX.RFLX_Types.Index (N) - 1);
               begin
                  FSM.Read
                    (Clients (CI).Ctx, FSM.C_App_Pending, View);
                  Buf.all (View'Range) := View;
                  Handle_Packet (CI, View'Last);
                  exit when not Clients (CI).In_Use;
               end;
            elsif FSM.Needs_Data (Clients (CI).Ctx, FSM.C_Network)
            then
               --  No more data to dispatch this round; selector
               --  will pick up the next inbound frame.
               exit;
            else
               exit;
            end if;
         end loop;
      end Drive_Client;

      ---------------------------------------------------------------
      --  Accept a new client.
      ---------------------------------------------------------------

      procedure Accept_New;
      procedure Accept_New is
         use GNAT.Sockets;
         Sock : Socket_Type;
         Peer : Sock_Addr_Type;
         Slot : constant Client_Index := Find_Free_Client;
      begin
         Accept_Socket (Listening_Sock, Sock, Peer);
         if Slot = 0 then
            --  No free slot — refuse politely.
            begin Close_Socket (Sock); exception when others => null;
            end;
            return;
         end if;
         Clients (Slot).In_Use := True;
         Clients (Slot).Sock := Sock;
         Clients (Slot).Inbound_Buf :=
           new RFLX.RFLX_Types.Bytes'(1 .. Client_Buffer_Size => 0);
         Clients (Slot).Working_Buf :=
           new RFLX.RFLX_Types.Bytes'(1 .. Client_Buffer_Size => 0);
         FSM.Initialize
           (Clients (Slot).Ctx, Clients (Slot).Inbound_Buf);
      end Accept_New;

      ---------------------------------------------------------------
      --  Read + feed one frame from a client; drive its FSM.
      ---------------------------------------------------------------

      procedure Service_Client (CI : Active_Client);

      procedure Service_Client (CI : Active_Client) is
         Buf : RFLX.RFLX_Types.Bytes_Ptr renames
           Clients (CI).Working_Buf;
         Last : RFLX.RFLX_Types.Index;
         OK   : Boolean;
      begin
         Read_Full_Packet (Clients (CI).Sock, Buf, Last, OK);
         if not OK then
            Disconnect_Client (CI);
            return;
         end if;
         if FSM.Needs_Data (Clients (CI).Ctx, FSM.C_Network) then
            FSM.Write
              (Clients (CI).Ctx, FSM.C_Network,
               Buf.all (Buf'First .. Last));
         end if;
         Drive_Client (CI);
      end Service_Client;

   begin
      if not Transport.Is_Listening (L.Trans) then
         raise Server_Error with "Listen must be called first";
      end if;

      --  Pull the listening socket out of the Transport opaque.
      --  Slightly grungy — we use the GNAT.Sockets handle directly
      --  here to drive Selector, since v0.2 broker is hosted only.
      Listening_Sock := Transport.Native_Socket (L.Trans);

      GNAT.Sockets.Create_Selector (Selector);
      L.Stopping := False;

      Main_Loop :
      loop
         exit Main_Loop when L.Stopping;

         GNAT.Sockets.Empty (Read_Set);
         GNAT.Sockets.Empty (W_Set);
         GNAT.Sockets.Set (Read_Set, Listening_Sock);
         for I in Clients'Range loop
            if Clients (I).In_Use then
               GNAT.Sockets.Set (Read_Set, Clients (I).Sock);
            end if;
         end loop;

         GNAT.Sockets.Check_Selector
           (Selector, Read_Set, W_Set, Status,
            Timeout => 1.0);

         if Status = GNAT.Sockets.Completed then
            if GNAT.Sockets.Is_Set (Read_Set, Listening_Sock) then
               Accept_New;
            end if;
            for I in Clients'Range loop
               if Clients (I).In_Use
                 and then GNAT.Sockets.Is_Set
                            (Read_Set, Clients (I).Sock)
               then
                  Service_Client (I);
               end if;
            end loop;
         end if;
      end loop Main_Loop;

      --  Cleanup remaining clients.
      for I in Clients'Range loop
         if Clients (I).In_Use then
            Disconnect_Client (I);
         end if;
      end loop;
      GNAT.Sockets.Close_Selector (Selector);
   end Run;

end Mqtt_Core.Broker;
