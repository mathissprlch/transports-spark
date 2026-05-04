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

   --  QoS inflight tracking — per client, both directions.
   --
   --  Outbound: when we forward a QoS≥1 PUBLISH to this subscriber
   --  we mint a fresh packet-id, store it as Awaiting_Puback (q1) or
   --  Awaiting_Pubrec (q2), and clear the slot when the matching ack
   --  arrives. v0.3 has no retransmit timer — a dropped ack just
   --  leaves the slot occupied until the client reconnects.
   --
   --  Inbound: when this client sends a QoS 2 PUBLISH we record the
   --  packet-id so a duplicate-DUP retransmission isn't re-routed,
   --  and clear it on the matching PUBREL.
   Max_Inflight : constant := 16;

   type Inflight_Stage is
     (Free, Awaiting_Puback, Awaiting_Pubrec, Awaiting_Pubcomp);

   --  Pid range is 1..65535 (0 is reserved by §2.3.1). The slot's
   --  Stage / In_Use flag is the source of truth for occupancy; the
   --  Pid field is meaningful only when the slot is non-Free.
   type Outbound_Inflight_Slot is record
      Stage : Inflight_Stage := Free;
      Pid   : Wire.Packet_Identifier := 1;
   end record;

   type Outbound_Inflight_Array is
     array (1 .. Max_Inflight) of Outbound_Inflight_Slot;

   type Inbound_Pid_Slot is record
      In_Use : Boolean := False;
      Pid    : Wire.Packet_Identifier := 1;
   end record;

   type Inbound_Pid_Array is
     array (1 .. Max_Inflight) of Inbound_Pid_Slot;

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
      --  Wraps from 65535 → 1, so initialize at 65535 and the first
      --  Next_Outbound_Pid call yields 1.
      Out_Pid_Counter : Wire.Packet_Identifier := 65535;
      Outbound_Inflight : Outbound_Inflight_Array;
      Inbound_QoS2 : Inbound_Pid_Array;
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
         Clients (CI).Out_Pid_Counter := 65535;
         for I in Clients (CI).Outbound_Inflight'Range loop
            Clients (CI).Outbound_Inflight (I) :=
              (Stage => Free, Pid => 1);
         end loop;
         for I in Clients (CI).Inbound_QoS2'Range loop
            Clients (CI).Inbound_QoS2 (I) :=
              (In_Use => False, Pid => 1);
         end loop;
      end Disconnect_Client;

      ---------------------------------------------------------------
      --  Inflight helpers — packet-id allocation, slot lookup.
      ---------------------------------------------------------------

      function Next_Outbound_Pid (CI : Active_Client)
        return Wire.Packet_Identifier;

      function Next_Outbound_Pid (CI : Active_Client)
        return Wire.Packet_Identifier
      is
         use type Wire.Packet_Identifier;
      begin
         --  Pid range is 1..65535 (0 reserved). Wrap at the top.
         if Clients (CI).Out_Pid_Counter >= 65535 then
            Clients (CI).Out_Pid_Counter := 1;
         else
            Clients (CI).Out_Pid_Counter :=
              Clients (CI).Out_Pid_Counter + 1;
         end if;
         return Clients (CI).Out_Pid_Counter;
      end Next_Outbound_Pid;

      function Find_Free_Outbound (CI : Active_Client) return Natural;

      function Find_Free_Outbound (CI : Active_Client) return Natural is
      begin
         for I in Clients (CI).Outbound_Inflight'Range loop
            if Clients (CI).Outbound_Inflight (I).Stage = Free then
               return I;
            end if;
         end loop;
         return 0;
      end Find_Free_Outbound;

      function Find_Outbound_By_Pid
        (CI : Active_Client; Pid : Wire.Packet_Identifier)
         return Natural;

      function Find_Outbound_By_Pid
        (CI : Active_Client; Pid : Wire.Packet_Identifier)
         return Natural
      is
         use type Wire.Packet_Identifier;
      begin
         for I in Clients (CI).Outbound_Inflight'Range loop
            if Clients (CI).Outbound_Inflight (I).Stage /= Free
              and then Clients (CI).Outbound_Inflight (I).Pid = Pid
            then
               return I;
            end if;
         end loop;
         return 0;
      end Find_Outbound_By_Pid;

      function Find_Inbound_QoS2_Slot
        (CI : Active_Client; Pid : Wire.Packet_Identifier)
         return Natural;

      function Find_Inbound_QoS2_Slot
        (CI : Active_Client; Pid : Wire.Packet_Identifier)
         return Natural
      is
         use type Wire.Packet_Identifier;
      begin
         for I in Clients (CI).Inbound_QoS2'Range loop
            if Clients (CI).Inbound_QoS2 (I).In_Use
              and then Clients (CI).Inbound_QoS2 (I).Pid = Pid
            then
               return I;
            end if;
         end loop;
         return 0;
      end Find_Inbound_QoS2_Slot;

      function Find_Free_Inbound_QoS2 (CI : Active_Client) return Natural;

      function Find_Free_Inbound_QoS2 (CI : Active_Client) return Natural
      is
      begin
         for I in Clients (CI).Inbound_QoS2'Range loop
            if not Clients (CI).Inbound_QoS2 (I).In_Use then
               return I;
            end if;
         end loop;
         return 0;
      end Find_Free_Inbound_QoS2;

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
                  --  §3.8.4 (3): outbound QoS = min(publish, granted).
                  Effective_QoS : constant
                    RFLX.Control_Packet.QoS_Level :=
                      (if Pub_QoS = RFLX.Control_Packet.QOS_0
                         or else Subs (I).QoS = RFLX.Control_Packet.QOS_0
                       then RFLX.Control_Packet.QOS_0
                       elsif Pub_QoS = RFLX.Control_Packet.QOS_1
                         or else Subs (I).QoS = RFLX.Control_Packet.QOS_1
                       then RFLX.Control_Packet.QOS_1
                       else RFLX.Control_Packet.QOS_2);
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
                           Send_All
                             (Clients (Owner).Sock,
                              Clients (Owner).Working_Buf.all
                                (Clients (Owner).Working_Buf'First
                                 .. Out_Last));
                           Sub_Count := Sub_Count + 1;

                        when RFLX.Control_Packet.QOS_1 =>
                           declare
                              Slot : constant Natural :=
                                Find_Free_Outbound (Owner);
                              Pid : Wire.Packet_Identifier;
                           begin
                              --  No free slot → backpressure (we'd
                              --  drop the message). v0.3 doesn't
                              --  retry; subscriber gets nothing this
                              --  round. Bumping Max_Inflight or
                              --  adding a queue is v0.4.
                              if Slot = 0 then
                                 null;
                              else
                                 Pid := Next_Outbound_Pid (Owner);
                                 Wire.Encode_Publish_Qos1
                                   (Buffer    =>
                                      Clients (Owner).Working_Buf,
                                    Last      => Out_Last,
                                    Packet_Id => Pid,
                                    Topic     => Topic,
                                    Payload   => Payload);
                                 Clients (Owner).Outbound_Inflight
                                   (Slot) :=
                                     (Stage => Awaiting_Puback,
                                      Pid   => Pid);
                                 Send_All
                                   (Clients (Owner).Sock,
                                    Clients (Owner).Working_Buf.all
                                      (Clients (Owner).Working_Buf'First
                                       .. Out_Last));
                                 Sub_Count := Sub_Count + 1;
                              end if;
                           end;

                        when RFLX.Control_Packet.QOS_2 =>
                           declare
                              Slot : constant Natural :=
                                Find_Free_Outbound (Owner);
                              Pid : Wire.Packet_Identifier;
                           begin
                              if Slot = 0 then
                                 null;
                              else
                                 Pid := Next_Outbound_Pid (Owner);
                                 Wire.Encode_Publish_Qos2
                                   (Buffer    =>
                                      Clients (Owner).Working_Buf,
                                    Last      => Out_Last,
                                    Packet_Id => Pid,
                                    Topic     => Topic,
                                    Payload   => Payload);
                                 Clients (Owner).Outbound_Inflight
                                   (Slot) :=
                                     (Stage => Awaiting_Pubrec,
                                      Pid   => Pid);
                                 Send_All
                                   (Clients (Owner).Sock,
                                    Clients (Owner).Working_Buf.all
                                      (Clients (Owner).Working_Buf'First
                                       .. Out_Last));
                                 Sub_Count := Sub_Count + 1;
                              end if;
                           end;
                     end case;
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
                  Max_Filters : constant := 8;
                  Valid : Boolean;
                  Pid   : Wire.Packet_Identifier;
                  Topics_Buf : Wire.Filter_Topic_Array (1 .. Max_Filters);
                  Topic_Lasts : Wire.Filter_Last_Array (1 .. Max_Filters);
                  Topic_QoS  : Wire.Filter_QoS_Array (1 .. Max_Filters);
                  Filter_N   : Natural;
                  Codes      : Wire.Suback_Wire_Codes (1 .. Max_Filters);
               begin
                  Wire.Decode_Subscribe_Filters
                    (Buf, Pkt_Last, Valid, Pid,
                     Topics_Buf, Topic_Lasts, Topic_QoS, Filter_N);
                  if not Valid or else Filter_N = 0 then
                     Disconnect_Client (CI);
                     return;
                  end if;

                  for K in 1 .. Filter_N loop
                     declare
                        Slot : constant Natural := Find_Free_Sub;
                     begin
                        if Slot = 0 then
                           --  Out of registry slots → grant the filter
                           --  with FAILURE; client may retry later.
                           Codes (K) := RFLX.Suback.FAILURE;
                        else
                           Subs (Slot) :=
                             (In_Use      => True,
                              Owner       => CI,
                              Topic_Filter => (others => ' '),
                              Filter_Last => Topic_Lasts (K),
                              QoS         => Topic_QoS (K));
                           Subs (Slot).Topic_Filter
                             (1 .. Topic_Lasts (K)) :=
                               Topics_Buf (K) (1 .. Topic_Lasts (K));
                           Codes (K) :=
                             (case Topic_QoS (K) is
                                when RFLX.Control_Packet.QOS_0 =>
                                  RFLX.Suback.SUCCESS_QOS_0,
                                when RFLX.Control_Packet.QOS_1 =>
                                  RFLX.Suback.SUCCESS_QOS_1,
                                when RFLX.Control_Packet.QOS_2 =>
                                  RFLX.Suback.SUCCESS_QOS_2);
                        end if;
                     end;
                  end loop;

                  Wire.Encode_Suback
                    (Buf, Out_Last, Pid, Codes (1 .. Filter_N));
                  Send_All
                    (Clients (CI).Sock,
                     Buf.all (Buf'First .. Out_Last));
                  for K in 1 .. Filter_N loop
                     On_Event
                       (Kind     => Client_Subscribed,
                        Client_Id =>
                          Clients (CI).Client_Id
                            (1 .. Clients (CI).Cid_Last),
                        Topic    =>
                          Topics_Buf (K) (1 .. Topic_Lasts (K)),
                        Payload  => Empty,
                        QoS      => Topic_QoS (K),
                        Subscriber_Count => 0);
                  end loop;
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
                  Suppress_Route : Boolean := False;
               begin
                  Wire.Decode_Publish
                    (Buf, Pkt_Last, Decode_OK,
                     QoS, Pid, Topic, Topic_Last,
                     Payload, Payload_Last);
                  if not Decode_OK then
                     Disconnect_Client (CI);
                     return;
                  end if;

                  --  §4.3 ack-protocol: deliver-on-receipt for q1/q2,
                  --  but for q2 record the packet-id so a DUP retry
                  --  doesn't deliver twice.
                  case QoS is
                     when RFLX.Control_Packet.QOS_1 =>
                        Wire.Encode_Puback (Buf, Out_Last, Pid);
                        Send_All
                          (Clients (CI).Sock,
                           Buf.all (Buf'First .. Out_Last));
                     when RFLX.Control_Packet.QOS_2 =>
                        if Find_Inbound_QoS2_Slot (CI, Pid) /= 0 then
                           --  DUP retransmission of a PUBLISH we
                           --  already routed; just re-emit PUBREC.
                           Suppress_Route := True;
                        else
                           declare
                              Slot : constant Natural :=
                                Find_Free_Inbound_QoS2 (CI);
                           begin
                              if Slot /= 0 then
                                 Clients (CI).Inbound_QoS2 (Slot) :=
                                   (In_Use => True, Pid => Pid);
                              end if;
                           end;
                        end if;
                        Wire.Encode_Pubrec (Buf, Out_Last, Pid);
                        Send_All
                          (Clients (CI).Sock,
                           Buf.all (Buf'First .. Out_Last));
                     when others => null;
                  end case;

                  --  Route to subscribers (skipping QoS 2 duplicates).
                  if not Suppress_Route then
                     if Payload_Last > 0 then
                        Route_Publish
                          (Topic (1 .. Topic_Last),
                           Payload
                             (Payload'First ..
                                Payload'First +
                                   RFLX.RFLX_Types.Index (Payload_Last)
                                   - 1),
                           QoS, Sub_Count);
                     else
                        Route_Publish
                          (Topic (1 .. Topic_Last),
                           Empty, QoS, Sub_Count);
                     end if;
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

            when RFLX.Control_Packet.PUBACK =>
               --  Subscriber acks an outbound q1 PUBLISH we forwarded.
               declare
                  Valid : Boolean;
                  Pid   : Wire.Packet_Identifier;
                  Slot  : Natural;
               begin
                  Wire.Decode_Puback (Buf, Pkt_Last, Valid, Pid);
                  if Valid then
                     Slot := Find_Outbound_By_Pid (CI, Pid);
                     if Slot /= 0
                       and then Clients (CI).Outbound_Inflight (Slot)
                                  .Stage = Awaiting_Puback
                     then
                        Clients (CI).Outbound_Inflight (Slot) :=
                          (Stage => Free, Pid => 1);
                     end if;
                  end if;
               end;

            when RFLX.Control_Packet.PUBREC =>
               --  Subscriber acks our q2 PUBLISH; reply PUBREL and
               --  advance the inflight slot to Awaiting_Pubcomp.
               declare
                  Valid : Boolean;
                  Pid   : Wire.Packet_Identifier;
                  Slot  : Natural;
               begin
                  Wire.Decode_Pubrec (Buf, Pkt_Last, Valid, Pid);
                  if Valid then
                     Slot := Find_Outbound_By_Pid (CI, Pid);
                     if Slot /= 0
                       and then Clients (CI).Outbound_Inflight (Slot)
                                  .Stage = Awaiting_Pubrec
                     then
                        Clients (CI).Outbound_Inflight (Slot).Stage :=
                          Awaiting_Pubcomp;
                     end if;
                     Wire.Encode_Pubrel (Buf, Out_Last, Pid);
                     Send_All
                       (Clients (CI).Sock,
                        Buf.all (Buf'First .. Out_Last));
                  end if;
               end;

            when RFLX.Control_Packet.PUBREL =>
               --  Publisher releases an inbound q2 packet-id; we
               --  forget the dup-suppression slot and reply PUBCOMP.
               declare
                  Valid : Boolean;
                  Pid   : Wire.Packet_Identifier;
                  Slot  : Natural;
               begin
                  Wire.Decode_Pubrel (Buf, Pkt_Last, Valid, Pid);
                  if Valid then
                     Slot := Find_Inbound_QoS2_Slot (CI, Pid);
                     if Slot /= 0 then
                        Clients (CI).Inbound_QoS2 (Slot) :=
                          (In_Use => False, Pid => 1);
                     end if;
                     Wire.Encode_Pubcomp (Buf, Out_Last, Pid);
                     Send_All
                       (Clients (CI).Sock,
                        Buf.all (Buf'First .. Out_Last));
                  end if;
               end;

            when RFLX.Control_Packet.PUBCOMP =>
               --  Final ack of our outbound q2 PUBLISH.
               declare
                  Valid : Boolean;
                  Pid   : Wire.Packet_Identifier;
                  Slot  : Natural;
               begin
                  Wire.Decode_Pubcomp (Buf, Pkt_Last, Valid, Pid);
                  if Valid then
                     Slot := Find_Outbound_By_Pid (CI, Pid);
                     if Slot /= 0
                       and then Clients (CI).Outbound_Inflight (Slot)
                                  .Stage = Awaiting_Pubcomp
                     then
                        Clients (CI).Outbound_Inflight (Slot) :=
                          (Stage => Free, Pid => 1);
                     end if;
                  end if;
               end;

            when others =>
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
