--  Mqtt_Core.Broker — multi-client event-loop body. Hosted only;
--  uses GNAT.Sockets selector primitives directly.

with RFLX.RFLX_Types; use type RFLX.RFLX_Types.Index;
with RFLX.RFLX_Builtin_Types;
with RFLX.Suback;
with RFLX.Connack;
with RFLX.Session.Broker_Reading.FSM;

with Ada.Real_Time;
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

   Retry_Topic_Cap   : constant := 128;
   Retry_Payload_Cap : constant := 512;

   --  RFC §4.4: a sender that doesn't get an expected ack is
   --  required to retransmit on reconnect. We do better and
   --  retransmit periodically while the connection is up, up to
   --  Retry_Max attempts spaced Retry_Period_Ms apart, then drop
   --  the slot. The slot caches the original PUBLISH content
   --  (topic + payload + effective QoS) so retries don't need the
   --  publisher to be still around.
   --
   --  Pid range is 1..65535 (0 is reserved by §2.3.1). The slot's
   --  Stage flag is the source of truth for occupancy; Pid /
   --  retry-state fields are meaningful only when Stage /= Free.
   type Outbound_Inflight_Slot is record
      Stage          : Inflight_Stage := Free;
      Pid            : Wire.Packet_Identifier := 1;
      Time_Last_Sent : Ada.Real_Time.Time := Ada.Real_Time.Time_First;
      Retry_Count    : Natural := 0;
      Topic          : String (1 .. Retry_Topic_Cap) := (others => ' ');
      Topic_Last     : Natural := 0;
      Payload        : RFLX.RFLX_Types.Bytes (1 .. Retry_Payload_Cap) :=
        (others => 0);
      Payload_Last   : Natural := 0;
   end record;

   --  Reset constant — used wherever a slot returns to Free.
   --  Hides the new retry-state fields from the call sites.
   Free_Inflight : constant Outbound_Inflight_Slot :=
     (Stage          => Free,
      Pid            => 1,
      Time_Last_Sent => Ada.Real_Time.Time_First,
      Retry_Count    => 0,
      Topic          => (others => ' '),
      Topic_Last     => 0,
      Payload        => (others => 0),
      Payload_Last   => 0);

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
      --  §3.1.2.5 / §3.1.3.2-3 — Will state captured at CONNECT.
      --  Will_Pending=True means the broker MUST publish (Will_Topic,
      --  Will_Message) on abnormal disconnect (network drop, malformed
      --  packet, KeepAlive timeout). A clean DISCONNECT clears it
      --  before the socket close so it isn't re-published.
      Will_Pending : Boolean := False;
      Will_Topic   : String (1 .. 64) := (others => ' ');
      Will_Topic_Last : Natural := 0;
      Will_Message : RFLX.RFLX_Types.Bytes (1 .. 256) :=
        (others => 0);
      Will_Message_Last : Natural := 0;
      Will_QoS     : RFLX.Control_Packet.QoS_Level :=
        RFLX.Control_Packet.QOS_0;
      Will_Retain  : Boolean := False;
      --  §3.1.2.4 — if False the broker preserves the client's
      --  subscriptions across this disconnect for resumption on
      --  the next CONNECT carrying the same Client_Id.
      Clean_Session : Boolean := True;
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
   --  Retained-message registry (§3.3.1.3)
   --
   --  When a subscriber issues SUBSCRIBE with a filter, the broker
   --  delivers any retained message whose topic matches that
   --  filter as the "initial value" — even if no client has
   --  PUBLISHed since the subscription was made.
   --
   --  Inbound PUBLISH with RETAIN=1: replace the slot whose Topic
   --  matches; if the topic is new, allocate a free slot.
   --  Inbound PUBLISH with RETAIN=1 and zero-length payload:
   --  clear the slot for that topic (§3.3.1.3 special-case).
   ----------------------------------------------------------------

   Max_Retained : constant := 32;

   type Retained_Slot is record
      In_Use       : Boolean := False;
      Topic        : String (1 .. 256) := (others => ' ');
      Topic_Last   : Natural := 0;
      Payload      : RFLX.RFLX_Types.Bytes (1 .. 1024) := (others => 0);
      Payload_Last : RFLX.RFLX_Types.Length := 0;
      QoS          : RFLX.Control_Packet.QoS_Level :=
        RFLX.Control_Packet.QOS_0;
   end record;

   subtype Retained_Index is Natural range 1 .. Max_Retained;
   type Retained_Array is array (Retained_Index) of Retained_Slot;

   ----------------------------------------------------------------
   --  Session registry (§3.1.2.4 persistent sessions)
   --
   --  When a client connects with Clean_Session=False and later
   --  disconnects, we capture its subscription set keyed by
   --  Client_Id. On a subsequent CONNECT (also Clean_Session=False)
   --  carrying the same Client_Id, we restore the subscriptions
   --  and set Session_Present=True in CONNACK.
   --
   --  v0.4 only preserves subscriptions; offline-message queuing
   --  (§4.1 "pending Server-to-Client messages") is deferred.
   ----------------------------------------------------------------

   Max_Sessions     : constant := 16;
   Max_Sub_Per_Session : constant := 16;

   type Saved_Sub is record
      Topic_Filter : String (1 .. 256) := (others => ' ');
      Filter_Last  : Natural := 0;
      QoS          : RFLX.Control_Packet.QoS_Level :=
        RFLX.Control_Packet.QOS_0;
   end record;

   type Saved_Sub_Array is
     array (1 .. Max_Sub_Per_Session) of Saved_Sub;

   type Session_Slot is record
      In_Use      : Boolean := False;
      Client_Id   : String (1 .. 64) := (others => ' ');
      Cid_Last    : Natural := 0;
      Subs        : Saved_Sub_Array;
      Sub_Count   : Natural := 0;
   end record;

   subtype Session_Index is Natural range 1 .. Max_Sessions;
   type Session_Array is array (Session_Index) of Session_Slot;

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
      Retained  : Retained_Array;
      Sessions  : Session_Array;
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

      procedure Update_Retained
        (Reg     : in out Retained_Array;
         Topic   : String;
         Payload : RFLX.RFLX_Types.Bytes;
         QoS     : RFLX.Control_Packet.QoS_Level);

      procedure Clear_Retained
        (Reg : in out Retained_Array; Topic : String);

      procedure Route_Publish
        (Topic   : String;
         Payload : RFLX.RFLX_Types.Bytes;
         Pub_QoS : RFLX.Control_Packet.QoS_Level;
         Sub_Count : out Natural);

      procedure Disconnect_Client (CI : Active_Client) is
         Sub_Count : Natural := 0;
      begin
         --  §3.1.2.5: if Will is still pending (i.e., the client did
         --  NOT issue a clean DISCONNECT), publish the Will message.
         --  Note: Subs are dropped *after* this so the publishing
         --  client's own subscriptions still match if the will is
         --  on a topic they themselves subscribed to.
         if Clients (CI).Will_Pending
           and then Clients (CI).Will_Topic_Last > 0
         then
            declare
               Pl : constant RFLX.RFLX_Types.Bytes :=
                 Clients (CI).Will_Message
                   (1 .. RFLX.RFLX_Types.Index
                           (Clients (CI).Will_Message_Last));
               T  : constant String :=
                 Clients (CI).Will_Topic
                   (1 .. Clients (CI).Will_Topic_Last);
            begin
               --  RETAIN handling: §3.3.1.3 — if Will_Retain is set
               --  the message is stored as the topic's retained
               --  value too.
               if Clients (CI).Will_Retain then
                  if Pl'Length = 0 then
                     Clear_Retained (Retained, T);
                  else
                     Update_Retained
                       (Retained, T, Pl, Clients (CI).Will_QoS);
                  end if;
               end if;
               Route_Publish (T, Pl, Clients (CI).Will_QoS, Sub_Count);
            end;
            Clients (CI).Will_Pending := False;
         end if;

         --  §3.1.2.4: snapshot subscriptions onto the Sessions
         --  table when Clean_Session=False so a future CONNECT for
         --  the same Client_Id can resume them.
         if not Clients (CI).Clean_Session
           and then Clients (CI).Cid_Last > 0
         then
            declare
               Cid : constant String :=
                 Clients (CI).Client_Id
                   (1 .. Clients (CI).Cid_Last);
               Sess_Idx : Natural := 0;
               Free_Idx : Natural := 0;
            begin
               for SI in Sessions'Range loop
                  if Sessions (SI).In_Use
                    and then Sessions (SI).Cid_Last = Cid'Length
                    and then Sessions (SI).Client_Id
                               (1 .. Sessions (SI).Cid_Last)
                             = Cid
                  then
                     Sess_Idx := SI;
                     exit;
                  elsif not Sessions (SI).In_Use
                    and then Free_Idx = 0
                  then
                     Free_Idx := SI;
                  end if;
               end loop;
               if Sess_Idx = 0 then
                  Sess_Idx := Free_Idx;
               end if;
               if Sess_Idx /= 0 then
                  Sessions (Sess_Idx).In_Use    := True;
                  Sessions (Sess_Idx).Client_Id := (others => ' ');
                  Sessions (Sess_Idx).Client_Id (1 .. Cid'Length)
                    := Cid;
                  Sessions (Sess_Idx).Cid_Last  := Cid'Length;
                  Sessions (Sess_Idx).Sub_Count := 0;
                  for I in Subs'Range loop
                     if Subs (I).In_Use
                       and then Subs (I).Owner = CI
                       and then Sessions (Sess_Idx).Sub_Count
                                < Max_Sub_Per_Session
                     then
                        Sessions (Sess_Idx).Sub_Count :=
                          Sessions (Sess_Idx).Sub_Count + 1;
                        declare
                           K : constant Positive :=
                             Sessions (Sess_Idx).Sub_Count;
                           Saved : Saved_Sub renames
                             Sessions (Sess_Idx).Subs (K);
                        begin
                           Saved.Topic_Filter := (others => ' ');
                           Saved.Topic_Filter
                             (1 .. Subs (I).Filter_Last) :=
                               Subs (I).Topic_Filter
                                 (1 .. Subs (I).Filter_Last);
                           Saved.Filter_Last := Subs (I).Filter_Last;
                           Saved.QoS := Subs (I).QoS;
                        end;
                     end if;
                  end loop;
               end if;
            end;
         end if;

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
              Free_Inflight;
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
      --  Retry policy: a packet that doesn't get its expected ack
      --  in Retry_Period gets retransmitted with the same Pid; if
      --  Retry_Max attempts go unanswered we give up and free the
      --  slot (the publisher's view: message lost).
      ---------------------------------------------------------------

      Retry_Period : constant Ada.Real_Time.Time_Span :=
        Ada.Real_Time.Milliseconds (1500);
      Retry_Max    : constant := 3;

      procedure Stash_Inflight
        (Owner   : Active_Client;
         Slot    : Positive;
         Stage   : Inflight_Stage;
         Pid     : Wire.Packet_Identifier;
         Topic   : String;
         Payload : RFLX.RFLX_Types.Bytes);

      procedure Stash_Inflight
        (Owner   : Active_Client;
         Slot    : Positive;
         Stage   : Inflight_Stage;
         Pid     : Wire.Packet_Identifier;
         Topic   : String;
         Payload : RFLX.RFLX_Types.Bytes)
      is
         Tlen : constant Natural :=
           Natural'Min (Topic'Length, Retry_Topic_Cap);
         Plen : constant Natural :=
           Natural'Min (Payload'Length, Retry_Payload_Cap);
      begin
         Clients (Owner).Outbound_Inflight (Slot) :=
           (Stage          => Stage,
            Pid            => Pid,
            Time_Last_Sent => Ada.Real_Time.Clock,
            Retry_Count    => 0,
            Topic          => (others => ' '),
            Topic_Last     => Tlen,
            Payload        => (others => 0),
            Payload_Last   => Plen);
         if Tlen > 0 then
            Clients (Owner).Outbound_Inflight (Slot).Topic
              (1 .. Tlen) :=
                Topic (Topic'First .. Topic'First + Tlen - 1);
         end if;
         if Plen > 0 then
            Clients (Owner).Outbound_Inflight (Slot).Payload
              (1 .. RFLX.RFLX_Types.Index (Plen)) :=
                Payload
                  (Payload'First ..
                     Payload'First + RFLX.RFLX_Types.Index (Plen) - 1);
         end if;
      end Stash_Inflight;

      procedure Sweep_Inflight_Retries;
      procedure Sweep_Inflight_Retries is
         use type Ada.Real_Time.Time;
         use type Ada.Real_Time.Time_Span;
         Now : constant Ada.Real_Time.Time := Ada.Real_Time.Clock;
         Out_Last : RFLX.RFLX_Types.Index;
      begin
         for CI in Clients'Range loop
            if Clients (CI).In_Use and then Clients (CI).Connected then
               for I in Clients (CI).Outbound_Inflight'Range loop
                  declare
                     Slot : Outbound_Inflight_Slot renames
                       Clients (CI).Outbound_Inflight (I);
                  begin
                     if Slot.Stage /= Free
                       and then Now - Slot.Time_Last_Sent
                                  >= Retry_Period
                     then
                        if Slot.Retry_Count >= Retry_Max then
                           --  Give up; slot returns to Free.
                           Slot := Free_Inflight;
                        else
                           --  Retransmit with the same Pid. Most
                           --  brokers/clients dedupe on Pid; DUP=1
                           --  flag would be ideal but the v0.3
                           --  Encode_Publish_* helpers don't yet
                           --  expose it.
                           case Slot.Stage is
                              when Awaiting_Puback =>
                                 Wire.Encode_Publish_Qos1
                                   (Buffer    =>
                                      Clients (CI).Working_Buf,
                                    Last      => Out_Last,
                                    Packet_Id => Slot.Pid,
                                    Topic     =>
                                      Slot.Topic
                                        (1 .. Slot.Topic_Last),
                                    Payload   =>
                                      Slot.Payload
                                        (1 ..
                                           RFLX.RFLX_Types.Index
                                             (Slot.Payload_Last)));
                                 Send_All
                                   (Clients (CI).Sock,
                                    Clients (CI).Working_Buf.all
                                      (Clients (CI).Working_Buf'First
                                       .. Out_Last));
                              when Awaiting_Pubrec =>
                                 Wire.Encode_Publish_Qos2
                                   (Buffer    =>
                                      Clients (CI).Working_Buf,
                                    Last      => Out_Last,
                                    Packet_Id => Slot.Pid,
                                    Topic     =>
                                      Slot.Topic
                                        (1 .. Slot.Topic_Last),
                                    Payload   =>
                                      Slot.Payload
                                        (1 ..
                                           RFLX.RFLX_Types.Index
                                             (Slot.Payload_Last)));
                                 Send_All
                                   (Clients (CI).Sock,
                                    Clients (CI).Working_Buf.all
                                      (Clients (CI).Working_Buf'First
                                       .. Out_Last));
                              when Awaiting_Pubcomp =>
                                 --  Resend PUBREL (we've already
                                 --  seen PUBREC; the peer's PUBCOMP
                                 --  is what we're waiting for).
                                 Wire.Encode_Pubrel
                                   (Buffer    =>
                                      Clients (CI).Working_Buf,
                                    Last      => Out_Last,
                                    Packet_Id => Slot.Pid);
                                 Send_All
                                   (Clients (CI).Sock,
                                    Clients (CI).Working_Buf.all
                                      (Clients (CI).Working_Buf'First
                                       .. Out_Last));
                              when Free => null;  --  unreachable
                           end case;
                           Slot.Time_Last_Sent := Now;
                           Slot.Retry_Count := Slot.Retry_Count + 1;
                        end if;
                     end if;
                  end;
               end loop;
            end if;
         end loop;
      end Sweep_Inflight_Retries;

      ---------------------------------------------------------------
      --  Retained-message helpers (§3.3.1.3)
      ---------------------------------------------------------------

      procedure Update_Retained
        (Reg     : in out Retained_Array;
         Topic   : String;
         Payload : RFLX.RFLX_Types.Bytes;
         QoS     : RFLX.Control_Packet.QoS_Level)
      is
         Free_Idx : Natural := 0;
      begin
         if Topic'Length = 0 or else Topic'Length > 256
           or else Payload'Length > 1024
         then
            return;
         end if;
         for I in Reg'Range loop
            if Reg (I).In_Use
              and then Reg (I).Topic_Last = Topic'Length
              and then Reg (I).Topic (1 .. Reg (I).Topic_Last) = Topic
            then
               Reg (I).Payload (1 ..
                 RFLX.RFLX_Types.Index (Payload'Length)) := Payload;
               Reg (I).Payload_Last :=
                 RFLX.RFLX_Types.Length (Payload'Length);
               Reg (I).QoS := QoS;
               return;
            elsif not Reg (I).In_Use and then Free_Idx = 0 then
               Free_Idx := I;
            end if;
         end loop;
         if Free_Idx /= 0 then
            Reg (Free_Idx).In_Use := True;
            Reg (Free_Idx).Topic := (others => ' ');
            Reg (Free_Idx).Topic (1 .. Topic'Length) := Topic;
            Reg (Free_Idx).Topic_Last := Topic'Length;
            Reg (Free_Idx).Payload (1 ..
              RFLX.RFLX_Types.Index (Payload'Length)) := Payload;
            Reg (Free_Idx).Payload_Last :=
              RFLX.RFLX_Types.Length (Payload'Length);
            Reg (Free_Idx).QoS := QoS;
         end if;
      end Update_Retained;

      procedure Clear_Retained
        (Reg : in out Retained_Array; Topic : String) is
      begin
         for I in Reg'Range loop
            if Reg (I).In_Use
              and then Reg (I).Topic_Last = Topic'Length
              and then Reg (I).Topic (1 .. Reg (I).Topic_Last) = Topic
            then
               Reg (I).In_Use := False;
               Reg (I).Topic_Last := 0;
               Reg (I).Payload_Last := 0;
            end if;
         end loop;
      end Clear_Retained;

      ---------------------------------------------------------------
      --  Route a published message to all matching subscribers.
      --  Outbound QoS = min(publish_qos, subscriber_granted_qos).
      --  v0.2 caps at QoS 1 (no PUBREC/PUBREL outbound flow).
      ---------------------------------------------------------------

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
                                 Stash_Inflight
                                   (Owner, Slot,
                                    Awaiting_Puback, Pid,
                                    Topic, Payload);
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
                                 Stash_Inflight
                                   (Owner, Slot,
                                    Awaiting_Pubrec, Pid,
                                    Topic, Payload);
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
      --  Replay retained messages matching `Filter` to the freshly
      --  subscribed client (§3.3.1.3 — RETAIN flag set to 1 so the
      --  client knows it's a stored value, not a fresh publish).
      ---------------------------------------------------------------

      procedure Replay_Retained_Matches
        (Reg     : Retained_Array;
         Owner   : Active_Client;
         Filter  : String;
         Granted : RFLX.Control_Packet.QoS_Level);

      procedure Replay_Retained_Matches
        (Reg     : Retained_Array;
         Owner   : Active_Client;
         Filter  : String;
         Granted : RFLX.Control_Packet.QoS_Level)
      is
         Out_Last : RFLX.RFLX_Types.Index;
      begin
         for I in Reg'Range loop
            if Reg (I).In_Use
              and then Topics.Matches
                         (Reg (I).Topic (1 .. Reg (I).Topic_Last),
                          Filter)
            then
               declare
                  Effective : constant RFLX.Control_Packet.QoS_Level :=
                    (if Reg (I).QoS = RFLX.Control_Packet.QOS_0
                       or else Granted = RFLX.Control_Packet.QOS_0
                     then RFLX.Control_Packet.QOS_0
                     elsif Reg (I).QoS = RFLX.Control_Packet.QOS_1
                       or else Granted = RFLX.Control_Packet.QOS_1
                     then RFLX.Control_Packet.QOS_1
                     else RFLX.Control_Packet.QOS_2);
                  Pl : constant RFLX.RFLX_Types.Bytes :=
                    Reg (I).Payload
                      (1 .. RFLX.RFLX_Types.Index
                              (Reg (I).Payload_Last));
               begin
                  if not Clients (Owner).In_Use
                    or else not Clients (Owner).Connected
                  then
                     return;
                  end if;
                  case Effective is
                     when RFLX.Control_Packet.QOS_0 =>
                        Wire.Encode_Publish_Qos0
                          (Clients (Owner).Working_Buf, Out_Last,
                           Reg (I).Topic (1 .. Reg (I).Topic_Last),
                           Pl, Retain => True);
                        Send_All
                          (Clients (Owner).Sock,
                           Clients (Owner).Working_Buf.all
                             (Clients (Owner).Working_Buf'First
                              .. Out_Last));
                     when RFLX.Control_Packet.QOS_1 =>
                        declare
                           Slot : constant Natural :=
                             Find_Free_Outbound (Owner);
                           Pid  : Wire.Packet_Identifier;
                        begin
                           if Slot /= 0 then
                              Pid := Next_Outbound_Pid (Owner);
                              Wire.Encode_Publish_Qos1
                                (Buffer    =>
                                   Clients (Owner).Working_Buf,
                                 Last      => Out_Last,
                                 Packet_Id => Pid,
                                 Topic     =>
                                   Reg (I).Topic
                                     (1 .. Reg (I).Topic_Last),
                                 Payload   => Pl,
                                 Retain    => True);
                              Stash_Inflight
                                (Owner, Slot, Awaiting_Puback, Pid,
                                 Reg (I).Topic
                                   (1 .. Reg (I).Topic_Last), Pl);
                              Send_All
                                (Clients (Owner).Sock,
                                 Clients (Owner).Working_Buf.all
                                   (Clients (Owner).Working_Buf'First
                                    .. Out_Last));
                           end if;
                        end;
                     when RFLX.Control_Packet.QOS_2 =>
                        declare
                           Slot : constant Natural :=
                             Find_Free_Outbound (Owner);
                           Pid  : Wire.Packet_Identifier;
                        begin
                           if Slot /= 0 then
                              Pid := Next_Outbound_Pid (Owner);
                              Wire.Encode_Publish_Qos2
                                (Buffer    =>
                                   Clients (Owner).Working_Buf,
                                 Last      => Out_Last,
                                 Packet_Id => Pid,
                                 Topic     =>
                                   Reg (I).Topic
                                     (1 .. Reg (I).Topic_Last),
                                 Payload   => Pl,
                                 Retain    => True);
                              Stash_Inflight
                                (Owner, Slot, Awaiting_Pubrec, Pid,
                                 Reg (I).Topic
                                   (1 .. Reg (I).Topic_Last), Pl);
                              Send_All
                                (Clients (Owner).Sock,
                                 Clients (Owner).Working_Buf.all
                                   (Clients (Owner).Working_Buf'First
                                    .. Out_Last));
                           end if;
                        end;
                  end case;
               end;
            end if;
         end loop;
      end Replay_Retained_Matches;

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
         Empty : constant RFLX.RFLX_Types.Bytes (1 .. 0) :=
           (others => 0);
      begin
         case Wire.Peek_Packet_Type (View) is
            when RFLX.Control_Packet.CONNECT =>
               declare
                  Valid : Boolean;
                  User_Name      : String (1 .. 64) :=
                    (others => ' ');
                  User_Name_Last : Natural := 0;
                  Password       : RFLX.RFLX_Types.Bytes
                    (1 .. 256) := (others => 0);
                  Password_Last  : Natural := 0;
                  Will_Flag      : Boolean;
                  Will_Topic     : String (1 .. 64) :=
                    (others => ' ');
                  Will_Topic_Last : Natural := 0;
                  Will_Msg       : RFLX.RFLX_Types.Bytes
                    (1 .. 256) := (others => 0);
                  Will_Msg_Last  : Natural := 0;
                  Will_QoS       : RFLX.Control_Packet.QoS_Level;
                  Will_Retain    : Boolean;
                  Clean_Sess     : Boolean;
               begin
                  Wire.Decode_Connect
                    (Buf, Pkt_Last, Valid,
                     Clients (CI).Client_Id,
                     Clients (CI).Cid_Last,
                     User_Name, User_Name_Last,
                     Password,  Password_Last,
                     Will_Flag, Will_Topic, Will_Topic_Last,
                     Will_Msg,  Will_Msg_Last,
                     Will_QoS,  Will_Retain,
                     Clean_Sess);
                  Clients (CI).Clean_Session := Clean_Sess;
                  if not Valid then
                     Disconnect_Client (CI);
                     return;
                  end if;

                  --  Capture Will state for later abnormal-disconnect
                  --  republishing (§3.1.2.5).
                  Clients (CI).Will_Pending := Will_Flag;
                  if Will_Flag then
                     Clients (CI).Will_Topic := (others => ' ');
                     Clients (CI).Will_Topic
                       (1 .. Will_Topic_Last) :=
                         Will_Topic (1 .. Will_Topic_Last);
                     Clients (CI).Will_Topic_Last :=
                       Will_Topic_Last;
                     Clients (CI).Will_Message := (others => 0);
                     Clients (CI).Will_Message
                       (1 .. RFLX.RFLX_Types.Index (Will_Msg_Last)) :=
                         Will_Msg
                           (1 .. RFLX.RFLX_Types.Index (Will_Msg_Last));
                     Clients (CI).Will_Message_Last := Will_Msg_Last;
                     Clients (CI).Will_QoS := Will_QoS;
                     Clients (CI).Will_Retain := Will_Retain;
                  end if;

                  --  §3.1.4.1: a server "MAY check that the contents
                  --  of the CONNECT Packet meet any further
                  --  restrictions and SHOULD perform authentication
                  --  and authorization checks." If the auth hook
                  --  rejects, return code 0x05 (Not_Authorized) per
                  --  §3.2.2.3 then close the network connection.
                  if not Authenticate
                    (Clients (CI).Client_Id (1 .. Clients (CI).Cid_Last),
                     User_Name (1 .. User_Name_Last),
                     Password
                       (Password'First
                        .. Password'First
                           + RFLX.RFLX_Types.Index (Password_Last) - 1))
                  then
                     Wire.Encode_Connack
                       (Buf, Out_Last,
                        Return_Code =>
                          RFLX.Connack.REFUSED_NOT_AUTHORIZED);
                     Send_All
                       (Clients (CI).Sock,
                        Buf.all (Buf'First .. Out_Last));
                     Disconnect_Client (CI);
                     return;
                  end if;
               end;
               --  §3.1.2.4 persistent sessions: look up any prior
               --  session for this Client_Id. With Clean_Session=
               --  True we drop it; with False we reinstate its
               --  subscriptions onto the current connection slot
               --  and signal Session_Present=True in CONNACK.
               declare
                  Cid : constant String :=
                    Clients (CI).Client_Id
                      (1 .. Clients (CI).Cid_Last);
                  Sess_Idx : Natural := 0;
                  Session_Present : Boolean := False;
               begin
                  for SI in Sessions'Range loop
                     if Sessions (SI).In_Use
                       and then Sessions (SI).Cid_Last = Cid'Length
                       and then Sessions (SI).Client_Id
                                  (1 .. Sessions (SI).Cid_Last)
                                = Cid
                     then
                        Sess_Idx := SI;
                        exit;
                     end if;
                  end loop;

                  if Clients (CI).Clean_Session then
                     if Sess_Idx /= 0 then
                        Sessions (Sess_Idx).In_Use := False;
                        Sessions (Sess_Idx).Sub_Count := 0;
                     end if;
                  elsif Sess_Idx /= 0 then
                     for K in 1 ..
                       Sessions (Sess_Idx).Sub_Count
                     loop
                        declare
                           Slot : constant Natural :=
                             Find_Free_Sub;
                           Saved : Saved_Sub renames
                             Sessions (Sess_Idx).Subs (K);
                        begin
                           if Slot /= 0 then
                              Subs (Slot) :=
                                (In_Use      => True,
                                 Owner       => CI,
                                 Topic_Filter => (others => ' '),
                                 Filter_Last  => Saved.Filter_Last,
                                 QoS          => Saved.QoS);
                              Subs (Slot).Topic_Filter
                                (1 .. Saved.Filter_Last) :=
                                  Saved.Topic_Filter
                                    (1 .. Saved.Filter_Last);
                           end if;
                        end;
                     end loop;
                     Session_Present := True;
                  end if;
                  Wire.Encode_Connack
                    (Buf, Out_Last,
                     Session_Present => Session_Present);
               end;
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
                     --  §3.3.1.3 (last paragraph): if any retained
                     --  message matches this filter, send it now
                     --  with RETAIN=1 so the subscriber can tell
                     --  it's the stored initial value rather than
                     --  a fresh publish.
                     if RFLX.Suback."/=" (Codes (K),
                                          RFLX.Suback.FAILURE)
                     then
                        Replay_Retained_Matches
                          (Retained, CI,
                           Topics_Buf (K) (1 .. Topic_Lasts (K)),
                           Topic_QoS (K));
                     end if;
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
                  Retain    : Boolean;
                  Sub_Count : Natural := 0;
                  Suppress_Route : Boolean := False;
               begin
                  Wire.Decode_Publish
                    (Buf, Pkt_Last, Decode_OK,
                     QoS, Pid, Topic, Topic_Last,
                     Payload, Payload_Last, Retain);
                  if not Decode_OK then
                     Disconnect_Client (CI);
                     return;
                  end if;

                  --  §3.3.1.3: RETAIN=1 with non-empty payload →
                  --  store as the new retained value (replacing any
                  --  prior retained for that topic). RETAIN=1 with
                  --  empty payload → clear any retained value but
                  --  still forward to current subscribers.
                  if Retain then
                     if Payload_Last = 0 then
                        Clear_Retained
                          (Retained, Topic (1 .. Topic_Last));
                     else
                        Update_Retained
                          (Retained,
                           Topic (1 .. Topic_Last),
                           Payload (Payload'First ..
                             Payload'First +
                               RFLX.RFLX_Types.Index (Payload_Last) - 1),
                           QoS);
                     end if;
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
               --  §3.1.2.5: a clean DISCONNECT cancels the Will.
               Clients (CI).Will_Pending := False;
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
                          Free_Inflight;
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
                          Free_Inflight;
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

         --  Even when the selector returned Expired (no socket
         --  woke us), the wake-up itself is the cue to scan for
         --  inflight slots whose retry window has elapsed.
         Sweep_Inflight_Retries;

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
