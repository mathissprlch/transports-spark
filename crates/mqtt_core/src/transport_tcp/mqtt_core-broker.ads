--  Mqtt_Core.Broker — multi-client MQTT 3.1.1 broker.
--
--  Single-task event-loop architecture: one Selector watches the
--  listening socket plus all active client sockets. When any socket
--  has data, the broker reads a frame and feeds it to that client's
--  Session::Broker_Reading FSM. Inbound PUBLISH is routed via a
--  topic-matcher to all subscribed clients (mqtt_core.Topics for
--  + / # wildcards per §4.7.1).
--
--  v0.2 broker capabilities:
--    * Up to Max_Clients concurrent clients (compile-time bound).
--    * Per-client subscription list (Max_Subscriptions slots total).
--    * QoS 0 + QoS 1 in both directions (q1 inbound → PUBACK to
--      publisher; q1 outbound to subscribers when their granted
--      QoS allows).
--    * Topic matching with `+` and `#` wildcards.
--    * Multi-filter SUBSCRIBE (each filter granted its requested QoS).
--    * UNSUBSCRIBE removes matching subscriptions.
--
--  Out of v0.2:
--    * QoS 2 routing (currently treated as q1 by capping outbound).
--    * Persistent sessions (Clean_Session=0).
--    * Will message / retained.
--    * TLS.
--    * MQTT 5.0 (Protocol_Level=5) — this is 3.1.1 only.
--
--  Verification dividend lives in the per-client
--  Session::Broker_Reading FSM (RFLX-generated): the dispatch table
--  enforces "CONNECT first, then any of 9 client→server packet
--  types". Multi-client routing + topic matching is hand-written
--  Ada glue.

with RFLX.RFLX_Types;
with RFLX.Control_Packet;

with Mqtt_Core.Transport;

package Mqtt_Core.Broker is

   Max_Clients       : constant := 16;
   Max_Subscriptions : constant := 64;

   type Listener is limited private;

   procedure Listen
     (L    : in out Listener;
      Host : String;
      Port : Natural := 1883);

   procedure Stop (L : in out Listener);

   --  Run the event loop until Stop_Flag is True (set externally,
   --  e.g. via SIGINT). On_Event is invoked once per significant
   --  application-level event for the caller's logging /
   --  observation. The broker has already done all protocol-level
   --  ACKs (CONNACK / SUBACK / UNSUBACK / PUBACK / PINGRESP) and
   --  routing before calling On_Event.
   type Event_Kind is
     (Client_Connected,
      Client_Subscribed,
      Client_Unsubscribed,
      Publish_Received,
      Publish_Forwarded,
      Pingreq_Received,
      Client_Disconnected);

   --  Default authentication hook — accepts every CONNECT regardless
   --  of credentials. Provided so brokers that don't care about auth
   --  can instantiate Run without writing one. Note that
   --  Password is binary (§3.1.3.5: arbitrary octets, not a string).
   pragma Warnings
     (Off, "formal parameter * is not referenced");
   function Allow_All_Auth
     (Client_Id : String;
      User_Name : String;
      Password  : RFLX.RFLX_Types.Bytes) return Boolean
   is (True);
   pragma Warnings
     (On, "formal parameter * is not referenced");

   generic
      with procedure On_Event
        (Kind         : Event_Kind;
         Client_Id    : String;
         Topic        : String;
         Payload      : RFLX.RFLX_Types.Bytes;
         QoS          : RFLX.Control_Packet.QoS_Level;
         Subscriber_Count : Natural);
      --  Returns True to accept the CONNECT, False to reject with
      --  CONNACK return code 0x05 (§3.2.2.3 — "not authorised").
      --  Empty user_name / password (length=0) means the client did
      --  not present that field; the hook can decide policy
      --  (anonymous-allowed vs deny).
      with function Authenticate
        (Client_Id : String;
         User_Name : String;
         Password  : RFLX.RFLX_Types.Bytes) return Boolean
        is Allow_All_Auth;
   procedure Run (L : in out Listener);

   Server_Error : exception;

private

   type Listener is limited record
      Trans     : Transport.Listener;
      Stopping  : Boolean := False;
   end record;

end Mqtt_Core.Broker;
