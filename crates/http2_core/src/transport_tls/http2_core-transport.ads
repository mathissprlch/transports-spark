--  Http2_Core.Transport -- TLS 1.3 transport adapter.
--
--  Same API surface as the TCP variant; the protocol layer above
--  (Http2_Core.Connection, Http2_Core.Server, Http2_Core.Mux_Server)
--  never knows whether bytes flow over raw TCP or TLS.
--
--  Selected by -XTRANSPORT=tls in http2_core.gpr.
--
--  Caller setup (before Connect / Accept_One):
--    Set_Trust_Anchor  -- client: DER-encoded CA certificate
--    Set_Server_Identity -- server: DER cert + raw private key

with RFLX.RFLX_Types;
with Tls_Transport;

package Http2_Core.Transport is

   type Channel is limited private;

   procedure Set_Trust_Anchor
     (Chan : in out Channel;
      Der  : RFLX.RFLX_Types.Bytes);

   procedure Connect
     (Chan : in out Channel;
      Host : String;
      Port : Natural);

   function Is_Open (Chan : Channel) return Boolean;

   procedure Send
     (Chan : Channel;
      Data : RFLX.RFLX_Types.Bytes)
   with Pre => Is_Open (Chan);

   procedure Receive
     (Chan    : Channel;
      Buffer  : out RFLX.RFLX_Types.Bytes;
      Last    : out RFLX.RFLX_Types.Index;
      Success : out Boolean)
   with Pre => Is_Open (Chan);

   function Has_Pending (Chan : Channel) return Boolean
   with Pre => Is_Open (Chan);

   procedure Wait_For_Data
     (Chan     : Channel;
      Timeout  : Duration;
      Got_Data : out Boolean)
   with Pre => Is_Open (Chan);

   procedure Receive_Full
     (Chan    : Channel;
      Buffer  : out RFLX.RFLX_Types.Bytes;
      Success : out Boolean)
   with Pre => Is_Open (Chan);

   procedure Close (Chan : in out Channel)
   with
     Pre  => Is_Open (Chan),
     Post => not Is_Open (Chan);

   type Listener is limited private;

   procedure Set_Server_Identity
     (L        : in out Listener;
      Cert_Der : RFLX.RFLX_Types.Bytes;
      Key_Raw  : RFLX.RFLX_Types.Bytes);

   procedure Listen
     (L    : in out Listener;
      Host : String;
      Port : Natural);

   function Is_Listening (L : Listener) return Boolean;

   procedure Accept_One
     (L    : in out Listener;
      Chan : in out Channel)
   with
     Pre  => Is_Listening (L),
     Post => Is_Open (Chan);

   procedure Stop (L : in out Listener)
   with
     Pre  => Is_Listening (L),
     Post => not Is_Listening (L);

   Connect_Error : exception;
   Send_Error    : exception;

private

   type Channel is limited record
      Tls       : aliased Tls_Transport.Channel;
      Cfg       : Tls_Transport.Tls_Config;
      Cfg_Set   : Boolean := False;
      Open      : Boolean := False;
   end record;

   type Listener is limited record
      Tls_L     : Tls_Transport.Listener;
      Srv_Cfg   : Tls_Transport.Tls_Config;
      Srv_Set   : Boolean := False;
      Listening : Boolean := False;
   end record;

end Http2_Core.Transport;
