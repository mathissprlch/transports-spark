with Tls_Core;

package body Mqtt_Core.Transport is

   use type RFLX.RFLX_Types.Index;
   use type RFLX.RFLX_Types.Length;

   type Tls_Chan_Acc is access all Tls_Transport.Channel;

   function To_Octets
     (B : RFLX.RFLX_Types.Bytes) return Tls_Core.Octet_Array
   is
      Result : Tls_Core.Octet_Array (1 .. B'Length);
   begin
      for I in B'Range loop
         Result (Natural (I - B'First) + 1) := Tls_Core.Octet (B (I));
      end loop;
      return Result;
   end To_Octets;

   function To_Bytes
     (O : Tls_Core.Octet_Array) return RFLX.RFLX_Types.Bytes
   is
      Result : RFLX.RFLX_Types.Bytes
        (RFLX.RFLX_Types.Index (O'First) ..
         RFLX.RFLX_Types.Index (O'Last));
   begin
      for I in O'Range loop
         Result (RFLX.RFLX_Types.Index (I)) :=
           RFLX.RFLX_Types.Byte (O (I));
      end loop;
      return Result;
   end To_Bytes;

   procedure Set_Trust_Anchor
     (Chan : in out Channel;
      Der  : RFLX.RFLX_Types.Bytes)
   is
      Len : constant Natural := Der'Length;
   begin
      if Len > Tls_Transport.Max_Trust then
         raise Connect_Error
           with "trust anchor exceeds Max_Trust";
      end if;
      Chan.Cfg.Mode := Tls_Transport.Cert_Ec;
      Chan.Cfg.Trust_Der (1 .. Len) := To_Octets (Der);
      Chan.Cfg.Trust_Der_Len := Len;
      Chan.Cfg_Set := True;
   end Set_Trust_Anchor;

   procedure Connect
     (Chan : in out Channel;
      Host : String;
      Port : Natural)
   is
      H_Len : constant Natural := Natural'Min (Host'Length,
        Tls_Transport.Max_Hostname);
   begin
      Chan.Cfg.Hostname (1 .. H_Len) := Host (Host'First ..
        Host'First + H_Len - 1);
      Chan.Cfg.Hostname_Len := H_Len;
      Tls_Transport.Connect (Chan.Tls, Host, Port, Chan.Cfg);
      Chan.Open := True;
   exception
      when Tls_Transport.Connect_Error =>
         Chan.Open := False;
         raise Connect_Error;
      when others =>
         Chan.Open := False;
         raise Connect_Error;
   end Connect;

   function Is_Open (Chan : Channel) return Boolean is (Chan.Open);

   procedure Send
     (Chan : Channel;
      Data : RFLX.RFLX_Types.Bytes)
   is
      P : constant Tls_Chan_Acc := Chan.Tls'Unrestricted_Access;
   begin
      Tls_Transport.Send (P.all, To_Octets (Data));
   exception
      when Tls_Transport.Send_Error =>
         raise Send_Error;
   end Send;

   procedure Receive
     (Chan    : Channel;
      Buffer  : out RFLX.RFLX_Types.Bytes;
      Last    : out RFLX.RFLX_Types.Index;
      Success : out Boolean)
   is
      Tls_Buf  : Tls_Core.Octet_Array (1 .. Buffer'Length) :=
        (others => 0);
      Tls_Last : Natural;
      Tls_OK   : Boolean;
      P        : constant Tls_Chan_Acc := Chan.Tls'Unrestricted_Access;
   begin
      Buffer  := (others => 0);
      Last    := Buffer'First;
      Success := False;
      Tls_Transport.Receive (P.all, Tls_Buf, Tls_Last, Tls_OK);
      if not Tls_OK or Tls_Last < 1 then
         return;
      end if;
      declare
         Copy_Len : constant Natural :=
           Natural'Min (Tls_Last, Buffer'Length);
         Out_Bytes : constant RFLX.RFLX_Types.Bytes :=
           To_Bytes (Tls_Buf (1 .. Copy_Len));
      begin
         Buffer (Buffer'First .. Buffer'First +
           RFLX.RFLX_Types.Index (Copy_Len) - 1) := Out_Bytes;
         Last := Buffer'First +
           RFLX.RFLX_Types.Index (Copy_Len) - 1;
         Success := True;
      end;
   end Receive;

   procedure Receive_Full
     (Chan    : Channel;
      Buffer  : out RFLX.RFLX_Types.Bytes;
      Success : out Boolean)
   is
      Cursor   : RFLX.RFLX_Types.Index := Buffer'First;
      Sub_Last : RFLX.RFLX_Types.Index;
      Sub_Ok   : Boolean;
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

   procedure Close (Chan : in out Channel) is
   begin
      if Tls_Transport.Is_Open (Chan.Tls) then
         Tls_Transport.Close (Chan.Tls);
      end if;
      Chan.Open := False;
   end Close;

   function Is_Listening (L : Listener) return Boolean is
     (L.Listening);

   procedure Set_Server_Identity
     (L        : in out Listener;
      Cert_Der : RFLX.RFLX_Types.Bytes;
      Key_Raw  : RFLX.RFLX_Types.Bytes)
   is
      C_Len : constant Natural := Cert_Der'Length;
      K_Len : constant Natural := Key_Raw'Length;
   begin
      L.Srv_Cfg.Mode := Tls_Transport.Cert_Ec;
      L.Srv_Cfg.Cert_Der (1 .. C_Len) := To_Octets (Cert_Der);
      L.Srv_Cfg.Cert_Der_Len := C_Len;
      if K_Len <= 32 then
         L.Srv_Cfg.Key_Raw (1 .. K_Len) := To_Octets (Key_Raw);
         L.Srv_Cfg.Key_Raw_Len := K_Len;
      end if;
      L.Srv_Set := True;
   end Set_Server_Identity;

   procedure Listen
     (L    : in out Listener;
      Host : String;
      Port : Natural)
   is
   begin
      Tls_Transport.Listen (L.Tls_L, Host, Port);
      L.Listening := True;
   exception
      when others =>
         L.Listening := False;
         raise Connect_Error;
   end Listen;

   procedure Accept_One
     (L    : in out Listener;
      Chan : in out Channel)
   is
   begin
      Tls_Transport.Accept_One (L.Tls_L, Chan.Tls, L.Srv_Cfg);
      Chan.Open := True;
   exception
      when others =>
         Chan.Open := False;
         raise Connect_Error;
   end Accept_One;

   procedure Stop (L : in out Listener) is
   begin
      Tls_Transport.Stop (L.Tls_L);
      L.Listening := False;
   end Stop;

end Mqtt_Core.Transport;
