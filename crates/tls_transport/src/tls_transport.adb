with Tls_Core.Aead_Channel;
with Tls_Core.Cert_Chain;
with Tls_Core.Suites;
with Tls_Core.Tls13_Driver;
with Tls_Core.Tcp_Transport;

package body Tls_Transport is

   use type Tls_Core.Octet;
   use type Tls_Core.Tls13_Driver.State;

   Ecdhe_Seed : constant Tls_Core.Octet_Array (1 .. 32) :=
     (16#A1#, 16#B2#, 16#C3#, 16#D4#, 16#E5#, 16#F6#, 16#07#, 16#18#,
      16#29#, 16#3A#, 16#4B#, 16#5C#, 16#6D#, 16#7E#, 16#8F#, 16#90#,
      16#01#, 16#12#, 16#23#, 16#34#, 16#45#, 16#56#, 16#67#, 16#78#,
      16#89#, 16#9A#, 16#AB#, 16#BC#, 16#CD#, 16#DE#, 16#EF#, 16#F0#);

   procedure Read_One_Record
     (Tcp    : Tls_Core.Tcp_Transport.Channel;
      Buf    : out Tls_Core.Octet_Array;
      Last   : out Natural;
      OK     : out Boolean)
   is
      use Tls_Core;
      Hdr_OK : Boolean;
   begin
      Last := 0;
      OK := False;
      Tcp_Transport.Recv_All (Tcp, Buf (Buf'First .. Buf'First + 4), Hdr_OK);
      if not Hdr_OK then return; end if;
      declare
         Rec_Len : constant Natural :=
           Natural (Buf (Buf'First + 3)) * 256
           + Natural (Buf (Buf'First + 4));
      begin
         if Buf'First + 5 + Rec_Len - 1 > Buf'Last then return; end if;
         Tcp_Transport.Recv_All
           (Tcp, Buf (Buf'First + 5 .. Buf'First + 4 + Rec_Len), Hdr_OK);
         if not Hdr_OK then return; end if;
         Last := Buf'First + 4 + Rec_Len;
         OK := True;
      end;
   end Read_One_Record;

   procedure Handshake_Loop
     (Chan : in out Channel)
   is
      use Tls_Core;
      use Tls_Core.Tls13_Driver;
      Out_Buf  : Octet_Array (1 .. 4096) := (others => 0);
      Out_Last : Natural;
      In_Buf   : Octet_Array (1 .. 16640) := (others => 0);
      In_Last  : Natural;
      In_OK    : Boolean;
   begin
      loop
         exit when Tls13_Driver.Current_State (Chan.Driver) = Done
           or else Tls13_Driver.Current_State (Chan.Driver) = Failed;

         Read_One_Record (Chan.Tcp, In_Buf, In_Last, In_OK);
         if not In_OK then
            raise Connect_Error with "TLS: EOF during handshake";
         end if;

         Step (Chan.Driver, In_Buf (1 .. In_Last), Out_Buf, Out_Last);

         if Out_Last > 0 then
            Tcp_Transport.Send_All (Chan.Tcp, Out_Buf (1 .. Out_Last));
         end if;
      end loop;

      if Tls13_Driver.Current_State (Chan.Driver) /= Done then
         raise Connect_Error with "TLS: handshake failed";
      end if;

      Open_App_Directions
        (Chan.Driver,
         Out_Dir => Chan.App_Out,
         In_Dir  => Chan.App_In);
      Chan.Open := True;
   end Handshake_Loop;

   procedure Connect
     (Chan   : in out Channel;
      Host   : String;
      Port   : Natural;
      Config : Tls_Config)
   is
      use Tls_Core;
      Out_Buf  : Octet_Array (1 .. 2048) := (others => 0);
      Out_Last : Natural;
   begin
      Tcp_Transport.Connect (Chan.Tcp, Host, Port);

      declare
         Trust_Spec : Tls_Core.Cert_Chain.Trust_Store;
         Host_Bytes : Octet_Array (1 .. Config.Hostname_Len);
      begin
         for I in Host_Bytes'Range loop
            Host_Bytes (I) := Octet (Character'Pos (
              Config.Hostname (I)));
         end loop;
         Trust_Spec.Count := 1;
         Trust_Spec.Entries (1) :=
           (First => 1, Last => Config.Trust_Der_Len);
         Tls13_Driver.Init_Cert_Client
           (D                  => Chan.Driver,
            Trust_Anchor_Bytes =>
              Config.Trust_Der (1 .. Config.Trust_Der_Len),
            Trust_Spec         => Trust_Spec,
            Hostname           => Host_Bytes,
            Ecdhe_Priv         => Ecdhe_Seed);
         if Config.Hostname_Len > 0 then
            Tls13_Driver.Set_Sni_Hostname (Chan.Driver, Host_Bytes);
         end if;
         if Config.Alpn_Len > 0 then
            declare
               Alpn_Bytes : Octet_Array (1 .. Config.Alpn_Len);
            begin
               for I in Alpn_Bytes'Range loop
                  Alpn_Bytes (I) := Octet (Character'Pos (
                    Config.Alpn (I)));
               end loop;
               Tls13_Driver.Set_Alpn_Offers (Chan.Driver, Alpn_Bytes);
            end;
         end if;
      end;

      Tls13_Driver.Step
        (Chan.Driver, Tls_Core.Octet_Array'(1 .. 0 => 0),
         Out_Buf, Out_Last);
      if Out_Last > 0 then
         Tcp_Transport.Send_All (Chan.Tcp, Out_Buf (1 .. Out_Last));
      end if;

      Handshake_Loop (Chan);
   end Connect;

   function Is_Open (Chan : Channel) return Boolean is
   begin
      return Chan.Open;
   end Is_Open;

   procedure Send
     (Chan : in out Channel;
      Data : Tls_Core.Octet_Array)
   is
      use Tls_Core;
      Rec : Octet_Array (1 .. Data'Length + 256) := (others => 0);
      Rec_Last : Natural;
   begin
      Aead_Channel.Send
        (Chan.App_Out, Data,
         Aead_Channel.Inner_Type_Application_Data,
         Rec, Rec_Last);
      Tcp_Transport.Send_All (Chan.Tcp, Rec (1 .. Rec_Last));
   end Send;

   procedure Receive
     (Chan    : in out Channel;
      Buffer  : out Tls_Core.Octet_Array;
      Last    : out Natural;
      Success : out Boolean)
   is
      use Tls_Core;
      Rec_Buf : Octet_Array (1 .. 16640 + 256) := (others => 0);
      Rec_Last : Natural;
      Rec_OK   : Boolean;
      Pt_Buf   : Octet_Array (1 .. 16640) := (others => 0);
      Pt_Last  : Natural;
      Inner_Type : Octet;
      Aead_OK : Boolean;
   begin
      Buffer := (others => 0);
      Last := Buffer'First - 1;
      Success := False;

      Read_One_Record (Chan.Tcp, Rec_Buf, Rec_Last, Rec_OK);
      if not Rec_OK then return; end if;

      Aead_Channel.Receive
        (Chan.App_In, Rec_Buf (1 .. Rec_Last),
         Pt_Buf, Pt_Last, Inner_Type, Aead_OK);
      if not Aead_OK then return; end if;
      if Inner_Type /= Aead_Channel.Inner_Type_Application_Data then
         return;
      end if;

      declare
         Copy_Len : constant Natural :=
           Natural'Min (Pt_Last, Buffer'Length);
      begin
         Buffer (Buffer'First .. Buffer'First + Copy_Len - 1) :=
           Pt_Buf (1 .. Copy_Len);
         Last := Buffer'First + Copy_Len - 1;
         Success := True;
      end;
   end Receive;

   procedure Close (Chan : in out Channel) is
   begin
      if Tls_Core.Tcp_Transport.Is_Open (Chan.Tcp) then
         Tls_Core.Tcp_Transport.Close (Chan.Tcp);
      end if;
      Chan.Open := False;
   end Close;

   procedure Listen
     (L    : in out Listener;
      Host : String;
      Port : Natural)
   is
   begin
      Tls_Core.Tcp_Transport.Listen (L.Tcp, Host, Port);
      L.Listening := True;
   end Listen;

   function Is_Listening (L : Listener) return Boolean is
   begin
      return L.Listening;
   end Is_Listening;

   procedure Accept_One
     (L      : in out Listener;
      Chan   : in out Channel;
      Config : Tls_Config)
   is
      use Tls_Core;
      Out_Buf  : Octet_Array (1 .. 4096) := (others => 0);
      Out_Last : Natural;
   begin
      Tcp_Transport.Accept_One (L.Tcp, Chan.Tcp);

      declare
         pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");
         Chain_Spec : Tls_Core.Cert_Chain.Chain;
      begin
         Chain_Spec.Count := 1;
         Chain_Spec.Entries (1) :=
           (First => 1, Last => Config.Cert_Der_Len);
         Tls13_Driver.Init_Cert_Server
           (D                => Chan.Driver,
            Cert_Chain_Bytes =>
              Config.Cert_Der (1 .. Config.Cert_Der_Len),
            Chain_Spec       => Chain_Spec,
            Sign_Priv_Key    =>
              Config.Key_Raw (1 .. 32),
            Sig_Alg          =>
              Tls_Core.Suites.Sig_Ecdsa_Secp256r1_Sha256,
            Ecdhe_Priv       => Ecdhe_Seed);
         if Config.Hostname_Len > 0 then
            declare
               Host_Bytes : Octet_Array (1 .. Config.Hostname_Len);
            begin
               for I in Host_Bytes'Range loop
                  Host_Bytes (I) := Octet (Character'Pos (
                    Config.Hostname (I)));
               end loop;
               Tls13_Driver.Set_Sni_Hostname (Chan.Driver, Host_Bytes);
            end;
         end if;
         if Config.Alpn_Len > 0 then
            declare
               Alpn_Bytes : Octet_Array (1 .. Config.Alpn_Len);
            begin
               for I in Alpn_Bytes'Range loop
                  Alpn_Bytes (I) := Octet (Character'Pos (
                    Config.Alpn (I)));
               end loop;
               Tls13_Driver.Set_Alpn_Offers (Chan.Driver, Alpn_Bytes);
            end;
         end if;
      end;

      Handshake_Loop (Chan);
   end Accept_One;

   procedure Stop (L : in out Listener) is
   begin
      Tls_Core.Tcp_Transport.Stop (L.Tcp);
      L.Listening := False;
   end Stop;

end Tls_Transport;
