with Ada.Streams;
with RFLX.RFLX_Types;
with RFLX.Record_Layer.Plaintext;
with Tls_Core.Aead_Channel;
with Tls_Core.Cert_Chain;
with Tls_Core.Suites;
with Tls_Core.Tls13_Driver;
with Tls_Core.Tcp_Transport;

package body Tls_Transport is

   use type Tls_Core.Octet;
   use type Tls_Core.Tls13_Driver.State;
   use type GNAT.Sockets.Selector_Status;

   Ecdhe_Seed : constant Tls_Core.Octet_Array (1 .. 32) :=
     (16#A1#, 16#B2#, 16#C3#, 16#D4#, 16#E5#, 16#F6#, 16#07#, 16#18#,
      16#29#, 16#3A#, 16#4B#, 16#5C#, 16#6D#, 16#7E#, 16#8F#, 16#90#,
      16#01#, 16#12#, 16#23#, 16#34#, 16#45#, 16#56#, 16#67#, 16#78#,
      16#89#, 16#9A#, 16#AB#, 16#BC#, 16#CD#, 16#DE#, 16#EF#, 16#F0#);

   Rflx_Rec_Max : constant := 16896;

   procedure Read_One_Record
     (Tcp      : Tls_Core.Tcp_Transport.Channel;
      Buf      : out Tls_Core.Octet_Array;
      Last     : out Natural;
      OK       : out Boolean;
      Rflx_Ptr : in out RFLX.RFLX_Types.Bytes_Ptr)
   is
      use Tls_Core;
      use type RFLX.RFLX_Types.Bytes_Ptr;
      use type RFLX.RFLX_Types.Index;
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
         if Rec_Len > 16640 or else
           Buf'First + 5 + Rec_Len - 1 > Buf'Last
         then
            return;
         end if;
         Tcp_Transport.Recv_All
           (Tcp, Buf (Buf'First + 5 .. Buf'First + 4 + Rec_Len), Hdr_OK);
         if not Hdr_OK then return; end if;
         Last := Buf'First + 4 + Rec_Len;
         if Rflx_Ptr /= null then
            declare
               use RFLX.RFLX_Types;
               Rec_Size : constant Index := Index (Last - Buf'First + 1);
               W_Last   : constant Bit_Length :=
                 To_Last_Bit_Index (Length (Rec_Size));
               Ctx : RFLX.Record_Layer.Plaintext.Context;
            begin
               for I in Buf'First .. Last loop
                  Rflx_Ptr (Index (I - Buf'First + 1)) :=
                    RFLX.RFLX_Types.Byte (Buf (I));
               end loop;
               begin
                  RFLX.Record_Layer.Plaintext.Initialize
                    (Ctx, Rflx_Ptr, Written_Last => W_Last);
                  RFLX.Record_Layer.Plaintext.Verify_Message (Ctx);
                  if not RFLX.Record_Layer.Plaintext.Well_Formed_Message (Ctx) then
                     RFLX.Record_Layer.Plaintext.Take_Buffer (Ctx, Rflx_Ptr);
                     OK := False;
                     return;
                  end if;
                  RFLX.Record_Layer.Plaintext.Take_Buffer (Ctx, Rflx_Ptr);
               end;
            end;
         end if;
         OK := True;
      end;
   end Read_One_Record;

   procedure Read_Flight
     (Tcp      : Tls_Core.Tcp_Transport.Channel;
      Buf      : out Tls_Core.Octet_Array;
      Last     : out Natural;
      OK       : out Boolean;
      Rflx_Ptr : in out RFLX.RFLX_Types.Bytes_Ptr)
   is
      use Tls_Core;
      Cursor : Natural := Buf'First;
      Rec_Last : Natural;
      Rec_OK   : Boolean;
   begin
      Last := 0;
      OK := False;
      Read_One_Record (Tcp, Buf (Cursor .. Buf'Last), Rec_Last, Rec_OK, Rflx_Ptr);
      if not Rec_OK then return; end if;
      Cursor := Rec_Last + 1;
      loop
         exit when Cursor + 5 > Buf'Last;
         declare
            use Ada.Streams;
            Peek     : Stream_Element_Array (1 .. 1);
            Peek_Sel : GNAT.Sockets.Selector_Type;
            R_Set    : GNAT.Sockets.Socket_Set_Type;
            W_Set    : GNAT.Sockets.Socket_Set_Type;
            Status   : GNAT.Sockets.Selector_Status;
            Sock     : constant GNAT.Sockets.Socket_Type :=
              Tcp_Transport.Native_Socket (Tcp);
         begin
            GNAT.Sockets.Create_Selector (Peek_Sel);
            GNAT.Sockets.Empty (R_Set);
            GNAT.Sockets.Empty (W_Set);
            GNAT.Sockets.Set (R_Set, Sock);
            GNAT.Sockets.Check_Selector
              (Peek_Sel, R_Set, W_Set, Status, Timeout => 0.001);
            GNAT.Sockets.Close_Selector (Peek_Sel);
            if Status /= GNAT.Sockets.Completed
              or else not GNAT.Sockets.Is_Set (R_Set, Sock)
            then
               exit;
            end if;
         end;
         Read_One_Record
           (Tcp, Buf (Cursor .. Buf'Last), Rec_Last, Rec_OK, Rflx_Ptr);
         exit when not Rec_OK;
         Cursor := Rec_Last + 1;
      end loop;
      Last := Cursor - 1;
      OK := True;
   end Read_Flight;

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

         if Current_State (Chan.Driver) = Awaiting_SF then
            Read_Flight (Chan.Tcp, In_Buf, In_Last, In_OK, Chan.Rflx_Buf);
         else
            Read_One_Record (Chan.Tcp, In_Buf, In_Last, In_OK, Chan.Rflx_Buf);
         end if;
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
      Chan.Rflx_Buf := new RFLX.RFLX_Types.Bytes'(1 .. Rflx_Rec_Max => 0);

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

      GNAT.Sockets.Create_Selector (Chan.Selector);
      Chan.Sel_Open := True;
   end Connect;

   function Is_Open (Chan : Channel) return Boolean is
   begin
      return Chan.Open;
   end Is_Open;

   procedure Poll_Internal
     (Chan    : Channel;
      Timeout : Duration;
      Ready   : out Boolean)
   is
      use GNAT.Sockets;
      Read_Set  : Socket_Set_Type;
      Write_Set : Socket_Set_Type;
      Status    : Selector_Status;
      Sock      : constant Socket_Type :=
        Tls_Core.Tcp_Transport.Native_Socket (Chan.Tcp);
   begin
      Ready := False;
      if not Chan.Sel_Open then
         return;
      end if;
      Empty (Read_Set);
      Empty (Write_Set);
      Set (Read_Set, Sock);
      Check_Selector
        (Chan.Selector, Read_Set, Write_Set, Status,
         Timeout => Timeout);
      Ready :=
        Status = Completed
          and then Is_Set (Read_Set, Sock);
   exception
      when others =>
         Ready := False;
   end Poll_Internal;

   function Has_Pending (Chan : Channel) return Boolean is
      Ready : Boolean;
   begin
      if Chan.Pend_First <= Chan.Pend_Last then
         return True;
      end if;
      Poll_Internal (Chan, 0.0, Ready);
      return Ready;
   end Has_Pending;

   procedure Wait_For_Data
     (Chan     : Channel;
      Timeout  : Duration;
      Got_Data : out Boolean)
   is
   begin
      Poll_Internal (Chan, Timeout, Got_Data);
   end Wait_For_Data;

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

   procedure Refill_Pending (Chan : in out Channel; OK : out Boolean)
   is
      use Tls_Core;
      Rec_Buf    : Octet_Array (1 .. Pt_Buf_Size + 256) := (others => 0);
      Rec_Last   : Natural;
      Rec_OK     : Boolean;
      Pt_Buf     : Octet_Array (1 .. Pt_Buf_Size) := (others => 0);
      Pt_Last    : Natural;
      Inner_Type : Octet;
      Aead_OK    : Boolean;
   begin
      OK := False;
      Read_One_Record (Chan.Tcp, Rec_Buf, Rec_Last, Rec_OK, Chan.Rflx_Buf);
      if not Rec_OK then return; end if;

      Aead_Channel.Receive
        (Chan.App_In, Rec_Buf (1 .. Rec_Last),
         Pt_Buf, Pt_Last, Inner_Type, Aead_OK);
      if not Aead_OK then return; end if;
      if Inner_Type /= Aead_Channel.Inner_Type_Application_Data then
         return;
      end if;
      if Pt_Last >= 1 then
         Chan.Pending (1 .. Pt_Last) := Pt_Buf (1 .. Pt_Last);
         Chan.Pend_First := 1;
         Chan.Pend_Last := Pt_Last;
         OK := True;
      end if;
   end Refill_Pending;

   procedure Receive
     (Chan    : in out Channel;
      Buffer  : out Tls_Core.Octet_Array;
      Last    : out Natural;
      Success : out Boolean)
   is
      use Tls_Core;
      Avail    : Natural;
      Copy_Len : Natural;
   begin
      Buffer := (others => 0);
      Last := Buffer'First - 1;
      Success := False;

      if Chan.Pend_First > Chan.Pend_Last then
         declare
            Refill_OK : Boolean;
         begin
            Refill_Pending (Chan, Refill_OK);
            if not Refill_OK then return; end if;
         end;
      end if;

      Avail := Chan.Pend_Last - Chan.Pend_First + 1;
      Copy_Len := Natural'Min (Avail, Buffer'Length);
      Buffer (Buffer'First .. Buffer'First + Copy_Len - 1) :=
        Chan.Pending (Chan.Pend_First .. Chan.Pend_First + Copy_Len - 1);
      Chan.Pend_First := Chan.Pend_First + Copy_Len;
      Last := Buffer'First + Copy_Len - 1;
      Success := True;
   end Receive;

   procedure Close (Chan : in out Channel) is
      use type RFLX.RFLX_Types.Bytes_Ptr;
   begin
      if Chan.Rflx_Buf /= null then
         RFLX.RFLX_Types.Free (Chan.Rflx_Buf);
      end if;
      if Chan.Sel_Open then
         begin
            GNAT.Sockets.Close_Selector (Chan.Selector);
         exception
            when others => null;
         end;
         Chan.Sel_Open := False;
      end if;
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
      Chan.Rflx_Buf := new RFLX.RFLX_Types.Bytes'(1 .. Rflx_Rec_Max => 0);

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

      GNAT.Sockets.Create_Selector (Chan.Selector);
      Chan.Sel_Open := True;
   end Accept_One;

   procedure Stop (L : in out Listener) is
   begin
      Tls_Core.Tcp_Transport.Stop (L.Tcp);
      L.Listening := False;
   end Stop;

end Tls_Transport;
