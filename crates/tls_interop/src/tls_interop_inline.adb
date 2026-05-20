with Ada.Calendar;
with Ada.Streams.Stream_IO;
with Tls_Core;
with Tls_Core.Aead_Channel;
with Tls_Core.Cert_Chain;
with Tls_Core.Suites;
with Tls_Core.Tls13_Driver;

package body Tls_Interop_Inline is

   use Tls_Core;
   use type Tls_Core.Octet;
   use type Tls_Core.Tls13_Driver.State;
   use Ada.Calendar;

   procedure Read_File
     (Path : String;
      Buf  : out Octet_Array;
      Len  : out Natural)
   is
      use Ada.Streams.Stream_IO;
      F : File_Type;
   begin
      Len := 0;
      Open (F, In_File, Path);
      declare
         N : constant Ada.Streams.Stream_Element_Offset :=
           Ada.Streams.Stream_Element_Offset (Size (F));
      begin
         if Natural (N) > Buf'Length then
            Close (F);
            return;
         end if;
         declare
            SE : Ada.Streams.Stream_Element_Array (1 .. N);
            Last : Ada.Streams.Stream_Element_Offset;
         begin
            Read (F, SE, Last);
            for I in 1 .. Natural (Last) loop
               Buf (Buf'First + I - 1) :=
                 Octet (SE (Ada.Streams.Stream_Element_Offset (I)));
            end loop;
            Len := Natural (Last);
         end;
      end;
      Close (F);
   exception
      when others =>
         Len := 0;
   end Read_File;

   procedure Read_Record
     (Chan     : Tls_Core.Tcp_Transport.Channel;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural;
      OK       : out Boolean)
   is
      Header   : Octet_Array (1 .. 5) := [others => 0];
      Body_Len : Natural;
   begin
      Out_Buf  := [others => 0];
      Out_Last := 0;
      OK       := False;
      Tls_Core.Tcp_Transport.Recv_All (Chan, Header, OK);
      if not OK then return; end if;
      Body_Len := Natural (Header (4)) * 256 + Natural (Header (5));
      if 5 + Body_Len > Out_Buf'Length then
         OK := False; return;
      end if;
      Out_Buf (1 .. 5) := Header;
      if Body_Len > 0 then
         declare
            Body_Buf : Octet_Array (1 .. Body_Len) := [others => 0];
         begin
            Tls_Core.Tcp_Transport.Recv_All (Chan, Body_Buf, OK);
            if not OK then return; end if;
            Out_Buf (6 .. 5 + Body_Len) := Body_Buf;
         end;
      end if;
      Out_Last := 5 + Body_Len;
      OK := True;
   end Read_Record;

   procedure Read_Flight
     (Chan     : Tls_Core.Tcp_Transport.Channel;
      N_Recs   : Positive;
      Acc_Buf  : out Octet_Array;
      Acc_Last : out Natural;
      OK       : out Boolean)
   is
      Rec_Buf  : Octet_Array (1 .. 16640 + 5);
      Rec_Last : Natural;
      Got      : Natural := 0;
   begin
      Acc_Buf  := [others => 0];
      Acc_Last := 0;
      OK       := True;
      while Got < N_Recs loop
         Read_Record (Chan, Rec_Buf, Rec_Last, OK);
         if not OK or else Rec_Last < 5 then
            OK := False; return;
         end if;
         if Rec_Buf (1) = 16#14# then
            null;
         else
            if Acc_Last + Rec_Last > Acc_Buf'Length then
               OK := False; return;
            end if;
            Acc_Buf (Acc_Last + 1 .. Acc_Last + Rec_Last) :=
              Rec_Buf (1 .. Rec_Last);
            Acc_Last := Acc_Last + Rec_Last;
            Got := Got + 1;
         end if;
      end loop;
   end Read_Flight;

   procedure Run_Handshake_C2S
     (Peer    : Peer_Kind;
      Mode    : Mode_Kind;
      Cipher  : Cipher_Kind;
      Port    : Natural;
      Result  : out Inline_Result;
      Elapsed : out Duration;
      Note    : out Unbounded_String)
   is
      pragma Unreferenced (Peer, Cipher);
      Sock : Tls_Core.Tcp_Transport.Channel;
      D    : Tls_Core.Tls13_Driver.Driver;

      Priv_Key : constant Octet_Array (1 .. 32) := [others => 16#42#];
      Trust_Buf : Octet_Array (1 .. 4096) := [others => 0];
      Trust_Len : Natural;
      Psk       : constant Octet_Array (1 .. 32) := [others => 16#42#];
      Psk_Id    : constant Octet_Array := [Character'Pos ('T'),
        Character'Pos ('e'), Character'Pos ('s'), Character'Pos ('t')];

      EC_Dir : constant String :=
        "crates/tls_core/tests/fixtures/interop/ec";
      Hostname : constant Octet_Array := [
        Character'Pos ('l'), Character'Pos ('o'), Character'Pos ('c'),
        Character'Pos ('a'), Character'Pos ('l'), Character'Pos ('h'),
        Character'Pos ('o'), Character'Pos ('s'), Character'Pos ('t')];

      T0 : Time;
      Server_Records : Positive := 5;
   begin
      Result  := Fail;
      Elapsed := 0.0;
      Note    := Null_Unbounded_String;

      case Mode is
         when Cert_Ec =>
            Read_File (EC_Dir & "/root.der", Trust_Buf, Trust_Len);
            if Trust_Len = 0 then
               Note := To_Unbounded_String ("cannot read trust anchor");
               return;
            end if;
            declare
               TS : Tls_Core.Cert_Chain.Trust_Store;
            begin
               TS.Count := 1;
               TS.Entries (1) := (First => 1, Last => Trust_Len);
               Tls_Core.Tls13_Driver.Init_Cert_Client
                 (D, Trust_Buf (1 .. Trust_Len), TS,
                  Hostname, Priv_Key);
            end;
         when Psk_Dhe_Ke =>
            Tls_Core.Tls13_Driver.Init_Psk_Client
              (D, Psk, Psk_Id, Priv_Key);
            Server_Records := 3;
         when others =>
            Note := To_Unbounded_String ("unsupported mode for inline");
            return;
      end case;

      begin
         Tls_Core.Tcp_Transport.Connect (Sock, "127.0.0.1", Port);
      exception
         when others =>
            Note := To_Unbounded_String ("TCP connect failed");
            return;
      end;

      T0 := Clock;

      declare
         Out_Buf  : Octet_Array (1 .. 4096) := [others => 0];
         Out_Last : Natural;
         Empty    : constant Octet_Array (1 .. 0) := [others => 0];
      begin
         Tls_Core.Tls13_Driver.Step
           (D, In_Bytes => Empty,
            Out_Buf => Out_Buf, Out_Last => Out_Last);
         if Out_Last = 0 then
            Note := To_Unbounded_String ("no CH produced");
            Tls_Core.Tcp_Transport.Close (Sock);
            return;
         end if;
         Tls_Core.Tcp_Transport.Send_All (Sock, Out_Buf (1 .. Out_Last));

         declare
            In_Buf  : Octet_Array (1 .. 16640 * 5 + 64) := [others => 0];
            In_Last : Natural;
            OK      : Boolean;
            CF_Buf  : Octet_Array (1 .. 4096) := [others => 0];
            CF_Last : Natural;
         begin
            Read_Flight (Sock, Server_Records, In_Buf, In_Last, OK);
            if not OK then
               Note := To_Unbounded_String ("read server flight failed");
               Tls_Core.Tcp_Transport.Close (Sock);
               return;
            end if;
            Tls_Core.Tls13_Driver.Step
              (D, In_Bytes => In_Buf (1 .. In_Last),
               Out_Buf => CF_Buf, Out_Last => CF_Last);
            if Tls_Core.Tls13_Driver.Current_State (D)
                 /= Tls_Core.Tls13_Driver.Done
            then
               Note := To_Unbounded_String
                 ("not Done: " & Tls_Core.Tls13_Driver.State'Image
                    (Tls_Core.Tls13_Driver.Current_State (D)));
               Tls_Core.Tcp_Transport.Close (Sock);
               return;
            end if;
            Tls_Core.Tcp_Transport.Send_All
              (Sock, CF_Buf (1 .. CF_Last));
         end;
      end;

      Elapsed := Clock - T0;
      Result := Pass;
      Tls_Core.Tcp_Transport.Close (Sock);
   exception
      when others =>
         Elapsed := Clock - T0;
         Note := To_Unbounded_String ("exception during handshake");
   end Run_Handshake_C2S;

   procedure Open_S2C_Listener
     (Port : Natural;
      L    : out Tls_Core.Tcp_Transport.Listener;
      OK   : out Boolean) is
   begin
      OK := False;
      Tls_Core.Tcp_Transport.Listen (L, "127.0.0.1", Port);
      OK := True;
   exception
      when others =>
         OK := False;
   end Open_S2C_Listener;

   procedure Run_Handshake_S2C
     (L       : in out Tls_Core.Tcp_Transport.Listener;
      Peer    : Peer_Kind;
      Mode    : Mode_Kind;
      Cipher  : Cipher_Kind;
      Result  : out Inline_Result;
      Elapsed : out Duration;
      Note    : out Unbounded_String)
   is
      pragma Unreferenced (Peer, Cipher);
      Sock : Tls_Core.Tcp_Transport.Channel;
      D    : Tls_Core.Tls13_Driver.Driver;

      Priv_Key : constant Octet_Array (1 .. 32) := [others => 16#42#];
      Cert_Buf : Octet_Array (1 .. 4096) := [others => 0];
      Cert_Len : Natural;
      Key_Buf  : Octet_Array (1 .. 4096) := [others => 0];
      Key_Len  : Natural;
      Psk      : constant Octet_Array (1 .. 32) := [others => 16#42#];
      Psk_Id   : constant Octet_Array := [Character'Pos ('T'),
        Character'Pos ('e'), Character'Pos ('s'), Character'Pos ('t')];

      EC_Dir : constant String :=
        "crates/tls_core/tests/fixtures/interop/ec";

      T0 : Time;
   begin
      Result  := Fail;
      Elapsed := 0.0;
      Note    := Null_Unbounded_String;

      case Mode is
         when Cert_Ec =>
            Read_File (EC_Dir & "/leaf.der", Cert_Buf, Cert_Len);
            Read_File (EC_Dir & "/leaf.priv", Key_Buf, Key_Len);
            if Cert_Len = 0 or else Key_Len /= 32 then
               Note := To_Unbounded_String ("cannot read cert/key");
               return;
            end if;
            declare
               CS : Tls_Core.Cert_Chain.Chain;
            begin
               CS.Count := 1;
               CS.Entries (1) := (First => 1, Last => Cert_Len);
               Tls_Core.Tls13_Driver.Init_Cert_Server
                 (D, Cert_Buf (1 .. Cert_Len), CS,
                  Key_Buf (1 .. 32),
                  Tls_Core.Suites.Sig_Ecdsa_Secp256r1_Sha256,
                  Priv_Key);
            end;
         when Psk_Dhe_Ke =>
            Tls_Core.Tls13_Driver.Init_Psk_Server
              (D, Psk, Psk_Id, Priv_Key);
         when others =>
            Note := To_Unbounded_String ("unsupported mode for inline");
            return;
      end case;

      Tls_Core.Tcp_Transport.Accept_One (L, Sock);
      T0 := Clock;

      declare
         In_Buf   : Octet_Array (1 .. 16640 + 5) := [others => 0];
         In_Last  : Natural;
         OK       : Boolean;
         Out_Buf  : Octet_Array (1 .. 4096) := [others => 0];
         Out_Last : Natural;
      begin
         Read_Flight (Sock, 1, In_Buf, In_Last, OK);
         if not OK or else In_Last = 0 then
            Note := To_Unbounded_String ("no CH received");
            Tls_Core.Tcp_Transport.Close (Sock);
            return;
         end if;
         Tls_Core.Tls13_Driver.Step
           (D, In_Bytes => In_Buf (1 .. In_Last),
            Out_Buf => Out_Buf, Out_Last => Out_Last);
         if Tls_Core.Tls13_Driver.Current_State (D)
              /= Tls_Core.Tls13_Driver.Awaiting_Cf
         then
            Note := To_Unbounded_String
              ("not Awaiting_Cf: " & Tls_Core.Tls13_Driver.State'Image
                 (Tls_Core.Tls13_Driver.Current_State (D)));
            Tls_Core.Tcp_Transport.Close (Sock);
            return;
         end if;
         Tls_Core.Tcp_Transport.Send_All (Sock, Out_Buf (1 .. Out_Last));

         Read_Flight (Sock, 1, In_Buf, In_Last, OK);
         if not OK then
            Note := To_Unbounded_String ("no CF received");
            Tls_Core.Tcp_Transport.Close (Sock);
            return;
         end if;
         Tls_Core.Tls13_Driver.Step
           (D, In_Bytes => In_Buf (1 .. In_Last),
            Out_Buf => Out_Buf, Out_Last => Out_Last);
         if Tls_Core.Tls13_Driver.Current_State (D)
              /= Tls_Core.Tls13_Driver.Done
         then
            Note := To_Unbounded_String
              ("not Done: " & Tls_Core.Tls13_Driver.State'Image
                 (Tls_Core.Tls13_Driver.Current_State (D)));
            Tls_Core.Tcp_Transport.Close (Sock);
            return;
         end if;
      end;

      Elapsed := Clock - T0;
      Result := Pass;
      Tls_Core.Tcp_Transport.Close (Sock);
      Tls_Core.Tcp_Transport.Stop (L);
   exception
      when others =>
         Elapsed := Clock - T0;
         Note := To_Unbounded_String ("exception during s2c handshake");
   end Run_Handshake_S2C;

   procedure Run_Throughput_C2S
     (Peer    : Peer_Kind;
      Mode    : Mode_Kind;
      Cipher  : Cipher_Kind;
      Port    : Natural;
      Bytes   : Natural;
      Result  : out Inline_Result;
      Elapsed : out Duration;
      Note    : out Unbounded_String)
   is
      pragma Unreferenced (Peer, Cipher);
      Sock : Tls_Core.Tcp_Transport.Channel;
      D    : Tls_Core.Tls13_Driver.Driver;

      Priv_Key : constant Octet_Array (1 .. 32) := [others => 16#42#];
      Trust_Buf : Octet_Array (1 .. 4096) := [others => 0];
      Trust_Len : Natural;
      Psk       : constant Octet_Array (1 .. 32) := [others => 16#42#];
      Psk_Id    : constant Octet_Array := [Character'Pos ('T'),
        Character'Pos ('e'), Character'Pos ('s'), Character'Pos ('t')];

      EC_Dir : constant String :=
        "crates/tls_core/tests/fixtures/interop/ec";
      Hostname : constant Octet_Array := [
        Character'Pos ('l'), Character'Pos ('o'), Character'Pos ('c'),
        Character'Pos ('a'), Character'Pos ('l'), Character'Pos ('h'),
        Character'Pos ('o'), Character'Pos ('s'), Character'Pos ('t')];

      Server_Records : Positive := 5;
   begin
      Result  := Fail;
      Elapsed := 0.0;
      Note    := Null_Unbounded_String;

      case Mode is
         when Cert_Ec =>
            Read_File (EC_Dir & "/root.der", Trust_Buf, Trust_Len);
            if Trust_Len = 0 then
               Note := To_Unbounded_String ("cannot read trust anchor");
               return;
            end if;
            declare
               TS : Tls_Core.Cert_Chain.Trust_Store;
            begin
               TS.Count := 1;
               TS.Entries (1) := (First => 1, Last => Trust_Len);
               Tls_Core.Tls13_Driver.Init_Cert_Client
                 (D, Trust_Buf (1 .. Trust_Len), TS,
                  Hostname, Priv_Key);
            end;
         when Psk_Dhe_Ke =>
            Tls_Core.Tls13_Driver.Init_Psk_Client
              (D, Psk, Psk_Id, Priv_Key);
            Server_Records := 3;
         when others =>
            Note := To_Unbounded_String ("unsupported mode for inline");
            return;
      end case;

      begin
         Tls_Core.Tcp_Transport.Connect (Sock, "127.0.0.1", Port);
      exception
         when others =>
            Note := To_Unbounded_String ("TCP connect failed");
            return;
      end;

      declare
         Out_Buf  : Octet_Array (1 .. 4096) := [others => 0];
         Out_Last : Natural;
         Empty    : constant Octet_Array (1 .. 0) := [others => 0];
      begin
         Tls_Core.Tls13_Driver.Step
           (D, In_Bytes => Empty,
            Out_Buf => Out_Buf, Out_Last => Out_Last);
         if Out_Last = 0 then
            Note := To_Unbounded_String ("no CH produced");
            Tls_Core.Tcp_Transport.Close (Sock);
            return;
         end if;
         Tls_Core.Tcp_Transport.Send_All (Sock, Out_Buf (1 .. Out_Last));

         declare
            In_Buf  : Octet_Array (1 .. 16640 * 5 + 64) := [others => 0];
            In_Last : Natural;
            OK      : Boolean;
            CF_Buf  : Octet_Array (1 .. 4096) := [others => 0];
            CF_Last : Natural;
         begin
            Read_Flight (Sock, Server_Records, In_Buf, In_Last, OK);
            if not OK then
               Note := To_Unbounded_String ("read server flight failed");
               Tls_Core.Tcp_Transport.Close (Sock);
               return;
            end if;
            Tls_Core.Tls13_Driver.Step
              (D, In_Bytes => In_Buf (1 .. In_Last),
               Out_Buf => CF_Buf, Out_Last => CF_Last);
            if Tls_Core.Tls13_Driver.Current_State (D)
                 /= Tls_Core.Tls13_Driver.Done
            then
               Note := To_Unbounded_String
                 ("not Done: " & Tls_Core.Tls13_Driver.State'Image
                    (Tls_Core.Tls13_Driver.Current_State (D)));
               Tls_Core.Tcp_Transport.Close (Sock);
               return;
            end if;
            Tls_Core.Tcp_Transport.Send_All
              (Sock, CF_Buf (1 .. CF_Last));
         end;
      end;

      declare
         Out_Dir, In_Dir : Tls_Core.Aead_Channel.Direction;
         Chunk   : constant Natural := 4096;
         Payload : constant Octet_Array (1 .. Chunk) := [others => 16#42#];
         Wire    : Octet_Array (1 .. Chunk + 256) := [others => 0];
         W_Last  : Natural;
         Sent    : Natural := 0;
         T0      : Time;
      begin
         Tls_Core.Tls13_Driver.Open_App_Directions (D, Out_Dir, In_Dir);
         T0 := Clock;
         while Sent < Bytes loop
            declare
               This : constant Natural :=
                 Natural'Min (Chunk, Bytes - Sent);
            begin
               Tls_Core.Aead_Channel.Send
                 (Out_Dir, Payload (1 .. This),
                  Tls_Core.Aead_Channel.Inner_Type_Application_Data,
                  Wire, W_Last);
               Tls_Core.Tcp_Transport.Send_All
                 (Sock, Wire (1 .. W_Last));
               Sent := Sent + This;
            end;
         end loop;
         Elapsed := Clock - T0;
      end;

      Result := Pass;
      Tls_Core.Tcp_Transport.Close (Sock);
   exception
      when others =>
         Note := To_Unbounded_String ("exception during throughput");
   end Run_Throughput_C2S;

   procedure Run_Peer_Vs_Peer
     (Server_Bin  : String;
      Server_Args : GNAT.OS_Lib.Argument_List;
      Client_Bin  : String;
      Client_Args : GNAT.OS_Lib.Argument_List;
      Result      : out Inline_Result;
      Elapsed     : out Duration;
      Note        : out Unbounded_String)
   is
      use GNAT.OS_Lib;
      Server_Pid, Client_Pid : Process_Id;
      T0 : Time;
   begin
      Result  := Fail;
      Elapsed := 0.0;
      Note    := Null_Unbounded_String;

      Server_Pid := Non_Blocking_Spawn
        (Server_Bin, Server_Args, "/dev/null", True);
      if Server_Pid = Invalid_Pid then
         Note := To_Unbounded_String ("peer server spawn failed");
         return;
      end if;
      delay 0.5;

      T0 := Clock;
      Client_Pid := Non_Blocking_Spawn
        (Client_Bin, Client_Args, "/dev/null", True);
      if Client_Pid = Invalid_Pid then
         Kill (Server_Pid, Hard_Kill => True);
         declare
            Rp : Process_Id; Ok : Boolean;
         begin
            Wait_Process (Rp, Ok);
         exception when others => null;
         end;
         Note := To_Unbounded_String ("peer client spawn failed");
         return;
      end if;

      declare
         Rp : Process_Id;
         Ok : Boolean;
      begin
         Wait_Process (Rp, Ok);
         Elapsed := Clock - T0;
         if Ok then
            Result := Pass;
         else
            Note := To_Unbounded_String ("peer client exited non-zero");
         end if;
      exception
         when others =>
            Elapsed := Clock - T0;
            Note := To_Unbounded_String ("wait failed");
      end;

      Kill (Server_Pid, Hard_Kill => True);
      declare
         Rp : Process_Id; Ok : Boolean;
      begin
         Wait_Process (Rp, Ok);
      exception when others => null;
      end;
   end Run_Peer_Vs_Peer;

end Tls_Interop_Inline;
