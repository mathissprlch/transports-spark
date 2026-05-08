--  tls_interop_server — Tier D harness binary.
--
--  Listens on a port, accepts ONE connection, drives
--  Tls_Core.Tls13_Driver as a PSK_KE (mode 3 / psk_dhe_ke) server,
--  echoes the first received application-data record back to the
--  client, sends close_notify, and exits.  Status codes:
--
--      0  — handshake completed, app-data echo OK,
--           close_notify issued cleanly.
--      1  — TLS-level failure.
--      2  — usage / argument error.
--
--  Mirrors the openssl-side `s_server -tls1_3 -psk ... -nocert`
--  shape — see scripts/interop/openssl_server.sh.
--
--  Plain Ada (no SPARK_Mode aspect): test harness, not part of the
--  proven core.  Uses only public Tls_Core.* APIs.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO;

with Interfaces;

with Tls_Core;
with Tls_Core.Aead_Channel;
with Tls_Core.Tcp_Transport;
with Tls_Core.Tls13_Driver;

procedure Tls_Interop_Server is

   use Ada.Text_IO;
   use type Interfaces.Unsigned_8;
   use type Tls_Core.Tls13_Driver.State;

   subtype Octet       is Tls_Core.Octet;
   subtype Octet_Array is Tls_Core.Octet_Array;

   Default_Host     : constant String := "127.0.0.1";
   Default_Port     : constant Natural := 4433;
   Default_Psk_Hex  : constant String :=
     "4242424242424242424242424242424242424242424242424242424242424242";
   Default_Identity : constant String := "Test";

   Host         : access String  := new String'(Default_Host);
   Port         : Natural        := Default_Port;
   Psk_Hex      : access String  := new String'(Default_Psk_Hex);
   Identity_Str : access String  := new String'(Default_Identity);

   Exit_Code : Integer := 0;
   Aborted   : Boolean := False;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("FAIL: " & Msg);
      Exit_Code := 1;
      Aborted   := True;
   end Fail;

   function From_Hex (S : String) return Octet_Array is
      Result : Octet_Array (1 .. S'Length / 2) := (others => 0);
      function Nibble (C : Character) return Octet is
      begin
         case C is
            when '0' .. '9' =>
               return Octet (Character'Pos (C) - Character'Pos ('0'));
            when 'a' .. 'f' =>
               return Octet (Character'Pos (C) - Character'Pos ('a') + 10);
            when 'A' .. 'F' =>
               return Octet (Character'Pos (C) - Character'Pos ('A') + 10);
            when others =>
               raise Constraint_Error;
         end case;
      end Nibble;
   begin
      if S'Length mod 2 /= 0 then
         raise Constraint_Error;
      end if;
      for I in 1 .. S'Length / 2 loop
         Result (I) :=
           Nibble (S (S'First + 2 * (I - 1))) * Octet (16)
           + Nibble (S (S'First + 2 * (I - 1) + 1));
      end loop;
      return Result;
   end From_Hex;

   function To_Bytes (S : String) return Octet_Array is
      Result : Octet_Array (1 .. S'Length);
   begin
      for I in S'Range loop
         Result (1 + I - S'First) := Octet (Character'Pos (S (I)));
      end loop;
      return Result;
   end To_Bytes;

   procedure Read_Record
     (Chan     : Tls_Core.Tcp_Transport.Channel;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural;
      OK       : out Boolean)
   is
      Header   : Octet_Array (1 .. 5) := (others => 0);
      Body_Len : Natural;
   begin
      Out_Buf  := (others => 0);
      Out_Last := 0;
      OK       := False;
      Tls_Core.Tcp_Transport.Recv_All (Chan, Header, OK);
      if not OK then
         return;
      end if;
      Body_Len :=
        Natural (Header (4)) * 256 + Natural (Header (5));
      if 5 + Body_Len > Out_Buf'Length then
         OK := False;
         return;
      end if;
      Out_Buf (1 .. 5) := Header;
      if Body_Len > 0 then
         declare
            Body_Buf : Octet_Array (1 .. Body_Len) := (others => 0);
         begin
            Tls_Core.Tcp_Transport.Recv_All (Chan, Body_Buf, OK);
            if not OK then
               return;
            end if;
            Out_Buf (6 .. 5 + Body_Len) := Body_Buf;
         end;
      end if;
      Out_Last := 5 + Body_Len;
      OK       := True;
   end Read_Record;

   procedure Read_One_Real_Record
     (Chan     : Tls_Core.Tcp_Transport.Channel;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural;
      OK       : out Boolean)
   is
      Rec_Buf  : Octet_Array (1 .. 16640 + 5);
      Rec_Last : Natural;
   begin
      Out_Buf  := (others => 0);
      Out_Last := 0;
      loop
         Read_Record (Chan, Rec_Buf, Rec_Last, OK);
         if not OK or else Rec_Last < 5 then
            OK := False;
            return;
         end if;
         exit when Rec_Buf (1) /= Octet (16#14#);
      end loop;
      if Rec_Last > Out_Buf'Length then
         OK := False;
         return;
      end if;
      Out_Buf (1 .. Rec_Last) := Rec_Buf (1 .. Rec_Last);
      Out_Last := Rec_Last;
      OK       := True;
   end Read_One_Real_Record;

   procedure Parse_Args is
      I    : Positive := 1;
      Argc : constant Natural := Ada.Command_Line.Argument_Count;
   begin
      while I <= Argc loop
         declare
            A : constant String := Ada.Command_Line.Argument (I);
         begin
            if A = "--host" and then I + 1 <= Argc then
               Host := new String'(Ada.Command_Line.Argument (I + 1));
               I := I + 2;
            elsif A = "--port" and then I + 1 <= Argc then
               Port := Natural'Value (Ada.Command_Line.Argument (I + 1));
               I := I + 2;
            elsif A = "--psk-hex" and then I + 1 <= Argc then
               Psk_Hex := new String'(Ada.Command_Line.Argument (I + 1));
               I := I + 2;
            elsif A = "--psk-identity" and then I + 1 <= Argc then
               Identity_Str := new String'(Ada.Command_Line.Argument (I + 1));
               I := I + 2;
            elsif A = "-h" or A = "--help" then
               Put_Line ("usage: tls_interop_server [--host H] [--port P]");
               Put_Line ("       [--psk-hex HEX] [--psk-identity ID]");
               Exit_Code := 2;
               Aborted   := True;
               return;
            else
               Put_Line ("unknown arg: " & A);
               Exit_Code := 2;
               Aborted   := True;
               return;
            end if;
         end;
      end loop;
   end Parse_Args;

   Listener : Tls_Core.Tcp_Transport.Listener;
   Sock     : Tls_Core.Tcp_Transport.Channel;
   D        : Tls_Core.Tls13_Driver.Driver;

begin
   Parse_Args;
   if not Aborted then
      Put_Line ("tls_interop_server: listening on "
                & Host.all & ":" & Natural'Image (Port));
      Tls_Core.Tcp_Transport.Listen (Listener, Host.all, Port);
      Put_Line ("  (bound port = "
                & Natural'Image
                    (Tls_Core.Tcp_Transport.Bound_Port (Listener)) & ")");
      Tls_Core.Tcp_Transport.Accept_One (Listener, Sock);
      Put_Line ("  <- client connected");

      declare
         Psk_Bytes : constant Octet_Array := From_Hex (Psk_Hex.all);
         Id_Bytes  : constant Octet_Array := To_Bytes (Identity_Str.all);
         Ecdhe     : constant Octet_Array (1 .. 32) := (others => 16#11#);
      begin
         Tls_Core.Tls13_Driver.Init_Psk_Server
           (D, Psk_Bytes, Id_Bytes, Ecdhe);
      end;

      --  Flight 1: read CH (one record, possibly preceded by CCS).
      if not Aborted then
         declare
            In_Buf   : Octet_Array (1 .. 16640 + 5) := (others => 0);
            In_Last  : Natural;
            OK       : Boolean;
            Out_Buf  : Octet_Array (1 .. 4096) := (others => 0);
            Out_Last : Natural;
         begin
            Read_One_Real_Record (Sock, In_Buf, In_Last, OK);
            if not OK or else In_Last = 0 then
               Fail ("could not read ClientHello");
            else
               Put_Line ("  <- read ClientHello ("
                         & Natural'Image (In_Last) & " bytes)");
               Tls_Core.Tls13_Driver.Step
                 (D, In_Bytes => In_Buf (1 .. In_Last),
                  Out_Buf => Out_Buf, Out_Last => Out_Last);
               if Tls_Core.Tls13_Driver.Current_State (D)
                    /= Tls_Core.Tls13_Driver.Awaiting_Cf
               then
                  Put_Line ("  state = "
                            & Tls_Core.Tls13_Driver.State'Image
                                (Tls_Core.Tls13_Driver.Current_State (D)));
                  Fail ("server did not advance to Awaiting_Cf");
               else
                  Tls_Core.Tcp_Transport.Send_All
                    (Sock, Out_Buf (1 .. Out_Last));
                  Put_Line ("  -> sent SH+EE+SF ("
                            & Natural'Image (Out_Last) & " bytes)");
               end if;
            end if;
         end;
      end if;

      --  Flight 2: client Finished.
      if not Aborted then
         declare
            In_Buf   : Octet_Array (1 .. 16640 + 5) := (others => 0);
            In_Last  : Natural;
            OK       : Boolean;
            Out_Buf  : Octet_Array (1 .. 1024) := (others => 0);
            Out_Last : Natural;
         begin
            Read_One_Real_Record (Sock, In_Buf, In_Last, OK);
            if not OK or else In_Last = 0 then
               Fail ("could not read client Finished");
            else
               Tls_Core.Tls13_Driver.Step
                 (D, In_Bytes => In_Buf (1 .. In_Last),
                  Out_Buf => Out_Buf, Out_Last => Out_Last);
               if Tls_Core.Tls13_Driver.Current_State (D)
                    /= Tls_Core.Tls13_Driver.Done
               then
                  Put_Line ("  state = "
                            & Tls_Core.Tls13_Driver.State'Image
                                (Tls_Core.Tls13_Driver.Current_State (D)));
                  Fail ("server did not reach Done after CF");
               else
                  Put_Line ("  <- server reached Done");
               end if;
            end if;
         end;
      end if;

      --  Echo one app-data record.
      if not Aborted then
         declare
            Out_Srv, In_Srv : Tls_Core.Aead_Channel.Direction;
            Wire_In   : Octet_Array (1 .. 4096) := (others => 0);
            Wire_In_Last : Natural;
            Decoded   : Octet_Array (1 .. 4096) := (others => 0);
            Decoded_Last : Natural;
            Inner     : Octet;
            Decode_OK : Boolean;
            Wire_Out  : Octet_Array (1 .. 4096) := (others => 0);
            Wire_Out_Last : Natural;
            OK        : Boolean;
         begin
            Tls_Core.Tls13_Driver.Open_App_Directions (D, Out_Srv, In_Srv);
            Read_Record (Sock, Wire_In, Wire_In_Last, OK);
            if not OK or else Wire_In_Last = 0 then
               Fail ("no app-data from client");
            else
               Tls_Core.Aead_Channel.Receive
                 (In_Srv, Wire_In (1 .. Wire_In_Last),
                  Decoded, Decoded_Last, Inner, Decode_OK);
               if not Decode_OK then
                  Fail ("app-data decrypt failed");
               else
                  Put_Line ("  <- decrypted "
                            & Natural'Image (Decoded_Last)
                            & " bytes from client");
                  Tls_Core.Aead_Channel.Send
                    (Out_Srv,
                     Decoded (1 .. Decoded_Last),
                     Tls_Core.Aead_Channel.Inner_Type_Application_Data,
                     Wire_Out, Wire_Out_Last);
                  Tls_Core.Tcp_Transport.Send_All
                    (Sock, Wire_Out (1 .. Wire_Out_Last));
                  Put_Line ("  -> echoed "
                            & Natural'Image (Decoded_Last) & " bytes back");
               end if;
            end if;
         end;
      end if;

      --  close_notify.
      if not Aborted then
         declare
            Out_Buf  : Octet_Array (1 .. 256) := (others => 0);
            Out_Last : Natural;
         begin
            Tls_Core.Tls13_Driver.Send_Close_Notify (D, Out_Buf, Out_Last);
            if Out_Last > 0 then
               Tls_Core.Tcp_Transport.Send_All
                 (Sock, Out_Buf (1 .. Out_Last));
               Put_Line ("  -> sent close_notify ("
                         & Natural'Image (Out_Last) & " bytes)");
            end if;
         end;
      end if;

      Tls_Core.Tcp_Transport.Close (Sock);
      Tls_Core.Tcp_Transport.Stop (Listener);
      if not Aborted then
         Put_Line ("tls_interop_server: OK");
      end if;
   end if;

   Ada.Command_Line.Set_Exit_Status
     (Ada.Command_Line.Exit_Status (Exit_Code));

exception
   when E : others =>
      Put_Line ("tls_interop_server: exception "
                & Ada.Exceptions.Exception_Name (E)
                & " — " & Ada.Exceptions.Exception_Message (E));
      Ada.Command_Line.Set_Exit_Status (1);
end Tls_Interop_Server;
