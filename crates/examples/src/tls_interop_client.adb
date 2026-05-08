--  tls_interop_client — Tier D harness binary.
--
--  Connects to HOST:PORT, drives Tls_Core.Tls13_Driver through a
--  full PSK_KE (mode 3, psk_dhe_ke) handshake against a real peer
--  (typically `openssl s_server -tls1_3 -psk ...`), exchanges a
--  fixed test phrase as application data, sends close_notify, and
--  exits.  Status codes:
--
--      0  — handshake completed, app-data round-trip OK,
--           close_notify exchanged cleanly.
--      1  — TLS-level failure (handshake or app-data path).
--      2  — usage / argument error.
--
--  This program is intentionally plain Ada (no SPARK_Mode aspect):
--  it is a test harness, not part of the proven core.  It uses only
--  the public Tls_Core.* APIs (Tls13_Driver + Aead_Channel +
--  Tcp_Transport) and does not peek into Driver private fields.
--  CLAUDE.md §0d is observed: no `SPARK_Mode (Off)` outside
--  Tcp_Transport, no `pragma Assume`, no Pre/Post bypass.
--
--  Wire-shape reminder: TLS records have a 5-byte header
--  (1 byte ContentType + 2 bytes legacy_version + 2 bytes u16
--  length).  We read records one at a time off the socket, skip
--  ChangeCipherSpec compat dummies (RFC 8446 §5), and feed the
--  expected flight (1 record after HRR; 3 records for SH+EE+SF) to
--  Tls13_Driver.Step.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Text_IO;
with Ada.Strings.Fixed;

with Interfaces;

with Tls_Core;
with Tls_Core.Aead_Channel;
with Tls_Core.Tcp_Transport;
with Tls_Core.Tls13_Driver;

procedure Tls_Interop_Client is

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

   --  Centralised "exit_status" since Ada.Command_Line has no
   --  Exit_Status_Value getter — we set this and bail to the
   --  outer block.
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

   procedure Put_Payload (Bytes : Octet_Array) is
      All_Printable : Boolean := True;
   begin
      for I in Bytes'Range loop
         if Bytes (I) < Octet (16#20#) or Bytes (I) > Octet (16#7E#) then
            All_Printable := False;
            exit;
         end if;
      end loop;
      if All_Printable then
         declare
            Buf : String (1 .. Bytes'Length);
         begin
            for I in Bytes'Range loop
               Buf (1 + I - Bytes'First) :=
                 Character'Val (Natural (Bytes (I)));
            end loop;
            Put_Line ("  reply: """ & Buf & """");
         end;
      else
         Put ("  reply hex:");
         for I in Bytes'Range loop
            declare
               package U8_IO is new Ada.Text_IO.Modular_IO (Octet);
               B : String (1 .. 7);
            begin
               U8_IO.Put (B, Bytes (I), Base => 16);
               Put (" " & Ada.Strings.Fixed.Trim (B, Ada.Strings.Both));
            end;
         end loop;
         New_Line;
      end if;
   end Put_Payload;

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

   procedure Read_N_Real_Records
     (Chan     : Tls_Core.Tcp_Transport.Channel;
      How_Many : Positive;
      Acc_Buf  : out Octet_Array;
      Acc_Last : out Natural;
      OK       : out Boolean)
   is
      Rec_Buf  : Octet_Array (1 .. 16640 + 5);
      Rec_Last : Natural;
      Got      : Natural := 0;
   begin
      Acc_Buf  := (others => 0);
      Acc_Last := 0;
      OK       := True;
      while Got < How_Many loop
         Read_Record (Chan, Rec_Buf, Rec_Last, OK);
         if not OK or else Rec_Last < 5 then
            OK := False;
            return;
         end if;
         if Rec_Buf (1) = Octet (16#14#) then
            null;  --  ChangeCipherSpec dummy — skip per RFC 8446 §5.
         else
            if Acc_Last + Rec_Last > Acc_Buf'Length then
               OK := False;
               return;
            end if;
            Acc_Buf (Acc_Last + 1 .. Acc_Last + Rec_Last) :=
              Rec_Buf (1 .. Rec_Last);
            Acc_Last := Acc_Last + Rec_Last;
            Got := Got + 1;
         end if;
      end loop;
   end Read_N_Real_Records;

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
               Put_Line ("usage: tls_interop_client [--host H] [--port P]");
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

   App_Phrase : constant String := "hello from spark-tls";

   Sock : Tls_Core.Tcp_Transport.Channel;
   D    : Tls_Core.Tls13_Driver.Driver;

begin
   Parse_Args;
   if not Aborted then
      Put_Line ("tls_interop_client: connecting to "
                & Host.all & ":" & Natural'Image (Port));
      Tls_Core.Tcp_Transport.Connect (Sock, Host.all, Port);

      declare
         Psk_Bytes : constant Octet_Array := From_Hex (Psk_Hex.all);
         Id_Bytes  : constant Octet_Array := To_Bytes (Identity_Str.all);
         Ecdhe     : constant Octet_Array (1 .. 32) := (others => 16#22#);
      begin
         Tls_Core.Tls13_Driver.Init_Psk_Client
           (D, Psk_Bytes, Id_Bytes, Ecdhe);
      end;

      --  Flight 1: emit ClientHello.
      if not Aborted then
         declare
            Out_Buf  : Octet_Array (1 .. 4096) := (others => 0);
            Out_Last : Natural;
            Empty    : constant Octet_Array (1 .. 0) := (others => 0);
         begin
            Tls_Core.Tls13_Driver.Step
              (D, In_Bytes => Empty,
               Out_Buf => Out_Buf, Out_Last => Out_Last);
            if Out_Last = 0
              or else Tls_Core.Tls13_Driver.Current_State (D)
                        /= Tls_Core.Tls13_Driver.Awaiting_Sf
            then
               Fail ("client did not produce CH or did not advance");
            else
               Tls_Core.Tcp_Transport.Send_All
                 (Sock, Out_Buf (1 .. Out_Last));
               Put_Line ("  -> sent ClientHello ("
                         & Natural'Image (Out_Last) & " bytes)");
            end if;
         end;
      end if;

      --  Flight 2: read SH + EE + SF (3 records, after CCS filter),
      --  feed driver, expect Done after emitting CF.
      if not Aborted then
         declare
            In_Buf   : Octet_Array (1 .. 16640 * 3 + 64) := (others => 0);
            In_Last  : Natural;
            OK       : Boolean;
            Out_Buf  : Octet_Array (1 .. 4096) := (others => 0);
            Out_Last : Natural;
         begin
            Read_N_Real_Records (Sock, 3, In_Buf, In_Last, OK);
            if not OK then
               Fail ("could not read 3 server records");
            else
               Put_Line ("  <- read server flight ("
                         & Natural'Image (In_Last) & " bytes after CCS)");
               Tls_Core.Tls13_Driver.Step
                 (D, In_Bytes => In_Buf (1 .. In_Last),
                  Out_Buf => Out_Buf, Out_Last => Out_Last);
               if Tls_Core.Tls13_Driver.Current_State (D)
                    /= Tls_Core.Tls13_Driver.Done
               then
                  Put_Line ("  state = "
                            & Tls_Core.Tls13_Driver.State'Image
                                (Tls_Core.Tls13_Driver.Current_State (D)));
                  Fail ("driver did not reach Done after server flight");
               elsif Out_Last > 0 then
                  Tls_Core.Tcp_Transport.Send_All
                    (Sock, Out_Buf (1 .. Out_Last));
                  Put_Line ("  -> sent client Finished ("
                            & Natural'Image (Out_Last) & " bytes)");
               end if;
            end if;
         end;
      end if;

      --  Application-data round trip.
      if not Aborted then
         declare
            Out_Cli, In_Cli : Tls_Core.Aead_Channel.Direction;
            Plaintext : constant Octet_Array := To_Bytes (App_Phrase);
            Wire      : Octet_Array (1 .. 4096) := (others => 0);
            Wire_Last : Natural;
            Reply_Buf : Octet_Array (1 .. 4096) := (others => 0);
            Reply_Last : Natural;
            Got       : Octet_Array (1 .. 4096) := (others => 0);
            Got_Last  : Natural;
            Inner     : Octet;
            Decode_OK : Boolean;
         begin
            Tls_Core.Tls13_Driver.Open_App_Directions (D, Out_Cli, In_Cli);
            Tls_Core.Aead_Channel.Send
              (Out_Cli,
               Plaintext,
               Tls_Core.Aead_Channel.Inner_Type_Application_Data,
               Wire, Wire_Last);
            Tls_Core.Tcp_Transport.Send_All (Sock, Wire (1 .. Wire_Last));
            Put_Line ("  -> sent """ & App_Phrase & """ ("
                      & Natural'Image (Plaintext'Length) & " bytes)");

            Read_Record (Sock, Reply_Buf, Reply_Last, Decode_OK);
            if not Decode_OK or else Reply_Last < 5 then
               Fail ("no app-data reply from peer");
            else
               Tls_Core.Aead_Channel.Receive
                 (In_Cli, Reply_Buf (1 .. Reply_Last),
                  Got, Got_Last, Inner, Decode_OK);
               if not Decode_OK then
                  Fail ("app-data decrypt failed");
               else
                  Put_Line ("  <- decrypted "
                            & Natural'Image (Got_Last) & " app-data bytes");
                  Put_Payload (Got (1 .. Got_Last));
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
            Tls_Core.Tls13_Driver.Send_Close_Notify
              (D, Out_Buf, Out_Last);
            if Out_Last > 0 then
               Tls_Core.Tcp_Transport.Send_All
                 (Sock, Out_Buf (1 .. Out_Last));
               Put_Line ("  -> sent close_notify ("
                         & Natural'Image (Out_Last) & " bytes)");
            end if;
         end;
      end if;

      Tls_Core.Tcp_Transport.Close (Sock);
      if not Aborted then
         Put_Line ("tls_interop_client: OK");
      end if;
   end if;

   Ada.Command_Line.Set_Exit_Status
     (Ada.Command_Line.Exit_Status (Exit_Code));

exception
   when E : others =>
      Put_Line ("tls_interop_client: exception "
                & Ada.Exceptions.Exception_Name (E)
                & " — " & Ada.Exceptions.Exception_Message (E));
      Ada.Command_Line.Set_Exit_Status (1);
end Tls_Interop_Client;
