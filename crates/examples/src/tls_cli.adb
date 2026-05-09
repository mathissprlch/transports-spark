--  tls_cli — production-shaped TLS 1.3 client / server CLI.
--
--  Per CLAUDE.md §10a: a single binary, CLI-controlled, that
--  exercises the same public Tls_Core APIs a downstream consumer
--  (http_core / mqtt_core / grpc_core) would link against.  The
--  tls_interop runner drives this binary; users can also invoke it
--  directly to talk to any RFC 8446 peer.
--
--  Usage:
--    tls_cli client --connect HOST:PORT --mode psk-dhe-ke
--                   --psk-file FILE --psk-id STRING
--                   [--sni HOST] [--alpn proto[,proto...]]
--                   [--send STRING] [--recv-len N]
--
--    tls_cli server --bind HOST:PORT --mode psk-dhe-ke
--                   --psk-file FILE --psk-id STRING
--                   [--echo | --serve-file FILE]
--
--    tls_cli client --connect HOST:PORT --mode cert-ec
--                   --trust FILE.der --hostname STRING
--                   ...                                    [TODO]
--    tls_cli server --bind HOST:PORT --mode cert-ec
--                   --cert FILE.der --key FILE
--                   ...                                    [TODO]
--
--  Common flags:
--    --connect HOST:PORT     Client mode endpoint
--    --bind HOST:PORT        Server mode listen address
--    --mode psk-dhe-ke|cert-ec|cert-rsa
--    --psk-file FILE         Read 32 raw bytes from FILE (default mode)
--    --psk-hex HEX           Alternate: 64 hex chars (testing only)
--    --psk-id STRING         PSK identity ASCII bytes
--    --sni HOST              client_hello.extensions.server_name
--    --alpn LIST             comma-separated ProtocolName list
--    --ecdhe-priv FILE       32 raw bytes; default = filled with 0x22
--    --send STRING           App data to send after handshake (client)
--    --recv-len N            Read N bytes after sending (client)
--    --echo                  Server: echo received bytes
--    --quiet                 Suppress per-step Put_Line tracing
--    --help                  Print usage and exit
--
--  Exit status:
--    0 = handshake + app-data + close_notify all clean
--    1 = TLS-level failure
--    2 = usage / argument / file-IO error
--
--  This program is plain Ada (no SPARK_Mode aspect): test/CLI
--  glue, not part of the proven core.  CLAUDE.md §0d compliance:
--  no SPARK_Mode (Off) outside Tcp_Transport, no pragma Assume,
--  no Pre/Post bypass.

with Ada.Command_Line;
with Ada.Exceptions;
with Ada.Strings.Fixed;
with Ada.Streams.Stream_IO;
with Ada.Text_IO;

with Interfaces;

with Tls_Core;
with Tls_Core.Aead_Channel;
with Tls_Core.Cert_Chain;
with Tls_Core.Session_Cache;
with Tls_Core.Session_Ticket;
with Tls_Core.Suites;
with Tls_Core.Tcp_Transport;
with Tls_Core.Tls13_Driver;

procedure Tls_Cli is

   use Ada.Text_IO;
   use type Interfaces.Unsigned_8;
   use type Tls_Core.Tls13_Driver.State;

   subtype Octet       is Tls_Core.Octet;
   subtype Octet_Array is Tls_Core.Octet_Array;

   --  ===== CLI configuration =====================================

   type Role_Kind is (R_Client, R_Server, R_None);
   type Mode_Kind is (M_Psk_Dhe_Ke, M_Cert_Ec, M_Cert_Rsa, M_Psk_Resume,
                      M_None);
   type App_Action is (A_None, A_Send_Recv, A_Echo);

   Role        : Role_Kind := R_None;
   Mode        : Mode_Kind := M_None;
   Endpoint    : access String := new String'("");
   Psk_Path    : access String := new String'("");
   Psk_Hex     : access String := new String'("");
   Psk_Id      : access String := new String'("Test");
   Sni_Host    : access String := new String'("");
   Alpn_List   : access String := new String'("");
   Ecdhe_Path  : access String := new String'("");
   Cert_Path   : access String := new String'("");  --  server leaf DER
   Key_Path    : access String := new String'("");  --  server priv (32 B EC)
   Trust_Path  : access String := new String'("");  --  client trust root DER
   Hostname    : access String := new String'("");  --  client SAN match
   Save_Ticket : access String := new String'("");  --  client: write Slot
   Load_Ticket : access String := new String'("");  --  client: read Slot
   Send_Str    : access String := new String'("");
   Recv_Len    : Natural := 0;
   Action      : App_Action := A_None;
   Quiet       : Boolean := False;

   Exit_Code : Integer := 0;
   Aborted   : Boolean := False;

   procedure Trace (S : String) is
   begin
      if not Quiet then
         Put_Line (S);
      end if;
   end Trace;

   procedure Fail (Msg : String) is
   begin
      Put_Line ("tls_cli: ERROR — " & Msg);
      Exit_Code := 1;
      Aborted   := True;
   end Fail;

   procedure Usage_Error (Msg : String) is
   begin
      Put_Line ("tls_cli: " & Msg);
      Put_Line ("Usage: tls_cli {client|server} [options]");
      Put_Line ("       tls_cli --help");
      Exit_Code := 2;
      Aborted   := True;
   end Usage_Error;

   --  ===== File I/O helpers =======================================

   function Read_File (Path : String) return Octet_Array is
      use Ada.Streams;
      File   : Stream_IO.File_Type;
      Result : Octet_Array (1 .. 65536) := (others => 0);
      Last   : Stream_Element_Offset;
   begin
      Stream_IO.Open (File, Stream_IO.In_File, Path);
      declare
         Buf : Stream_Element_Array (1 .. 65536);
         for Buf'Address use Result'Address;
      begin
         Stream_IO.Read (File, Buf, Last);
      end;
      Stream_IO.Close (File);
      return Result (1 .. Natural (Last));
   exception
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
         Fail ("could not read file: " & Path);
         return Octet_Array'(1 .. 0 => 0);
   end Read_File;

   function To_Bytes (S : String) return Octet_Array is
      Result : Octet_Array (1 .. S'Length) := (others => 0);
   begin
      for I in S'Range loop
         Result (1 + I - S'First) := Octet (Character'Pos (S (I)));
      end loop;
      return Result;
   end To_Bytes;

   function From_Hex (S : String) return Octet_Array is
      Result : Octet_Array (1 .. S'Length / 2) := (others => 0);
      function Nibble (C : Character) return Octet is
      begin
         case C is
            when '0' .. '9' =>
               return Octet (Character'Pos (C) - Character'Pos ('0'));
            when 'a' .. 'f' =>
               return Octet (10 + Character'Pos (C) - Character'Pos ('a'));
            when 'A' .. 'F' =>
               return Octet (10 + Character'Pos (C) - Character'Pos ('A'));
            when others =>
               raise Constraint_Error;
         end case;
      end Nibble;
   begin
      if S'Length mod 2 /= 0 then
         raise Constraint_Error;
      end if;
      for I in 0 .. (S'Length / 2) - 1 loop
         Result (1 + I) :=
           Nibble (S (S'First + 2 * I)) * 16 +
           Nibble (S (S'First + 2 * I + 1));
      end loop;
      return Result;
   end From_Hex;

   --  Returns the colon index in S, or 0 if absent.  Caller slices
   --  Host = S (S'First .. Colon - 1) and Port = S (Colon + 1 ..).
   function Find_Colon (S : String) return Natural is
   begin
      for I in S'Range loop
         if S (I) = ':' then
            return I;
         end if;
      end loop;
      return 0;
   end Find_Colon;

   --  ===== Argument parsing =======================================

   procedure Print_Help is
   begin
      Put_Line ("tls_cli — RFC 8446 TLS 1.3 client/server CLI");
      Put_Line ("");
      Put_Line ("USAGE");
      Put_Line ("  tls_cli client --connect HOST:PORT --mode MODE [opts]");
      Put_Line ("  tls_cli server --bind HOST:PORT --mode MODE [opts]");
      Put_Line ("");
      Put_Line ("MODES");
      Put_Line ("  --mode psk-dhe-ke    PSK + ECDHE (RFC 8446 §7.1 mode 3)");
      Put_Line ("  --mode cert-ec       Cert mode, ECDSA-P256 [client/server]");
      Put_Line ("  --mode cert-rsa      Cert mode, RSA-PSS verify only [client]");
      Put_Line ("");
      Put_Line ("PSK CONFIG");
      Put_Line ("  --psk-file FILE      32-byte PSK material (recommended)");
      Put_Line ("  --psk-hex HEX        64 hex chars (testing only)");
      Put_Line ("  --psk-id STRING      PSK identity (default ""Test"")");
      Put_Line ("");
      Put_Line ("CERT CONFIG (TODO — driver supports it; CLI plumbing pending)");
      Put_Line ("  --cert FILE.der      Server's DER-encoded leaf cert");
      Put_Line ("  --key FILE           Server's private key (32-byte raw)");
      Put_Line ("  --trust FILE.der     Client's trust anchor (root cert DER)");
      Put_Line ("  --hostname STRING    Client: SAN dNSName to validate");
      Put_Line ("");
      Put_Line ("EXTENSIONS");
      Put_Line ("  --sni HOST           ClientHello server_name (RFC 6066)");
      Put_Line ("  --alpn LIST          ALPN ProtocolName list (h2,http/1.1)");
      Put_Line ("  --ecdhe-priv FILE    Client X25519 private scalar (32 bytes)");
      Put_Line ("");
      Put_Line ("APP-DATA ROUND TRIP");
      Put_Line ("  --send STRING        Client: send STRING after handshake");
      Put_Line ("  --recv-len N         Client: read N bytes after sending");
      Put_Line ("  --echo               Server: echo received bytes back");
      Put_Line ("");
      Put_Line ("MISC");
      Put_Line ("  --quiet              Suppress per-step trace output");
      Put_Line ("  --help               This message");
      Put_Line ("");
      Put_Line ("EXIT STATUS");
      Put_Line ("  0  handshake + app-data + close_notify clean");
      Put_Line ("  1  TLS-level failure");
      Put_Line ("  2  usage / argument / I/O error");
   end Print_Help;

   procedure Parse_Args is
      A : Natural := 1;
   begin
      if Ada.Command_Line.Argument_Count = 0 then
         Print_Help;
         Aborted := True;
         Exit_Code := 2;
         return;
      end if;

      while A <= Ada.Command_Line.Argument_Count loop
         declare
            Arg : constant String := Ada.Command_Line.Argument (A);
         begin
            if Arg = "--help" or else Arg = "-h" then
               Print_Help;
               Aborted := True;
               return;
            elsif Arg = "client" then
               Role := R_Client;
            elsif Arg = "server" then
               Role := R_Server;
            elsif Arg = "--connect" or else Arg = "--bind" then
               A := A + 1;
               Endpoint := new String'(Ada.Command_Line.Argument (A));
            elsif Arg = "--mode" then
               A := A + 1;
               declare
                  M : constant String := Ada.Command_Line.Argument (A);
               begin
                  if M = "psk-dhe-ke" then
                     Mode := M_Psk_Dhe_Ke;
                  elsif M = "cert-ec" then
                     Mode := M_Cert_Ec;
                  elsif M = "cert-rsa" then
                     Mode := M_Cert_Rsa;
                  elsif M = "psk-resume" then
                     Mode := M_Psk_Resume;
                  else
                     Usage_Error ("unknown --mode: " & M);
                     return;
                  end if;
               end;
            elsif Arg = "--psk-file" then
               A := A + 1;
               Psk_Path := new String'(Ada.Command_Line.Argument (A));
            elsif Arg = "--psk-hex" then
               A := A + 1;
               Psk_Hex := new String'(Ada.Command_Line.Argument (A));
            elsif Arg = "--psk-id" then
               A := A + 1;
               Psk_Id := new String'(Ada.Command_Line.Argument (A));
            elsif Arg = "--sni" then
               A := A + 1;
               Sni_Host := new String'(Ada.Command_Line.Argument (A));
            elsif Arg = "--alpn" then
               A := A + 1;
               Alpn_List := new String'(Ada.Command_Line.Argument (A));
            elsif Arg = "--ecdhe-priv" then
               A := A + 1;
               Ecdhe_Path := new String'(Ada.Command_Line.Argument (A));
            elsif Arg = "--cert" then
               A := A + 1;
               Cert_Path := new String'(Ada.Command_Line.Argument (A));
            elsif Arg = "--key" then
               A := A + 1;
               Key_Path := new String'(Ada.Command_Line.Argument (A));
            elsif Arg = "--trust" then
               A := A + 1;
               Trust_Path := new String'(Ada.Command_Line.Argument (A));
            elsif Arg = "--hostname" then
               A := A + 1;
               Hostname := new String'(Ada.Command_Line.Argument (A));
            elsif Arg = "--save-ticket" then
               A := A + 1;
               Save_Ticket := new String'(Ada.Command_Line.Argument (A));
            elsif Arg = "--load-ticket" then
               A := A + 1;
               Load_Ticket := new String'(Ada.Command_Line.Argument (A));
            elsif Arg = "--send" then
               A := A + 1;
               Send_Str := new String'(Ada.Command_Line.Argument (A));
               Action := A_Send_Recv;
            elsif Arg = "--recv-len" then
               A := A + 1;
               Recv_Len :=
                 Natural'Value (Ada.Command_Line.Argument (A));
            elsif Arg = "--echo" then
               Action := A_Echo;
            elsif Arg = "--quiet" then
               Quiet := True;
            else
               Usage_Error ("unknown argument: " & Arg);
               return;
            end if;
         end;
         A := A + 1;
      end loop;

      if Role = R_None then
         Usage_Error ("must specify 'client' or 'server'");
         return;
      end if;
      if Mode = M_None then
         Usage_Error ("must specify --mode");
         return;
      end if;
      if Endpoint.all = "" then
         Usage_Error ("must specify --connect (client) or --bind (server)");
         return;
      end if;
   end Parse_Args;

   --  ===== Wire-shape glue (TLS records on the socket) ===========

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
      Body_Len := Natural (Header (4)) * 256 + Natural (Header (5));
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
            null;  --  CCS dummy — RFC 8446 §5
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

   --  ===== ALPN parsing ==========================================
   --
   --  Convert a comma-separated protocol list ("h2,http/1.1") into
   --  the flattened RFC 7301 wire format: u8 N || N name bytes,
   --  repeated.

   function Alpn_To_Wire (S : String) return Octet_Array is
      --  Worst case: every byte becomes part of a 1-name list with
      --  one length-prefix byte → output is at most S'Length + N
      --  where N is the number of commas + 1.  A 256-byte cap covers
      --  any realistic ALPN list and matches the driver's API bound.
      Out_Buf : Octet_Array (1 .. 256) := (others => 0);
      Out_Last : Natural := 0;
      Start    : Positive := S'First;
   begin
      if S'Length = 0 then
         return Octet_Array'(1 .. 0 => 0);
      end if;
      for I in S'First .. S'Last loop
         if S (I) = ',' or else I = S'Last then
            declare
               Name_End : constant Positive :=
                 (if S (I) = ',' then I - 1 else I);
               Name_Len : constant Natural := Name_End - Start + 1;
            begin
               if Out_Last + 1 + Name_Len > Out_Buf'Length then
                  return Octet_Array'(1 .. 0 => 0);
               end if;
               Out_Last := Out_Last + 1;
               Out_Buf (Out_Last) := Octet (Name_Len);
               for K in 1 .. Name_Len loop
                  Out_Last := Out_Last + 1;
                  Out_Buf (Out_Last) :=
                    Octet (Character'Pos (S (Start + K - 1)));
               end loop;
               Start := I + 1;
            end;
         end if;
      end loop;
      return Out_Buf (1 .. Out_Last);
   end Alpn_To_Wire;

   --  ===== Driver setup ===========================================

   procedure Load_Psk (Out_Bytes : out Octet_Array; OK : out Boolean) is
   begin
      OK := True;
      if Psk_Path.all /= "" then
         declare
            Buf : constant Octet_Array := Read_File (Psk_Path.all);
         begin
            if Buf'Length /= 32 then
               Fail ("--psk-file must be exactly 32 bytes; got "
                     & Natural'Image (Buf'Length));
               OK := False;
               return;
            end if;
            Out_Bytes := Buf;
         end;
      elsif Psk_Hex.all /= "" then
         declare
            Buf : constant Octet_Array := From_Hex (Psk_Hex.all);
         begin
            if Buf'Length /= 32 then
               Fail ("--psk-hex must decode to 32 bytes");
               OK := False;
               return;
            end if;
            Out_Bytes := Buf;
         end;
      else
         Fail ("PSK mode requires --psk-file or --psk-hex");
         OK := False;
      end if;
   end Load_Psk;

   procedure Load_Ecdhe (Out_Bytes : out Octet_Array; OK : out Boolean) is
   begin
      OK := True;
      if Ecdhe_Path.all /= "" then
         declare
            Buf : constant Octet_Array := Read_File (Ecdhe_Path.all);
         begin
            if Buf'Length /= 32 then
               Fail ("--ecdhe-priv must be exactly 32 bytes");
               OK := False;
               return;
            end if;
            Out_Bytes := Buf;
         end;
      else
         --  Default: deterministic dummy private scalar (test only).
         --  A production user would always pass --ecdhe-priv from a
         --  CSPRNG.
         Out_Bytes := (others => 16#22#);
      end if;
   end Load_Ecdhe;

   --  ===== Session-ticket persistence (resumption-PSK) =============
   --
   --  Compact binary serialisation of a Session_Cache.Slot.  The
   --  matrix and downstream callers persist the slot to disk between
   --  the cert-mode "ticket-issuing" handshake and the resumption-
   --  PSK "ticket-presenting" handshake.
   --
   --  Layout (big-endian):
   --    1B  Suite_Id (0=Chacha20_Poly1305, 1=Aes_128_Gcm, 2=Aes_256_Gcm)
   --    4B  Lifetime
   --    4B  Age_Add
   --    1B  Ticket_Nonce_Len   (n, 0..255)
   --    nB  Ticket_Nonce
   --    2B  Ticket_Len         (m, 1..1024)
   --    mB  Ticket
   --   32B  Resumption_Secret  (SHA-256 digest)

   procedure Save_Slot
     (Slot : Tls_Core.Session_Cache.Slot;
      Path : String;
      OK   : out Boolean)
   is
      use Ada.Streams;
      use type Tls_Core.Session_Ticket.U32;
      Suite_Id : constant Octet :=
        (case Slot.Suite is
           when Tls_Core.Suites.Chacha20_Poly1305_Sha256 => 0,
           when Tls_Core.Suites.Aes_128_Gcm_Sha256       => 1,
           when Tls_Core.Suites.Aes_256_Gcm_Sha384       => 2);
      Buf : Octet_Array (1 .. 1 + 4 + 4 + 1
                          + Tls_Core.Session_Ticket.Max_Ticket_Nonce_Length
                          + 2 + Tls_Core.Session_Ticket.Max_Ticket_Length
                          + 32) := (others => 0);
      Cursor : Natural := 0;
      File   : Stream_IO.File_Type;
   begin
      OK := False;
      Cursor := Cursor + 1; Buf (Cursor) := Suite_Id;
      for I in 0 .. 3 loop
         Cursor := Cursor + 1;
         Buf (Cursor) := Octet
           ((Slot.Lifetime / 2 ** (8 * (3 - I))) and 16#FF#);
      end loop;
      for I in 0 .. 3 loop
         Cursor := Cursor + 1;
         Buf (Cursor) := Octet
           ((Slot.Age_Add / 2 ** (8 * (3 - I))) and 16#FF#);
      end loop;
      Cursor := Cursor + 1; Buf (Cursor) := Octet (Slot.Ticket_Nonce_Len);
      if Slot.Ticket_Nonce_Len > 0 then
         Buf (Cursor + 1 .. Cursor + Slot.Ticket_Nonce_Len) :=
           Slot.Ticket_Nonce (1 .. Slot.Ticket_Nonce_Len);
         Cursor := Cursor + Slot.Ticket_Nonce_Len;
      end if;
      Cursor := Cursor + 1; Buf (Cursor) :=
        Octet (Slot.Ticket_Len / 256);
      Cursor := Cursor + 1; Buf (Cursor) :=
        Octet (Slot.Ticket_Len mod 256);
      Buf (Cursor + 1 .. Cursor + Slot.Ticket_Len) :=
        Slot.Ticket (1 .. Slot.Ticket_Len);
      Cursor := Cursor + Slot.Ticket_Len;
      Buf (Cursor + 1 .. Cursor + 32) := Slot.Resumption_Secret;
      Cursor := Cursor + 32;

      Stream_IO.Create (File, Stream_IO.Out_File, Path);
      declare
         SEA : Stream_Element_Array (1 .. Stream_Element_Offset (Cursor));
         for SEA'Address use Buf'Address;
      begin
         Stream_IO.Write (File, SEA);
      end;
      Stream_IO.Close (File);
      OK := True;
   exception
      when others =>
         if Stream_IO.Is_Open (File) then
            Stream_IO.Close (File);
         end if;
   end Save_Slot;

   procedure Load_Slot
     (Path : String;
      Slot : out Tls_Core.Session_Cache.Slot;
      OK   : out Boolean)
   is
      use type Tls_Core.Session_Ticket.U32;
      Buf : constant Octet_Array := Read_File (Path);
      P : Natural := Buf'First;
      Suite_Id : Octet;
      function R_U32 (Start : Natural) return Tls_Core.Session_Ticket.U32 is
        (Tls_Core.Session_Ticket.U32 (Buf (Start))     * 16#01000000#
         + Tls_Core.Session_Ticket.U32 (Buf (Start + 1)) * 16#00010000#
         + Tls_Core.Session_Ticket.U32 (Buf (Start + 2)) * 16#00000100#
         + Tls_Core.Session_Ticket.U32 (Buf (Start + 3)));
   begin
      OK := False;
      Slot := (others => <>);
      if Buf'Length < 1 + 4 + 4 + 1 + 2 + 1 + 32 then
         return;
      end if;
      Suite_Id := Buf (P); P := P + 1;
      Slot.Suite :=
        (case Suite_Id is
           when 0 => Tls_Core.Suites.Chacha20_Poly1305_Sha256,
           when 1 => Tls_Core.Suites.Aes_128_Gcm_Sha256,
           when 2 => Tls_Core.Suites.Aes_256_Gcm_Sha384,
           when others => Tls_Core.Suites.Aes_128_Gcm_Sha256);
      Slot.Lifetime := R_U32 (P); P := P + 4;
      Slot.Age_Add  := R_U32 (P); P := P + 4;
      Slot.Ticket_Nonce_Len := Natural (Buf (P)); P := P + 1;
      if Slot.Ticket_Nonce_Len
        > Tls_Core.Session_Ticket.Max_Ticket_Nonce_Length
      then
         return;
      end if;
      if P - 1 + Slot.Ticket_Nonce_Len > Buf'Last then return; end if;
      if Slot.Ticket_Nonce_Len > 0 then
         Slot.Ticket_Nonce (1 .. Slot.Ticket_Nonce_Len) :=
           Buf (P .. P + Slot.Ticket_Nonce_Len - 1);
         P := P + Slot.Ticket_Nonce_Len;
      end if;
      if P + 1 > Buf'Last then return; end if;
      Slot.Ticket_Len :=
        Natural (Buf (P)) * 256 + Natural (Buf (P + 1));
      P := P + 2;
      if Slot.Ticket_Len < 1
        or else Slot.Ticket_Len > Tls_Core.Session_Ticket.Max_Ticket_Length
      then
         return;
      end if;
      if P - 1 + Slot.Ticket_Len > Buf'Last then return; end if;
      Slot.Ticket (1 .. Slot.Ticket_Len) :=
        Buf (P .. P + Slot.Ticket_Len - 1);
      P := P + Slot.Ticket_Len;
      if P + 31 > Buf'Last then return; end if;
      Slot.Resumption_Secret := Buf (P .. P + 31);
      Slot.Used := True;
      Slot.Insertion_Seq := 1;
      OK := True;
   end Load_Slot;

   --  ===== Main runtime ==========================================

   --  Run_Client.  PSK mode → 3 server records (SH+EE+SF).  Cert
   --  mode → 5 records (SH+EE+Cert+CV+SF).  CCS records (RFC 8446
   --  Appendix D.4 middlebox-compat) are skipped by Read_N_Real_
   --  Records.  Driver Step expects the full flight in one call.
   procedure Run_Client
     (Sock           : in out Tls_Core.Tcp_Transport.Channel;
      D              : in out Tls_Core.Tls13_Driver.Driver;
      Server_Records : Positive)
   is
      Out_Buf  : Octet_Array (1 .. 4096) := (others => 0);
      Out_Last : Natural;
      Empty    : constant Octet_Array (1 .. 0) := (others => 0);
   begin
      Tls_Core.Tls13_Driver.Step
        (D, In_Bytes => Empty, Out_Buf => Out_Buf, Out_Last => Out_Last);
      if Out_Last = 0
        or else Tls_Core.Tls13_Driver.Current_State (D)
                  /= Tls_Core.Tls13_Driver.Awaiting_Sf
      then
         Fail ("client did not produce CH or did not advance");
         return;
      end if;
      Tls_Core.Tcp_Transport.Send_All (Sock, Out_Buf (1 .. Out_Last));
      Trace ("  -> sent ClientHello (" & Natural'Image (Out_Last) & " B)");

      declare
         In_Buf   : Octet_Array (1 .. 16640 * 5 + 64) := (others => 0);
         In_Last  : Natural;
         OK       : Boolean;
         CF_Buf   : Octet_Array (1 .. 4096) := (others => 0);
         CF_Last  : Natural;
      begin
         Read_N_Real_Records (Sock, Server_Records, In_Buf, In_Last, OK);
         if not OK then
            Fail ("could not read"
                  & Natural'Image (Server_Records)
                  & " server records");
            return;
         end if;
         Trace ("  <- read server flight (" & Natural'Image (In_Last) & " B)");
         Tls_Core.Tls13_Driver.Step
           (D, In_Bytes => In_Buf (1 .. In_Last),
            Out_Buf => CF_Buf, Out_Last => CF_Last);
         if Tls_Core.Tls13_Driver.Current_State (D)
              /= Tls_Core.Tls13_Driver.Done
         then
            Fail ("client did not reach Done; state = "
                  & Tls_Core.Tls13_Driver.State'Image
                      (Tls_Core.Tls13_Driver.Current_State (D))
                  & "; alert ="
                  & Natural'Image
                      (Natural (Tls_Core.Tls13_Driver
                                 .Last_Alert_Description (D))));
            return;
         end if;
         Tls_Core.Tcp_Transport.Send_All (Sock, CF_Buf (1 .. CF_Last));
         Trace ("  -> sent client Finished (" & Natural'Image (CF_Last) & " B)");
      end;
   end Run_Client;

   procedure Run_Server
     (Sock : in out Tls_Core.Tcp_Transport.Channel;
      D    : in out Tls_Core.Tls13_Driver.Driver)
   is
      In_Buf   : Octet_Array (1 .. 16640 + 5) := (others => 0);
      In_Last  : Natural;
      OK       : Boolean;
      Out_Buf  : Octet_Array (1 .. 4096) := (others => 0);
      Out_Last : Natural;
   begin
      Read_N_Real_Records (Sock, 1, In_Buf, In_Last, OK);
      if not OK or else In_Last = 0 then
         Fail ("could not read ClientHello");
         return;
      end if;
      Trace ("  <- read CH (" & Natural'Image (In_Last) & " B)");
      Tls_Core.Tls13_Driver.Step
        (D, In_Bytes => In_Buf (1 .. In_Last),
         Out_Buf => Out_Buf, Out_Last => Out_Last);
      if Tls_Core.Tls13_Driver.Current_State (D)
           /= Tls_Core.Tls13_Driver.Awaiting_Cf
      then
         Fail ("server did not advance to Awaiting_Cf; state = "
               & Tls_Core.Tls13_Driver.State'Image
                   (Tls_Core.Tls13_Driver.Current_State (D))
               & "; alert ="
               & Natural'Image
                   (Natural (Tls_Core.Tls13_Driver
                              .Last_Alert_Description (D))));
         return;
      end if;
      Tls_Core.Tcp_Transport.Send_All (Sock, Out_Buf (1 .. Out_Last));
      Trace ("  -> sent SH+EE+SF (" & Natural'Image (Out_Last) & " B)");

      Read_N_Real_Records (Sock, 1, In_Buf, In_Last, OK);
      if not OK then
         Fail ("could not read CF");
         return;
      end if;
      Tls_Core.Tls13_Driver.Step
        (D, In_Bytes => In_Buf (1 .. In_Last),
         Out_Buf => Out_Buf, Out_Last => Out_Last);
      if Tls_Core.Tls13_Driver.Current_State (D)
           /= Tls_Core.Tls13_Driver.Done
      then
         Fail ("server did not reach Done; state = "
               & Tls_Core.Tls13_Driver.State'Image
                   (Tls_Core.Tls13_Driver.Current_State (D)));
         return;
      end if;
      Trace ("  <- server reached Done");
   end Run_Server;

   procedure Run_App_Phase
     (Sock : in out Tls_Core.Tcp_Transport.Channel;
      D    : in out Tls_Core.Tls13_Driver.Driver)
   is
      Out_Dir, In_Dir : Tls_Core.Aead_Channel.Direction;
   begin
      Tls_Core.Tls13_Driver.Open_App_Directions (D, Out_Dir, In_Dir);

      case Action is
         when A_Send_Recv =>
            declare
               Plaintext : constant Octet_Array := To_Bytes (Send_Str.all);
               Wire      : Octet_Array (1 .. 4096) := (others => 0);
               Wire_Last : Natural;
               Reply     : Octet_Array (1 .. 4096) := (others => 0);
               Reply_Last : Natural;
               Got       : Octet_Array (1 .. 4096) := (others => 0);
               Got_Last  : Natural;
               Inner     : Octet;
               OK        : Boolean;
            begin
               Tls_Core.Aead_Channel.Send
                 (Out_Dir, Plaintext,
                  Tls_Core.Aead_Channel.Inner_Type_Application_Data,
                  Wire, Wire_Last);
               Tls_Core.Tcp_Transport.Send_All (Sock, Wire (1 .. Wire_Last));
               Trace ("  -> sent app-data (" & Natural'Image (Plaintext'Length)
                      & " B plaintext)");
               if Recv_Len > 0 then
                  Read_Record (Sock, Reply, Reply_Last, OK);
                  if not OK or else Reply_Last < 5 then
                     Fail ("no app-data reply");
                     return;
                  end if;
                  Tls_Core.Aead_Channel.Receive
                    (In_Dir, Reply (1 .. Reply_Last),
                     Got, Got_Last, Inner, OK);
                  if not OK then
                     Fail ("app-data decrypt failed");
                     return;
                  end if;
                  Trace ("  <- decrypted " & Natural'Image (Got_Last)
                         & " B reply");
               end if;
            end;
         when A_Echo =>
            declare
               Reply     : Octet_Array (1 .. 4096) := (others => 0);
               Reply_Last : Natural;
               Got       : Octet_Array (1 .. 4096) := (others => 0);
               Got_Last  : Natural;
               Inner     : Octet;
               OK        : Boolean;
               Wire      : Octet_Array (1 .. 4096) := (others => 0);
               Wire_Last : Natural;
            begin
               Read_Record (Sock, Reply, Reply_Last, OK);
               if not OK then
                  Fail ("server: no app-data from client");
                  return;
               end if;
               Tls_Core.Aead_Channel.Receive
                 (In_Dir, Reply (1 .. Reply_Last),
                  Got, Got_Last, Inner, OK);
               if not OK then
                  Fail ("server: app-data decrypt failed");
                  return;
               end if;
               Trace ("  <- received " & Natural'Image (Got_Last)
                      & " B; echoing back");
               Tls_Core.Aead_Channel.Send
                 (Out_Dir, Got (1 .. Got_Last),
                  Tls_Core.Aead_Channel.Inner_Type_Application_Data,
                  Wire, Wire_Last);
               Tls_Core.Tcp_Transport.Send_All (Sock, Wire (1 .. Wire_Last));
            end;
         when A_None =>
            null;
      end case;
   end Run_App_Phase;

begin
   Parse_Args;
   if Aborted then
      Ada.Command_Line.Set_Exit_Status
        (Ada.Command_Line.Exit_Status (Exit_Code));
      return;
   end if;

   --  Build connection.
   declare
      Colon : constant Natural := Find_Colon (Endpoint.all);
      Host  : constant String :=
        (if Colon = 0 then Endpoint.all
         else Endpoint (Endpoint'First .. Colon - 1));
      Port  : constant Natural :=
        (if Colon = 0 then 4433
         else Natural'Value
                (Endpoint (Colon + 1 .. Endpoint'Last)));
      Sock : Tls_Core.Tcp_Transport.Channel;
      Lstn : Tls_Core.Tcp_Transport.Listener;
      D    : Tls_Core.Tls13_Driver.Driver;
   begin
      if Role = R_Client then
         Trace ("tls_cli client: " & Host & ":" & Natural'Image (Port));
         Tls_Core.Tcp_Transport.Connect (Sock, Host, Port);
      else
         Trace ("tls_cli server: bind " & Host & ":" & Natural'Image (Port));
         Tls_Core.Tcp_Transport.Listen (Lstn, Host, Port);
         Trace ("  (bound port =" & Natural'Image
                  (Tls_Core.Tcp_Transport.Bound_Port (Lstn)) & ")");
         Tls_Core.Tcp_Transport.Accept_One (Lstn, Sock);
         Trace ("  <- client connected");
      end if;

      --  Initialise driver.
      case Mode is
         when M_Psk_Dhe_Ke =>
            declare
               Psk_Bytes   : Octet_Array (1 .. 32) := (others => 0);
               Ecdhe_Bytes : Octet_Array (1 .. 32) := (others => 0);
               OK          : Boolean;
            begin
               Load_Psk (Psk_Bytes, OK);
               if not OK then
                  goto Cleanup;
               end if;
               Load_Ecdhe (Ecdhe_Bytes, OK);
               if not OK then
                  goto Cleanup;
               end if;
               if Role = R_Client then
                  Tls_Core.Tls13_Driver.Init_Psk_Client
                    (D, Psk_Bytes, To_Bytes (Psk_Id.all), Ecdhe_Bytes);
                  if Sni_Host.all /= "" then
                     Tls_Core.Tls13_Driver.Set_Sni_Hostname
                       (D, To_Bytes (Sni_Host.all));
                  end if;
                  if Alpn_List.all /= "" then
                     Tls_Core.Tls13_Driver.Set_Alpn_Offers
                       (D, Alpn_To_Wire (Alpn_List.all));
                  end if;
               else
                  Tls_Core.Tls13_Driver.Init_Psk_Server
                    (D, Psk_Bytes, To_Bytes (Psk_Id.all), Ecdhe_Bytes);
               end if;
            end;
         when M_Cert_Ec =>
            declare
               Ecdhe_Bytes : Octet_Array (1 .. 32) := (others => 0);
               OK          : Boolean;
            begin
               Load_Ecdhe (Ecdhe_Bytes, OK);
               if not OK then
                  goto Cleanup;
               end if;
               if Role = R_Client then
                  if Trust_Path.all = "" then
                     Fail ("client cert mode requires --trust DER_FILE");
                     goto Cleanup;
                  end if;
                  declare
                     Trust_Bytes : constant Octet_Array :=
                       Read_File (Trust_Path.all);
                     Trust_Spec  : Tls_Core.Cert_Chain.Trust_Store;
                     Host_Bytes  : constant Octet_Array :=
                       To_Bytes (Hostname.all);
                  begin
                     if Trust_Bytes'Length not in 16 .. 4096 then
                        Fail ("--trust DER size out of range (16..4096)");
                        goto Cleanup;
                     end if;
                     Trust_Spec.Count := 1;
                     Trust_Spec.Entries (1) :=
                       (First => 1, Last => Trust_Bytes'Length);
                     Tls_Core.Tls13_Driver.Init_Cert_Client
                       (D                  => D,
                        Trust_Anchor_Bytes => Trust_Bytes,
                        Trust_Spec         => Trust_Spec,
                        Hostname           => Host_Bytes,
                        Ecdhe_Priv         => Ecdhe_Bytes);
                     if Sni_Host.all /= "" then
                        Tls_Core.Tls13_Driver.Set_Sni_Hostname
                          (D, To_Bytes (Sni_Host.all));
                     end if;
                     if Alpn_List.all /= "" then
                        Tls_Core.Tls13_Driver.Set_Alpn_Offers
                          (D, Alpn_To_Wire (Alpn_List.all));
                     end if;
                  end;
               else
                  if Cert_Path.all = "" or else Key_Path.all = "" then
                     Fail ("server cert mode requires --cert and --key");
                     goto Cleanup;
                  end if;
                  declare
                     Cert_Bytes : constant Octet_Array :=
                       Read_File (Cert_Path.all);
                     Key_Bytes  : constant Octet_Array :=
                       Read_File (Key_Path.all);
                     Chain_Spec : Tls_Core.Cert_Chain.Chain;
                  begin
                     if Cert_Bytes'Length not in 1 .. 4096 then
                        Fail ("--cert DER size out of range (1..4096)");
                        goto Cleanup;
                     end if;
                     if Key_Bytes'Length /= 32 then
                        Fail ("--key must be exactly 32 bytes (raw EC scalar)");
                        goto Cleanup;
                     end if;
                     Chain_Spec.Count := 1;
                     Chain_Spec.Entries (1) :=
                       (First => 1, Last => Cert_Bytes'Length);
                     Tls_Core.Tls13_Driver.Init_Cert_Server
                       (D                => D,
                        Cert_Chain_Bytes => Cert_Bytes,
                        Chain_Spec       => Chain_Spec,
                        Sign_Priv_Key    => Key_Bytes,
                        Sig_Alg          =>
                          Tls_Core.Suites.Sig_Ecdsa_Secp256r1_Sha256,
                        Ecdhe_Priv       => Ecdhe_Bytes);
                  end;
               end if;
            end;
         when M_Cert_Rsa =>
            Fail ("--mode cert-rsa: server-side RSA-PSS signing not in "
                  & "v0.5 driver scope (verify path only). Use cert-ec.");
            goto Cleanup;
         when M_Psk_Resume =>
            --  Resumption-PSK client: load Slot from --load-ticket
            --  and feed it to Init_Psk_Resumption_Client.  Server
            --  side does NOT use this mode — the matrix peer is the
            --  server in resumption tests.
            if Role /= R_Client then
               Fail ("--mode psk-resume only supported on client side");
               goto Cleanup;
            end if;
            if Load_Ticket.all = "" then
               Fail ("--mode psk-resume requires --load-ticket FILE");
               goto Cleanup;
            end if;
            declare
               Slot : Tls_Core.Session_Cache.Slot;
               OK   : Boolean;
            begin
               Load_Slot (Load_Ticket.all, Slot, OK);
               if not OK then
                  Fail ("could not load ticket from " & Load_Ticket.all);
                  goto Cleanup;
               end if;
               Tls_Core.Tls13_Driver.Init_Psk_Resumption_Client
                 (D    => D,
                  Slot => Slot);
            end;
         when M_None =>
            Usage_Error ("must specify --mode");
            goto Cleanup;
      end case;

      --  Run the handshake.  PSK server flight = 3 records (SH+EE+SF);
      --  cert server flight = 5 records (SH+EE+Cert+CV+SF).
      if Role = R_Client then
         Run_Client (Sock, D,
                     Server_Records =>
                       (case Mode is
                          when M_Psk_Dhe_Ke | M_Psk_Resume => 3,
                          when others                      => 5));
      else
         Run_Server (Sock, D);
      end if;

      --  --save-ticket: cert-mode client drains the post-handshake
      --  NewSessionTicket record and persists the resulting Slot
      --  to disk.  Done BEFORE Run_App_Phase so the openssl/gnutls
      --  servers (which emit NST immediately after their flight)
      --  see no app-data interleave. RFC 8446 §4.6.1.
      if not Aborted
        and then Role = R_Client
        and then (Mode = M_Cert_Ec or else Mode = M_Cert_Rsa)
        and then Save_Ticket.all /= ""
      then
         declare
            Out_Dir, In_Dir : Tls_Core.Aead_Channel.Direction;
            Cache : Tls_Core.Session_Cache.Cache;
            Rec_Buf : Octet_Array (1 .. 4096) := (others => 0);
            Rec_Last : Natural;
            OK : Boolean;
            NST_OK : Boolean := False;
         begin
            Tls_Core.Session_Cache.Init (Cache);
            Tls_Core.Tls13_Driver.Open_App_Directions
              (D, Out_Dir => Out_Dir, In_Dir => In_Dir);
            Read_Record (Sock, Rec_Buf, Rec_Last, OK);
            if not OK or else Rec_Last < (5 + 1 + 16) then
               Trace ("  (no NST received from server)");
            else
               Tls_Core.Tls13_Driver.Receive_New_Session_Ticket
                 (D            => D,
                  In_Dir       => In_Dir,
                  Cache        => Cache,
                  Record_Bytes => Rec_Buf (1 .. Rec_Last),
                  OK           => NST_OK);
            end if;
            if NST_OK then
               declare
                  Index : Tls_Core.Session_Cache.Slot_Index;
                  Found : Boolean;
               begin
                  Tls_Core.Session_Cache.Lookup_Most_Recent
                    (Cache, Index, Found);
                  if Found then
                     declare
                        Saved : Boolean;
                     begin
                        Save_Slot (Cache.Slots (Index),
                                   Save_Ticket.all, Saved);
                        if Saved then
                           Trace ("  <- captured NST; ticket="
                                  & Natural'Image
                                       (Cache.Slots (Index).Ticket_Len)
                                  & " B → "
                                  & Save_Ticket.all);
                        else
                           Trace ("  (NST captured; save_slot failed)");
                        end if;
                     end;
                  end if;
               end;
            end if;
         end;
      end if;

      if not Aborted then
         Run_App_Phase (Sock, D);
      end if;

      --  Send close_notify when we're the client (server's CN may not
      --  be needed depending on the test; can be added behind a flag).
      if not Aborted and then Role = R_Client then
         declare
            CN_Buf  : Octet_Array (1 .. 256) := (others => 0);
            CN_Last : Natural;
         begin
            Tls_Core.Tls13_Driver.Send_Close_Notify (D, CN_Buf, CN_Last);
            if CN_Last > 0 then
               Tls_Core.Tcp_Transport.Send_All (Sock, CN_Buf (1 .. CN_Last));
               Trace ("  -> sent close_notify (" & Natural'Image (CN_Last)
                      & " B)");
            end if;
         end;
      end if;

      <<Cleanup>>
      if Tls_Core.Tcp_Transport.Is_Open (Sock) then
         Tls_Core.Tcp_Transport.Close (Sock);
      end if;
      if Role = R_Server
        and then Tls_Core.Tcp_Transport.Is_Listening (Lstn)
      then
         Tls_Core.Tcp_Transport.Stop (Lstn);
      end if;
   end;

   if not Aborted then
      Trace ("tls_cli: OK");
   end if;
   Ada.Command_Line.Set_Exit_Status
     (Ada.Command_Line.Exit_Status (Exit_Code));

exception
   when E : others =>
      Put_Line ("tls_cli: exception " & Ada.Exceptions.Exception_Name (E)
                & " — " & Ada.Exceptions.Exception_Message (E));
      Ada.Command_Line.Set_Exit_Status (1);
end Tls_Cli;
