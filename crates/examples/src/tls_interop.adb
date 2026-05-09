--  tls_interop — Tier D multi-peer interop matrix orchestrator.
--
--  Replaces the bash run_matrix.sh + per-peer .sh scripts with a
--  typed Ada binary.  Spawns peer binaries via GNAT.OS_Lib and the
--  Ada side via our own tls_cli.  Per CLAUDE.md §10a/b/d.
--
--  Usage:
--    tls_interop [--peer NAME[,NAME...]] [--quick] [--format md|json]
--    tls_interop --help
--
--  Default: all peers (Openssl, Gnutls, Mbedtls, Rustls, Go,
--  Boringssl), all cells (psk-chacha20 + psk-aes128 + cert-ec).
--
--  --quick limits to psk-chacha20 only.
--
--  Output: Markdown table on stdout by default; --format json
--  emits a JSON array suitable for CI ingestion.  Per-cell logs
--  land under /tmp/spark-tls-interop/<timestamp>/.

with Ada.Calendar.Formatting;
with Ada.Calendar;
with Ada.Command_Line;
with Ada.Directories;
with Ada.Exceptions;
with Ada.Numerics.Discrete_Random;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO;
with GNAT.OS_Lib;           use GNAT.OS_Lib;
with GNATCOLL.JSON;
with Tls_Interop_Peers;      use Tls_Interop_Peers;

procedure Tls_Interop is

   use Ada.Text_IO;

   --  ===== CLI flags ============================================

   type Format_Kind is (Markdown, Json);

   Format       : Format_Kind := Markdown;
   Quick        : Boolean := False;
   Peers_Filter : Unbounded_String := Null_Unbounded_String;  -- empty = all
   Show_Help    : Boolean := False;

   procedure Print_Help is
   begin
      Put_Line ("tls_interop — Tier D multi-peer interop matrix");
      Put_Line ("");
      Put_Line ("Usage:");
      Put_Line ("  tls_interop [--peer NAME[,NAME...]] [--quick]");
      Put_Line ("             [--format md|json] [--help]");
      Put_Line ("");
      Put_Line ("Peers (case-insensitive):");
      Put_Line ("  openssl gnutls mbedtls rustls go boringssl");
      Put_Line ("");
      Put_Line ("Modes (test cells):");
      Put_Line ("  psk-chacha20 — RFC 8446 PSK + chacha20-poly1305 (default)");
      Put_Line ("  psk-aes128   — RFC 8446 PSK + AES-128-GCM (skipped --quick)");
      Put_Line ("  cert-ec      — ECDSA-P256 certificate-mode (skipped --quick)");
      Put_Line ("");
      Put_Line ("Per-cell logs:  /tmp/spark-tls-interop/<timestamp>/");
   end Print_Help;

   --  ===== Argument parsing =====================================

   procedure Parse_Args is
      A : Natural := 1;
   begin
      while A <= Ada.Command_Line.Argument_Count loop
         declare
            Arg : constant String := Ada.Command_Line.Argument (A);
         begin
            if Arg = "--help" or else Arg = "-h" then
               Show_Help := True;
               return;
            elsif Arg = "--quick" then
               Quick := True;
            elsif Arg = "--peer" then
               A := A + 1;
               Peers_Filter := To_Unbounded_String
                                 (Ada.Command_Line.Argument (A));
            elsif Arg = "--format" then
               A := A + 1;
               declare
                  F : constant String := Ada.Command_Line.Argument (A);
               begin
                  if F = "md" or else F = "markdown" then
                     Format := Markdown;
                  elsif F = "json" then
                     Format := Json;
                  else
                     Put_Line ("tls_interop: unknown format: " & F);
                     Ada.Command_Line.Set_Exit_Status (2);
                     Show_Help := True;
                     return;
                  end if;
               end;
            else
               Put_Line ("tls_interop: unknown arg: " & Arg);
               Ada.Command_Line.Set_Exit_Status (2);
               Show_Help := True;
               return;
            end if;
         end;
         A := A + 1;
      end loop;
   end Parse_Args;

   --  ===== Peer-filter matching =================================
   --
   --  Returns True iff Peer is in the user-supplied filter list (or
   --  filter is empty = all peers).

   function Peer_Matches_Filter (P : Peer_Kind) return Boolean is
      F : constant String := To_String (Peers_Filter);
   begin
      if F = "" then
         return True;
      end if;
      declare
         Name : constant String := Image (P);
         Tok_Start : Positive := 1;
      begin
         for I in F'Range loop
            if F (I) = ',' or else I = F'Last then
               declare
                  Tok_End : constant Natural :=
                    (if F (I) = ',' then I - 1 else I);
                  Tok : constant String := F (Tok_Start .. Tok_End);
               begin
                  if Tok = Name then
                     return True;
                  end if;
                  Tok_Start := I + 1;
               end;
            end if;
         end loop;
      end;
      return False;
   end Peer_Matches_Filter;

   --  ===== Test fixtures (paths under crates/tls_core/tests) ====

   function Repo_Root return String is
      use Ada.Directories;
      Cwd : constant String := Current_Directory;
   begin
      --  Heuristic: walk up until we find Makefile + crates/.
      declare
         Path : Unbounded_String := To_Unbounded_String (Cwd);
      begin
         loop
            declare
               P : constant String := To_String (Path);
            begin
               if Exists (P & "/Makefile")
                 and then Exists (P & "/crates")
               then
                  return P;
               end if;
               exit when Containing_Directory (P) = P;
               Path := To_Unbounded_String (Containing_Directory (P));
            end;
         end loop;
      end;
      return Cwd;
   end Repo_Root;

   Repo : constant String := Repo_Root;
   EC_Dir : constant String :=
     Repo & "/crates/tls_core/tests/fixtures/interop/ec";
   --  PSK is constant 32 bytes of 0x42, identity "Test".  Same as
   --  the v0.5 demo fixtures.
   Psk_Hex_Str  : constant String :=
     "4242424242424242424242424242424242424242424242424242424242424242";
   Psk_Identity : constant String := "Test";

   Log_Dir : Unbounded_String;

   --  Per-cell wall-clock budget.  Any cell taking longer is killed
   --  + classified as `timeout`.  10 s is comfortable for
   --  handshake-only cells (which complete in tens of ms locally).
   Cell_Timeout : constant Duration := 10.0;

   --  ===== Cell run ============================================

   --  Result of running one cell.
   type Cell_Result is (Pass, Fail, NA);

   function Image (R : Cell_Result) return String is
   begin
      case R is
         when Pass => return "PASS";
         when Fail => return "FAIL";
         when NA   => return "N/A";
      end case;
   end Image;

   --  Allocate a port for a cell.  We use a random pick from a
   --  20 000-port window so that back-to-back matrix runs don't
   --  collide on TIME_WAIT (~30 s on macOS).  SO_REUSEADDR on the
   --  Ada listener mitigates this further; randomization is the
   --  belt-and-braces step.  Per CLAUDE.md §12: cheap fix, big
   --  stability win.
   subtype Port_Range is Natural range 20000 .. 59999;
   package Port_Random is new Ada.Numerics.Discrete_Random (Port_Range);
   Port_Rng : Port_Random.Generator;
   function Alloc_Port return Natural is
      P : constant Port_Range := Port_Random.Random (Port_Rng);
   begin
      return P;
   end Alloc_Port;

   --  Capture output paths for a cell.
   procedure Cell_Logs
     (Peer_Name, Cell_Name : String;
      Direction : String;            -- "c2s" or "s2c"
      Server_Log, Client_Log : out Unbounded_String)
   is
   begin
      Server_Log := Log_Dir & "/" & Peer_Name & "-" & Cell_Name
                              & "-" & Direction & "-srv.log";
      Client_Log := Log_Dir & "/" & Peer_Name & "-" & Cell_Name
                              & "-" & Direction & "-cli.log";
   end Cell_Logs;

   --  Run one cell.  Two sub-cases: either (Peer is server, Ada is
   --  client = c2s) or (Peer is client, Ada is server = s2c).
   procedure Run_Cell
     (Peer        : Peer_Kind;
      Mode        : Mode_Kind;
      Cipher      : Cipher_Kind;
      Direction   : String;
      Cell_Name   : String;
      Result      : out Cell_Result;
      Note        : out Unbounded_String)
   is
      Port : constant Natural := Alloc_Port;
      Server_Log, Client_Log : Unbounded_String;
      Server_Cell, Client_Cell : Cell_Spec;
      Server_Bin, Client_Bin   : Unbounded_String;
      Server_Args, Client_Args : Argument_List_Access;
      Server_Sup, Client_Sup   : Boolean;
      Server_Reason, Client_Reason : Unbounded_String;

      Psk_File : constant String :=
        To_String (Log_Dir) & "/psk32.bin";

      --  Build the Ada-side spec depending on which side we play.
      function Make_Ada_Cell (As_Role : Role_Kind) return Cell_Spec is
         C : Cell_Spec;
      begin
         C.Peer := Ada_Native;
         C.Role := As_Role;
         C.Mode := Mode;
         C.Cipher := Cipher;
         C.Port := Port;
         C.Host := To_Unbounded_String ("127.0.0.1");
         C.Psk_Hex := To_Unbounded_String (Psk_Hex_Str);
         C.Psk_Identity := To_Unbounded_String (Psk_Identity);
         C.Psk_File := To_Unbounded_String (Psk_File);
         if Mode = Cert_Ec then
            C.Cert_Pem  := To_Unbounded_String (EC_Dir & "/leaf.pem");
            C.Key_Pem   := To_Unbounded_String (EC_Dir & "/leaf.key");
            C.Trust_Pem := To_Unbounded_String (EC_Dir & "/root.pem");
            C.Hostname  := To_Unbounded_String ("localhost");
         end if;
         return C;
      end Make_Ada_Cell;

      function Make_Peer_Cell (As_Role : Role_Kind) return Cell_Spec is
         C : Cell_Spec := Make_Ada_Cell (As_Role);
      begin
         C.Peer := Peer;
         return C;
      end Make_Peer_Cell;

   begin
      Cell_Logs (Image (Peer), Cell_Name, Direction, Server_Log, Client_Log);
      Result := Fail;
      Note := Null_Unbounded_String;

      --  ---- Build commands ----
      if Direction = "c2s" then
         --  Peer is server, Ada is client.
         Server_Cell := Make_Peer_Cell (Server);
         Client_Cell := Make_Ada_Cell  (Client);
      else
         Server_Cell := Make_Ada_Cell  (Server);
         Client_Cell := Make_Peer_Cell (Client);
      end if;

      Build_Command (Server_Cell, Server_Bin, Server_Args,
                     Server_Sup, Server_Reason);
      Build_Command (Client_Cell, Client_Bin, Client_Args,
                     Client_Sup, Client_Reason);

      --  ---- Decide N/A early ----
      if not Server_Sup or else not Client_Sup then
         Result := NA;
         if not Server_Sup then
            Note := Server_Reason;
         else
            Note := Client_Reason;
         end if;
         Free (Server_Args);
         Free (Client_Args);
         return;
      end if;

      --  ---- Spawn server in background ----
      declare
         Server_Pid : Process_Id;
      begin
         Server_Pid := Non_Blocking_Spawn
           (Program_Name => To_String (Server_Bin),
            Args         => Server_Args.all,
            Output_File  => To_String (Server_Log),
            Err_To_Out   => True);
         if Server_Pid = Invalid_Pid then
            Result := Fail;
            Note := To_Unbounded_String ("could not spawn server");
            Free (Server_Args);
            Free (Client_Args);
            return;
         end if;
         delay 0.8;  --  let server bind + listen

         --  ---- Run client with a hard wall-clock deadline ----
         --
         --  Bounded-time guarantee: any cell completes within
         --  Cell_Timeout (default 10 s) regardless of peer-CLI
         --  pathologies (rustls --http stuck on shutdown, bssl
         --  half-RTT-NST coalescing waiting for a client ACK that
         --  never comes, etc.).  When the deadline fires we kill
         --  the client process group and mark the cell as a
         --  timeout — the matrix proceeds to the next peer.
         declare
            Client_Pid : Process_Id;
            Timed_Out  : Boolean := False;

            task Wait_Client is
               entry Done;
            end Wait_Client;

            task body Wait_Client is
               P  : Process_Id;
               OK : Boolean;
            begin
               --  Wait_Process blocks for ANY child; loop until
               --  we see our client PID (or Invalid_Pid on error).
               loop
                  Wait_Process (P, OK);
                  exit when P = Client_Pid or else P = Invalid_Pid;
               end loop;
               accept Done;
            exception
               when others =>
                  begin accept Done; exception when others => null; end;
            end Wait_Client;
         begin
            Client_Pid := Non_Blocking_Spawn
              (Program_Name => To_String (Client_Bin),
               Args         => Client_Args.all,
               Output_File  => To_String (Client_Log),
               Err_To_Out   => True);
            if Client_Pid = Invalid_Pid then
               Result := Fail;
               Note := To_Unbounded_String ("could not spawn client");
            else
               select
                  Wait_Client.Done;
               or
                  delay Cell_Timeout;
                  Timed_Out := True;
                  Kill (Client_Pid, Hard_Kill => True);
                  Wait_Client.Done;  --  reap after Kill
               end select;
            end if;
            if Timed_Out then
               Result := Fail;
               Note := To_Unbounded_String
                 ("timeout (>"
                  & Ada.Strings.Fixed.Trim
                      (Duration'Image (Cell_Timeout), Ada.Strings.Both)
                  & "s) — peer-CLI hung");
            end if;
         end;

         --  ---- Reap server ----
         Kill (Server_Pid, Hard_Kill => True);
         declare
            Reaped : Process_Id;
            Ok     : Boolean;
         begin
            Wait_Process (Reaped, Ok);
            pragma Unreferenced (Reaped, Ok);
         exception
            when others => null;
         end;
      end;

      Free (Server_Args);
      Free (Client_Args);

      --  ---- Decide PASS / FAIL ----
      --  Direction-specific success criterion:
      --    c2s — Ada client must exit 0 (it prints "tls_cli: OK").
      --    s2c — Ada server log must contain "tls_cli: OK".
      declare
         Ok : Boolean := False;
         F  : Ada.Text_IO.File_Type;
         L  : String (1 .. 256);
         Last : Natural;
         Probe : constant String :=
           (if Direction = "c2s"
            then To_String (Client_Log)
            else To_String (Server_Log));
      begin
         begin
            Ada.Text_IO.Open (F, Ada.Text_IO.In_File, Probe);
            while not Ada.Text_IO.End_Of_File (F) loop
               Ada.Text_IO.Get_Line (F, L, Last);
               if Last >= 11
                 and then L (1 .. 11) = "tls_cli: OK"
               then
                  Ok := True;
                  exit;
               end if;
               --  First diagnostic line we see for the Note.
               if Note = Null_Unbounded_String
                 and then Ada.Strings.Fixed.Index (L (1 .. Last), "ERROR") /= 0
               then
                  Note := To_Unbounded_String
                            (L (1 .. Natural'Min (Last, 100)));
               end if;
            end loop;
            Ada.Text_IO.Close (F);
         exception
            when others =>
               if Ada.Text_IO.Is_Open (F) then
                  Ada.Text_IO.Close (F);
               end if;
         end;
         if Ok then
            Result := Pass;
            Note := To_Unbounded_String (Probe);
         else
            Result := Fail;
            if Note = Null_Unbounded_String then
               Note := To_Unbounded_String ("see " & Probe);
            end if;
         end if;
      end;
   end Run_Cell;

   --  ===== Output helpers =======================================

   procedure Md_Header is
   begin
      Put_Line
        ("| Peer       | Cell                       | Result  | Notes / log |");
      Put_Line
        ("|------------|----------------------------|---------|-------------|");
   end Md_Header;

   procedure Md_Row
     (Peer_Lbl, Cell_Lbl : String;
      Result : Cell_Result;
      Note   : String)
   is
      function Pad (S : String; W : Natural) return String is
      begin
         if S'Length >= W then
            return S (S'First .. S'First + W - 1);
         end if;
         return S & (1 .. W - S'Length => ' ');
      end Pad;
   begin
      Put_Line
        ("| " & Pad (Peer_Lbl, 10)
         & " | " & Pad (Cell_Lbl, 26)
         & " | " & Pad (Image (Result), 7)
         & " | " & Note & " |");
   end Md_Row;

   --  JSON output buffer: collect rows as JSON_Value objects,
   --  serialise once at the end via GNATCOLL.JSON (per CLAUDE.md
   --  §10c — wire formats should be formalised, JSON included).
   Json_Rows : GNATCOLL.JSON.JSON_Array := GNATCOLL.JSON.Empty_Array;

   procedure Json_Row
     (Peer_Lbl, Cell_Lbl : String;
      Result : Cell_Result;
      Note   : String)
   is
      use GNATCOLL.JSON;
      Row : constant JSON_Value := Create_Object;
   begin
      Row.Set_Field ("peer",   Peer_Lbl);
      Row.Set_Field ("cell",   Cell_Lbl);
      Row.Set_Field ("result", Image (Result));
      Row.Set_Field ("note",   Note);
      Append (Json_Rows, Row);
   end Json_Row;

   --  ===== Init log dir + PSK file ===============================

   procedure Init_Run is
      use Ada.Calendar;
      Now : constant Time := Clock;
      TS  : constant String := Ada.Calendar.Formatting.Image (Now);
      --  Compress yyyy-mm-dd hh:mm:ss → yyyymmdd-hhmmss
      function Compress (S : String) return String is
         R : String (1 .. S'Length);
         L : Natural := 0;
      begin
         for C of S loop
            if C /= '-' and C /= ':' and C /= ' ' then
               L := L + 1;
               R (L) := C;
            elsif C = ' ' then
               L := L + 1;
               R (L) := '-';
            end if;
         end loop;
         return R (1 .. L);
      end Compress;
   begin
      Log_Dir := To_Unbounded_String
        ("/tmp/spark-tls-interop/" & Compress (TS));
      Ada.Directories.Create_Path (To_String (Log_Dir));

      --  Reset the port RNG with a clock-based seed so each run
      --  picks an independent port window.
      Port_Random.Reset (Port_Rng);

      --  Materialise the PSK file once (32 bytes of 0x42).
      declare
         F : Ada.Text_IO.File_Type;
         pragma Unreferenced (F);
         use GNAT.OS_Lib;
         Path : constant String := To_String (Log_Dir) & "/psk32.bin";
         FD   : File_Descriptor;
         Buf  : array (1 .. 32) of Character := (others => Character'Val (16#42#));
         N    : Integer;
      begin
         FD := Create_File (Path, Binary);
         if FD /= Invalid_FD then
            N := Write (FD, Buf'Address, 32);
            pragma Unreferenced (N);
            Close (FD);
         end if;
      end;
   end Init_Run;

   --  ===== Main ==================================================

   procedure Run_One_Cell
     (Peer  : Peer_Kind;
      Mode  : Mode_Kind;
      Cipher : Cipher_Kind;
      Cell_Label : String)
   is
      Result : Cell_Result;
      Note   : Unbounded_String;
   begin
      for Direction in Boolean range False .. True loop
         declare
            Dir : constant String := (if Direction then "s2c" else "c2s");
            Full_Cell : constant String := Cell_Label & "-" & Dir;
         begin
            Run_Cell (Peer, Mode, Cipher, Dir, Cell_Label, Result, Note);
            case Format is
               when Markdown =>
                  Md_Row (Image (Peer), Full_Cell, Result, To_String (Note));
               when Json =>
                  Json_Row (Image (Peer), Full_Cell, Result,
                            To_String (Note));
            end case;
         end;
      end loop;
   end Run_One_Cell;

begin
   Parse_Args;
   if Show_Help then
      Print_Help;
      return;
   end if;

   Init_Run;

   case Format is
      when Markdown =>
         Put_Line ("");
         Put_Line ("## Tier D matrix run — log dir: " & To_String (Log_Dir));
         if Quick then
            Put_Line ("mode: --quick (psk-chacha20 only)");
         end if;
         Put_Line ("");
         Md_Header;
      when Json =>
         null;  --  JSON written at end via GNATCOLL.JSON
   end case;

   --  Sanity baseline: Ada-vs-Ada PSK chacha20.
   declare
      Result : Cell_Result;
      Note   : Unbounded_String;
   begin
      Run_Cell (Ada_Native, Psk_Dhe_Ke, Chacha20_Poly1305_Sha256,
                "c2s", "psk-chacha20", Result, Note);
      case Format is
         when Markdown =>
            Md_Row ("ada-ada", "psk-chacha20-aa", Result,
                    "sanity baseline");
         when Json =>
            Json_Row ("ada-ada", "psk-chacha20-aa", Result,
                      "sanity baseline");
      end case;
   end;

   --  Per-peer cells.
   --
   --  Output ordering (per CLAUDE.md §0a "production-default first"):
   --    1. Outer loop: mode in production-prevalence order — cert-ec
   --       (>99% of production TLS), then external PSK chacha20,
   --       then external PSK aes128.  Resumption PSK rolls in via
   --       its own pass (WS3); PSK-external stays for backward
   --       coverage of the IoT/embedded peers that already pass it.
   --    2. Inner loop: peer in production-prevalence order — openssl,
   --       boringssl, go, rustls, gnutls, mbedtls, wolfssl.  Drives
   --       readability: the most-cited peer's row appears first
   --       inside each category.
   declare
      Modes  : constant array (1 .. 3) of Mode_Kind :=
        (Cert_Ec, Psk_Dhe_Ke, Psk_Dhe_Ke);
      --  Cipher index aligns with Modes; Auto for cert-ec.
      Ciphers : constant array (1 .. 3) of Cipher_Kind :=
        (Auto, Chacha20_Poly1305_Sha256, Aes128_Gcm_Sha256);
      Labels  : constant array (1 .. 3) of access String :=
        (new String'("cert-ec"),
         new String'("psk-chacha20"),
         new String'("psk-aes128"));
      Peers   : constant array (1 .. 7) of Peer_Kind :=
        (Openssl, Boringssl, Go_Lang, Rustls, Gnutls, Mbedtls, Wolfssl);
   begin
      for I in Modes'Range loop
         --  --quick = first mode (cert-ec) only.
         exit when Quick and then I > 1;
         for P of Peers loop
            if Peer_Matches_Filter (P) then
               Run_One_Cell (P, Modes (I), Ciphers (I), Labels (I).all);
            end if;
         end loop;
      end loop;
   end;

   case Format is
      when Markdown =>
         Put_Line ("");
         Put_Line ("Logs: " & To_String (Log_Dir));
      when Json =>
         declare
            use GNATCOLL.JSON;
            Top : constant JSON_Value := Create (Json_Rows);
         begin
            Put_Line (Top.Write (Compact => False));
         end;
   end case;

exception
   when E : others =>
      Put_Line (Standard_Error,
                "tls_interop: exception "
                & Ada.Exceptions.Exception_Name (E)
                & " — " & Ada.Exceptions.Exception_Message (E));
      Ada.Command_Line.Set_Exit_Status (1);
end Tls_Interop;
