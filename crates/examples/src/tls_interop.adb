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

   --  Cell outcome — four buckets per the v0.5 reporting format:
   --    PASS           — both sides have it; ran green
   --    FAIL           — both sides have it; ran but produced wrong
   --                     result (deviation we can fix)
   --    NOT_IMPL_ADA   — peer has it; Ada driver doesn't yet.  Note
   --                     field carries a v0.5-not-impl.md anchor.
   --    NOT_IMPL_3P    — Ada has it; peer's CLI doesn't expose it
   --                     (or peer lib doesn't have it at all)
   type Cell_Result is (Pass, Fail, Xfail_Ada, Not_Impl_3P);

   function Image (R : Cell_Result) return String is
   begin
      case R is
         when Pass       => return "PASS";
         when Fail       => return "FAIL";
         when Xfail_Ada  => return "XFAIL";
         when Not_Impl_3P => return "NOT_IMPL_3P";
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
      Note        : out Unbounded_String;
      Elapsed     : out Duration)
   is
      Port : constant Natural := Alloc_Port;
      use Ada.Calendar;
      Cell_Start : constant Time := Clock;
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
      Elapsed := 0.0;

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

      --  ---- Decide NOT_IMPL_3P early ----
      --  Build_Command's Supported = False means peer's CLI / lib
      --  doesn't expose this feature.  (Distinct from NOT_IMPL_ADA,
      --  which the orchestrator decides upstream from
      --  Tls_Interop_Peers.Ada_Supports.)
      if not Server_Sup or else not Client_Sup then
         Result := Not_Impl_3P;
         if not Server_Sup then
            Note := Server_Reason;
         else
            Note := Client_Reason;
         end if;
         Free (Server_Args);
         Free (Client_Args);
         Elapsed := 0.0;
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
            Elapsed := 0.0;
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
      Elapsed := Clock - Cell_Start;
   end Run_Cell;

   --  ===== Output helpers =======================================

   --  Pretty-print a Duration as "1.234 s" with millisecond
   --  precision, padded to 8 chars wide.
   function Image_Time (D : Duration) return String is
      Ms : constant Integer := Integer (D * 1000.0);
      function Pad (S : String) return String is
      begin
         if S'Length >= 8 then return S (S'First .. S'First + 7); end if;
         return (1 .. 8 - S'Length => ' ') & S;
      end Pad;
   begin
      if Ms = 0 then
         return "       -";
      end if;
      declare
         Whole : constant Integer := Ms / 1000;
         Frac  : constant Integer := Ms mod 1000;
         W_Img : constant String := Ada.Strings.Fixed.Trim
                   (Integer'Image (Whole), Ada.Strings.Both);
         F_Img : constant String := (if Frac < 10 then "00"
                                     elsif Frac < 100 then "0" else "")
                   & Ada.Strings.Fixed.Trim
                       (Integer'Image (Frac), Ada.Strings.Both);
      begin
         return Pad (W_Img & "." & F_Img & " s");
      end;
   end Image_Time;

   procedure Md_Peer_Header (Peer : Peer_Kind) is
   begin
      Put_Line ("");
      Put_Line ("### " & Image (Peer));
      Put_Line ("");
      Put_Line
        ("| Feature                       | c2s            | s2c            | Notes |");
      Put_Line
        ("|-------------------------------|----------------|----------------|-------|");
   end Md_Peer_Header;

   --  One row in a per-peer table covers BOTH directions (c2s + s2c).
   procedure Md_Feature_Row
     (Feature_Lbl : String;
      C2S_Result, S2C_Result : Cell_Result;
      C2S_Time,   S2C_Time   : Duration;
      Note : String)
   is
      function Pad (S : String; W : Natural) return String is
      begin
         if S'Length >= W then
            return S (S'First .. S'First + W - 1);
         end if;
         return S & (1 .. W - S'Length => ' ');
      end Pad;
      function Cell (R : Cell_Result; T : Duration) return String is
        ((case R is
            when Pass       => "PASS",
            when Fail       => "FAIL",
            when Xfail_Ada  => "XFAIL",
            when Not_Impl_3P => "NI-3P")
         & " "
         & (if R in Pass | Fail | Xfail_Ada
            then Image_Time (T) else "       -"));
   begin
      Put_Line
        ("| " & Pad (Feature_Lbl, 29)
         & " | " & Pad (Cell (C2S_Result, C2S_Time), 14)
         & " | " & Pad (Cell (S2C_Result, S2C_Time), 14)
         & " | " & Note & " |");
   end Md_Feature_Row;

   --  JSON output: array of {peer, feature, c2s:{result,time,note}, s2c:{...}}.
   Json_Rows : GNATCOLL.JSON.JSON_Array := GNATCOLL.JSON.Empty_Array;

   procedure Json_Peer_Feature
     (Peer : Peer_Kind;
      Feat : Feature_Kind;
      C2S_Result, S2C_Result : Cell_Result;
      C2S_Time,   S2C_Time   : Duration;
      Note : String)
   is
      use GNATCOLL.JSON;
      Row : constant JSON_Value := Create_Object;
      function Make_Side
        (R : Cell_Result; T : Duration) return JSON_Value
      is
         V : constant JSON_Value := Create_Object;
      begin
         V.Set_Field ("result", Image (R));
         V.Set_Field ("time_ms", Integer (T * 1000.0));
         return V;
      end Make_Side;
   begin
      Row.Set_Field ("peer",    Image (Peer));
      Row.Set_Field ("feature", Image (Feat));
      Row.Set_Field ("c2s",     Make_Side (C2S_Result, C2S_Time));
      Row.Set_Field ("s2c",     Make_Side (S2C_Result, S2C_Time));
      Row.Set_Field ("note",    Note);
      Append (Json_Rows, Row);
   end Json_Peer_Feature;

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

   --  Map a Feature_Kind to (Mode_Kind, Cipher_Kind) suitable for
   --  Build_Command.  Some features run additional setup (e.g.,
   --  resumption-PSK chains a cert-mode handshake first); for v0.5
   --  this matrix records the inner-handshake cell only — the
   --  chained variant is exercised separately via tls_cli flags.
   procedure Feature_To_Cell
     (F : Feature_Kind;
      M : out Mode_Kind;
      C : out Cipher_Kind)
   is
   begin
      case F is
         when Cert_Ecdsa_P256_Sha256 =>
            M := Cert_Ec; C := Auto;
         when Cert_Rsa_Pss_Sha256 =>
            M := Cert_Rsa; C := Auto;
         when Psk_External_Chacha20 =>
            M := Psk_Dhe_Ke; C := Chacha20_Poly1305_Sha256;
         when Psk_External_Aes128 =>
            M := Psk_Dhe_Ke; C := Aes128_Gcm_Sha256;
         when Psk_External_Aes256 =>
            M := Psk_Dhe_Ke; C := Aes256_Gcm_Sha384;
         when Psk_Resumption =>
            --  Resumption is handled as a two-phase special case
            --  in Run_Peer_Feature; this branch is not reached.
            M := Cert_Ec; C := Auto;
         when Hello_Retry_Request =>
            M := Cert_Ec; C := Auto;
         when Sni_Alpn =>
            M := Cert_Ec; C := Auto;
         when Zero_Rtt =>
            M := Cert_Ec; C := Auto;
         when Key_Update =>
            M := Cert_Ec; C := Auto;
      end case;
   end Feature_To_Cell;

   --  Run the (peer, feature) entry — iterates both directions.
   --  Returns the row-summary directly through the output sink
   --  for the current --format.
   procedure Run_Peer_Feature
     (Peer : Peer_Kind;
      Feat : Feature_Kind)
   is
      M : Mode_Kind;
      C : Cipher_Kind;
      C2S_Result, S2C_Result : Cell_Result;
      C2S_Note,   S2C_Note   : Unbounded_String;
      C2S_Time,   S2C_Time   : Duration := 0.0;
      Note : Unbounded_String;
   begin
      --  XFAIL short-circuit: Ada driver doesn't support this
      --  feature yet, and the test can't meaningfully run (e.g.
      --  0-RTT requires early-data CLI plumbing that doesn't exist).
      --  We still report it as XFAIL so it's visible in the matrix.
      if not Ada_Supports (Feat) and then not Ada_Can_Attempt (Feat) then
         C2S_Result := Xfail_Ada;
         S2C_Result := Xfail_Ada;
         Note := To_Unbounded_String
           ("XFAIL: see " & Ada_Unblock_Link (Feat));
      --  NOT_IMPL_3P short-circuit: peer's CLI / lib doesn't
      --  expose this feature.
      elsif not Peer_Supports (Peer, Feat) then
         C2S_Result := Not_Impl_3P;
         S2C_Result := Not_Impl_3P;
         Note := To_Unbounded_String ("peer-CLI gap");
      elsif Feat = Psk_Resumption then
         --  Two-phase cell: cert-ec → save ticket → psk-resume
         --  with ticket, against the same peer server. Delegates
         --  to scripts/test-psk-resumption.sh <peer>.
         --  c2s only; s2c (Ada server accepting external
         --  resumption) is not yet wired.
         S2C_Result := Xfail_Ada;
         S2C_Note   := To_Unbounded_String
           ("Ada server resumption-accept not wired");
         declare
            use Ada.Calendar;
            T0 : constant Time := Clock;
            Script : GNAT.OS_Lib.String_Access :=
              Locate_Exec_On_Path ("bash");
            Script_Path : constant String :=
              Repo & "/scripts/test-psk-resumption.sh";
            Peer_Str : constant String := Image (Peer);
            Log_File : constant String :=
              To_String (Log_Dir) & "/" & Peer_Str
              & "-psk-resumption-c2s.log";
            Args : Argument_List_Access :=
              new Argument_List'
                (new String'(Script_Path),
                 new String'(Peer_Str));
            Ret : Boolean;
            Pid : Process_Id;
         begin
            if Script = null then
               C2S_Result := Fail;
               C2S_Note := To_Unbounded_String ("bash not found");
            else
               Pid := Non_Blocking_Spawn
                 (Program_Name => Script.all,
                  Args         => Args.all,
                  Output_File  => Log_File,
                  Err_To_Out   => True);
               Free (Script);
               if Pid = Invalid_Pid then
                  C2S_Result := Fail;
                  C2S_Note := To_Unbounded_String
                    ("could not spawn resumption script");
               else
                  declare
                     Reaped : Process_Id;
                     Ok     : Boolean;
                  begin
                     loop
                        Wait_Process (Reaped, Ok);
                        exit when Reaped = Pid
                          or else Reaped = Invalid_Pid;
                     end loop;
                  end;
                  declare
                     F  : Ada.Text_IO.File_Type;
                     L  : String (1 .. 256);
                     Last : Natural;
                     Found_Pass : Boolean := False;
                     Found_Skip : Boolean := False;
                  begin
                     Ada.Text_IO.Open
                       (F, Ada.Text_IO.In_File, Log_File);
                     while not Ada.Text_IO.End_Of_File (F) loop
                        Ada.Text_IO.Get_Line (F, L, Last);
                        if Last >= 4
                          and then L (1 .. 4) = "=== "
                          and then Ada.Strings.Fixed.Index
                                    (L (1 .. Last), "PASS") /= 0
                        then
                           Found_Pass := True;
                        end if;
                        if Last >= 5
                          and then L (1 .. 5) = "SKIP:"
                        then
                           Found_Skip := True;
                        end if;
                     end loop;
                     Ada.Text_IO.Close (F);
                     if Found_Pass then
                        C2S_Result := Pass;
                        C2S_Note := To_Unbounded_String (Log_File);
                     elsif Found_Skip then
                        C2S_Result := Not_Impl_3P;
                        C2S_Note := To_Unbounded_String
                          ("peer-CLI gap (resumption c2s)");
                     else
                        C2S_Result := Fail;
                        C2S_Note := To_Unbounded_String
                          ("see " & Log_File);
                     end if;
                  exception
                     when others =>
                        C2S_Result := Fail;
                        C2S_Note := To_Unbounded_String
                          ("see " & Log_File);
                  end;
               end if;
            end if;
            Free (Args);
            C2S_Time := Clock - T0;
         end;
         Note := (if C2S_Result = Pass
                  then To_Unbounded_String (To_String (Log_Dir))
                  else C2S_Note);
      else
         Feature_To_Cell (Feat, M, C);
         Run_Cell (Peer, M, C, "c2s", Image (Feat),
                   C2S_Result, C2S_Note, C2S_Time);
         Run_Cell (Peer, M, C, "s2c", Image (Feat),
                   S2C_Result, S2C_Note, S2C_Time);
         --  Compose a single short note.  Prefer FAIL note over
         --  PASS log path; if both PASS, point at log dir only.
         if C2S_Result = Fail or else S2C_Result = Fail then
            Note := (if C2S_Result = Fail then C2S_Note else S2C_Note);
         elsif C2S_Result = Pass and then S2C_Result = Pass then
            Note := To_Unbounded_String (To_String (Log_Dir));
         else
            Note := (if C2S_Note /= Null_Unbounded_String
                     then C2S_Note else S2C_Note);
         end if;
      end if;

      --  Reclassify: if a feature is known-unimplemented in Ada and
      --  the test failed, mark as XFAIL with the reason annotation.
      if not Ada_Supports (Feat) then
         declare
            Link : constant String := Ada_Unblock_Link (Feat);
            Ann  : constant Unbounded_String :=
              To_Unbounded_String
                ((if Link'Length > 0 then "XFAIL: see " & Link
                  else "XFAIL: Ada driver gap"));
         begin
            if C2S_Result = Fail then
               C2S_Result := Xfail_Ada;
               Note := Ann;
            end if;
            if S2C_Result = Fail then
               S2C_Result := Xfail_Ada;
               Note := Ann;
            end if;
         end;
      end if;
      case Format is
         when Markdown =>
            Md_Feature_Row (Image (Feat),
                            C2S_Result, S2C_Result,
                            C2S_Time, S2C_Time,
                            To_String (Note));
         when Json =>
            Json_Peer_Feature (Peer, Feat,
                               C2S_Result, S2C_Result,
                               C2S_Time, S2C_Time,
                               To_String (Note));
      end case;
   end Run_Peer_Feature;

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
         Put_Line ("# v0.5 Tier D interop matrix");
         Put_Line ("");
         Put_Line ("Log directory: `" & To_String (Log_Dir) & "`");
         Put_Line ("");
         Put_Line ("Result classes: PASS, FAIL (Ada bug), "
                   & "XFAIL (expected fail, Ada gap), NI-3P (peer-CLI gap)");
         Put_Line ("");
         if Quick then
            Put_Line ("Mode: `--quick` (cert-ecdsa-p256-sha256 only)");
            Put_Line ("");
         end if;
      when Json =>
         null;  --  JSON written at end via GNATCOLL.JSON
   end case;

   --  Per-peer iteration — peers ordered by production prevalence.
   declare
      Peers : constant array (1 .. 7) of Peer_Kind :=
        (Openssl, Boringssl, Go_Lang, Rustls, Gnutls, Mbedtls, Wolfssl);
   begin
      for P of Peers loop
         exit when not Peer_Matches_Filter (P);
         if Peer_Matches_Filter (P) then
            if Format = Markdown then
               Md_Peer_Header (P);
            end if;
            for F in Feature_Kind'Range loop
               --  --quick = first feature only (cert-ec).
               exit when Quick and then F > Cert_Ecdsa_P256_Sha256;
               Run_Peer_Feature (P, F);
            end loop;
         end if;
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
