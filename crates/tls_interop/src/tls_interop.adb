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
with Tls_Interop_Bench;
with Tls_Interop_Output;
with Tls_Interop_Peers;      use Tls_Interop_Peers;

procedure Tls_Interop is

   use Ada.Text_IO;

   type Format_Kind is (Markdown, Json);

   Format       : Format_Kind := Markdown;
   Quick        : Boolean := False;
   Bench        : Boolean := False;
   Bench_Runs   : Positive := 5;
   Bench_Bytes  : Natural := 1_048_576;
   Peers_Filter : Unbounded_String := Null_Unbounded_String;
   Show_Help    : Boolean := False;

   procedure Print_Help is
   begin
      Put_Line ("tls_interop — Tier D multi-peer interop matrix");
      Put_Line ("");
      Put_Line ("Usage:");
      Put_Line ("  tls_interop [--peer NAME[,NAME...]] [--quick]");
      Put_Line ("             [--format md|json] [--help]");
      Put_Line ("");
      Put_Line ("Peers: openssl gnutls mbedtls rustls go boringssl");
   end Print_Help;

   procedure Parse_Args is
      A : Natural := 1;
   begin
      while A <= Ada.Command_Line.Argument_Count loop
         declare
            Arg : constant String := Ada.Command_Line.Argument (A);
         begin
            if Arg = "--help" or else Arg = "-h" then
               Show_Help := True; return;
            elsif Arg = "--quick" then
               Quick := True;
            elsif Arg = "--bench" then
               Bench := True;
            elsif Arg = "--bench-runs" then
               A := A + 1;
               Bench_Runs :=
                 Positive'Value (Ada.Command_Line.Argument (A));
            elsif Arg = "--bench-bytes" then
               A := A + 1;
               Bench_Bytes :=
                 Natural'Value (Ada.Command_Line.Argument (A));
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
                     Show_Help := True; return;
                  end if;
               end;
            else
               Put_Line ("tls_interop: unknown arg: " & Arg);
               Ada.Command_Line.Set_Exit_Status (2);
               Show_Help := True; return;
            end if;
         end;
         A := A + 1;
      end loop;
   end Parse_Args;

   function Peer_Matches_Filter (P : Peer_Kind) return Boolean is
      F : constant String := To_String (Peers_Filter);
   begin
      if F = "" then return True; end if;
      declare
         Name : constant String := Image (P);
         Tok_Start : Positive := 1;
      begin
         for I in F'Range loop
            if F (I) = ',' or else I = F'Last then
               declare
                  Tok_End : constant Natural :=
                    (if F (I) = ',' then I - 1 else I);
               begin
                  if F (Tok_Start .. Tok_End) = Name then
                     return True;
                  end if;
                  Tok_Start := I + 1;
               end;
            end if;
         end loop;
      end;
      return False;
   end Peer_Matches_Filter;

   function Repo_Root return String is
      use Ada.Directories;
      Path : Unbounded_String :=
        To_Unbounded_String (Current_Directory);
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
      return Ada.Directories.Current_Directory;
   end Repo_Root;

   Repo : constant String := Repo_Root;
   EC_Dir : constant String :=
     Repo & "/crates/tls_core/tests/fixtures/interop/ec";
   Psk_Hex_Str  : constant String :=
     "4242424242424242424242424242424242424242424242424242424242424242";
   Psk_Identity : constant String := "Test";

   Log_Dir : Unbounded_String;

   Cell_Timeout : constant Duration := 10.0;

   subtype Port_Range is Natural range 20000 .. 59999;
   package Port_Random is new Ada.Numerics.Discrete_Random (Port_Range);
   Port_Rng : Port_Random.Generator;

   function Alloc_Port return Natural is
   begin
      return Port_Random.Random (Port_Rng);
   end Alloc_Port;

   procedure Cell_Logs
     (Peer_Name, Cell_Name, Direction : String;
      Server_Log, Client_Log : out Unbounded_String)
   is
   begin
      Server_Log := Log_Dir & "/" & Peer_Name & "-" & Cell_Name
                              & "-" & Direction & "-srv.log";
      Client_Log := Log_Dir & "/" & Peer_Name & "-" & Cell_Name
                              & "-" & Direction & "-cli.log";
   end Cell_Logs;

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

      function Make_Ada_Cell (As_Role : Role_Kind) return Cell_Spec is
         C : Cell_Spec;
      begin
         C.Peer := Ada_Native; C.Role := As_Role;
         C.Mode := Mode; C.Cipher := Cipher;
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
      Cell_Logs (Image (Peer), Cell_Name, Direction,
                 Server_Log, Client_Log);
      Result := Fail; Note := Null_Unbounded_String; Elapsed := 0.0;

      if Direction = "c2s" then
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

      if not Server_Sup or else not Client_Sup then
         Result := Not_Impl_3P;
         Note := (if not Server_Sup then Server_Reason
                  else Client_Reason);
         Free (Server_Args); Free (Client_Args);
         return;
      end if;

      declare
         Server_Pid : Process_Id;
      begin
         Server_Pid := Non_Blocking_Spawn
           (To_String (Server_Bin), Server_Args.all,
            To_String (Server_Log), True);
         if Server_Pid = Invalid_Pid then
            Result := Fail;
            Note := To_Unbounded_String ("could not spawn server");
            Free (Server_Args); Free (Client_Args);
            return;
         end if;
         delay 0.8;

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
               loop
                  Wait_Process (P, OK);
                  exit when P = Client_Pid or else P = Invalid_Pid;
               end loop;
               accept Done;
            exception
               when others =>
                  begin accept Done;
                  exception when others => null; end;
            end Wait_Client;
         begin
            Client_Pid := Non_Blocking_Spawn
              (To_String (Client_Bin), Client_Args.all,
               To_String (Client_Log), True);
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
                  Wait_Client.Done;
               end select;
            end if;
            if Timed_Out then
               Result := Fail;
               Note := To_Unbounded_String
                 ("timeout (>"
                  & Ada.Strings.Fixed.Trim
                      (Duration'Image (Cell_Timeout),
                       Ada.Strings.Both)
                  & "s)");
            end if;
         end;

         Kill (Server_Pid, Hard_Kill => True);
         declare
            Reaped : Process_Id; Ok : Boolean;
         begin
            Wait_Process (Reaped, Ok);
         exception when others => null;
         end;
      end;
      Free (Server_Args); Free (Client_Args);

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
                  Ok := True; exit;
               end if;
               if Note = Null_Unbounded_String
                 and then Ada.Strings.Fixed.Index
                            (L (1 .. Last), "ERROR") /= 0
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
         elsif Result /= Fail then
            Result := Fail;
            if Note = Null_Unbounded_String then
               Note := To_Unbounded_String ("see " & Probe);
            end if;
         end if;
      end;
      Elapsed := Clock - Cell_Start;
   end Run_Cell;

   procedure Run_Peer_Feature
     (Peer : Peer_Kind; Feat : Feature_Kind)
   is
      M : Mode_Kind;
      C : Cipher_Kind;
      C2S_Result, S2C_Result : Cell_Result;
      C2S_Note,   S2C_Note   : Unbounded_String;
      C2S_Time,   S2C_Time   : Duration := 0.0;
      Note : Unbounded_String;
   begin
      if not Ada_Supports (Feat)
        and then not Ada_Can_Attempt (Feat)
      then
         C2S_Result := Xfail_Ada; S2C_Result := Xfail_Ada;
         Note := To_Unbounded_String
           ("XFAIL: see " & Ada_Unblock_Link (Feat));
      elsif not Peer_Supports (Peer, Feat) then
         C2S_Result := Not_Impl_3P; S2C_Result := Not_Impl_3P;
         Note := To_Unbounded_String ("peer-CLI gap");
      elsif Feat = Psk_Resumption then
         S2C_Result := Xfail_Ada;
         S2C_Note := To_Unbounded_String
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
            Pid : Process_Id;
         begin
            if Script = null then
               C2S_Result := Fail;
               C2S_Note := To_Unbounded_String ("bash not found");
            else
               Pid := Non_Blocking_Spawn
                 (Script.all, Args.all, Log_File, True);
               Free (Script);
               if Pid = Invalid_Pid then
                  C2S_Result := Fail;
                  C2S_Note := To_Unbounded_String
                    ("could not spawn resumption script");
               else
                  declare
                     Reaped : Process_Id; Ok : Boolean;
                  begin
                     loop
                        Wait_Process (Reaped, Ok);
                        exit when Reaped = Pid
                          or else Reaped = Invalid_Pid;
                     end loop;
                  end;
                  declare
                     F : Ada.Text_IO.File_Type;
                     L : String (1 .. 256);
                     Last : Natural;
                     Found_Pass, Found_Skip : Boolean := False;
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
         if C2S_Result = Fail or else S2C_Result = Fail then
            Note := (if C2S_Result = Fail then C2S_Note
                     else S2C_Note);
         elsif C2S_Result = Pass and then S2C_Result = Pass then
            Note := To_Unbounded_String (To_String (Log_Dir));
         else
            Note := (if C2S_Note /= Null_Unbounded_String
                     then C2S_Note else S2C_Note);
         end if;
      end if;

      if not Ada_Supports (Feat) then
         declare
            Link : constant String := Ada_Unblock_Link (Feat);
            Ann  : constant Unbounded_String :=
              To_Unbounded_String
                ((if Link'Length > 0 then "XFAIL: see " & Link
                  else "XFAIL: Ada driver gap"));
         begin
            if C2S_Result = Fail then
               C2S_Result := Xfail_Ada; Note := Ann;
            end if;
            if S2C_Result = Fail then
               S2C_Result := Xfail_Ada; Note := Ann;
            end if;
         end;
      end if;

      case Format is
         when Markdown =>
            Tls_Interop_Output.Md_Feature_Row
              (Image (Feat), C2S_Result, S2C_Result,
               C2S_Time, S2C_Time, To_String (Note));
         when Json =>
            Tls_Interop_Output.Json_Peer_Feature
              (Peer, Feat, C2S_Result, S2C_Result,
               C2S_Time, S2C_Time, To_String (Note));
      end case;
   end Run_Peer_Feature;

   procedure Init_Run is
      use Ada.Calendar;
      TS : constant String :=
        Ada.Calendar.Formatting.Image (Clock);
      function Compress (S : String) return String is
         R : String (1 .. S'Length);
         L : Natural := 0;
      begin
         for C of S loop
            if C /= '-' and C /= ':' and C /= ' ' then
               L := L + 1; R (L) := C;
            elsif C = ' ' then
               L := L + 1; R (L) := '-';
            end if;
         end loop;
         return R (1 .. L);
      end Compress;
   begin
      Log_Dir := To_Unbounded_String
        ("/tmp/spark-tls-interop/" & Compress (TS));
      Ada.Directories.Create_Path (To_String (Log_Dir));
      Port_Random.Reset (Port_Rng);

      declare
         Path : constant String :=
           To_String (Log_Dir) & "/psk32.bin";
         FD : File_Descriptor;
         Buf : array (1 .. 32) of Character :=
           (others => Character'Val (16#42#));
         N : Integer;
      begin
         FD := Create_File (Path, Binary);
         if FD /= Invalid_FD then
            N := Write (FD, Buf'Address, 32);
            pragma Unreferenced (N);
            Close (FD);
         end if;
      end;
   end Init_Run;

   Peers : constant array (1 .. 7) of Peer_Kind :=
     (Openssl, Boringssl, Go_Lang, Rustls,
      Gnutls, Mbedtls, Wolfssl);

begin
   Parse_Args;
   if Show_Help then Print_Help; return; end if;

   Init_Run;

   case Format is
      when Markdown =>
         Put_Line ("");
         Put_Line ("# v0.5 Tier D interop matrix");
         Put_Line ("");
         Put_Line ("Log directory: `" & To_String (Log_Dir) & "`");
         Put_Line ("");
         Put_Line ("Result classes: PASS, FAIL (Ada bug), "
                   & "XFAIL (expected fail, Ada gap), "
                   & "NI-3P (peer-CLI gap)");
         Put_Line ("");
         if Quick then
            Put_Line ("Mode: `--quick` "
                      & "(cert-ec across all 3 AEAD ciphers)");
            Put_Line ("");
         end if;
      when Json => null;
   end case;

   for P of Peers loop
      exit when not Peer_Matches_Filter (P);
      if Peer_Matches_Filter (P) then
         if Format = Markdown then
            Tls_Interop_Output.Md_Peer_Header (P);
         end if;
         for F in Feature_Kind'Range loop
            exit when Quick
              and then F > Cert_Ec_Aes256;
            Run_Peer_Feature (P, F);
         end loop;
      end if;
   end loop;

   if Bench and then Format = Markdown then
      declare
         use Tls_Interop_Bench;
         use GNATCOLL.JSON;
         Filtered : Peer_Array (1 .. 7);
         N : Natural := 0;
         All_Feat : Feature_Array (1 .. Feature_Kind'Pos (Feature_Kind'Last) + 1);
         NF : Natural := 0;
         Tput_Feat : constant Feature_Array :=
           (Cert_Ec_Chacha20,
            Cert_Ec_Aes128,
            Cert_Ec_Aes256,
            Psk_External_Chacha20,
            Psk_External_Aes128,
            Psk_External_Aes256);
         Ref_Peers : constant Peer_Array :=
           (Openssl, Go_Lang, Mbedtls, Gnutls);
         Ref_Filtered : Peer_Array (1 .. 4);
         NR : Natural := 0;

         Hs_Rows  : JSON_Array := Empty_Array;
         Pvp_Rows : JSON_Array := Empty_Array;
         Tp_Rows  : JSON_Array := Empty_Array;

         --  Bench results land in Log_Dir/bench.json — full numeric
         --  table for downstream parsing (CI, dashboards, regression
         --  trackers).  Stdout gets one terse progress line per row.
         --  See docs/conventions.md §15.
         Bench_Json_Path : constant String :=
           To_String (Log_Dir) & "/bench.json";
      begin
         for P of Peers loop
            if Peer_Matches_Filter (P) then
               N := N + 1; Filtered (N) := P;
            end if;
         end loop;
         for F in Feature_Kind'Range loop
            exit when Quick
              and then F > Cert_Ec_Aes256;
            NF := NF + 1; All_Feat (NF) := F;
         end loop;
         for P of Ref_Peers loop
            if Peer_Matches_Filter (P) then
               NR := NR + 1; Ref_Filtered (NR) := P;
            end if;
         end loop;

         Run_Handshake_Bench
           (Filtered (1 .. N), All_Feat (1 .. NF), Bench_Runs,
            To_String (Log_Dir), EC_Dir, Psk_Hex_Str, Psk_Identity,
            Hs_Rows);

         Run_Peer_Vs_Peer_Bench
           (Ref_Filtered (1 .. NR), Bench_Runs, EC_Dir,
            Pvp_Rows);

         Run_Throughput_Bench
           (Filtered (1 .. N), Tput_Feat, Bench_Runs, Bench_Bytes,
            To_String (Log_Dir), EC_Dir, Psk_Hex_Str, Psk_Identity,
            Tp_Rows);

         declare
            Top : constant JSON_Value := Create_Object;
            Cfg : constant JSON_Value := Create_Object;
            F   : Ada.Text_IO.File_Type;
         begin
            Cfg.Set_Field ("runs",       Bench_Runs);
            Cfg.Set_Field ("bytes",      Bench_Bytes);
            Cfg.Set_Field ("quick",      Quick);
            Top.Set_Field ("schema",      "tls-bench-v1");
            Top.Set_Field ("log_dir",     To_String (Log_Dir));
            Top.Set_Field ("config",      Cfg);
            Top.Set_Field ("handshake",   Hs_Rows);
            Top.Set_Field ("peer_vs_peer", Pvp_Rows);
            Top.Set_Field ("throughput",  Tp_Rows);
            Ada.Text_IO.Create
              (F, Ada.Text_IO.Out_File, Bench_Json_Path);
            Ada.Text_IO.Put_Line (F, Top.Write (Compact => False));
            Ada.Text_IO.Close (F);
            Put_Line ("");
            Put_Line ("Bench results: " & Bench_Json_Path);
         exception
            when others =>
               if Ada.Text_IO.Is_Open (F) then
                  Ada.Text_IO.Close (F);
               end if;
               Put_Line
                 (Standard_Error,
                  "tls_interop: failed to write " & Bench_Json_Path);
         end;
      end;
   end if;

   case Format is
      when Markdown =>
         Put_Line ("");
         Put_Line ("Logs: " & To_String (Log_Dir));
      when Json =>
         declare
            use GNATCOLL.JSON;
            Top : constant JSON_Value :=
              Create (Tls_Interop_Output.Json_Rows);
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
