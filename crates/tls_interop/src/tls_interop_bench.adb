with Ada.Numerics.Discrete_Random;
with Ada.Numerics.Elementary_Functions;
with Ada.Strings.Fixed;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO;
with GNAT.OS_Lib;           use GNAT.OS_Lib;
with GNATCOLL.JSON;         use GNATCOLL.JSON;
with Tls_Core.Tcp_Transport;
with Tls_Interop_Inline;

package body Tls_Interop_Bench is

   use Ada.Text_IO;

   function Img_Int (X : Integer) return String is
     (Ada.Strings.Fixed.Trim (Integer'Image (X), Ada.Strings.Both));

   function Img_Ms (Sec : Float) return String is
     (Img_Int (Integer (Sec * 1000.0)) & "ms");

   subtype Port_Range is Natural range 20000 .. 59999;
   package Port_Random is new Ada.Numerics.Discrete_Random (Port_Range);
   Port_Rng : Port_Random.Generator;
   Rng_Init : Boolean := False;

   function Alloc_Port return Natural is
   begin
      if not Rng_Init then
         Port_Random.Reset (Port_Rng);
         Rng_Init := True;
      end if;
      return Port_Random.Random (Port_Rng);
   end Alloc_Port;

   function Make_Cell
     (P       : Peer_Kind;
      R       : Role_Kind;
      M       : Mode_Kind;
      C       : Cipher_Kind;
      Port    : Natural;
      Log_Dir : String;
      EC_Dir  : String;
      Psk_Hex : String;
      Psk_Id  : String) return Cell_Spec
   is
      CS : Cell_Spec;
   begin
      CS.Peer := P; CS.Role := R;
      CS.Mode := M; CS.Cipher := C;
      CS.Port := Port;
      CS.Host := To_Unbounded_String ("127.0.0.1");
      CS.Psk_Hex := To_Unbounded_String (Psk_Hex);
      CS.Psk_Identity := To_Unbounded_String (Psk_Id);
      CS.Psk_File := To_Unbounded_String (Log_Dir & "/psk32.bin");
      if M = Cert_Ec then
         CS.Cert_Pem  := To_Unbounded_String (EC_Dir & "/leaf.pem");
         CS.Key_Pem   := To_Unbounded_String (EC_Dir & "/leaf.key");
         CS.Trust_Pem := To_Unbounded_String (EC_Dir & "/root.pem");
         if R = Client then
            CS.Hostname := To_Unbounded_String ("localhost");
         end if;
      end if;
      return CS;
   end Make_Cell;

   type Stats is record
      Mean, Sd, Min_V, Max_V : Float := 0.0;
   end record;

   type Float_Vector is array (Positive range <>) of Float;

   function Compute_Stats (Vals : Float_Vector) return Stats is
      N : constant Positive := Vals'Length;
      S : Stats;
      Sum, Ssq : Float := 0.0;
   begin
      S.Min_V := Float'Last;
      for V of Vals loop
         Sum := Sum + V;
         if V < S.Min_V then S.Min_V := V; end if;
         if V > S.Max_V then S.Max_V := V; end if;
      end loop;
      S.Mean := Sum / Float (N);
      for V of Vals loop
         declare
            D : constant Float := V - S.Mean;
         begin
            Ssq := Ssq + D * D;
         end;
      end loop;
      S.Sd := (if N > 1
               then Ada.Numerics.Elementary_Functions.Sqrt
                      (Ssq / Float (N))
               else 0.0);
      return S;
   end Compute_Stats;

   procedure Spawn_And_Reap
     (Cell   : Cell_Spec;
      Pid    : out Process_Id;
      Sup    : out Boolean)
   is
      Bin  : Unbounded_String;
      Args : Argument_List_Access;
      Reason : Unbounded_String;
   begin
      Build_Command (Cell, Bin, Args, Sup, Reason);
      if Sup then
         Pid := Non_Blocking_Spawn
           (To_String (Bin), Args.all, "/dev/null", True);
         Free (Args);
      else
         Pid := Invalid_Pid;
         Free (Args);
      end if;
   end Spawn_And_Reap;

   procedure Kill_And_Wait (Pid : Process_Id) is
      Rp : Process_Id;
      Ok : Boolean;
   begin
      Kill (Pid, Hard_Kill => True);
      Wait_Process (Rp, Ok);
   exception
      when others => null;
   end Kill_And_Wait;

   procedure Run_Handshake_Bench
     (Peers       : Peer_Array;
      Features    : Feature_Array;
      Runs        : Positive;
      Log_Dir     : String;
      EC_Dir      : String;
      Psk_Hex     : String;
      Psk_Id      : String;
      Json_Out    : in out GNATCOLL.JSON.JSON_Array)
   is
   begin
      Put_Line (Standard_Error,
                "[bench] handshake: " & Img_Int (Runs) & " runs/cell");
      for P of Peers loop
         for F of Features loop
            if Ada_Supports (F) and then Peer_Supports (P, F)
              and then F /= Psk_Resumption
            then
               declare
                  M : Mode_Kind;
                  C : Cipher_Kind;
               begin
                  Feature_To_Cell (F, M, C);
                  for Dir_Idx in 1 .. 2 loop
                     declare
                        Dir_S    : constant String :=
                          (if Dir_Idx = 1 then "c2s" else "s2c");
                        Times    : Float_Vector (1 .. Runs) :=
                          (others => 0.0);
                        All_Pass : Boolean := True;
                     begin
                        for I in 1 .. Runs loop
                           declare
                              use Tls_Interop_Inline;
                              IR     : Inline_Result;
                              I_Note : Unbounded_String;
                              Bp     : constant Natural := Alloc_Port;
                              Peer_Role : constant Role_Kind :=
                                (if Dir_S = "c2s" then Server
                                 else Client);
                              PC     : constant Cell_Spec :=
                                Make_Cell (P, Peer_Role, M, C, Bp,
                                           Log_Dir, EC_Dir,
                                           Psk_Hex, Psk_Id);
                              Pid    : Process_Id;
                              Sup    : Boolean;
                              El     : Duration;
                           begin
                              if Dir_S = "c2s" then
                                 Spawn_And_Reap (PC, Pid, Sup);
                                 if not Sup then
                                    All_Pass := False;
                                 else
                                    delay 0.3;
                                    declare
                                       Timed_Out : Boolean := False;
                                       task Hs is
                                          entry Done;
                                       end Hs;
                                       task body Hs is
                                       begin
                                          Run_Handshake_C2S
                                            (P, M, C, Bp,
                                             IR, El, I_Note);
                                          accept Done;
                                       exception
                                          when others =>
                                             begin accept Done;
                                             exception
                                                when others => null;
                                             end;
                                       end Hs;
                                    begin
                                       select
                                          Hs.Done;
                                       or
                                          delay 1.0;
                                          Timed_Out := True;
                                          Kill (Pid,
                                                Hard_Kill => True);
                                          Hs.Done;
                                       end select;
                                       if not Timed_Out then
                                          Kill_And_Wait (Pid);
                                       else
                                          declare
                                             Rp : Process_Id;
                                             Ok : Boolean;
                                          begin
                                             Wait_Process (Rp, Ok);
                                          exception
                                             when others => null;
                                          end;
                                       end if;
                                       if Timed_Out
                                         or else IR /=
                                                   Tls_Interop_Inline
                                                     .Pass
                                       then
                                          All_Pass := False;
                                       else
                                          Times (I) := Float (El);
                                       end if;
                                    end;
                                 end if;
                              else
                                 --  s2c: open Ada listener BEFORE
                                 --  spawning the peer client so the
                                 --  peer's connect() finds a queued
                                 --  socket (avoids Accept_One hangs
                                 --  on lost-race connect refused).
                                 declare
                                    L : Tls_Core.Tcp_Transport.Listener;
                                    L_OK : Boolean;
                                 begin
                                    Open_S2C_Listener (Bp, L, L_OK);
                                    if not L_OK then
                                       All_Pass := False;
                                    else
                                       Spawn_And_Reap (PC, Pid, Sup);
                                       if not Sup then
                                          All_Pass := False;
                                          Tls_Core.Tcp_Transport.Stop
                                            (L);
                                       else
                                          delay 0.3;
                                          declare
                                             Timed_Out : Boolean
                                               := False;
                                             task Hs is
                                                entry Done;
                                             end Hs;
                                             task body Hs is
                                             begin
                                                Run_Handshake_S2C
                                                  (L, P, M, C,
                                                   IR, El, I_Note);
                                                accept Done;
                                             exception
                                                when others =>
                                                   begin accept Done;
                                                   exception
                                                      when others =>
                                                         null;
                                                   end;
                                             end Hs;
                                          begin
                                             select
                                                Hs.Done;
                                             or
                                                delay 1.0;
                                                Timed_Out := True;
                                                Kill (Pid,
                                                  Hard_Kill => True);
                                                begin
                                                   Tls_Core
                                                     .Tcp_Transport
                                                     .Stop (L);
                                                exception
                                                   when others =>
                                                      null;
                                                end;
                                                Hs.Done;
                                             end select;
                                             if not Timed_Out then
                                                Kill_And_Wait (Pid);
                                                Tls_Core
                                                  .Tcp_Transport
                                                  .Stop (L);
                                             else
                                                declare
                                                   Rp : Process_Id;
                                                   Ok : Boolean;
                                                begin
                                                   Wait_Process
                                                     (Rp, Ok);
                                                exception
                                                   when others =>
                                                      null;
                                                end;
                                                --  listener already
                                                --  stopped above
                                             end if;
                                             if Timed_Out
                                               or else IR /=
                                                       Tls_Interop_Inline
                                                         .Pass
                                             then
                                                All_Pass := False;
                                             else
                                                Times (I) :=
                                                  Float (El);
                                             end if;
                                          end;
                                       end if;
                                    end if;
                                 end;
                              end if;
                           end;
                           exit when not All_Pass;
                        end loop;
                        if All_Pass then
                           declare
                              S : constant Stats :=
                                Compute_Stats (Times);
                              Row : constant JSON_Value :=
                                Create_Object;
                              Runs_Json : JSON_Array := Empty_Array;
                           begin
                              for I in 1 .. Runs loop
                                 Append
                                   (Runs_Json,
                                    Create (Times (I)));
                              end loop;
                              Row.Set_Field ("peer",      Image (P));
                              Row.Set_Field ("feature",   Image (F));
                              Row.Set_Field ("direction", Dir_S);
                              Row.Set_Field ("runs_s",    Runs_Json);
                              Row.Set_Field ("mean_s",    S.Mean);
                              Row.Set_Field ("sd_s",      S.Sd);
                              Row.Set_Field ("min_s",     S.Min_V);
                              Row.Set_Field ("max_s",     S.Max_V);
                              Append (Json_Out, Row);
                              Put_Line (Standard_Error,
                                "[bench] hs " & Image (P)
                                & " " & Image (F)
                                & " " & Dir_S
                                & " mean=" & Img_Ms (S.Mean)
                                & " sd="   & Img_Ms (S.Sd));
                           end;
                        else
                           Put_Line (Standard_Error,
                             "[bench] hs " & Image (P)
                             & " " & Image (F)
                             & " " & Dir_S & " SKIP");
                        end if;
                     end;
                  end loop;
               end;
            end if;
         end loop;
      end loop;
   end Run_Handshake_Bench;

   procedure Run_Peer_Vs_Peer_Bench
     (Peers    : Peer_Array;
      Runs     : Positive;
      EC_Dir   : String;
      Json_Out : in out GNATCOLL.JSON.JSON_Array)
   is
   begin
      Put_Line (Standard_Error, "[bench] peer-vs-peer (cert-ec)");
      for RP of Peers loop
         declare
            Bp : constant Natural := Alloc_Port;
            Srv : constant Cell_Spec :=
              Make_Cell (RP, Server, Cert_Ec, Auto, Bp,
                         "", EC_Dir, "", "");
            Cli : Cell_Spec := Srv;
            Srv_Bin, Cli_Bin : Unbounded_String;
            Srv_Args, Cli_Args : Argument_List_Access;
            Srv_Sup, Cli_Sup : Boolean;
            Srv_R, Cli_R : Unbounded_String;
            Ts : Float_Vector (1 .. Runs) := (others => 0.0);
            Ok : Boolean := True;
         begin
            Cli.Role := Client;
            Cli.Hostname := To_Unbounded_String ("localhost");
            Build_Command (Srv, Srv_Bin, Srv_Args, Srv_Sup, Srv_R);
            Build_Command (Cli, Cli_Bin, Cli_Args, Cli_Sup, Cli_R);
            if Srv_Sup and then Cli_Sup then
               for I in 1 .. Runs loop
                  declare
                     use Tls_Interop_Inline;
                     IR     : Inline_Result;
                     I_Note : Unbounded_String;
                     El     : Duration;
                  begin
                     Run_Peer_Vs_Peer
                       (To_String (Srv_Bin), Srv_Args.all,
                        To_String (Cli_Bin), Cli_Args.all,
                        IR, El, I_Note);
                     if IR /= Tls_Interop_Inline.Pass then
                        Ok := False; exit;
                     end if;
                     Ts (I) := Float (El);
                  end;
               end loop;
               if Ok then
                  declare
                     S : constant Stats :=
                       Compute_Stats (Ts);
                     Row : constant JSON_Value := Create_Object;
                     Runs_Json : JSON_Array := Empty_Array;
                  begin
                     for I in 1 .. Runs loop
                        Append (Runs_Json, Create (Ts (I)));
                     end loop;
                     Row.Set_Field
                       ("matchup", Image (RP) & "->" & Image (RP));
                     Row.Set_Field ("runs_s", Runs_Json);
                     Row.Set_Field ("mean_s", S.Mean);
                     Row.Set_Field ("sd_s",   S.Sd);
                     Row.Set_Field ("min_s",  S.Min_V);
                     Row.Set_Field ("max_s",  S.Max_V);
                     Append (Json_Out, Row);
                     Put_Line (Standard_Error,
                       "[bench] pvp " & Image (RP) & "->" & Image (RP)
                       & " mean=" & Img_Ms (S.Mean)
                       & " sd="   & Img_Ms (S.Sd));
                  end;
               else
                  Put_Line (Standard_Error,
                    "[bench] pvp " & Image (RP) & "->" & Image (RP)
                    & " SKIP");
               end if;
            end if;
            Free (Srv_Args); Free (Cli_Args);
         end;
      end loop;
   end Run_Peer_Vs_Peer_Bench;

   procedure Run_Throughput_Bench
     (Peers       : Peer_Array;
      Features    : Feature_Array;
      Runs        : Positive;
      Bytes       : Natural;
      Log_Dir     : String;
      EC_Dir      : String;
      Psk_Hex     : String;
      Psk_Id      : String;
      Json_Out    : in out GNATCOLL.JSON.JSON_Array)
   is
      Mib : constant Float := Float (Bytes) / 1_048_576.0;
   begin
      Put_Line (Standard_Error,
                "[bench] throughput: " & Img_Int (Bytes / 1024)
                & " KiB, " & Img_Int (Runs) & " runs/cell");
      for P of Peers loop
         for F of Features loop
            if Ada_Supports (F) and then Peer_Supports (P, F) then
               declare
                  M : Mode_Kind;
                  C : Cipher_Kind;
                  Tputs    : Float_Vector (1 .. Runs) := (others => 0.0);
                  All_Pass : Boolean := True;
               begin
                  Feature_To_Cell (F, M, C);
                  for I in 1 .. Runs loop
                     declare
                        use Tls_Interop_Inline;
                        IR  : Inline_Result;
                        I_Note : Unbounded_String;
                        Bp  : constant Natural := Alloc_Port;
                        PC  : constant Cell_Spec :=
                          Make_Cell (P, Server, M, C, Bp,
                                     Log_Dir, EC_Dir, Psk_Hex, Psk_Id);
                        Pid : Process_Id;
                        Sup : Boolean;
                        El  : Duration;
                     begin
                        Spawn_And_Reap (PC, Pid, Sup);
                        if not Sup then
                           All_Pass := False;
                        else
                           delay 0.3;
                           declare
                              Timed_Out : Boolean := False;
                              task Tp is
                                 entry Done;
                              end Tp;
                              task body Tp is
                              begin
                                 Run_Throughput_C2S
                                   (P, M, C, Bp, Bytes,
                                    IR, El, I_Note);
                                 accept Done;
                              exception
                                 when others =>
                                    begin accept Done;
                                    exception
                                       when others => null;
                                    end;
                              end Tp;
                           begin
                              select
                                 Tp.Done;
                              or
                                 delay 1.0;
                                 Timed_Out := True;
                                 Kill (Pid, Hard_Kill => True);
                                 Tp.Done;
                              end select;
                              if not Timed_Out then
                                 Kill_And_Wait (Pid);
                              else
                                 declare
                                    Rp : Process_Id;
                                    Ok : Boolean;
                                 begin
                                    Wait_Process (Rp, Ok);
                                 exception
                                    when others => null;
                                 end;
                              end if;
                              if not Timed_Out
                                and then IR = Tls_Interop_Inline.Pass
                                and then El > 0.0
                              then
                                 Tputs (I) := Mib / Float (El);
                              else
                                 All_Pass := False;
                              end if;
                           end;
                        end if;
                     end;
                     exit when not All_Pass;
                  end loop;
                  if All_Pass then
                     declare
                        S : constant Stats :=
                          Compute_Stats (Tputs);
                        Row : constant JSON_Value := Create_Object;
                        Runs_Json : JSON_Array := Empty_Array;
                     begin
                        for I in 1 .. Runs loop
                           Append
                             (Runs_Json, Create (Tputs (I)));
                        end loop;
                        Row.Set_Field ("peer",    Image (P));
                        Row.Set_Field ("feature", Image (F));
                        Row.Set_Field ("bytes",   Bytes);
                        Row.Set_Field ("runs_mibps", Runs_Json);
                        Row.Set_Field ("mean_mibps", S.Mean);
                        Row.Set_Field ("sd_mibps",   S.Sd);
                        Row.Set_Field ("min_mibps",  S.Min_V);
                        Row.Set_Field ("max_mibps",  S.Max_V);
                        Append (Json_Out, Row);
                        Put_Line (Standard_Error,
                          "[bench] tp " & Image (P)
                          & " " & Image (F)
                          & " mean=" & Img_Int (Integer (S.Mean))
                          & "MiB/s sd="
                          & Img_Int (Integer (S.Sd)));
                     end;
                  else
                     Put_Line (Standard_Error,
                       "[bench] tp " & Image (P)
                       & " " & Image (F) & " SKIP");
                  end if;
               end;
            end if;
         end loop;
      end loop;
   end Run_Throughput_Bench;

end Tls_Interop_Bench;
