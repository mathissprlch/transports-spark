with RFLX.RFLX_Types;
with Logger;

package body Http2_Core.Flow_Gate
with SPARK_Mode
is

   use type RFLX.RFLX_Types.Length;
   use type RFLX.RFLX_Types.Index;
   use type RFLX.RFLX_Builtin_Types.Byte;
   use type RFLX.Flow_Gate.Send_Gate.FSM.Channel;
   use type RFLX.Flow_Gate.Send_Gate.FSM.State;

   subtype Byte is RFLX.RFLX_Types.Byte;

   --  Op_Packet / Decision_Packet wire layout per flow_gate.rflx:
   --    byte 0    : Kind (Op_Kind / Decision_Kind, 8-bit)
   --    byte 1..4 : Bytes (Window_Bytes, 32-bit big-endian)
   --  Total: 5 bytes.

   Msg_Bytes : constant := 5;

   subtype Msg_Buffer is RFLX.RFLX_Types.Bytes (1 .. Msg_Bytes);

   --  Op_Kind encoding from the .rflx aspect clause.
   Op_Send_Request : constant Byte := 1;
   Op_Wu_Conn      : constant Byte := 2;
   Op_Wu_Stream    : constant Byte := 3;
   Op_Init_Stream  : constant Byte := 4;

   Dec_Allow      : constant Byte := 1;
   Dec_Deny       : constant Byte := 2;

   ------------------------------------------------------------------
   --  Internal helpers
   ------------------------------------------------------------------

   procedure Build_Op
     (Kind  : Byte;
      Bytes : Window_Bytes;
      Buf   : out Msg_Buffer)
   is
   begin
      Buf (1) := Kind;
      Buf (2) := Byte (Bytes / 2 ** 24);
      Buf (3) := Byte ((Bytes / 2 ** 16) mod 256);
      Buf (4) := Byte ((Bytes / 2 ** 8) mod 256);
      Buf (5) := Byte (Bytes mod 256);
   end Build_Op;

   procedure Parse_Decision
     (Buf     : Msg_Buffer;
      Outcome : out Decision)
   is
      Kind : constant Byte := Buf (1);
   begin
      if Kind = Dec_Allow then
         Outcome := Decision_Allow;
      elsif Kind = Dec_Deny then
         Outcome := Decision_Deny;
      else
         Outcome := Decision_Flow_Error;
      end if;
   end Parse_Decision;

   --  Drive the FSM through exactly ONE cycle starting from S_Idle.
   --  Returns when FSM lands back at S_Idle (cycle complete) or
   --  dies. Reads at most one Decision_Packet off App_Decision and
   --  returns it via Out_Msg / Got.
   --
   --  Subtlety: re-running FSM.Run at S_Idle with empty Pending
   --  ticks Idle once, which then transitions to S_Final (Idle's
   --  "goto null if not Pending'Valid"). So we MUST exit before
   --  re-entering Idle without fresh Outbox data. The
   --  Next_State = S_Idle check is the load-bearing guard.
   procedure Drive_One_Cycle
     (G       : in out Gate;
      Out_Msg : out Msg_Buffer;
      Got     : out Boolean)
   is
      package FSM renames RFLX.Flow_Gate.Send_Gate.FSM;
   begin
      Out_Msg := (others => 0);
      Got     := False;
      loop
         pragma Loop_Invariant (Is_Active (G));
         FSM.Run (G.Ctx);
         exit when not FSM.Active (G.Ctx);
         if FSM.Has_Data (G.Ctx, FSM.C_App_Decision)
           and then FSM.Read_Buffer_Size
             (G.Ctx, FSM.C_App_Decision) >= Msg_Bytes
         then
            FSM.Read (G.Ctx, FSM.C_App_Decision, Out_Msg);
            Got := True;
         end if;
         --  Cycle complete when FSM is parked back at S_Idle. Do
         --  NOT call Run again — that would tick Idle with empty
         --  Pending and the FSM would transition to S_Final.
         exit when FSM.Next_State (G.Ctx) = FSM.S_Idle;
      end loop;
   end Drive_One_Cycle;

   ------------------------------------------------------------------
   --  Public API
   ------------------------------------------------------------------

   procedure Initialize (G : in out Gate) is
      package FSM renames RFLX.Flow_Gate.Send_Gate.FSM;
   begin
      FSM.Initialize (G.Ctx);
      Logger.Log (Logger.Debug, "flow_gate: init");
   end Initialize;

   procedure Finalize (G : in out Gate) is
      package FSM renames RFLX.Flow_Gate.Send_Gate.FSM;
   begin
      FSM.Finalize (G.Ctx);
      Logger.Log (Logger.Debug, "flow_gate: finalize");
   end Finalize;

   procedure Request_Send
     (G        : in out Gate;
      Bytes    : Window_Bytes;
      Outcome  : out Decision)
   is
      package FSM renames RFLX.Flow_Gate.Send_Gate.FSM;
      Op  : Msg_Buffer;
      Dec : Msg_Buffer;
      Got : Boolean;
   begin
      Outcome := Decision_Deny;
      Build_Op (Op_Send_Request, Bytes, Op);
      if not FSM.Needs_Data (G.Ctx, FSM.C_App_Outbox) then
         FSM.Run (G.Ctx);
      end if;
      if FSM.Needs_Data (G.Ctx, FSM.C_App_Outbox)
        and then FSM.Write_Buffer_Size
          (G.Ctx, FSM.C_App_Outbox) >= Msg_Bytes
      then
         FSM.Write (G.Ctx, FSM.C_App_Outbox, Op);
      end if;
      Drive_One_Cycle (G, Dec, Got);
      if Got then
         Parse_Decision (Dec, Outcome);
      end if;
      Logger.Log
        (Logger.Debug,
         "flow_gate: send req bytes="
         & Window_Bytes'Image (Bytes)
         & " outcome=" & Decision'Image (Outcome));
   end Request_Send;

   procedure Apply_Wu_Conn
     (G     : in out Gate;
      Bytes : Window_Bytes;
      OK    : out Boolean)
   is
      package FSM renames RFLX.Flow_Gate.Send_Gate.FSM;
      Op  : Msg_Buffer;
      Dec : Msg_Buffer;
      Got : Boolean;
      Outcome : Decision := Decision_Allow;
   begin
      OK := True;
      Build_Op (Op_Wu_Conn, Bytes, Op);
      if FSM.Needs_Data (G.Ctx, FSM.C_App_Outbox)
        and then FSM.Write_Buffer_Size
          (G.Ctx, FSM.C_App_Outbox) >= Msg_Bytes
      then
         FSM.Write (G.Ctx, FSM.C_App_Outbox, Op);
      end if;
      --  WU paths in the FSM normally return to Idle without
      --  emitting; if the overflow guard fires they emit
      --  Dec_Flow_Error. Drive to either outcome.
      Drive_One_Cycle (G, Dec, Got);
      if Got then
         Parse_Decision (Dec, Outcome);
         if Outcome = Decision_Flow_Error then
            OK := False;
         end if;
      end if;
      Logger.Log
        (Logger.Debug,
         "flow_gate: wu_conn +"
         & Window_Bytes'Image (Bytes)
         & " ok=" & Boolean'Image (OK));
   end Apply_Wu_Conn;

   procedure Apply_Wu_Stream
     (G     : in out Gate;
      Bytes : Window_Bytes;
      OK    : out Boolean)
   is
      package FSM renames RFLX.Flow_Gate.Send_Gate.FSM;
      Op  : Msg_Buffer;
      Dec : Msg_Buffer;
      Got : Boolean;
      Outcome : Decision := Decision_Allow;
   begin
      OK := True;
      Build_Op (Op_Wu_Stream, Bytes, Op);
      if FSM.Needs_Data (G.Ctx, FSM.C_App_Outbox)
        and then FSM.Write_Buffer_Size
          (G.Ctx, FSM.C_App_Outbox) >= Msg_Bytes
      then
         FSM.Write (G.Ctx, FSM.C_App_Outbox, Op);
      end if;
      Drive_One_Cycle (G, Dec, Got);
      if Got then
         Parse_Decision (Dec, Outcome);
         if Outcome = Decision_Flow_Error then
            OK := False;
         end if;
      end if;
      Logger.Log
        (Logger.Debug,
         "flow_gate: wu_stream +"
         & Window_Bytes'Image (Bytes)
         & " ok=" & Boolean'Image (OK));
   end Apply_Wu_Stream;

   procedure Init_Stream
     (G     : in out Gate;
      Bytes : Window_Bytes)
   is
      package FSM renames RFLX.Flow_Gate.Send_Gate.FSM;
      Op  : Msg_Buffer;
   begin
      declare
         Dec : Msg_Buffer;
         Got : Boolean;
      begin
         Build_Op (Op_Init_Stream, Bytes, Op);
         if FSM.Needs_Data (G.Ctx, FSM.C_App_Outbox)
           and then FSM.Write_Buffer_Size
             (G.Ctx, FSM.C_App_Outbox) >= Msg_Bytes
         then
            FSM.Write (G.Ctx, FSM.C_App_Outbox, Op);
         end if;
         Drive_One_Cycle (G, Dec, Got);
      end;
      Logger.Log
        (Logger.Debug,
         "flow_gate: init_stream window="
         & Window_Bytes'Image (Bytes));
   end Init_Stream;

end Http2_Core.Flow_Gate;
