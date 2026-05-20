--  http2_soak — repeatedly drive Http2_Core.Connection.Round_Trip
--  against a real HTTP/2 server (default localhost:8080) and log
--  every anomaly. Tests the connection driver against an external
--  HTTP/2 stack — first time the wire bytes are exercised end-to-
--  end against a third-party implementation.
--
--  Iteration: open a fresh connection, do one Round_Trip with a
--  varied (path, body) pair, close. Log if open fails, round-trip
--  raises, or response doesn't match expectation.
--
--  Reads iteration count from argv[1] (default 1000) and host:port
--  from argv[2] (default "127.0.0.1:8080").

with Ada.Text_IO;
with Ada.Command_Line;
with Ada.Calendar;
with Ada.Exceptions;
with Ada.Numerics.Discrete_Random;
with Interfaces;

with RFLX.RFLX_Types;
with RFLX.RFLX_Builtin_Types;

with Http2_Core.Hpack;
with Http2_Core.Connection;

procedure Http2_Soak is
   use Ada.Text_IO;
   use Ada.Calendar;
   use type RFLX.RFLX_Builtin_Types.Index;
   use type RFLX.RFLX_Builtin_Types.Byte;

   package Byte_Random is new
     Ada.Numerics.Discrete_Random (Interfaces.Unsigned_8);
   Byte_Gen : Byte_Random.Generator;

   Iterations : Natural := 1_000;
   Host       : String (1 .. 32) := (others => ' ');
   Host_Last  : Natural := 0;
   Port       : Natural := 8080;

   --  Counters.
   Total         : Natural := 0;
   OK            : Natural := 0;
   Open_Fail     : Natural := 0;
   RPC_Fail      : Natural := 0;
   Other_Fail    : Natural := 0;
   Body_Mismatch : Natural := 0;

   Anomaly_Log : File_Type;

   procedure Log_Anomaly (Iter : Natural; Why : String);
   procedure Log_Anomaly (Iter : Natural; Why : String) is
   begin
      Put_Line (Anomaly_Log, "iter=" & Iter'Image & " " & Why);
      Flush (Anomaly_Log);
   end Log_Anomaly;

   procedure Parse_Host (Spec : String);
   procedure Parse_Host (Spec : String) is
      Colon_At : Natural := 0;
   begin
      for I in Spec'Range loop
         if Spec (I) = ':' then
            Colon_At := I;
            exit;
         end if;
      end loop;
      if Colon_At = 0 then
         Host (1 .. Spec'Length) := Spec;
         Host_Last := Spec'Length;
      else
         declare
            H_Len : constant Natural := Colon_At - Spec'First;
         begin
            Host (1 .. H_Len) := Spec (Spec'First .. Colon_At - 1);
            Host_Last := H_Len;
            Port := Natural'Value (Spec (Colon_At + 1 .. Spec'Last));
         end;
      end if;
   end Parse_Host;

   procedure One_Iteration (I : Natural);
   procedure One_Iteration (I : Natural) is
      C               : Http2_Core.Connection.Connection;
      --  Per-iteration buffers. Heap is fine in the test harness;
      --  production code paths in http2_core itself never call `new`.
      --  Three buffers: working + Stream::Half_Open's Inbound + Outgoing
      --  external slots.
      Buffer_Capacity : constant := 16 * 1024 + 64;
      Conn_Buf        : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. Buffer_Capacity => 0);
      Inbound_Buf     : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. Buffer_Capacity => 0);
      Outgoing_Buf    : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. Buffer_Capacity => 0);

      --  Vary body size: deterministic from iteration index, but
      --  bounded so the soak never asks for more than the
      --  Connection's buffer can hold (16 KB).
      Body_Size  : constant Natural := (I mod 256) + 1;
      Body_Bytes :
        RFLX.RFLX_Types.Bytes (1 .. RFLX.RFLX_Types.Index (Body_Size));

      Path_Buf : String (1 .. 32);
      Path_Len : Natural;

      Resp_Hdrs : Http2_Core.Hpack.Header_Block (1 .. 16);
      Hdrs_Last : Natural;
      Resp_Body : RFLX.RFLX_Types.Bytes (1 .. 16384) := [others => 0];
      Body_Last : Natural;
   begin
      --  Random body of (deterministic-per-iteration size).
      for J in Body_Bytes'Range loop
         Body_Bytes (J) :=
           RFLX.RFLX_Types.Byte (Byte_Random.Random (Byte_Gen));
      end loop;

      --  Path includes iteration index for traceability.
      declare
         Img     : constant String := I'Image;
         --  Strip leading space from 'Image.
         Idx_Str : constant String :=
           (if Img'Length > 0 and then Img (Img'First) = ' '
            then Img (Img'First + 1 .. Img'Last)
            else Img);
         Prefix  : constant String := "/echo/";
      begin
         Path_Buf (1 .. Prefix'Length) := Prefix;
         Path_Buf (Prefix'Length + 1 .. Prefix'Length + Idx_Str'Length) :=
           Idx_Str;
         Path_Len := Prefix'Length + Idx_Str'Length;
      end;

      Http2_Core.Connection.Attach_Buffers
        (C, Conn_Buf, Inbound_Buf, Outgoing_Buf);
      Http2_Core.Connection.Open
        (C => C, Host => Host (1 .. Host_Last), Port => Port);

      declare
         Headers : constant Http2_Core.Hpack.Header_Block (1 .. 5) :=
           [Http2_Core.Hpack.Make_Header (":method", "POST"),
            Http2_Core.Hpack.Make_Header (":scheme", "http"),
            Http2_Core.Hpack.Make_Header (":path", Path_Buf (1 .. Path_Len)),
            Http2_Core.Hpack.Make_Header (":authority", Host (1 .. Host_Last)),
            Http2_Core.Hpack.Make_Header ("content-type", "application/grpc")];
      begin
         Http2_Core.Connection.Round_Trip
           (C                     => C,
            Request_Headers       => Headers,
            Request_Body          => Body_Bytes,
            Response_Headers      => Resp_Hdrs,
            Response_Headers_Last => Hdrs_Last,
            Response_Body         => Resp_Body,
            Response_Body_Last    => Body_Last);

         --  Validate body echo. Body_Last is Natural; Resp_Body'First
         --  is Index. Convert before subtracting.
         declare
            Got_Size : constant Integer :=
              Body_Last - Integer (Resp_Body'First) + 1;
         begin
            if Got_Size /= Body_Size then
               Body_Mismatch := Body_Mismatch + 1;
               Log_Anomaly
                 (I,
                  "body_size mismatch: expected"
                  & Body_Size'Image
                  & " got"
                  & Got_Size'Image);
            else
               declare
                  All_Match : Boolean := True;
               begin
                  for J in 1 .. Body_Size loop
                     if Resp_Body
                          (Resp_Body'First + RFLX.RFLX_Types.Index (J) - 1)
                       /= Body_Bytes
                            (Body_Bytes'First + RFLX.RFLX_Types.Index (J) - 1)
                     then
                        All_Match := False;
                        exit;
                     end if;
                  end loop;
                  if not All_Match then
                     Body_Mismatch := Body_Mismatch + 1;
                     Log_Anomaly (I, "body bytes differ");
                  end if;
               end;
            end if;
         end;
         OK := OK + 1;
      end;

      Http2_Core.Connection.Close (C);
      Http2_Core.Connection.Detach_Buffers
        (C, Conn_Buf, Inbound_Buf, Outgoing_Buf);
      RFLX.RFLX_Types.Free (Conn_Buf);
      RFLX.RFLX_Types.Free (Inbound_Buf);
      RFLX.RFLX_Types.Free (Outgoing_Buf);

   exception
      when E : Http2_Core.Connection.Connect_Error =>
         Open_Fail := Open_Fail + 1;
         Log_Anomaly
           (I, "Connect_Error: " & Ada.Exceptions.Exception_Message (E));
      when E : Http2_Core.Connection.RPC_Error =>
         RPC_Fail := RPC_Fail + 1;
         Log_Anomaly (I, "RPC_Error: " & Ada.Exceptions.Exception_Message (E));
      when E : others =>
         Other_Fail := Other_Fail + 1;
         Log_Anomaly
           (I,
            Ada.Exceptions.Exception_Name (E)
            & ": "
            & Ada.Exceptions.Exception_Message (E));
   end One_Iteration;

   Start_Time : Time;
begin
   if Ada.Command_Line.Argument_Count >= 1 then
      Iterations := Natural'Value (Ada.Command_Line.Argument (1));
   end if;
   if Ada.Command_Line.Argument_Count >= 2 then
      Parse_Host (Ada.Command_Line.Argument (2));
   else
      Host (1 .. 9) := "127.0.0.1";
      Host_Last := 9;
   end if;

   Byte_Random.Reset (Byte_Gen, 23);

   Create (Anomaly_Log, Out_File, "h2_soak_anomalies.log");
   Put_Line (Anomaly_Log, "# http2_soak anomaly log");
   Flush (Anomaly_Log);

   Put_Line
     ("http2_soak: "
      & Iterations'Image
      & " iterations against "
      & Host (1 .. Host_Last)
      & ":"
      & Port'Image);
   Start_Time := Clock;

   for I in 1 .. Iterations loop
      Total := Total + 1;
      One_Iteration (I);
      if I mod 50 = 0 then
         Put_Line
           ("["
            & I'Image
            & "]"
            & " elapsed="
            & Duration'Image (Clock - Start_Time)
            & "s"
            & " ok="
            & OK'Image
            & " open_fail="
            & Open_Fail'Image
            & " rpc_fail="
            & RPC_Fail'Image
            & " body_mismatch="
            & Body_Mismatch'Image);
      end if;
   end loop;

   Put_Line ("=== final ===");
   Put_Line
     ("total="
      & Total'Image
      & " ok="
      & OK'Image
      & " open_fail="
      & Open_Fail'Image
      & " rpc_fail="
      & RPC_Fail'Image
      & " body_mismatch="
      & Body_Mismatch'Image
      & " other_fail="
      & Other_Fail'Image);
   Close (Anomaly_Log);
end Http2_Soak;
