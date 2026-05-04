--  greeter_bench_client — looping unary client for benchmarks.
--  Opens a single HTTP/2 connection at startup and re-uses it
--  for every SayHello — Http2_Core.Connection.Round_Trip
--  increments the per-connection stream-id (1, 3, 5, …) so
--  arbitrarily many round-trips share one TCP/SETTINGS handshake.
--  This measures steady-state per-RPC cost rather than connection
--  setup.
--
--  Args: <host:port> <duration-seconds> <name-length>
--  Output: JSON to stdout matching the Go bench client's shape.

with Ada.Text_IO;
with Ada.Command_Line;
with Ada.Real_Time; use Ada.Real_Time;

with RFLX.RFLX_Types;
use type RFLX.RFLX_Types.Bytes_Ptr;

with Http2_Core.Hpack;
with Http2_Core.Connection;
with Protobuf_Core.Wire;

procedure Greeter_Bench_Client is
   use Ada.Text_IO;
   use type RFLX.RFLX_Types.Index;

   --  Args.
   Host : String (1 .. 64) := (others => ' ');
   Host_Last : Natural := 0;
   Port : Natural := 50051;
   Duration_S : Float := 10.0;
   Name_Len : Natural := 4;

   procedure Parse_Target (Spec : String);
   procedure Parse_Target (Spec : String) is
      Colon : Natural := 0;
   begin
      for I in Spec'Range loop
         if Spec (I) = ':' then Colon := I; exit; end if;
      end loop;
      if Colon = 0 then
         Host (1 .. Spec'Length) := Spec;
         Host_Last := Spec'Length;
      else
         Host (1 .. Colon - Spec'First) :=
           Spec (Spec'First .. Colon - 1);
         Host_Last := Colon - Spec'First;
         Port := Natural'Value (Spec (Colon + 1 .. Spec'Last));
      end if;
   end Parse_Target;

   --  Latency samples (microseconds).
   Max_Samples : constant := 200_000;
   Samples : array (1 .. Max_Samples) of Natural := (others => 0);
   N_Samples : Natural := 0;
   Errors : Natural := 0;

   procedure Insertion_Sort_Samples;
   procedure Insertion_Sort_Samples is
      Tmp : Natural;
   begin
      for I in 2 .. N_Samples loop
         Tmp := Samples (I);
         declare J : Natural := I - 1;
         begin
            while J >= 1 and then Samples (J) > Tmp loop
               Samples (J + 1) := Samples (J);
               J := J - 1;
            end loop;
            Samples (J + 1) := Tmp;
         end;
      end loop;
   end Insertion_Sort_Samples;

   function Pct (P : Float) return Natural;
   function Pct (P : Float) return Natural is
      Idx : constant Natural := Natural (Float (N_Samples - 1) * P / 100.0) + 1;
   begin
      if Idx < 1 then return 0; end if;
      if Idx > N_Samples then return Samples (N_Samples); end if;
      return Samples (Idx);
   end Pct;

   --  Build a HelloRequest body:  gRPC 5-byte prefix + protobuf
   --  field-1 (length-delimited) string of length Name_Len bytes
   --  ('a' repeated).
   procedure Build_Body
     (Out_Buf : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out RFLX.RFLX_Types.Index);

   procedure Build_Body
     (Out_Buf : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out RFLX.RFLX_Types.Index)
   is
      PB_Buf  : RFLX.RFLX_Types.Bytes (1 .. 65536) := (others => 0);
      PB_Last : RFLX.RFLX_Types.Index;
      Name_Str : String (1 .. Name_Len) := (others => 'a');
      OK : Boolean;
      Len : Natural;
   begin
      Protobuf_Core.Wire.Encode_String_Field
        (PB_Buf, PB_Buf'First, 1, Name_Str, PB_Last, OK);
      Len := Natural (PB_Last);
      Out_Buf (Out_Buf'First) := 0;
      Out_Buf (Out_Buf'First + 1) :=
        RFLX.RFLX_Types.Byte ((Len / 16777216) mod 256);
      Out_Buf (Out_Buf'First + 2) :=
        RFLX.RFLX_Types.Byte ((Len / 65536) mod 256);
      Out_Buf (Out_Buf'First + 3) :=
        RFLX.RFLX_Types.Byte ((Len / 256) mod 256);
      Out_Buf (Out_Buf'First + 4) :=
        RFLX.RFLX_Types.Byte (Len mod 256);
      for I in 1 .. Len loop
         Out_Buf (Out_Buf'First + 4 + RFLX.RFLX_Types.Index (I)) :=
           PB_Buf (PB_Buf'First + RFLX.RFLX_Types.Index (I) - 1);
      end loop;
      Out_Last := Out_Buf'First + 4 + RFLX.RFLX_Types.Index (Len);
   end Build_Body;

begin
   if Ada.Command_Line.Argument_Count < 1 then
      Put_Line ("usage: greeter_bench_client <host:port> [dur_s] [name_len]");
      return;
   end if;
   Parse_Target (Ada.Command_Line.Argument (1));
   if Ada.Command_Line.Argument_Count >= 2 then
      Duration_S := Float'Value (Ada.Command_Line.Argument (2));
   end if;
   if Ada.Command_Line.Argument_Count >= 3 then
      Name_Len := Natural'Value (Ada.Command_Line.Argument (3));
   end if;

   declare
      T0 : constant Time := Clock;
      Deadline : constant Time := T0 + To_Time_Span (Duration (Duration_S));

      --  Pre-built request body — same content every iter, encoded once.
      Body_Buf : RFLX.RFLX_Types.Bytes (1 .. 16384) := (others => 0);
      Body_Last : RFLX.RFLX_Types.Index;

      Headers : constant Http2_Core.Hpack.Header_Block (1 .. 7) :=
        (Http2_Core.Hpack.Make_Header (":method", "POST"),
         Http2_Core.Hpack.Make_Header (":scheme", "http"),
         Http2_Core.Hpack.Make_Header
           (":path", "/helloworld.Greeter/SayHello"),
         Http2_Core.Hpack.Make_Header (":authority",
                                       Host (1 .. Host_Last)),
         Http2_Core.Hpack.Make_Header
           ("content-type", "application/grpc"),
         Http2_Core.Hpack.Make_Header ("te", "trailers"),
         Http2_Core.Hpack.Make_Header
           ("user-agent", "grpc-ada-bench"));
   begin
      Build_Body (Body_Buf, Body_Last);

      declare
         C            : Http2_Core.Connection.Connection;
         Conn_Buf     : RFLX.RFLX_Types.Bytes_Ptr :=
           new RFLX.RFLX_Types.Bytes' (1 .. 32 * 1024 + 64 => 0);
         Inbound_Buf  : RFLX.RFLX_Types.Bytes_Ptr :=
           new RFLX.RFLX_Types.Bytes' (1 .. 32 * 1024 + 64 => 0);
         Outgoing_Buf : RFLX.RFLX_Types.Bytes_Ptr :=
           new RFLX.RFLX_Types.Bytes' (1 .. 32 * 1024 + 64 => 0);
      begin
         --  One TCP connection + HTTP/2 preface + SETTINGS for the
         --  whole bench. Every Round_Trip below uses the next
         --  client-initiated stream id (1, 3, 5, …).
         Http2_Core.Connection.Attach_Buffers
           (C, Conn_Buf, Inbound_Buf, Outgoing_Buf);
         Http2_Core.Connection.Open
           (C => C, Host => Host (1 .. Host_Last), Port => Port);

         while Clock < Deadline and N_Samples < Max_Samples loop
            declare
               T_Start : constant Time := Clock;
               Resp_Hdrs : Http2_Core.Hpack.Header_Block (1 .. 16);
               Hdrs_Last : Natural;
               Resp_Body : RFLX.RFLX_Types.Bytes (1 .. 16384) :=
                 (others => 0);
               Resp_Body_Last : Natural;
               T_End : Time;
            begin
               Http2_Core.Connection.Round_Trip
                 (C                     => C,
                  Request_Headers       => Headers,
                  Request_Body          =>
                    Body_Buf (Body_Buf'First .. Body_Last),
                  Response_Headers      => Resp_Hdrs,
                  Response_Headers_Last => Hdrs_Last,
                  Response_Body         => Resp_Body,
                  Response_Body_Last    => Resp_Body_Last);

               T_End := Clock;
               N_Samples := N_Samples + 1;
               Samples (N_Samples) :=
                 Natural
                   (Float (To_Duration (T_End - T_Start)) * 1_000_000.0);
            exception
               when others =>
                  Errors := Errors + 1;
                  exit;  --  Connection is likely toast — bail.
            end;
         end loop;

         begin
            Http2_Core.Connection.Close (C);
         exception when others => null;
         end;
         Http2_Core.Connection.Detach_Buffers
           (C, Conn_Buf, Inbound_Buf, Outgoing_Buf);
         if Conn_Buf /= null then
            RFLX.RFLX_Types.Free (Conn_Buf);
         end if;
         if Inbound_Buf /= null then
            RFLX.RFLX_Types.Free (Inbound_Buf);
         end if;
         if Outgoing_Buf /= null then
            RFLX.RFLX_Types.Free (Outgoing_Buf);
         end if;
      end;

      declare
         Wall_Span : constant Time_Span := Clock - T0;
         Wall_S    : constant Float :=
           Float (To_Duration (Wall_Span));
         Sum : Long_Long_Integer := 0;
      begin
         if N_Samples > 0 then
            Insertion_Sort_Samples;
            for I in 1 .. N_Samples loop
               Sum := Sum + Long_Long_Integer (Samples (I));
            end loop;
         end if;
         Put_Line ("{");
         Put_Line ("  ""client"": ""ada"",");
         Put_Line ("  ""workload"": ""unary_" & Name_Len'Image (2 .. Name_Len'Image'Last) & "B"",");
         Put_Line ("  ""count"": " & N_Samples'Image (2 .. N_Samples'Image'Last) & ",");
         Put_Line ("  ""errors"": " & Errors'Image (2 .. Errors'Image'Last) & ",");
         if N_Samples > 0 then
            Put_Line ("  ""p50_us"": " & Pct (50.0)'Image (2 .. Pct (50.0)'Image'Last) & ",");
            Put_Line ("  ""p95_us"": " & Pct (95.0)'Image (2 .. Pct (95.0)'Image'Last) & ",");
            Put_Line ("  ""p99_us"": " & Pct (99.0)'Image (2 .. Pct (99.0)'Image'Last) & ",");
            Put_Line ("  ""mean_us"": "
                      & Long_Long_Integer'Image (Sum / Long_Long_Integer (N_Samples))
                          (2 .. Long_Long_Integer'Image (Sum / Long_Long_Integer (N_Samples))'Last)
                      & ",");
         end if;
         Put_Line ("  ""wall_s"": " & Wall_S'Image & ",");
         if N_Samples > 0 and Wall_S > 0.0 then
            declare
               Ops : constant Float := Float (N_Samples) / Wall_S;
            begin
               Put_Line ("  ""ops_per_s"": " & Ops'Image);
            end;
         else
            Put_Line ("  ""ops_per_s"": 0.0");
         end if;
         Put_Line ("}");
      end;
   end;
end Greeter_Bench_Client;
