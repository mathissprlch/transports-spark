with Ada.Calendar;
with Ada.Command_Line;
with Ada.Text_IO;          use Ada.Text_IO;
with RFLX.RFLX_Types;
use type RFLX.RFLX_Types.Index;

with Grpc_Core.Framing;
with Http2_Core.Connection;
with Http2_Core.Hpack;
with Protobuf_Core.Wire;

procedure Grpc_Bench_Client is

   N    : Natural := 100;
   Size : Natural := 1024;
   Host : String (1 .. 64) := (others => ' ');
   Host_Last : Natural := 9;
   Port : Natural := 50_051;

begin
   Host (1 .. 9) := "127.0.0.1";

   for I in 1 .. Ada.Command_Line.Argument_Count loop
      declare
         A : constant String := Ada.Command_Line.Argument (I);
      begin
         if A'Length > 3 and then A (A'First .. A'First + 2) = "-n=" then
            N := Natural'Value (A (A'First + 3 .. A'Last));
         elsif A'Length > 6 and then A (A'First .. A'First + 5) = "-size=" then
            Size := Natural'Value (A (A'First + 6 .. A'Last));
         elsif A'Length > 6 and then A (A'First .. A'First + 5) = "-port=" then
            Port := Natural'Value (A (A'First + 6 .. A'Last));
         elsif A'Length > 6 and then A (A'First .. A'First + 5) = "-host=" then
            declare
               H : constant String := A (A'First + 6 .. A'Last);
            begin
               Host (1 .. H'Length) := H;
               Host_Last := H'Length;
            end;
         end if;
      end;
   end loop;

   declare
      use Ada.Calendar;

      Payload : constant String (1 .. Size) := (others => 'X');
      PB_Buf  : RFLX.RFLX_Types.Bytes
        (1 .. RFLX.RFLX_Types.Index (Size) + 64) := (others => 0);
      Frame_Buf : RFLX.RFLX_Types.Bytes
        (1 .. RFLX.RFLX_Types.Index (Size) + 128) := (others => 0);

      C       : Http2_Core.Connection.Connection;
      Conn_Buf     : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. 4 * 1024 * 1024 + 64 => 0);
      Inbound_Buf  : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. 4 * 1024 * 1024 + 64 => 0);
      Outgoing_Buf : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. 4 * 1024 * 1024 + 64 => 0);

      Headers : constant Http2_Core.Hpack.Header_Block (1 .. 7) :=
        (Http2_Core.Hpack.Make_Header (":method", "POST"),
         Http2_Core.Hpack.Make_Header (":scheme", "http"),
         Http2_Core.Hpack.Make_Header
           (":path", "/helloworld.Greeter/SayHello"),
         Http2_Core.Hpack.Make_Header
           (":authority", Host (1 .. Host_Last)),
         Http2_Core.Hpack.Make_Header
           ("content-type", "application/grpc"),
         Http2_Core.Hpack.Make_Header ("te", "trailers"),
         Http2_Core.Hpack.Make_Header
           ("user-agent", "grpc-ada-bench"));

      Resp_Hdrs : Http2_Core.Hpack.Header_Block (1 .. 16);
      Hdrs_Last : Natural;
      Resp_Body : RFLX.RFLX_Types.Bytes (1 .. 4 * 1024 * 1024) :=
        (others => 0);
      Body_Last : Natural;

      PB_Last   : RFLX.RFLX_Types.Index;
      PB_OK     : Boolean;
      Frame_Last : RFLX.RFLX_Types.Index;
      Frame_OK   : Boolean;

      T_Start   : Time;
      T_End     : Time;
      Elapsed_S : Duration;
   begin
      Protobuf_Core.Wire.Encode_String_Field
        (Buffer    => PB_Buf,
         First     => 1,
         Field_Num => 1,
         Value     => Payload,
         Last      => PB_Last,
         OK        => PB_OK);
      if not PB_OK then
         Put_Line ("protobuf encode failed");
         return;
      end if;

      Grpc_Core.Framing.Encode
        (Buffer      => Frame_Buf,
         Message     => PB_Buf (1 .. PB_Last),
         Output_Last => Frame_Last,
         Output_OK   => Frame_OK);
      if not Frame_OK then
         Put_Line ("grpc framing failed");
         return;
      end if;

      Http2_Core.Connection.Attach_Buffers
        (C, Conn_Buf, Inbound_Buf, Outgoing_Buf);
      Http2_Core.Connection.Open
        (C, Host (1 .. Host_Last), Port);

      Put_Line ("[bench] ada→go " & Natural'Image (N) & " RPCs ×"
                & Natural'Image (Size) & "B payload");

      T_Start := Clock;
      for I in 1 .. N loop
         Http2_Core.Connection.Round_Trip
           (C                     => C,
            Request_Headers       => Headers,
            Request_Body          =>
              Frame_Buf (Frame_Buf'First .. Frame_Last),
            Response_Headers      => Resp_Hdrs,
            Response_Headers_Last => Hdrs_Last,
            Response_Body         => Resp_Body,
            Response_Body_Last    => Body_Last);
      end loop;
      T_End := Clock;
      Elapsed_S := T_End - T_Start;

      Http2_Core.Connection.Close (C);
      Http2_Core.Connection.Detach_Buffers
        (C, Conn_Buf, Inbound_Buf, Outgoing_Buf);

      declare
         Elapsed_Ms : constant Long_Float :=
           Long_Float (Elapsed_S) * 1000.0;
         RPS : constant Long_Float :=
           Long_Float (N) / Long_Float (Elapsed_S);
         MB_S : constant Long_Float :=
           Long_Float (N) * Long_Float (Size)
           / Long_Float (Elapsed_S) / (1024.0 * 1024.0);
         Lat_Us : constant Long_Float :=
           Long_Float (Elapsed_S) * 1_000_000.0 / Long_Float (N);
      begin
         Put_Line ("[bench] ada→go " & Natural'Image (N)
                   & " RPCs ×" & Natural'Image (Size) & "B:"
                   & Long_Float'Image (RPS) & " req/s,"
                   & Long_Float'Image (MB_S) & " MB/s,"
                   & Long_Float'Image (Lat_Us) & " us/req");
         Put_Line ("{""client"":""ada"",""server"":""go"","
                   & """rpcs"":" & Natural'Image (N)
                   & ",""payload_bytes"":" & Natural'Image (Size)
                   & ",""elapsed_ms"":" & Long_Float'Image (Elapsed_Ms)
                   & ",""rps"":" & Long_Float'Image (RPS)
                   & ",""throughput_mbps"":" & Long_Float'Image (MB_S)
                   & ",""latency_us_mean"":" & Long_Float'Image (Lat_Us)
                   & "}");
      end;
   end;
end Grpc_Bench_Client;
