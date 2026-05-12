--  grpc_tls_demo — gRPC SayHello over TLS 1.3 with a ~5 KB request.
--
--  Full verified stack: TLS 1.3 → HTTP/2 → gRPC → protobuf.
--  Request is ~5 KB to force multi-record TLS application data.
--
--  Usage:
--    # Start TLS gRPC server (Python):
--    cd overnight/grpc_helloworld && source venv/bin/activate
--    python3 grpc_helloworld_server_tls.py \
--      --cert ../../crates/tls_core/tests/fixtures/interop/ec/leaf.pem \
--      --key  ../../crates/tls_core/tests/fixtures/interop/ec/leaf.key
--
--    # Build + run (from repo root):
--    make grpc-tls-demo
--    ./crates/examples/bin/grpc_tls_demo

with Ada.Streams.Stream_IO;
with Ada.Text_IO;          use Ada.Text_IO;
with RFLX.RFLX_Types;
use type RFLX.RFLX_Types.Index;

with Grpc_Core.Framing;
with Grpc_Core.Status;
use type Grpc_Core.Status.Code;
with Http2_Core.Connection;
with Http2_Core.Hpack;
with Protobuf_Core.Wire;

procedure Grpc_Tls_Demo is

   function Load_Der (Path : String) return RFLX.RFLX_Types.Bytes is
      use Ada.Streams;
      F : Stream_IO.File_Type;
   begin
      Stream_IO.Open (F, Stream_IO.In_File, Path);
      declare
         N   : constant Stream_Element_Offset :=
           Stream_Element_Offset (Stream_IO.Size (F));
         Buf : Stream_Element_Array (1 .. N);
         Last : Stream_Element_Offset;
         Res : RFLX.RFLX_Types.Bytes
           (1 .. RFLX.RFLX_Types.Index (N));
      begin
         Stream_IO.Read (F, Buf, Last);
         Stream_IO.Close (F);
         for I in 1 .. RFLX.RFLX_Types.Index (Last) loop
            Res (I) := RFLX.RFLX_Types.Byte
              (Buf (Stream_Element_Offset (I)));
         end loop;
         return Res;
      end;
   exception
      when others =>
         if Stream_IO.Is_Open (F) then Stream_IO.Close (F); end if;
         return RFLX.RFLX_Types.Bytes'(1 .. 0 => 0);
   end Load_Der;

   EC_Dir : constant String :=
     "crates/tls_core/tests/fixtures/interop/ec";

   --  Build a ~5 KB name to force multi-record TLS application data.
   Big_Name : constant String (1 .. 5000) := (others => 'X');

   Scratch : RFLX.RFLX_Types.Bytes (1 .. 16 * 1024) := (others => 0);

   C : Http2_Core.Connection.Connection;

   Conn_Buf     : RFLX.RFLX_Types.Bytes_Ptr :=
     new RFLX.RFLX_Types.Bytes'(1 .. 32 * 1024 => 0);
   Inbound_Buf  : RFLX.RFLX_Types.Bytes_Ptr :=
     new RFLX.RFLX_Types.Bytes'(1 .. 32 * 1024 => 0);
   Outgoing_Buf : RFLX.RFLX_Types.Bytes_Ptr :=
     new RFLX.RFLX_Types.Bytes'(1 .. 32 * 1024 => 0);

begin
   Put_Line ("grpc_tls_demo: encoding 5000-byte HelloRequest");

   --  Encode protobuf: field 1 (string name) = Big_Name
   declare
      PB_Last  : RFLX.RFLX_Types.Index;
      PB_OK    : Boolean;
   begin
      Protobuf_Core.Wire.Encode_String_Field
        (Buffer    => Scratch,
         First     => 1,
         Field_Num => 1,
         Value     => Big_Name,
         Last      => PB_Last,
         OK        => PB_OK);
      if not PB_OK then
         Put_Line ("grpc_tls_demo: protobuf encode FAILED");
         return;
      end if;
      Put_Line ("grpc_tls_demo: protobuf ="
                & Natural'Image (Natural (PB_Last)) & " bytes");

      --  gRPC frame the protobuf.
      declare
         Frame_First : constant RFLX.RFLX_Types.Index := PB_Last + 1;
         Frame_Last  : RFLX.RFLX_Types.Index;
         Frame_OK    : Boolean;
         Frame_Slice : RFLX.RFLX_Types.Bytes
           (Frame_First .. Scratch'Last);
      begin
         Frame_Slice := Scratch (Frame_First .. Scratch'Last);
         Grpc_Core.Framing.Encode
           (Buffer      => Frame_Slice,
            Message     => Scratch (1 .. PB_Last),
            Output_Last => Frame_Last,
            Output_OK   => Frame_OK);
         if not Frame_OK then
            Put_Line ("grpc_tls_demo: gRPC framing FAILED");
            return;
         end if;
         Scratch (Frame_First .. Scratch'Last) := Frame_Slice;
         Put_Line ("grpc_tls_demo: gRPC frame ="
                   & Natural'Image
                       (Natural (Frame_Last - Frame_First + 1))
                   & " bytes");

         --  TLS + HTTP/2 + gRPC Round_Trip
         declare
            Trust : constant RFLX.RFLX_Types.Bytes :=
              Load_Der (EC_Dir & "/root.der");
            Headers : constant Http2_Core.Hpack.Header_Block
              (1 .. 7) :=
              (Http2_Core.Hpack.Make_Header (":method", "POST"),
               Http2_Core.Hpack.Make_Header (":scheme", "https"),
               Http2_Core.Hpack.Make_Header
                 (":path", "/helloworld.Greeter/SayHello"),
               Http2_Core.Hpack.Make_Header
                 (":authority", "localhost"),
               Http2_Core.Hpack.Make_Header
                 ("content-type", "application/grpc"),
               Http2_Core.Hpack.Make_Header ("te", "trailers"),
               Http2_Core.Hpack.Make_Header
                 ("user-agent", "grpc-ada-v0.5-tls"));
            Resp_Hdrs : Http2_Core.Hpack.Header_Block (1 .. 16);
            Hdrs_Last : Natural;
            Resp_Body : RFLX.RFLX_Types.Bytes (1 .. 4096) :=
              (others => 0);
            Body_Last : Natural;
         begin
            if Trust'Length = 0 then
               Put_Line ("grpc_tls_demo: no trust anchor");
               return;
            end if;

            Http2_Core.Connection.Attach_Buffers
              (C, Conn_Buf, Inbound_Buf, Outgoing_Buf);
            Http2_Core.Connection.Configure_Tls_Client (C, Trust);
            Http2_Core.Connection.Open (C, "127.0.0.1", 50443);
            Put_Line ("grpc_tls_demo: TLS + HTTP/2 open");

            Http2_Core.Connection.Round_Trip
              (C                     => C,
               Request_Headers       => Headers,
               Request_Body          =>
                 Scratch (Frame_First .. Frame_Last),
               Response_Headers      => Resp_Hdrs,
               Response_Headers_Last => Hdrs_Last,
               Response_Body         => Resp_Body,
               Response_Body_Last    => Body_Last);
            Put_Line ("grpc_tls_demo: round-trip ok ("
                      & Natural'Image (Body_Last)
                      & " B response)");

            --  Decode gRPC response.
            if Body_Last >= 5 then
               declare
                  Msg_Buf : RFLX.RFLX_Types.Bytes (1 .. 4096) :=
                    (others => 0);
                  Msg_Len : RFLX.RFLX_Types.Length;
                  Compressed : Boolean;
                  D_OK : Boolean;
               begin
                  Grpc_Core.Framing.Decode
                    (Input           => Resp_Body
                       (1 .. RFLX.RFLX_Types.Index (Body_Last)),
                     Message         => Msg_Buf,
                     Message_Length   => Msg_Len,
                     Compressed_Flag => Compressed,
                     Output_OK       => D_OK);
                  if D_OK then
                     Put_Line ("grpc_tls_demo: reply payload ="
                               & RFLX.RFLX_Types.Length'Image (Msg_Len)
                               & " B");
                  end if;
               end;
            end if;

            Put_Line ("grpc_tls_demo: grpc-status = (check trailers)");

            Http2_Core.Connection.Close (C);
            Http2_Core.Connection.Detach_Buffers
              (C, Conn_Buf, Inbound_Buf, Outgoing_Buf);
         end;
      end;
   end;
   Put_Line ("grpc_tls_demo: done.");
exception
   when others =>
      Put_Line ("grpc_tls_demo: exception during TLS+gRPC");
end Grpc_Tls_Demo;
