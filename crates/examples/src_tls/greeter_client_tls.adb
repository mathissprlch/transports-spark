--  greeter_client_tls -- gRPC SayHello over TLS 1.3.
--
--  Same logic as greeter_client_v02, but the transport is our
--  pure-Ada/SPARK TLS 1.3. Build with -XTRANSPORT=tls.
--
--  Usage: greeter_client_tls [name [host:port]]

with Ada.Text_IO;
with Ada.Command_Line;
with Ada.Directories;
with Ada.Streams.Stream_IO;

with RFLX.RFLX_Types;

with Http2_Core.Hpack;
with Http2_Core.Connection;
with Http2_Core.Transport;
with Grpc_Core.Framing;
with Grpc_Core.Status;
with Protobuf_Core.Wire;

procedure Greeter_Client_Tls is

   use Ada.Text_IO;
   use type RFLX.RFLX_Types.Index;
   use type RFLX.RFLX_Types.Length;
   use type Grpc_Core.Status.Code;

   Root_Path : constant String :=
     "../tls_core/tests/fixtures/interop/ec/root.der";

   function Load_File (Path : String) return RFLX.RFLX_Types.Bytes;
   function Load_File (Path : String) return RFLX.RFLX_Types.Bytes is
      use Ada.Streams;
      F    : Ada.Streams.Stream_IO.File_Type;
      Sz   : constant Natural :=
        Natural (Ada.Directories.Size (Path));
      Buf  : Stream_Element_Array (1 .. Stream_Element_Offset (Sz));
      Last : Stream_Element_Offset;
      Result : RFLX.RFLX_Types.Bytes (1 .. RFLX.RFLX_Types.Index (Sz));
   begin
      Ada.Streams.Stream_IO.Open (F, Ada.Streams.Stream_IO.In_File, Path);
      Ada.Streams.Read (Ada.Streams.Stream_IO.Stream (F).all, Buf, Last);
      Ada.Streams.Stream_IO.Close (F);
      for I in Result'Range loop
         Result (I) := RFLX.RFLX_Types.Byte (
           Buf (Stream_Element_Offset (I)));
      end loop;
      return Result;
   end Load_File;

   Default_Host : constant String  := "127.0.0.1";
   Default_Port : constant Natural := 50_051;

   Host      : String (1 .. 64) := (others => ' ');
   Host_Last : Natural := 0;
   Port      : Natural := Default_Port;

   Name_Buf  : String (1 .. 256) := (others => ' ');
   Name_Last : Natural := 0;

   procedure Set_Host (Spec : String);
   procedure Set_Host (Spec : String) is
      Colon_At : Natural := 0;
   begin
      for I in Spec'Range loop
         if Spec (I) = ':' then Colon_At := I; exit; end if;
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
   end Set_Host;

begin
   if Ada.Command_Line.Argument_Count >= 1 then
      declare
         A : constant String := Ada.Command_Line.Argument (1);
      begin
         Name_Buf (1 .. A'Length) := A;
         Name_Last := A'Length;
      end;
   else
      Name_Buf (1 .. 5) := "World";
      Name_Last := 5;
   end if;

   if Ada.Command_Line.Argument_Count >= 2 then
      Set_Host (Ada.Command_Line.Argument (2));
   else
      Host (1 .. Default_Host'Length) := Default_Host;
      Host_Last := Default_Host'Length;
   end if;

   Put_Line ("greeter_client_tls: gRPC over TLS 1.3");
   Put_Line ("  target = " & Host (1 .. Host_Last) & ":" & Port'Image);
   Put_Line ("  name   = " & Name_Buf (1 .. Name_Last));

   declare
      Scratch : RFLX.RFLX_Types.Bytes (1 .. 512) := (others => 0);
      PB_Last : RFLX.RFLX_Types.Index;
      PB_OK   : Boolean;
   begin
      Protobuf_Core.Wire.Encode_String_Field
        (Scratch, 1, 1, Name_Buf (1 .. Name_Last), PB_Last, PB_OK);
      if not PB_OK then
         Put_Line ("encode HelloRequest: FAILED");
         return;
      end if;

      declare
         Frame_First : constant RFLX.RFLX_Types.Index := 33;
         Frame_Last  : RFLX.RFLX_Types.Index;
         Frame_OK    : Boolean;
         Frame_Slice : RFLX.RFLX_Types.Bytes
           (Frame_First .. Scratch'Last);
      begin
         Frame_Slice := Scratch (Frame_First .. Scratch'Last);
         Grpc_Core.Framing.Encode
           (Frame_Slice, Scratch (1 .. PB_Last), Frame_Last, Frame_OK);
         if not Frame_OK then
            Put_Line ("gRPC framing: FAILED");
            return;
         end if;
         Scratch (Frame_First .. Scratch'Last) := Frame_Slice;

         declare
            C            : aliased Http2_Core.Connection.Connection;
            Conn_Buf     : RFLX.RFLX_Types.Bytes_Ptr :=
              new RFLX.RFLX_Types.Bytes'(1 .. 16 * 1024 + 64 => 0);
            Inbound_Buf  : RFLX.RFLX_Types.Bytes_Ptr :=
              new RFLX.RFLX_Types.Bytes'(1 .. 16 * 1024 + 64 => 0);
            Outgoing_Buf : RFLX.RFLX_Types.Bytes_Ptr :=
              new RFLX.RFLX_Types.Bytes'(1 .. 16 * 1024 + 64 => 0);

            Root_Der : constant RFLX.RFLX_Types.Bytes :=
              Load_File (Root_Path);

            Headers : constant Http2_Core.Hpack.Header_Block (1 .. 7) :=
              (Http2_Core.Hpack.Make_Header (":method", "POST"),
               Http2_Core.Hpack.Make_Header (":scheme", "https"),
               Http2_Core.Hpack.Make_Header
                 (":path", "/helloworld.Greeter/SayHello"),
               Http2_Core.Hpack.Make_Header
                 (":authority", Host (1 .. Host_Last)),
               Http2_Core.Hpack.Make_Header
                 ("content-type", "application/grpc"),
               Http2_Core.Hpack.Make_Header ("te", "trailers"),
               Http2_Core.Hpack.Make_Header
                 ("user-agent", "grpc-ada-tls-v0.5"));

            Resp_Hdrs : Http2_Core.Hpack.Header_Block (1 .. 16);
            Hdrs_Last : Natural;
            Resp_Body : RFLX.RFLX_Types.Bytes (1 .. 4096) :=
              (others => 0);
            Body_Last : Natural;
         begin
            Http2_Core.Connection.Attach_Buffers
              (C, Conn_Buf, Inbound_Buf, Outgoing_Buf);

            Http2_Core.Transport.Set_Trust_Anchor
              (Http2_Core.Connection.Get_Transport (C).all,
               Root_Der);

            Http2_Core.Connection.Open
              (C, Host (1 .. Host_Last), Port);
            Put_Line ("  tls + h2 connection: open");

            Http2_Core.Connection.Round_Trip
              (C, Headers,
               Scratch (Frame_First .. Frame_Last),
               Resp_Hdrs, Hdrs_Last,
               Resp_Body, Body_Last);
            Put_Line ("  round trip: ok (" & Body_Last'Image & "B)");

            Http2_Core.Connection.Close (C);
            Http2_Core.Connection.Detach_Buffers
              (C, Conn_Buf, Inbound_Buf, Outgoing_Buf);
            RFLX.RFLX_Types.Free (Conn_Buf);
            RFLX.RFLX_Types.Free (Inbound_Buf);
            RFLX.RFLX_Types.Free (Outgoing_Buf);

            for I in 1 .. Hdrs_Last loop
               declare
                  H : Http2_Core.Hpack.Header_Field renames Resp_Hdrs (I);
               begin
                  if H.Name (1 .. H.Name_Last) = "grpc-status" then
                     declare
                        Code : Grpc_Core.Status.Code;
                        Valid : Boolean;
                     begin
                        Grpc_Core.Status.From_String
                          (H.Value (1 .. H.Value_Last), Code, Valid);
                        if Valid and then Code = Grpc_Core.Status.OK then
                           Put_Line ("  grpc-status: OK");
                        else
                           Put_Line ("  grpc-status: " & Code'Image);
                        end if;
                     end;
                  end if;
               end;
            end loop;

            if Body_Last >= Integer (Resp_Body'First) + 5 then
               declare
                  PB_Reply : RFLX.RFLX_Types.Bytes (1 .. 4096) :=
                    (others => 0);
                  PB_Len   : RFLX.RFLX_Types.Length;
                  Comp     : Boolean;
                  Dec_OK   : Boolean;
               begin
                  Grpc_Core.Framing.Decode
                    (Resp_Body (Resp_Body'First ..
                       RFLX.RFLX_Types.Index (Body_Last)),
                     PB_Reply, PB_Len, Comp, Dec_OK);
                  if Dec_OK and then PB_Len > 0 then
                     declare
                        Reply_Str  : String (1 .. 1024) := (others => ' ');
                        Reply_Last : Natural;
                        Tag_Last   : RFLX.RFLX_Types.Index;
                        Tag_OK     : Boolean;
                        FN         : Natural;
                        WT         : Natural;
                        Str_End    : RFLX.RFLX_Types.Index;
                        Str_OK     : Boolean;
                     begin
                        Protobuf_Core.Wire.Decode_Tag
                          (PB_Reply (1 .. RFLX.RFLX_Types.Index (PB_Len)),
                           1, FN, WT, Tag_Last, Tag_OK);
                        if Tag_OK and then FN = 1 then
                           Protobuf_Core.Wire.Decode_String_Value
                             (PB_Reply (1 ..
                                RFLX.RFLX_Types.Index (PB_Len)),
                              Tag_Last + 1,
                              Reply_Str, Reply_Last, Str_End, Str_OK);
                           if Str_OK then
                              Put_Line ("  reply: " &
                                Reply_Str (1 .. Reply_Last));
                           end if;
                        end if;
                     end;
                  end if;
               end;
            end if;

            Put_Line ("greeter_client_tls: SUCCESS");
         end;
      end;
   end;
end Greeter_Client_Tls;
