--  greeter_client_v02 — gRPC unary RPC over the v0.2 SPARK stack.
--
--  Wires the three independently-verified layers together:
--
--    Protobuf_Core.Wire     encode HelloRequest / decode HelloReply
--    Grpc_Core.Framing      5-byte length-prefix message frame
--    Http2_Core.Connection  HTTP/2 transport (preface + SETTINGS +
--                           HEADERS + DATA + trailing HEADERS)
--
--  Calls helloworld.Greeter/SayHello on the Python reference server
--  (overnight/grpc_helloworld_server.py) and prints the reply. No AWS,
--  no v0.1 codegen, no heap traffic in the library code paths.
--
--  Wire layout produced for SayHello("World"):
--
--    HEADERS frame:
--      :method  POST
--      :scheme  http
--      :path    /helloworld.Greeter/SayHello
--      :authority <host>:<port>
--      content-type application/grpc
--      te         trailers
--      user-agent grpc-ada-v0.2
--    DATA frame:
--      <gRPC framing: 1B compression flag + 4B BE length>
--      <protobuf HelloRequest = 0x0A 0x05 'W' 'o' 'r' 'l' 'd'>
--
--  Server replies with HEADERS (:status=200, content-type) + DATA
--  (gRPC-framed protobuf HelloReply) + trailing HEADERS
--  (grpc-status=0). Connection.Round_Trip aggregates the lot; we
--  strip the framing prefix and decode the protobuf reply.

with Ada.Text_IO;
with Ada.Command_Line;

with RFLX.RFLX_Types;

with Http2_Core.Hpack;
with Http2_Core.Connection;
with Grpc_Core.Framing;
with Grpc_Core.Status;
with Protobuf_Core.Wire;

procedure Greeter_Client_V02 is

   use Ada.Text_IO;
   use type RFLX.RFLX_Types.Index;
   use type RFLX.RFLX_Types.Length;
   use type Grpc_Core.Status.Code;

   --  Default endpoint matches grpc_helloworld_server.py.
   Default_Host : constant String  := "127.0.0.1";
   Default_Port : constant Natural := 50_051;

   Host : String (1 .. 64) := (others => ' ');
   Host_Last : Natural := 0;
   Port : Natural := Default_Port;

   --  Name to greet — argv[1] if provided.
   Name_Buf  : String (1 .. 256) := (others => ' ');
   Name_Last : Natural := 0;

   procedure Set_Host (Spec : String);
   procedure Set_Host (Spec : String) is
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
   end Set_Host;

   procedure Print_Hex (S : String);
   procedure Print_Hex (S : String) is
      Hex : constant String := "0123456789abcdef";
   begin
      for C of S loop
         declare
            B : constant Natural := Character'Pos (C);
         begin
            Put (Hex (Hex'First + B / 16));
            Put (Hex (Hex'First + B mod 16));
            Put (' ');
         end;
      end loop;
   end Print_Hex;

begin
   --  Parse argv: [name [host:port]]
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

   Put_Line ("greeter_client_v02: SPARK stack end-to-end gRPC");
   Put_Line ("  target  = " & Host (1 .. Host_Last) & ":" & Port'Image);
   Put_Line ("  call    = helloworld.Greeter/SayHello");
   Put_Line ("  request = HelloRequest{name='"
             & Name_Buf (1 .. Name_Last) & "'}");
   New_Line;

   ----------------------------------------------------------------
   --  Build the request.
   --
   --    Outer scratch buffer holds, in order:
   --      [0 .. 31]    protobuf-encoded HelloRequest
   --      [40 .. 99]   gRPC-framed wrapper of the same
   ----------------------------------------------------------------

   declare
      Scratch : RFLX.RFLX_Types.Bytes (1 .. 512) := (others => 0);
      PB_Last : RFLX.RFLX_Types.Index;
      PB_OK   : Boolean;

      --  Encode HelloRequest = { string name = 1; } at Scratch (1..).
      PB_First : constant RFLX.RFLX_Types.Index := 1;
   begin
      Protobuf_Core.Wire.Encode_String_Field
        (Buffer    => Scratch,
         First     => PB_First,
         Field_Num => 1,
         Value     => Name_Buf (1 .. Name_Last),
         Last      => PB_Last,
         OK        => PB_OK);
      if not PB_OK then
         Put_Line ("encode HelloRequest: FAILED");
         Ada.Command_Line.Set_Exit_Status (Ada.Command_Line.Failure);
         return;
      end if;

      Put ("  HelloRequest bytes ("
           & Natural'Image (Natural (PB_Last - PB_First + 1)) & "B):  ");
      declare
         Hex : constant String := "0123456789abcdef";
      begin
         for I in PB_First .. PB_Last loop
            declare
               B : constant Natural := Natural (Scratch (I));
            begin
               Put (Hex (Hex'First + B / 16));
               Put (Hex (Hex'First + B mod 16));
               Put (' ');
            end;
         end loop;
      end;
      New_Line;

      --  gRPC frame the protobuf payload at Scratch (33..).
      declare
         Frame_First : constant RFLX.RFLX_Types.Index := 33;
         Frame_Last  : RFLX.RFLX_Types.Index;
         Frame_OK    : Boolean;
         Frame_Slice : RFLX.RFLX_Types.Bytes
           (Frame_First .. Scratch'Last);
      begin
         Frame_Slice := Scratch (Frame_First .. Scratch'Last);
         Grpc_Core.Framing.Encode
           (Buffer      => Frame_Slice,
            Message     => Scratch (PB_First .. PB_Last),
            Output_Last => Frame_Last,
            Output_OK   => Frame_OK);
         if not Frame_OK then
            Put_Line ("gRPC framing encode: FAILED");
            Ada.Command_Line.Set_Exit_Status
              (Ada.Command_Line.Failure);
            return;
         end if;
         Scratch (Frame_First .. Scratch'Last) := Frame_Slice;

         --  Now Scratch (Frame_First .. Frame_Last) is the framed
         --  payload. We'll hand it as Request_Body to Round_Trip.
         declare
            C       : Http2_Core.Connection.Connection;
            Conn_Buf     : RFLX.RFLX_Types.Bytes_Ptr :=
              new RFLX.RFLX_Types.Bytes'
                (1 .. 16 * 1024 + 64 => 0);
            Inbound_Buf  : RFLX.RFLX_Types.Bytes_Ptr :=
              new RFLX.RFLX_Types.Bytes'
                (1 .. 16 * 1024 + 64 => 0);
            Outgoing_Buf : RFLX.RFLX_Types.Bytes_Ptr :=
              new RFLX.RFLX_Types.Bytes'
                (1 .. 16 * 1024 + 64 => 0);

            Headers : constant Http2_Core.Hpack.Header_Block (1 .. 7) :=
              (Http2_Core.Hpack.Make_Header (":method", "POST"),
               Http2_Core.Hpack.Make_Header (":scheme", "http"),
               Http2_Core.Hpack.Make_Header
                 (":path", "/helloworld.Greeter/SayHello"),
               Http2_Core.Hpack.Make_Header
                 (":authority", Host (1 .. Host_Last)),
               Http2_Core.Hpack.Make_Header
                 ("content-type", "application/grpc"),
               Http2_Core.Hpack.Make_Header
                 ("te", "trailers"),
               Http2_Core.Hpack.Make_Header
                 ("user-agent", "grpc-ada-v0.2"));

            Resp_Hdrs : Http2_Core.Hpack.Header_Block (1 .. 16);
            Hdrs_Last : Natural;
            Resp_Body : RFLX.RFLX_Types.Bytes (1 .. 4096) :=
              (others => 0);
            Body_Last : Natural;
         begin
            Http2_Core.Connection.Attach_Buffers
              (C, Conn_Buf, Inbound_Buf, Outgoing_Buf);
            Http2_Core.Connection.Open
              (C    => C,
               Host => Host (1 .. Host_Last),
               Port => Port);
            Put_Line ("  http/2 connection: open + preface ok");

            Http2_Core.Connection.Round_Trip
              (C                     => C,
               Request_Headers       => Headers,
               Request_Body          =>
                 Scratch (Frame_First .. Frame_Last),
               Response_Headers      => Resp_Hdrs,
               Response_Headers_Last => Hdrs_Last,
               Response_Body         => Resp_Body,
               Response_Body_Last    => Body_Last);
            Put_Line ("  http/2 round trip: ok ("
                      & Natural'Image (Body_Last) & "B body)");

            Http2_Core.Connection.Close (C);
            Http2_Core.Connection.Detach_Buffers
              (C, Conn_Buf, Inbound_Buf, Outgoing_Buf);
            RFLX.RFLX_Types.Free (Conn_Buf);
            RFLX.RFLX_Types.Free (Inbound_Buf);
            RFLX.RFLX_Types.Free (Outgoing_Buf);

            ----------------------------------------------------------
            --  Inspect headers (server's trailing HEADERS overwrites
            --  the initial set in v0.2 — see SCOPE.md).
            ----------------------------------------------------------

            New_Line;
            Put_Line ("response headers ("
                      & Natural'Image (Hdrs_Last) & "):");
            for I in 1 .. Hdrs_Last loop
               declare
                  H : Http2_Core.Hpack.Header_Field renames Resp_Hdrs (I);
               begin
                  Put_Line ("  "
                            & H.Name (1 .. H.Name_Last)
                            & " = "
                            & H.Value (1 .. H.Value_Last));
               end;
            end loop;

            ----------------------------------------------------------
            --  Walk headers for grpc-status. 0 = OK.
            ----------------------------------------------------------

            declare
               Grpc_Status_Code : Grpc_Core.Status.Code :=
                 Grpc_Core.Status.Unknown;
               Status_Valid : Boolean := False;
            begin
               for I in 1 .. Hdrs_Last loop
                  declare
                     H : Http2_Core.Hpack.Header_Field renames
                       Resp_Hdrs (I);
                  begin
                     if H.Name (1 .. H.Name_Last) = "grpc-status" then
                        Grpc_Core.Status.From_String
                          (H.Value (1 .. H.Value_Last),
                           Grpc_Status_Code, Status_Valid);
                     end if;
                  end;
               end loop;
               New_Line;
               if Status_Valid then
                  Put_Line ("grpc-status = "
                            & Grpc_Core.Status.Code'Image
                                (Grpc_Status_Code));
                  if Grpc_Status_Code /= Grpc_Core.Status.OK then
                     Put_Line ("RPC failed at gRPC layer.");
                     Ada.Command_Line.Set_Exit_Status
                       (Ada.Command_Line.Failure);
                     return;
                  end if;
               else
                  Put_Line ("grpc-status not present in response trailers");
                  Ada.Command_Line.Set_Exit_Status
                    (Ada.Command_Line.Failure);
                  return;
               end if;
            end;

            ----------------------------------------------------------
            --  Decode the response body: 5-byte gRPC framing prefix
            --  + protobuf HelloReply.
            ----------------------------------------------------------

            if Body_Last < Integer (Resp_Body'First) + 4 then
               Put_Line ("response body too short for gRPC frame");
               Ada.Command_Line.Set_Exit_Status
                 (Ada.Command_Line.Failure);
               return;
            end if;

            declare
               PB_Reply  : RFLX.RFLX_Types.Bytes (1 .. 4096) :=
                 (others => 0);
               PB_Len    : RFLX.RFLX_Types.Length;
               Compressed : Boolean;
               Frame_OK_R : Boolean;
            begin
               Grpc_Core.Framing.Decode
                 (Input           =>
                    Resp_Body
                      (Resp_Body'First ..
                         RFLX.RFLX_Types.Index (Body_Last)),
                  Message         => PB_Reply,
                  Message_Length  => PB_Len,
                  Compressed_Flag => Compressed,
                  Output_OK       => Frame_OK_R);
               if not Frame_OK_R then
                  Put_Line ("gRPC framing decode: FAILED");
                  Ada.Command_Line.Set_Exit_Status
                    (Ada.Command_Line.Failure);
                  return;
               end if;
               if Compressed then
                  Put_Line ("server sent compressed message; "
                            & "v0.2 doesn't decompress.");
                  Ada.Command_Line.Set_Exit_Status
                    (Ada.Command_Line.Failure);
                  return;
               end if;

               Put ("  HelloReply protobuf ("
                    & Natural'Image (Natural (PB_Len)) & "B):    ");
               declare
                  Hex : constant String := "0123456789abcdef";
               begin
                  for I in PB_Reply'First ..
                            PB_Reply'First +
                              RFLX.RFLX_Types.Index (PB_Len) - 1
                  loop
                     declare
                        B : constant Natural :=
                          Natural (PB_Reply (I));
                     begin
                        Put (Hex (Hex'First + B / 16));
                        Put (Hex (Hex'First + B mod 16));
                        Put (' ');
                     end;
                  end loop;
               end;
               New_Line;

               --  Parse: tag (field 1, length-delim) + string.
               declare
                  Tag_Last  : RFLX.RFLX_Types.Index;
                  Tag_OK    : Boolean;
                  Field_Num : Natural;
                  Wire_Tp   : Natural;
                  Reply_Str : String (1 .. 1024) := (others => ' ');
                  Reply_Last : Natural;
                  Str_End   : RFLX.RFLX_Types.Index;
                  Str_OK    : Boolean;
               begin
                  if PB_Len < 1 then
                     Put_Line ("HelloReply payload empty");
                     Ada.Command_Line.Set_Exit_Status
                       (Ada.Command_Line.Failure);
                     return;
                  end if;

                  Protobuf_Core.Wire.Decode_Tag
                    (Input     => PB_Reply
                       (PB_Reply'First ..
                          PB_Reply'First +
                            RFLX.RFLX_Types.Index (PB_Len) - 1),
                     First     => PB_Reply'First,
                     Field_Num => Field_Num,
                     Wire      => Wire_Tp,
                     Last      => Tag_Last,
                     OK        => Tag_OK);
                  if not Tag_OK then
                     Put_Line ("HelloReply tag decode: FAILED");
                     Ada.Command_Line.Set_Exit_Status
                       (Ada.Command_Line.Failure);
                     return;
                  end if;
                  if Field_Num /= 1 or else
                     Wire_Tp /=
                       Protobuf_Core.Wire.Wire_Length_Delim
                  then
                     Put_Line ("HelloReply: unexpected tag "
                               & " field=" & Field_Num'Image
                               & " wire=" & Wire_Tp'Image);
                     Ada.Command_Line.Set_Exit_Status
                       (Ada.Command_Line.Failure);
                     return;
                  end if;

                  Protobuf_Core.Wire.Decode_String_Value
                    (Input      => PB_Reply
                       (PB_Reply'First ..
                          PB_Reply'First +
                            RFLX.RFLX_Types.Index (PB_Len) - 1),
                     First      => Tag_Last + 1,
                     Value      => Reply_Str,
                     Value_Last => Reply_Last,
                     Last       => Str_End,
                     OK         => Str_OK);
                  if not Str_OK then
                     Put_Line ("HelloReply string decode: FAILED");
                     Ada.Command_Line.Set_Exit_Status
                       (Ada.Command_Line.Failure);
                     return;
                  end if;

                  New_Line;
                  Put_Line ("==============================================");
                  Put_Line ("HelloReply.message = "
                            & '"' & Reply_Str (1 .. Reply_Last) & '"');
                  Put_Line ("==============================================");
                  Put_Line ("greeter_client_v02: SUCCESS");
               end;
            end;
         end;
      end;
   end;

end Greeter_Client_V02;
