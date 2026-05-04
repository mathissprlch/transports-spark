--  greeter_mux_server — multi-stream HTTP/2 server.
--
--  v0.3 demo: a single connection accepts up to Max_Streams (16)
--  concurrent gRPC RPCs. Frames are demuxed by stream-id into
--  per-stream Stream::Open FSM contexts.
--
--  Modes (argv[1]):
--    unary           SayHello (default) — N concurrent unary calls.
--    server-stream   LotsOfReplies      — N concurrent server-streaming
--                                         calls, each producing 5 replies.
--    client-stream   LotsOfGreetings    — N concurrent client-streaming
--                                         calls, each summarizing the names.
--    bidi            BidiHello          — N concurrent bidi streams,
--                                         each request → one reply.
--  Port via argv[2] (default 50051).
--
--  Run:
--    ./bin/greeter_mux_server unary 50051
--    ./bin/greeter_mux_server server-stream 50051

with Ada.Text_IO;
with Ada.Command_Line;
with Ada.Strings.Fixed;

with RFLX.RFLX_Types;

with Http2_Core.Hpack;
with Http2_Core.Mux_Server;
with Protobuf_Core.Wire;

procedure Greeter_Mux_Server is
   use Ada.Text_IO;
   use type RFLX.RFLX_Types.Index;

   Max_Slots : constant Positive := Http2_Core.Mux_Server.Max_Streams;

   procedure Decode_Name
     (Body_Bytes : RFLX.RFLX_Types.Bytes;
      Name_Buf   : out String;
      Name_Last  : out Natural;
      OK         : out Boolean);

   procedure Decode_Name
     (Body_Bytes : RFLX.RFLX_Types.Bytes;
      Name_Buf   : out String;
      Name_Last  : out Natural;
      OK         : out Boolean)
   is
      Field_Num : Natural;
      Wire_Tp   : Natural;
      Tag_Last  : RFLX.RFLX_Types.Index;
      Tag_OK    : Boolean;
      Str_End   : RFLX.RFLX_Types.Index;
   begin
      Name_Buf := (others => ' ');
      Name_Last := 0;
      OK := False;
      if Body_Bytes'Length < 7 then return; end if;
      declare
         PB : constant RFLX.RFLX_Types.Bytes :=
           Body_Bytes (Body_Bytes'First + 5 .. Body_Bytes'Last);
      begin
         Protobuf_Core.Wire.Decode_Tag
           (PB, PB'First, Field_Num, Wire_Tp, Tag_Last, Tag_OK);
         if not Tag_OK or else Field_Num /= 1
           or else Wire_Tp /= Protobuf_Core.Wire.Wire_Length_Delim
         then return; end if;
         Protobuf_Core.Wire.Decode_String_Value
           (PB, Tag_Last + 1, Name_Buf, Name_Last, Str_End, OK);
      end;
   end Decode_Name;

   procedure Encode_Reply_Bytes
     (Text     : String;
      Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out RFLX.RFLX_Types.Index;
      OK       : out Boolean);

   procedure Encode_Reply_Bytes
     (Text     : String;
      Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out RFLX.RFLX_Types.Index;
      OK       : out Boolean)
   is
      PB_Buf  : RFLX.RFLX_Types.Bytes (1 .. 16384) := (others => 0);
      PB_Last : RFLX.RFLX_Types.Index;
   begin
      Out_Last := Out_Buf'First;
      Protobuf_Core.Wire.Encode_String_Field
        (PB_Buf, PB_Buf'First, 1, Text, PB_Last, OK);
      if not OK then return; end if;
      declare
         Len : constant Natural := Natural (PB_Last);
      begin
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
      end;
   end Encode_Reply_Bytes;

   procedure Set_Headers_And_Trailers
     (Resp_Hdrs       : in out Http2_Core.Hpack.Header_Block;
      Resp_Hdrs_Last  : out Natural;
      Trailers        : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last   : out Natural);

   procedure Set_Headers_And_Trailers
     (Resp_Hdrs       : in out Http2_Core.Hpack.Header_Block;
      Resp_Hdrs_Last  : out Natural;
      Trailers        : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last   : out Natural) is
   begin
      Resp_Hdrs (Resp_Hdrs'First) :=
        Http2_Core.Hpack.Make_Header (":status", "200");
      Resp_Hdrs (Resp_Hdrs'First + 1) :=
        Http2_Core.Hpack.Make_Header ("content-type", "application/grpc");
      Resp_Hdrs_Last := Resp_Hdrs'First + 1;
      Trailers (Trailers'First) :=
        Http2_Core.Hpack.Make_Header ("grpc-status", "0");
      Trailers_Last := Trailers'First;
   end Set_Headers_And_Trailers;

   ----------------------------------------------------------------
   --  Unary mode: SayHello (one request → one reply per stream).
   ----------------------------------------------------------------

   Call_Counter : Natural := 0;

   procedure Handle_SayHello
     (Slot                  : Positive;
      Request_Headers       : Http2_Core.Hpack.Header_Block;
      Request_Headers_Last  : Natural;
      Request_Body          : RFLX.RFLX_Types.Bytes;
      Request_Body_Last     : Natural;
      Response_Headers      : in out Http2_Core.Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Response_Body         : in out RFLX.RFLX_Types.Bytes;
      Response_Body_Last    : out Natural;
      Trailers              : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last         : out Natural);

   procedure Handle_SayHello
     (Slot                  : Positive;
      Request_Headers       : Http2_Core.Hpack.Header_Block;
      Request_Headers_Last  : Natural;
      Request_Body          : RFLX.RFLX_Types.Bytes;
      Request_Body_Last     : Natural;
      Response_Headers      : in out Http2_Core.Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Response_Body         : in out RFLX.RFLX_Types.Bytes;
      Response_Body_Last    : out Natural;
      Trailers              : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last         : out Natural)
   is
      pragma Unreferenced (Slot);
      pragma Unreferenced (Request_Headers);
      pragma Unreferenced (Request_Headers_Last);
      pragma Unreferenced (Request_Body_Last);
      Name : String (1 .. 256);
      Name_Last : Natural;
      OK : Boolean;
      Reply_Last : RFLX.RFLX_Types.Index;
   begin
      Decode_Name (Request_Body, Name, Name_Last, OK);
      if not OK then
         Name (1 .. 7) := "Unknown"; Name_Last := 7;
      end if;
      Call_Counter := Call_Counter + 1;
      Put_Line ("  ← call#" & Call_Counter'Image
                & " name=" & Name (1 .. Name_Last));

      Encode_Reply_Bytes
        (Text     => "Hello, " & Name (1 .. Name_Last) & "!",
         Out_Buf  => Response_Body,
         Out_Last => Reply_Last,
         OK       => OK);
      Response_Body_Last := Integer (Reply_Last);

      Set_Headers_And_Trailers
        (Response_Headers, Response_Headers_Last,
         Trailers, Trailers_Last);
   end Handle_SayHello;

   procedure Mux_Run_Unary is new
     Http2_Core.Mux_Server.Accept_And_Serve_Multi
       (Handle_Request => Handle_SayHello);

   ----------------------------------------------------------------
   --  Server-stream mode: LotsOfReplies (one request → 5 replies
   --  per stream). Per-slot reply counter + cached name.
   ----------------------------------------------------------------

   Total_Replies : constant := 5;
   type Slot_Index is range 1 .. Max_Slots;
   Slot_Reply_Counter : array (Slot_Index) of Natural := (others => 0);
   Slot_Name : array (Slot_Index) of String (1 .. 256) :=
     (others => (others => ' '));
   Slot_Name_Last : array (Slot_Index) of Natural := (others => 0);

   procedure SS_Setup
     (Slot                  : Positive;
      Request_Headers       : Http2_Core.Hpack.Header_Block;
      Request_Headers_Last  : Natural;
      Request_Body          : RFLX.RFLX_Types.Bytes;
      Request_Body_Last     : Natural;
      Response_Headers      : in out Http2_Core.Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Trailers              : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last         : out Natural);

   procedure SS_Setup
     (Slot                  : Positive;
      Request_Headers       : Http2_Core.Hpack.Header_Block;
      Request_Headers_Last  : Natural;
      Request_Body          : RFLX.RFLX_Types.Bytes;
      Request_Body_Last     : Natural;
      Response_Headers      : in out Http2_Core.Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Trailers              : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last         : out Natural)
   is
      pragma Unreferenced (Request_Headers);
      pragma Unreferenced (Request_Headers_Last);
      pragma Unreferenced (Request_Body_Last);
      OK : Boolean;
      S  : constant Slot_Index := Slot_Index (Slot);
   begin
      Slot_Reply_Counter (S) := 0;
      Decode_Name (Request_Body,
                   Slot_Name (S), Slot_Name_Last (S), OK);
      if not OK then
         Slot_Name (S) (1 .. 7) := "Unknown"; Slot_Name_Last (S) := 7;
      end if;
      Put_Line ("  ← stream slot" & Slot'Image
                & " name=" & Slot_Name (S) (1 .. Slot_Name_Last (S)));
      Set_Headers_And_Trailers
        (Response_Headers, Response_Headers_Last,
         Trailers, Trailers_Last);
   end SS_Setup;

   function SS_Next
     (Slot     : Positive;
      Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out RFLX.RFLX_Types.Index)
      return Boolean;

   function SS_Next
     (Slot     : Positive;
      Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out RFLX.RFLX_Types.Index)
      return Boolean
   is
      use Ada.Strings.Fixed;
      OK : Boolean;
      S  : constant Slot_Index := Slot_Index (Slot);
   begin
      Out_Last := Out_Buf'First;
      if Slot_Reply_Counter (S) >= Total_Replies then
         return False;
      end if;
      Slot_Reply_Counter (S) := Slot_Reply_Counter (S) + 1;
      Encode_Reply_Bytes
        ("Hello, " & Slot_Name (S) (1 .. Slot_Name_Last (S))
         & "! [" & Trim (Slot_Reply_Counter (S)'Image, Ada.Strings.Both)
         & "/" & Trim (Total_Replies'Image, Ada.Strings.Both) & "]",
         Out_Buf, Out_Last, OK);
      return OK;
   end SS_Next;

   procedure Mux_Run_SS is new
     Http2_Core.Mux_Server.Accept_And_Serve_Multi_Server_Stream
       (Setup_Response => SS_Setup,
        Next_Reply     => SS_Next);

   ----------------------------------------------------------------
   --  Client-stream mode: LotsOfGreetings (N requests → 1 reply).
   ----------------------------------------------------------------

   Slot_Names_Buf : array (Slot_Index) of String (1 .. 4096) :=
     (others => (others => ' '));
   Slot_Names_Last : array (Slot_Index) of Natural := (others => 0);

   procedure CS_On_Message
     (Slot    : Positive;
      Message : RFLX.RFLX_Types.Bytes);

   procedure CS_On_Message
     (Slot    : Positive;
      Message : RFLX.RFLX_Types.Bytes)
   is
      Field_Num : Natural;
      Wire_Tp   : Natural;
      Tag_Last  : RFLX.RFLX_Types.Index;
      Tag_OK    : Boolean;
      Str_End   : RFLX.RFLX_Types.Index;
      Name_Buf  : String (1 .. 256);
      Name_Last : Natural;
      OK        : Boolean;
      S         : constant Slot_Index := Slot_Index (Slot);
   begin
      if Message'Length < 2 then return; end if;
      Protobuf_Core.Wire.Decode_Tag
        (Message, Message'First, Field_Num, Wire_Tp, Tag_Last, Tag_OK);
      if not Tag_OK or else Field_Num /= 1
        or else Wire_Tp /= Protobuf_Core.Wire.Wire_Length_Delim
      then return; end if;
      Protobuf_Core.Wire.Decode_String_Value
        (Message, Tag_Last + 1, Name_Buf, Name_Last, Str_End, OK);
      if not OK or else Name_Last = 0 then return; end if;

      if Slot_Names_Last (S) > 0 then
         Slot_Names_Buf (S) (Slot_Names_Last (S) + 1
                             .. Slot_Names_Last (S) + 2) := ", ";
         Slot_Names_Last (S) := Slot_Names_Last (S) + 2;
      end if;
      Slot_Names_Buf (S) (Slot_Names_Last (S) + 1
                          .. Slot_Names_Last (S) + Name_Last) :=
        Name_Buf (1 .. Name_Last);
      Slot_Names_Last (S) := Slot_Names_Last (S) + Name_Last;
      Put_Line ("  ← slot" & Slot'Image & " request "
                & Name_Buf (1 .. Name_Last));
   end CS_On_Message;

   procedure CS_Build
     (Slot                  : Positive;
      Request_Headers       : Http2_Core.Hpack.Header_Block;
      Request_Headers_Last  : Natural;
      Response_Headers      : in out Http2_Core.Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Response_Body         : in out RFLX.RFLX_Types.Bytes;
      Response_Body_Last    : out Natural;
      Trailers              : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last         : out Natural);

   procedure CS_Build
     (Slot                  : Positive;
      Request_Headers       : Http2_Core.Hpack.Header_Block;
      Request_Headers_Last  : Natural;
      Response_Headers      : in out Http2_Core.Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Response_Body         : in out RFLX.RFLX_Types.Bytes;
      Response_Body_Last    : out Natural;
      Trailers              : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last         : out Natural)
   is
      pragma Unreferenced (Request_Headers);
      pragma Unreferenced (Request_Headers_Last);
      OK : Boolean;
      Reply_Last : RFLX.RFLX_Types.Index;
      S : constant Slot_Index := Slot_Index (Slot);
   begin
      Encode_Reply_Bytes
        ("Hello to all: "
         & Slot_Names_Buf (S) (1 .. Slot_Names_Last (S))
         & "!",
         Response_Body, Reply_Last, OK);
      Response_Body_Last := Integer (Reply_Last);
      --  Reset for slot reuse.
      Slot_Names_Last (S) := 0;
      Set_Headers_And_Trailers
        (Response_Headers, Response_Headers_Last,
         Trailers, Trailers_Last);
   end CS_Build;

   procedure Mux_Run_CS is new
     Http2_Core.Mux_Server.Accept_And_Serve_Multi_Client_Stream
       (On_Request_Message => CS_On_Message,
        Build_Response     => CS_Build);

   ----------------------------------------------------------------
   --  Bidi mode: BidiHello (each ping → one pong, full duplex).
   ----------------------------------------------------------------

   --  Per-slot pending name from the latest inbound message,
   --  plus a "have-pending" flag the Next_Reply can drain.
   Slot_Pending_Name : array (Slot_Index) of String (1 .. 256) :=
     (others => (others => ' '));
   Slot_Pending_Last : array (Slot_Index) of Natural := (others => 0);

   procedure Bidi_Setup
     (Slot                  : Positive;
      Request_Headers       : Http2_Core.Hpack.Header_Block;
      Request_Headers_Last  : Natural;
      Response_Headers      : in out Http2_Core.Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Trailers              : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last         : out Natural);

   procedure Bidi_Setup
     (Slot                  : Positive;
      Request_Headers       : Http2_Core.Hpack.Header_Block;
      Request_Headers_Last  : Natural;
      Response_Headers      : in out Http2_Core.Hpack.Header_Block;
      Response_Headers_Last : out Natural;
      Trailers              : in out Http2_Core.Hpack.Header_Block;
      Trailers_Last         : out Natural)
   is
      pragma Unreferenced (Request_Headers);
      pragma Unreferenced (Request_Headers_Last);
      S : constant Slot_Index := Slot_Index (Slot);
   begin
      Slot_Pending_Last (S) := 0;
      Set_Headers_And_Trailers
        (Response_Headers, Response_Headers_Last,
         Trailers, Trailers_Last);
   end Bidi_Setup;

   procedure Bidi_On_Message
     (Slot    : Positive;
      Message : RFLX.RFLX_Types.Bytes);

   procedure Bidi_On_Message
     (Slot    : Positive;
      Message : RFLX.RFLX_Types.Bytes)
   is
      Field_Num : Natural;
      Wire_Tp   : Natural;
      Tag_Last  : RFLX.RFLX_Types.Index;
      Tag_OK    : Boolean;
      Str_End   : RFLX.RFLX_Types.Index;
      OK        : Boolean;
      S         : constant Slot_Index := Slot_Index (Slot);
   begin
      if Message'Length < 2 then return; end if;
      Protobuf_Core.Wire.Decode_Tag
        (Message, Message'First, Field_Num, Wire_Tp, Tag_Last, Tag_OK);
      if not Tag_OK or else Field_Num /= 1
        or else Wire_Tp /= Protobuf_Core.Wire.Wire_Length_Delim
      then return; end if;
      Protobuf_Core.Wire.Decode_String_Value
        (Message, Tag_Last + 1,
         Slot_Pending_Name (S), Slot_Pending_Last (S),
         Str_End, OK);
      if OK and then Slot_Pending_Last (S) > 0 then
         Put_Line ("  ← slot" & Slot'Image & " ping "
                   & Slot_Pending_Name (S) (1 .. Slot_Pending_Last (S)));
      end if;
   end Bidi_On_Message;

   function Bidi_Next
     (Slot     : Positive;
      Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out RFLX.RFLX_Types.Index)
      return Boolean;

   function Bidi_Next
     (Slot     : Positive;
      Out_Buf  : in out RFLX.RFLX_Types.Bytes;
      Out_Last : out RFLX.RFLX_Types.Index)
      return Boolean
   is
      OK : Boolean;
      S  : constant Slot_Index := Slot_Index (Slot);
   begin
      Out_Last := Out_Buf'First;
      if Slot_Pending_Last (S) = 0 then return False; end if;
      Encode_Reply_Bytes
        ("Hi, " & Slot_Pending_Name (S) (1 .. Slot_Pending_Last (S))
         & "!",
         Out_Buf, Out_Last, OK);
      Slot_Pending_Last (S) := 0;
      return OK;
   end Bidi_Next;

   procedure Mux_Run_Bidi is new
     Http2_Core.Mux_Server.Accept_And_Serve_Multi_Bidi_Stream
       (Setup_Response     => Bidi_Setup,
        On_Request_Message => Bidi_On_Message,
        Next_Reply         => Bidi_Next);

   ----------------------------------------------------------------

   L : Http2_Core.Mux_Server.Listener;

   Buffer_Size : constant := 16384;
   Conn_Buf : RFLX.RFLX_Types.Bytes_Ptr :=
     new RFLX.RFLX_Types.Bytes'(1 .. Buffer_Size => 0);

   Mode : String (1 .. 32) := (others => ' ');
   Mode_Last : Natural := 0;
   Port : Natural := 50051;
begin
   if Ada.Command_Line.Argument_Count >= 1 then
      declare
         A : constant String := Ada.Command_Line.Argument (1);
      begin
         Mode (1 .. A'Length) := A;
         Mode_Last := A'Length;
      end;
   else
      Mode (1 .. 5) := "unary"; Mode_Last := 5;
   end if;
   if Ada.Command_Line.Argument_Count >= 2 then
      Port := Natural'Value (Ada.Command_Line.Argument (2));
   end if;

   Http2_Core.Mux_Server.Listen (L, "0.0.0.0", Port);
   Http2_Core.Mux_Server.Attach_Buffer (L, Conn_Buf);

   Put_Line ("greeter_mux_server: mode=" & Mode (1 .. Mode_Last)
             & " port=" & Port'Image
             & " (max" & Http2_Core.Mux_Server.Max_Streams'Image
             & " concurrent streams per connection)");

   loop
      Put_Line ("greeter_mux_server: awaiting client...");
      begin
         if Mode (1 .. Mode_Last) = "server-stream" then
            Mux_Run_SS (L);
         elsif Mode (1 .. Mode_Last) = "client-stream" then
            Mux_Run_CS (L);
         elsif Mode (1 .. Mode_Last) = "bidi" then
            Mux_Run_Bidi (L);
         else
            Mux_Run_Unary (L);
         end if;
         Put_Line ("greeter_mux_server: connection closed");
      exception
         when others =>
            Put_Line ("greeter_mux_server: connection error, retrying");
      end;
   end loop;
end Greeter_Mux_Server;
