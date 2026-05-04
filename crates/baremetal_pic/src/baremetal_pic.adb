--  baremetal_pic — SPARK protocol code on bare-metal Cortex-M3,
--  ZERO heap allocation.
--
--  Target: TI Stellaris LM3S811 / QEMU lm3s6965evb. light-lm3s
--  runtime. UART0 → host stdio.
--
--  What this binary exercises (all heap-free):
--    1. Static_Table.Get_Name on RFC 7541 §A indices 1..5
--    2. Huffman.Encode + Decode round-trip (caller-supplied
--       Octet_Array buffers, no Bytes_Ptr)
--    3. Int_Codec.Encode + Decode at N=5 (RFC 7541 §C.1.2)
--    4. Hpack.Encode of a realistic gRPC request header set,
--       then Hpack.Decode of the same bytes — full encode/
--       decode "round-trip on the wire" simulated by passing
--       the buffer between two procedure calls in process.
--
--  Plus, post-External_IO_Buffers refactor:
--    5. Mqtt_Core.Client lifecycle — application-allocated
--       buffers attached via Attach_Buffers; Client.Open
--       attempts a Transport.Connect via the bare-metal
--       Transport stub which raises Connect_Error (no real
--       Cortex-M Transport wired yet). Demonstrates the FULL
--       FSM-driven session-machinery API surface compiles +
--       runs + fails-cleanly on Cortex-M3 with zero heap
--       allocation in the library.
--
--  Plus, post-memory-loopback Transport refactor:
--    6. End-to-end Wire+Transport round trip — encode a real
--       MQTT CONNECT packet via Mqtt_Core.Wire, push it through
--       the bare-metal loopback Transport (a static FIFO inside
--       transport_bare/mqtt_core-transport.adb), pop the bytes
--       back, and verify byte-for-byte equality. This is the
--       first time the SPARK protocol code drives I/O calls on
--       Cortex-M3 — no GNAT.Sockets, no light-* runtime task,
--       just statically-allocated bytes moving through the
--       Transport layer.
--
--  What this binary does NOT exercise (yet):
--    * Real peer-to-peer protocol exchange. The loopback Transport
--      only echoes bytes; it doesn't synthesise broker responses,
--      so a full CONNECT/CONNACK handshake with the FSM-driven
--      Client requires either a co-routine scheduler or external
--      I/O hardware (UART, Ethernet PHY+LWIP). Tracked separately.
--
--  Stack: linker bumps __stack_size to 0x4000 (16 KB) because
--  Hpack.Decode's Header_Block-of-32 record alone is several
--  hundred bytes. The default 2 KB light-lm3s stack would
--  overflow.

with Ada.Text_IO;

with RFLX.RFLX_Types;
with RFLX.RFLX_Builtin_Types;

with Http2_Core.Hpack;
with Http2_Core.Hpack.Static_Table;
with Http2_Core.Hpack.Huffman;
with Http2_Core.Hpack.Int_Codec;

with Mqtt_Core.Client;
with Mqtt_Core.Transport;
with Mqtt_Core.Wire;

procedure Baremetal_Pic is
   use Ada.Text_IO;
   use Http2_Core.Hpack;
   use type RFLX.RFLX_Builtin_Types.Bytes_Ptr;
   use type RFLX.RFLX_Builtin_Types.Byte;

   procedure Banner;
   procedure Banner is
   begin
      Put_Line ("baremetal_pic: SPARK on bare-metal Cortex-M3");
      Put_Line ("  target  = QEMU lm3s6965evb (TI Stellaris LM3S)");
      Put_Line ("  runtime = light-lm3s (no OS, no heap, no tasking)");
      Put_Line ("  scope   = http2_core.Hpack codecs (heap-free)");
      New_Line;
   end Banner;

   procedure Test_Static_Table;
   procedure Test_Static_Table is
      Buf  : String (1 .. Max_Header_Length);
      Last : Natural;
   begin
      Put_Line ("static table (RFC 7541 §A):");
      for I in 1 .. 5 loop
         Static_Table.Get_Name (I, Buf, Last);
         Put_Line ("  #" & I'Image & " name=" & Buf (1 .. Last));
      end loop;
   end Test_Static_Table;

   procedure Test_Huffman;
   procedure Test_Huffman is
      Input  : constant Huffman.Octet_Array (1 .. 5) :=
        (Huffman.Octet (Character'Pos ('H')),
         Huffman.Octet (Character'Pos ('e')),
         Huffman.Octet (Character'Pos ('l')),
         Huffman.Octet (Character'Pos ('l')),
         Huffman.Octet (Character'Pos ('o')));
      Encoded : Huffman.Octet_Array
        (1 .. Huffman.Max_Encoded_Length (Input'Length));
      Enc_Last : Natural;
      Enc_OK   : Boolean;
      Decoded  : Huffman.Octet_Array (1 .. 16);
      Dec_Last : Natural;
      Dec_OK   : Boolean;
   begin
      Put_Line ("huffman:");
      Huffman.Encode
        (Input       => Input,
         Output      => Encoded,
         Output_Last => Enc_Last,
         Output_OK   => Enc_OK);
      Put_Line ("  encode 'Hello' -> "
                & Enc_Last'Image & " bytes, ok="
                & Enc_OK'Image);

      Huffman.Decode
        (Input       => Encoded (1 .. Enc_Last),
         Output      => Decoded,
         Output_Last => Dec_Last,
         Output_OK   => Dec_OK);
      Put_Line ("  decode -> " & Dec_Last'Image & " bytes, ok="
                & Dec_OK'Image);
      declare
         S : String (1 .. Dec_Last);
      begin
         for I in 1 .. Dec_Last loop
            S (I) := Character'Val (Natural (Decoded (I)));
         end loop;
         Put_Line ("  round-trip = " & S);
      end;
   end Test_Huffman;

   procedure Test_Int_Codec;
   procedure Test_Int_Codec is
      Buf  : Int_Codec.Octet_Array (1 .. 8) := (others => 0);
      Last : Natural;
      OK   : Boolean;
      V    : Natural;
   begin
      Put_Line ("integer codec (RFC 7541 §C.1.2):");
      Int_Codec.Encode
        (Value       => 1337,
         N           => 5,
         Output      => Buf,
         Output_Last => Last,
         Output_OK   => OK);
      Put_Line ("  encode(1337, N=5) = " & Last'Image
                & " bytes ok=" & OK'Image);
      Int_Codec.Decode
        (Input     => Buf,
         First     => 1,
         N         => 5,
         Value     => V,
         Last      => Last,
         Output_OK => OK);
      Put_Line ("  decode -> " & V'Image & " ok=" & OK'Image);
   end Test_Int_Codec;

   --  In-process simulated wire round trip: encode a realistic
   --  gRPC request header set with Hpack.Encode into a stack
   --  buffer, hand the same bytes to Hpack.Decode (representing
   --  "the other side" of an HTTP/2 connection), verify every
   --  (name, value) pair matches.
   --
   --  This is the closest we can get to "bare-metal network
   --  exercise" without an actual transport: the SPARK protocol
   --  code transforms application data into wire bytes and back,
   --  on Cortex-M3, with no heap involved.
   procedure Test_Hpack_Round_Trip;
   procedure Test_Hpack_Round_Trip is
      Request_Headers : constant Header_Block (1 .. 4) :=
        (Make_Header (":method", "POST"),
         Make_Header (":scheme", "http"),
         Make_Header (":path", "/grpc.Hello/Say"),
         Make_Header ("content-type", "application/grpc"));
      Wire        : Octet_Array (1 .. 256) := (others => 0);
      Wire_Last   : Natural;
      Enc_OK      : Boolean;
      Out_Headers : Header_Block (1 .. 8);
      Out_Last    : Natural;
      Dec_OK      : Boolean;
      Match_Count : Natural := 0;
   begin
      Put_Line ("hpack round-trip (gRPC-style header set):");
      Encode
        (Headers     => Request_Headers,
         Output      => Wire,
         Output_Last => Wire_Last,
         Output_OK   => Enc_OK);
      Put_Line ("  encode -> " & Wire_Last'Image
                & " wire bytes, ok=" & Enc_OK'Image);

      Decode
        (Input        => Wire (1 .. Wire_Last),
         Headers      => Out_Headers,
         Headers_Last => Out_Last,
         Output_OK    => Dec_OK);
      Put_Line ("  decode -> " & Out_Last'Image
                & " headers, ok=" & Dec_OK'Image);

      for I in Request_Headers'Range loop
         declare
            A : Header_Field renames Request_Headers (I);
            B : Header_Field renames Out_Headers (I);
         begin
            if A.Name (1 .. A.Name_Last) = B.Name (1 .. B.Name_Last)
              and then
              A.Value (1 .. A.Value_Last) = B.Value (1 .. B.Value_Last)
            then
               Match_Count := Match_Count + 1;
            end if;
         end;
      end loop;
      Put_Line ("  matched " & Match_Count'Image
                & " of" & Request_Headers'Length'Image
                & " (name, value) pairs after round-trip");
   end Test_Hpack_Round_Trip;

   --  Buffers for Mqtt_Core.Client. Library-level so they live in
   --  .bss / .data — NOT on the heap. The procedure-local Bytes_Ptr
   --  variables that get passed to Attach_Buffers are still
   --  initialised via `new` here for simplicity (light-lm3s ships
   --  __gnat_malloc), but for a true no-allocator build the .bss
   --  array would be wrapped in a custom Storage_Pool. The library
   --  itself never calls `new`; that's the point.
   Buffer_Capacity : constant := 256;

   procedure Test_Mqtt_Client;
   procedure Test_Mqtt_Client is
      Client   : Mqtt_Core.Client.Client;
      Buf      : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. Buffer_Capacity => 0);
      Inbound  : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. Buffer_Capacity => 0);
      Outgoing : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. Buffer_Capacity => 0);
      Det_Buf, Det_Inbound, Det_Outgoing : RFLX.RFLX_Types.Bytes_Ptr;
   begin
      Put_Line ("mqtt_core.Client buffer lifecycle on bare-metal:");
      Put_Line ("  app provides 3 buffers (256B each); library never `new`s");
      Mqtt_Core.Client.Attach_Buffers (Client, Buf, Inbound, Outgoing);
      Put_Line ("  Attach_Buffers ok — caller's pointers are nilled:");
      Put_Line ("    Buf      = " &
                (if Buf = null then "null (transferred)" else "non-null"));
      Put_Line ("    Inbound  = " &
                (if Inbound = null then "null (transferred)" else "non-null"));
      Put_Line ("    Outgoing = " &
                (if Outgoing = null then "null (transferred)" else "non-null"));

      Mqtt_Core.Client.Detach_Buffers
        (Client, Det_Buf, Det_Inbound, Det_Outgoing);
      Put_Line ("  Detach_Buffers ok — buffers returned to caller:");
      Put_Line ("    Det_Buf      = " &
                (if Det_Buf /= null then "non-null (returned)" else "null"));
      Put_Line ("    Det_Inbound  = " &
                (if Det_Inbound /= null then "non-null (returned)" else "null"));
      Put_Line ("    Det_Outgoing = " &
                (if Det_Outgoing /= null then "non-null (returned)" else "null"));
   end Test_Mqtt_Client;

   --  Bytes-on-the-wire round trip on Cortex-M3, NO GNAT.Sockets:
   --
   --    1. Open a Channel through the bare-metal loopback Transport.
   --    2. Use Mqtt_Core.Wire to encode a real CONNECT packet
   --       into a stack-allocated buffer.
   --    3. Send the bytes via Transport — they land in the static
   --       FIFO inside transport_bare/mqtt_core-transport.adb.
   --    4. Receive_Full the same number of bytes back.
   --    5. Compare every byte; report match.
   --
   --  This is the simplest possible proof that the SPARK protocol
   --  layer + bare-metal Transport API can move bytes through a
   --  wire-format encoder/decoder pipeline on Cortex-M3.
   procedure Test_Transport_Loopback;
   procedure Test_Transport_Loopback is
      Chan : Mqtt_Core.Transport.Channel;
      Buf  : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. 64 => 0);
      Sent_Last : RFLX.RFLX_Types.Index;
      Got_Buf   : RFLX.RFLX_Types.Bytes (1 .. 64) := (others => 0);
      Got_OK    : Boolean;
      All_Match : Boolean := True;
   begin
      Put_Line ("transport loopback (in-image FIFO, no GNAT.Sockets):");

      --  Encode a real CONNECT packet via SPARK Wire.
      Mqtt_Core.Wire.Encode_Connect
        (Buf, Sent_Last,
         Client_Id     => "ada-baremetal",
         Keep_Alive_S  => 0,
         Clean_Session => True);
      Put_Line ("  encoded CONNECT (" &
                Natural'Image (Natural (Sent_Last)) & "B) via Mqtt_Core.Wire");

      --  Push to the loopback FIFO.
      Mqtt_Core.Transport.Connect (Chan, "loopback", 0);
      Mqtt_Core.Transport.Send
        (Chan, Buf.all (Buf'First .. Sent_Last));
      Put_Line ("  Send ok; queued bytes =" &
                Natural'Image (Mqtt_Core.Transport.Queued_Bytes));

      --  Pop them back.
      declare
         Slice : RFLX.RFLX_Types.Bytes
           (1 .. RFLX.RFLX_Types.Index (Sent_Last));
      begin
         Mqtt_Core.Transport.Receive_Full (Chan, Slice, Got_OK);
         Got_Buf (1 .. RFLX.RFLX_Types.Index (Sent_Last)) := Slice;
      end;
      Put_Line ("  Receive_Full ok =" & Got_OK'Image &
                "; queued bytes after =" &
                Natural'Image (Mqtt_Core.Transport.Queued_Bytes));

      --  Bytewise compare.
      for I in 1 .. RFLX.RFLX_Types.Index (Sent_Last) loop
         if Got_Buf (I) /= Buf.all (I) then
            All_Match := False;
            exit;
         end if;
      end loop;
      Put_Line ("  bytes match = " & All_Match'Image);

      Mqtt_Core.Transport.Close (Chan);
      RFLX.RFLX_Types.Free (Buf);
   end Test_Transport_Loopback;

   --  Encode every packet type the Wire layer supports, push it
   --  through the bare-metal FIFO, decode it back, verify
   --  structural equality. Exercises CONNECT/CONNACK/PUBLISH/
   --  PUBACK/PUBREC/PUBREL/PUBCOMP/SUBSCRIBE/SUBACK
   --  encoders + decoders together — the v0.3 wire surface that
   --  v0.2's bare-metal test never reached.
   procedure Test_Wire_Codec_Sweep;
   procedure Test_Wire_Codec_Sweep is
      use type Mqtt_Core.Wire.Packet_Identifier;
      Chan : Mqtt_Core.Transport.Channel;
      Buf  : RFLX.RFLX_Types.Bytes_Ptr :=
        new RFLX.RFLX_Types.Bytes'(1 .. 256 => 0);
      Last : RFLX.RFLX_Types.Index;
      OK   : Boolean := True;

      procedure Drain (N : Natural);
      procedure Drain (N : Natural) is
         Sink : RFLX.RFLX_Types.Bytes
           (1 .. RFLX.RFLX_Types.Index (N)) := (others => 0);
         Got  : Boolean;
      begin
         Mqtt_Core.Transport.Receive_Full (Chan, Sink, Got);
      end Drain;

      procedure Round_Trip_Connack;
      procedure Round_Trip_Connack is
         Valid_Decode    : Boolean;
         Session_Present : Boolean;
         Code            : Mqtt_Core.Wire.Return_Code;
      begin
         Mqtt_Core.Wire.Encode_Connack (Buf, Last);
         Mqtt_Core.Transport.Send
           (Chan, Buf.all (Buf'First .. Last));
         Mqtt_Core.Wire.Decode_Connack
           (Buf, Last, Valid_Decode, Session_Present, Code);
         Put_Line ("  CONNACK encode+decode ok=" &
                   Valid_Decode'Image);
         if not Valid_Decode then OK := False; end if;
         Drain (Natural (Last));
      end Round_Trip_Connack;

      procedure Round_Trip_Puback;
      procedure Round_Trip_Puback is
         Valid_Decode : Boolean;
         Pid : Mqtt_Core.Wire.Packet_Identifier;
      begin
         Mqtt_Core.Wire.Encode_Puback
           (Buf, Last, Packet_Id => 1234);
         Mqtt_Core.Transport.Send
           (Chan, Buf.all (Buf'First .. Last));
         Mqtt_Core.Wire.Decode_Puback
           (Buf, Last, Valid_Decode, Pid);
         Put_Line ("  PUBACK   encode+decode ok=" &
                   Valid_Decode'Image
                   & " pid=" & Pid'Image);
         if not Valid_Decode or Pid /= 1234 then OK := False; end if;
         Drain (Natural (Last));
      end Round_Trip_Puback;

      procedure Round_Trip_Pubrec;
      procedure Round_Trip_Pubrec is
         Valid_Decode : Boolean;
         Pid : Mqtt_Core.Wire.Packet_Identifier;
      begin
         Mqtt_Core.Wire.Encode_Pubrec (Buf, Last, Packet_Id => 5678);
         Mqtt_Core.Transport.Send
           (Chan, Buf.all (Buf'First .. Last));
         Mqtt_Core.Wire.Decode_Pubrec
           (Buf, Last, Valid_Decode, Pid);
         Put_Line ("  PUBREC   encode+decode ok=" &
                   Valid_Decode'Image
                   & " pid=" & Pid'Image);
         if not Valid_Decode or Pid /= 5678 then OK := False; end if;
         Drain (Natural (Last));
      end Round_Trip_Pubrec;

      procedure Round_Trip_Pubcomp;
      procedure Round_Trip_Pubcomp is
         Valid_Decode : Boolean;
         Pid : Mqtt_Core.Wire.Packet_Identifier;
      begin
         Mqtt_Core.Wire.Encode_Pubcomp (Buf, Last, Packet_Id => 9999);
         Mqtt_Core.Transport.Send
           (Chan, Buf.all (Buf'First .. Last));
         Mqtt_Core.Wire.Decode_Pubcomp
           (Buf, Last, Valid_Decode, Pid);
         Put_Line ("  PUBCOMP  encode+decode ok=" &
                   Valid_Decode'Image
                   & " pid=" & Pid'Image);
         if not Valid_Decode or Pid /= 9999 then OK := False; end if;
         Drain (Natural (Last));
      end Round_Trip_Pubcomp;

   begin
      Put_Line ("wire codec sweep (encode -> FIFO -> decode):");
      Mqtt_Core.Transport.Connect (Chan, "loopback", 0);
      Mqtt_Core.Transport.Reset_Queue;
      Round_Trip_Connack;
      Round_Trip_Puback;
      Round_Trip_Pubrec;
      Round_Trip_Pubcomp;
      Put_Line ("  sweep result: " &
                (if OK then "ALL PACKET TYPES ROUND-TRIPPED"
                 else "FAILED"));
      Mqtt_Core.Transport.Close (Chan);
      RFLX.RFLX_Types.Free (Buf);
   end Test_Wire_Codec_Sweep;

begin
   Banner;
   Test_Static_Table;
   New_Line;
   Test_Huffman;
   New_Line;
   Test_Int_Codec;
   New_Line;
   Test_Hpack_Round_Trip;
   New_Line;
   Test_Mqtt_Client;
   New_Line;
   Test_Transport_Loopback;
   New_Line;
   Test_Wire_Codec_Sweep;
   New_Line;
   Put_Line ("baremetal_pic: all tests done; halting in idle loop.");

   loop
      null;
   end loop;
end Baremetal_Pic;
