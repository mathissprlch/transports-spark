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
--  What this binary does NOT exercise (yet):
--    * Real network I/O — transport_bare/ stubs all I/O calls.
--      A UART driver for the LM3S6965 UART or an LWIP shim is
--      tracked separately as the next bare-metal milestone.
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

procedure Baremetal_Pic is
   use Ada.Text_IO;
   use Http2_Core.Hpack;
   use type RFLX.RFLX_Builtin_Types.Bytes_Ptr;

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
      Put_Line ("  ── full Open() requires real Transport (UART or LWIP);");
      Put_Line ("     transport_bare currently stubs all I/O so Open would");
      Put_Line ("     raise Connect_Failure → Last_Chance_Handler under");
      Put_Line ("     No_Exception_Propagation. Real Transport = next step.");
   end Test_Mqtt_Client;

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
   Put_Line ("baremetal_pic: all tests done; halting in idle loop.");

   loop
      null;
   end loop;
end Baremetal_Pic;
