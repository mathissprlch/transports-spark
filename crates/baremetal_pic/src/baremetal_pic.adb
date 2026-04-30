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
--  What this binary does NOT exercise (yet):
--    * mqtt_core.Wire codecs — those take Bytes_Ptr (access-to-
--      unconstrained), which on Ada requires either heap
--      allocation or a custom storage pool. Refactoring the
--      MQTT API to take `in out Bytes` slices is on the
--      bare-metal track roadmap (CLAUDE.md).
--    * A real network transport — that's transport_bare's
--      stub for now; UART loopback or LWIP over Ethernet is
--      the next chunk after the API refactor lands.
--
--  Stack: linker bumps __stack_size to 0x4000 (16 KB) because
--  Hpack.Decode's Header_Block-of-32 record alone is several
--  hundred bytes. The default 2 KB light-lm3s stack would
--  overflow.

with Ada.Text_IO;

with Http2_Core.Hpack;
with Http2_Core.Hpack.Static_Table;
with Http2_Core.Hpack.Huffman;
with Http2_Core.Hpack.Int_Codec;

procedure Baremetal_Pic is
   use Ada.Text_IO;
   use Http2_Core.Hpack;

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
   Put_Line ("baremetal_pic: all tests done; halting in idle loop.");

   loop
      null;
   end loop;
end Baremetal_Pic;
