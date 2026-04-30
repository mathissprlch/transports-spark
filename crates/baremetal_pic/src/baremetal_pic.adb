--  baremetal_pic — Proof-In-Concrete that the SPARK protocol code
--  in http2_core actually runs on a bare-metal ARM Cortex-M3.
--
--  Target: TI Stellaris LM3S811 (Cortex-M3) under
--  `qemu-system-arm -M lm3s6965evb -nographic`. The light-lm3s
--  runtime ships with the gnat_arm_elf toolchain. UART0 maps
--  to QEMU's stdio so Ada.Text_IO output goes to the host.
--
--  Test surface:
--    1. Static_Table.Get_Name on indices 1..5 of RFC 7541 §A
--    2. Hpack.Huffman.Encode on a short ASCII string
--    3. Hpack.Huffman.Decode round-trip
--    4. Hpack.Int_Codec.Encode/Decode at N=5 (RFC §C.1.2)
--
--  All inputs are in-memory; no transport. The protocol code
--  itself is what's being smoke-tested on bare metal — not the
--  I/O layer.

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
      Put_Line ("  test surface = http2_core.Hpack codecs");
      New_Line;
   end Banner;

   procedure Test_Static_Table;
   procedure Test_Static_Table is
      Buf  : String (1 .. Max_Header_Length);
      Last : Natural;
   begin
      Put_Line ("static table:");
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
      --  1337 with N=5 → 3 bytes 0x1F 0x9A 0x0A
      Buf := (others => 0);
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

begin
   Banner;
   Test_Static_Table;
   New_Line;
   Test_Huffman;
   New_Line;
   Test_Int_Codec;
   New_Line;
   Put_Line ("baremetal_pic: all tests done; halting in idle loop.");

   loop
      null;
   end loop;
end Baremetal_Pic;
