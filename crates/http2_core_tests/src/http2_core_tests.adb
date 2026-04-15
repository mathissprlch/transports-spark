--  http2_core_tests — runs in-tree spot checks against the
--  hand-written http2_core algorithm code (HPACK + Huffman + integer
--  + string-literal codecs). Lives in its own crate because
--  http2_core's RFLX-generated runtime files would conflict with
--  mqtt_core's identical copies if we tried to test from `examples`
--  (open risk #6 in CLAUDE.md).
--
--  Not an AUnit suite — straight runnable procedure that prints
--  ok/FAIL per check. Catches table-aggregate typos, off-by-one
--  bit-shift errors, and obvious round-trip breakages before any
--  HTTP/2 wire integration is attempted.

with Ada.Text_IO;
with Interfaces;
with Http2_Core.Hpack;
with Http2_Core.Hpack.Static_Table;
with Http2_Core.Hpack.Huffman;
with Http2_Core.Hpack.Int_Codec;

procedure Http2_Core_Tests is
   use Ada.Text_IO;
   use Http2_Core.Hpack;
   use type Interfaces.Unsigned_8;

   subtype U8 is Interfaces.Unsigned_8;

   Pass_Count : Natural := 0;
   Fail_Count : Natural := 0;

   procedure Check (Label : String; Cond : Boolean);
   procedure Check (Label : String; Cond : Boolean) is
   begin
      if Cond then
         Pass_Count := Pass_Count + 1;
         Put_Line ("  ok   " & Label);
      else
         Fail_Count := Fail_Count + 1;
         Put_Line ("  FAIL " & Label);
      end if;
   end Check;

   --  Convert a String to an Octet_Array.
   function To_Octet (S : String) return Octet_Array;
   function To_Octet (S : String) return Octet_Array is
      R : Octet_Array (1 .. S'Length);
   begin
      for I in 1 .. S'Length loop
         R (I) := U8 (Character'Pos (S (S'First + I - 1)));
      end loop;
      return R;
   end To_Octet;

   ----------------------------------------------------------------------
   --  Static table
   ----------------------------------------------------------------------

   procedure Test_Static_Table;
   procedure Test_Static_Table is
      N_Buf  : String (1 .. Max_Header_Length);
      N_Last : Natural;
      V_Buf  : String (1 .. Max_Header_Length);
      V_Last : Natural;
      Idx    : Natural;
      Exact  : Boolean;
   begin
      Put_Line ("static table:");
      Static_Table.Get_Name (2, N_Buf, N_Last);
      Static_Table.Get_Value (2, V_Buf, V_Last);
      Check ("#2 :method=GET",
             N_Buf (1 .. N_Last) = ":method"
             and then V_Buf (1 .. V_Last) = "GET");

      Static_Table.Get_Name (61, N_Buf, N_Last);
      Check ("#61 www-authenticate",
             N_Buf (1 .. N_Last) = "www-authenticate");

      Static_Table.Get_Name (62, N_Buf, N_Last);
      Check ("#62 out-of-range Last=0", N_Last = 0);

      Static_Table.Find (":method", "GET", Idx, Exact);
      Check ("Find :method=GET → exact #2", Idx = 2 and Exact);

      Static_Table.Find (":method", "PUT", Idx, Exact);
      Check ("Find :method=PUT → name-only (2 or 3)",
             (Idx = 2 or Idx = 3) and not Exact);

      Static_Table.Find ("x-custom", "v", Idx, Exact);
      Check ("Find unknown → 0", Idx = 0 and not Exact);
   end Test_Static_Table;

   ----------------------------------------------------------------------
   --  Integer codec — round-trip on a few values per RFC 7541 §5.1
   --  examples (10 with 5-bit prefix → single byte; 1337 with 5-bit
   --  prefix → 3 bytes; 42 with 8-bit prefix → single byte).
   ----------------------------------------------------------------------

   procedure Test_Int_Codec;
   procedure Test_Int_Codec is
      Buf      : Int_Codec.Octet_Array (1 .. 8) := (others => 0);
      L        : Natural;
      OK       : Boolean;
      V        : Natural;
   begin
      Put_Line ("integer codec:");
      --  10 fits in 5-bit prefix (mask = 31; 10 < 31): single byte
      --  with low-5-bit value = 10. We pre-clear discriminator to 0
      --  to get a clean 0x0A.
      Buf := (others => 0);
      Int_Codec.Encode
        (Value => 10, N => 5, Output => Buf,
         Output_Last => L, Output_OK => OK);
      Check ("Encode(10, N=5) → 1 byte, 0x0A",
             OK and L = 1 and Buf (1) = 16#0A#);

      Int_Codec.Decode
        (Input => Buf, First => 1, N => 5,
         Value => V, Last => L, Output_OK => OK);
      Check ("Decode round-trip 10", OK and V = 10 and L = 1);

      --  1337 with N=5: too big, all-1s prefix (31), then 1337-31=1306
      --  encoded as little-endian 7-bit-per-byte continuation.
      Buf := (others => 0);
      Int_Codec.Encode
        (Value => 1337, N => 5, Output => Buf,
         Output_Last => L, Output_OK => OK);
      Check ("Encode(1337, N=5) → 3 bytes",
             OK and L = 3
             and Buf (1) = 16#1F#
             and Buf (2) = 16#9A#
             and Buf (3) = 16#0A#);

      Int_Codec.Decode
        (Input => Buf, First => 1, N => 5,
         Value => V, Last => L, Output_OK => OK);
      Check ("Decode round-trip 1337", OK and V = 1337);
   end Test_Int_Codec;

   ----------------------------------------------------------------------
   --  Huffman round-trip on a few common header strings.
   ----------------------------------------------------------------------

   procedure Test_Huffman;
   procedure Test_Huffman is
      procedure Round_Trip (Label : String; S : String);
      procedure Round_Trip (Label : String; S : String) is
         Hin     : Huffman.Octet_Array (1 .. S'Length);
         Hbuf    : Huffman.Octet_Array
           (1 .. Huffman.Max_Encoded_Length (S'Length));
         Hout    : Huffman.Octet_Array (1 .. S'Length);
         L1, L2  : Natural;
         OK1, OK2 : Boolean;
         Match   : Boolean := True;
      begin
         for I in 1 .. S'Length loop
            Hin (I) :=
              Huffman.Octet (Character'Pos (S (S'First + I - 1)));
         end loop;
         Huffman.Encode
           (Input => Hin, Output => Hbuf,
            Output_Last => L1, Output_OK => OK1);
         if not OK1 then
            Check (Label & " encode", False);
            return;
         end if;
         Huffman.Decode
           (Input => Hbuf (1 .. L1), Output => Hout,
            Output_Last => L2, Output_OK => OK2);
         if not OK2 or L2 /= S'Length then
            Check (Label & " decode", False);
            return;
         end if;
         for I in 1 .. S'Length loop
            if Hout (I) /= Hin (I) then
               Match := False;
               exit;
            end if;
         end loop;
         Check (Label & " round-trip", Match);
      end Round_Trip;
   begin
      Put_Line ("huffman:");
      Round_Trip ("'a'", "a");
      Round_Trip ("ASCII short", "Hello");
      Round_Trip ("path-like", "/v1/getuser");
      Round_Trip ("user-agent",
                  "grpc-ada/0.2 (transports-spark)");
   end Test_Huffman;

   ----------------------------------------------------------------------
   --  HPACK encode → decode round-trip on a realistic gRPC header set.
   ----------------------------------------------------------------------

   procedure Test_Hpack_Round_Trip;
   procedure Test_Hpack_Round_Trip is
      In_Headers : constant Header_Block (1 .. 5) :=
        (Make_Header (":method", "POST"),
         Make_Header (":scheme", "https"),
         Make_Header (":path", "/helloworld.Greeter/SayHello"),
         Make_Header (":authority", "localhost:50051"),
         Make_Header ("content-type", "application/grpc"));
      Wire        : Octet_Array (1 .. 256) := (others => 0);
      Wire_Last   : Natural;
      Enc_OK      : Boolean;
      Out_Headers : Header_Block (1 .. 16);
      Out_Last    : Natural;
      Dec_OK      : Boolean;
      All_Match   : Boolean := True;
   begin
      Put_Line ("hpack round-trip (gRPC header set):");
      Encode
        (Headers     => In_Headers,
         Output      => Wire,
         Output_Last => Wire_Last,
         Output_OK   => Enc_OK);
      Check ("encode", Enc_OK);
      if not Enc_OK then return; end if;
      Put_Line ("  encoded" & Wire_Last'Image & "B");

      Decode
        (Input        => Wire (1 .. Wire_Last),
         Headers      => Out_Headers,
         Headers_Last => Out_Last,
         Output_OK    => Dec_OK);
      Check ("decode", Dec_OK);
      if not Dec_OK then return; end if;
      Check ("count" & In_Headers'Length'Image,
             Out_Last = In_Headers'Length);
      if Out_Last /= In_Headers'Length then return; end if;

      for I in In_Headers'Range loop
         declare
            A : Header_Field renames In_Headers (I);
            B : Header_Field renames Out_Headers (I);
         begin
            if A.Name (1 .. A.Name_Last)   /= B.Name (1 .. B.Name_Last)
              or A.Value (1 .. A.Value_Last) /= B.Value (1 .. B.Value_Last)
            then
               Put_Line ("  mismatch at #" & I'Image
                         & ": "
                         & A.Name (1 .. A.Name_Last)
                         & "=" & A.Value (1 .. A.Value_Last)
                         & " vs "
                         & B.Name (1 .. B.Name_Last)
                         & "=" & B.Value (1 .. B.Value_Last));
               All_Match := False;
            end if;
         end;
      end loop;
      Check ("all fields match after round-trip", All_Match);
   end Test_Hpack_Round_Trip;

   pragma Unreferenced (To_Octet);

begin
   Put_Line ("http2_core_tests");
   Test_Static_Table;
   Test_Int_Codec;
   Test_Huffman;
   Test_Hpack_Round_Trip;
   New_Line;
   Put_Line ("summary: " & Pass_Count'Image & " passed,"
             & Fail_Count'Image & " failed");
end Http2_Core_Tests;
