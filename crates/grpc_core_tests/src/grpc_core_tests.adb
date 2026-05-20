--  grpc_core_tests — spot checks for the gRPC framing layer +
--  status code parser.

with Ada.Text_IO;
with RFLX.RFLX_Types;
with RFLX.RFLX_Builtin_Types;
with Grpc_Core.Framing;
with Grpc_Core.Status;

procedure Grpc_Core_Tests is
   use Ada.Text_IO;
   use type RFLX.RFLX_Types.Index;
   use type RFLX.RFLX_Types.Length;
   use type RFLX.RFLX_Builtin_Types.Byte;
   use type Grpc_Core.Status.Code;

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

   ----------------------------------------------------------------------
   --  Framing — encode → decode round-trip.
   ----------------------------------------------------------------------

   procedure Test_Framing;
   procedure Test_Framing is
      Msg     : constant RFLX.RFLX_Types.Bytes (1 .. 11) :=
        [16#48#,
         16#65#,
         16#6C#,
         16#6C#,
         16#6F#,  --  "Hello"
         16#2C#,
         16#20#,                          --  ", "
         16#67#,
         16#52#,
         16#50#,
         16#43#];         --  "gRPC"
      Frame   : RFLX.RFLX_Types.Bytes (1 .. 64) := [others => 0];
      F_Last  : RFLX.RFLX_Types.Index;
      Enc_OK  : Boolean;
      Out_Msg : RFLX.RFLX_Types.Bytes (1 .. 64) := [others => 0];
      M_Len   : RFLX.RFLX_Types.Length;
      Compr   : Boolean;
      Dec_OK  : Boolean;
   begin
      Put_Line ("framing round-trip:");
      Grpc_Core.Framing.Encode
        (Buffer      => Frame,
         Message     => Msg,
         Output_Last => F_Last,
         Output_OK   => Enc_OK);
      Check ("encode OK", Enc_OK);
      Check ("framed size = 5 + 11", F_Last = 5 + 11);
      Check ("compression flag = 0", Frame (1) = 0);
      --  Big-endian length: 11 = 0x0000000B
      Check
        ("length BE bytes",
         Frame (2) = 0 and Frame (3) = 0 and Frame (4) = 0 and Frame (5) = 11);

      Grpc_Core.Framing.Decode
        (Input           => Frame (1 .. F_Last),
         Message         => Out_Msg,
         Message_Length  => M_Len,
         Compressed_Flag => Compr,
         Output_OK       => Dec_OK);
      Check ("decode OK", Dec_OK);
      Check ("decompressed flag", not Compr);
      Check ("payload length = 11", M_Len = 11);
      declare
         Bytes_Match : Boolean := True;
      begin
         for I in 1 .. 11 loop
            if Out_Msg (RFLX.RFLX_Types.Index (I))
              /= Msg (RFLX.RFLX_Types.Index (I))
            then
               Bytes_Match := False;
            end if;
         end loop;
         Check ("payload bytes match", Bytes_Match);
      end;
   end Test_Framing;

   ----------------------------------------------------------------------
   --  Status — From_String / To_String round-trip on every code.
   ----------------------------------------------------------------------

   procedure Test_Status;
   procedure Test_Status is
      Buf            : String (1 .. 4) := (others => ' ');
      Last           : Natural;
      C              : Grpc_Core.Status.Code;
      OK             : Boolean;
      All_Round_Trip : Boolean := True;
   begin
      Put_Line ("status:");
      for Code in Grpc_Core.Status.Code'Range loop
         Grpc_Core.Status.To_String (Code, Buf, Last);
         Grpc_Core.Status.From_String (Buf (Buf'First .. Last), C, OK);
         if not OK or C /= Code then
            All_Round_Trip := False;
            Put_Line
              ("  mismatch "
               & Code'Image
               & " → "
               & Buf (Buf'First .. Last)
               & " → "
               & C'Image);
         end if;
      end loop;
      Check ("all 17 codes round-trip", All_Round_Trip);

      --  Specific spot checks aligning with the wire form.
      Grpc_Core.Status.From_String ("0", C, OK);
      Check ("'0' → OK", OK and C = Grpc_Core.Status.OK);
      Grpc_Core.Status.From_String ("16", C, OK);
      Check
        ("'16' → Unauthenticated",
         OK and C = Grpc_Core.Status.Unauthenticated);
      Grpc_Core.Status.From_String ("17", C, OK);
      Check ("'17' → invalid", not OK);
      Grpc_Core.Status.From_String ("abc", C, OK);
      Check ("non-digit → invalid", not OK);
   end Test_Status;

begin
   Put_Line ("grpc_core_tests");
   Test_Framing;
   Test_Status;
   New_Line;
   Put_Line
     ("summary: "
      & Pass_Count'Image
      & " passed,"
      & Fail_Count'Image
      & " failed");
end Grpc_Core_Tests;
