--  grpc_core_fuzz — random-bytes-in fuzzer for the gRPC framing
--  decoder. Same shape as http2_core_fuzz; logs every uncaught
--  exception with the byte sequence that triggered it.

with Ada.Text_IO;
with Ada.Command_Line;
with Ada.Numerics.Discrete_Random;
with Ada.Calendar;
with Ada.Exceptions;
with Interfaces;

with RFLX.RFLX_Types;
with RFLX.RFLX_Builtin_Types;

with Grpc_Core.Framing;
with Grpc_Core.Status;

procedure Grpc_Core_Fuzz is
   use Ada.Text_IO;
   use Ada.Calendar;
   use type RFLX.RFLX_Builtin_Types.Index;

   package Byte_Random is new
     Ada.Numerics.Discrete_Random (Interfaces.Unsigned_8);
   package Length_Random is new
     Ada.Numerics.Discrete_Random (Positive);

   Byte_Gen : Byte_Random.Generator;
   Len_Gen  : Length_Random.Generator;

   type Outcome_Count is record
      Total       : Natural := 0;
      OK_True     : Natural := 0;
      OK_False    : Natural := 0;
      Constraint  : Natural := 0;
      Storage     : Natural := 0;
      Program     : Natural := 0;
      Other       : Natural := 0;
   end record;

   Framing_R    : Outcome_Count;
   Status_R     : Outcome_Count;

   Iterations : Natural := 1_000_000;

   Crash_Log : File_Type;

   procedure Log_Crash
     (Decoder : String;
      Bytes   : RFLX.RFLX_Types.Bytes;
      Why     : String);

   procedure Log_Crash
     (Decoder : String;
      Bytes   : RFLX.RFLX_Types.Bytes;
      Why     : String)
   is
      Hex : constant String := "0123456789abcdef";
   begin
      Put (Crash_Log, "CRASH " & Decoder & " " & Why & " bytes=");
      for B of Bytes loop
         declare
            N : constant Natural := Natural (B);
         begin
            Put (Crash_Log, Hex (Hex'First + N / 16));
            Put (Crash_Log, Hex (Hex'First + N mod 16));
         end;
      end loop;
      New_Line (Crash_Log);
      Flush (Crash_Log);
   end Log_Crash;

   procedure One_Iteration;
   procedure One_Iteration is
      Len : constant Positive :=
        (Length_Random.Random (Len_Gen) mod 512) + 5;
      --  Framing.Decode requires Input'Length >= 5; bias toward
      --  satisfying the precondition so most inputs at least try
      --  to be parsed (otherwise we just bounce off the precondition
      --  guard at the harness boundary and never exercise body).
      Buf : RFLX.RFLX_Types.Bytes
        (1 .. RFLX.RFLX_Types.Index (Len));
   begin
      for I in Buf'Range loop
         Buf (I) := RFLX.RFLX_Types.Byte
                      (Byte_Random.Random (Byte_Gen));
      end loop;

      --  Framing.Decode
      Framing_R.Total := Framing_R.Total + 1;
      declare
         Out_Msg : RFLX.RFLX_Types.Bytes (1 .. 1024) := [others => 0];
         M_Len   : RFLX.RFLX_Types.Length;
         Compr   : Boolean;
         OK      : Boolean;
      begin
         Grpc_Core.Framing.Decode
           (Input           => Buf,
            Message         => Out_Msg,
            Message_Length  => M_Len,
            Compressed_Flag => Compr,
            Output_OK       => OK);
         if OK then
            Framing_R.OK_True := Framing_R.OK_True + 1;
         else
            Framing_R.OK_False := Framing_R.OK_False + 1;
         end if;
      exception
         when E : Constraint_Error =>
            Framing_R.Constraint := Framing_R.Constraint + 1;
            Log_Crash ("Framing.Decode", Buf,
                       "Constraint_Error: " &
                       Ada.Exceptions.Exception_Message (E));
         when E : Storage_Error =>
            Framing_R.Storage := Framing_R.Storage + 1;
            Log_Crash ("Framing.Decode", Buf,
                       "Storage_Error: " &
                       Ada.Exceptions.Exception_Message (E));
         when E : Program_Error =>
            Framing_R.Program := Framing_R.Program + 1;
            Log_Crash ("Framing.Decode", Buf,
                       "Program_Error: " &
                       Ada.Exceptions.Exception_Message (E));
         when E : others =>
            Framing_R.Other := Framing_R.Other + 1;
            Log_Crash ("Framing.Decode", Buf,
                       Ada.Exceptions.Exception_Name (E) & ": " &
                       Ada.Exceptions.Exception_Message (E));
      end;

      --  Status.From_String — feed a random-length ASCII slice.
      Status_R.Total := Status_R.Total + 1;
      declare
         S_Len : constant Natural := Natural (Buf (Buf'First)) mod 5;
         S     : String (1 .. S_Len);
         C     : Grpc_Core.Status.Code;
         OK    : Boolean;
      begin
         for I in 1 .. S_Len loop
            S (I) := Character'Val
              (Natural
                (Buf (Buf'First +
                        RFLX.RFLX_Types.Index (I))) mod 128);
         end loop;
         Grpc_Core.Status.From_String (S, C, OK);
         if OK then
            Status_R.OK_True := Status_R.OK_True + 1;
         else
            Status_R.OK_False := Status_R.OK_False + 1;
         end if;
      exception
         when E : Constraint_Error =>
            Status_R.Constraint := Status_R.Constraint + 1;
            Log_Crash ("Status.From_String", Buf,
                       "Constraint_Error: " &
                       Ada.Exceptions.Exception_Message (E));
         when E : others =>
            Status_R.Other := Status_R.Other + 1;
            Log_Crash ("Status.From_String", Buf,
                       Ada.Exceptions.Exception_Name (E) & ": " &
                       Ada.Exceptions.Exception_Message (E));
      end;
   end One_Iteration;

   procedure Report (Label : String; R : Outcome_Count);
   procedure Report (Label : String; R : Outcome_Count) is
   begin
      Put_Line (Label
                & ": total=" & R.Total'Image
                & " OK_True=" & R.OK_True'Image
                & " OK_False=" & R.OK_False'Image
                & " Constraint=" & R.Constraint'Image
                & " Storage=" & R.Storage'Image
                & " Program=" & R.Program'Image
                & " Other=" & R.Other'Image);
   end Report;

   Start_Time : Time;
begin
   if Ada.Command_Line.Argument_Count >= 1 then
      Iterations := Natural'Value (Ada.Command_Line.Argument (1));
   end if;

   Byte_Random.Reset (Byte_Gen, 19);
   Length_Random.Reset (Len_Gen, 137);
   Create (Crash_Log, Out_File, "grpc_fuzz_crashes.log");
   Put_Line (Crash_Log, "# grpc_core_fuzz crash log");
   Flush (Crash_Log);

   Put_Line ("grpc_core_fuzz: " & Iterations'Image & " iterations");
   Start_Time := Clock;
   for I in 1 .. Iterations loop
      One_Iteration;
      if I mod 10_000 = 0 then
         Put_Line ("[" & I'Image & "]"
                   & " elapsed=" & Duration'Image (Clock - Start_Time) & "s");
      end if;
   end loop;
   Put_Line ("=== final ===");
   Report ("Framing.Decode    ", Framing_R);
   Report ("Status.From_String", Status_R);
   Close (Crash_Log);
end Grpc_Core_Fuzz;
