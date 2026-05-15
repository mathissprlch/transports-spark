with Ada.Text_IO;           use Ada.Text_IO;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Interfaces;
with Protobuf.IO;
with Benchmark.Benchmark_Request;
with Benchmark.Benchmark_Reply;
with Benchmark.Priority;
use type Interfaces.Integer_64;
use type Interfaces.Unsigned_64;
use type Interfaces.Unsigned_32;
use type Interfaces.IEEE_Float_64;
use type Interfaces.IEEE_Float_32;
use type Benchmark.Priority.T;

procedure Benchmark_Oneof_Test is
   use Benchmark.Benchmark_Request;
   use Benchmark.Benchmark_Reply;

   use type Protobuf.IO.Octet_Count;
   Buf    : Protobuf.IO.Octet_Array (1 .. 64 * 1024) := (others => 0);
   Cursor : Protobuf.IO.Write_Cursor;

   Fail_Count : Natural := 0;
   Pass_Count : Natural := 0;

   procedure Check (Cond : Boolean; Label : String) is
   begin
      if Cond then
         Pass_Count := Pass_Count + 1;
      else
         Fail_Count := Fail_Count + 1;
         Put_Line ("  FAIL: " & Label);
      end if;
   end Check;

   procedure Test_All_Types is
      Req : Benchmark.Benchmark_Request.T;
      Dec : Benchmark.Benchmark_Request.T;
   begin
      Req.Client_Id     := To_Unbounded_String ("bench-001");
      Req.Timestamp_Ms  := 1_700_000_000_000;
      Req.Raw_Payload   := To_Unbounded_String ("raw bytes here");
      Req.Score         := 99.5;
      Req.Threshold     := 0.75;
      Req.Priority      := Benchmark.Priority.HIGH;
      Req.Sequence      := 42;
      Req.Compress      := True;
      Req.Payload_Which := Payload_Text_Payload;
      Req.Text_Payload  := To_Unbounded_String ("oneof text");
      Req.Tags.Append (To_Unbounded_String ("tag-a"));
      Req.Tags.Append (To_Unbounded_String ("tag-b"));
      Req.Measurements.Append (100);
      Req.Measurements.Append (200);
      Req.Measurements.Append (300);

      Cursor := (Position => 0);
      Benchmark.Benchmark_Request.Encode (Req, Buf, Cursor);
      Put_Line ("all_types encode: "
                & Natural'Image (Natural (Cursor.Position)) & " bytes");

      Benchmark.Benchmark_Request.Decode
        (Buf (1 .. Cursor.Position), Dec);

      Check (To_String (Dec.Client_Id) = "bench-001",     "client_id");
      Check (Dec.Timestamp_Ms = 1_700_000_000_000,        "timestamp_ms");
      Check (To_String (Dec.Raw_Payload) = "raw bytes here", "bytes");
      Check (Dec.Score = 99.5,                              "double");
      Check (Dec.Threshold = 0.75,                          "float");
      Check (Dec.Priority = Benchmark.Priority.HIGH,        "enum");
      Check (Dec.Sequence = 42,                             "uint32");
      Check (Dec.Compress,                                  "bool");
      Check (Dec.Payload_Which = Payload_Text_Payload,      "oneof_which");
      Check (To_String (Dec.Text_Payload) = "oneof text",   "oneof_text");
      Check (Natural (Dec.Tags.Length) = 2,                  "tags_count");
      Check (Natural (Dec.Measurements.Length) = 3,          "meas_count");
   end Test_All_Types;

   procedure Test_Reply is
      Rep : Benchmark.Benchmark_Reply.T;
      Dec : Benchmark.Benchmark_Reply.T;
   begin
      Rep.Ok             := True;
      Rep.Summary        := To_Unbounded_String ("done");
      Rep.Elapsed_Us     := 12345;
      Rep.Throughput_Mbps := 100.25;
      Rep.Bytes_Processed := 4_194_304;
      Rep.Result_Priority := Benchmark.Priority.CRITICAL;
      Rep.Result_Which   := Result_Numeric_Result;
      Rep.Numeric_Result := -999;

      Cursor := (Position => 0);
      Benchmark.Benchmark_Reply.Encode (Rep, Buf, Cursor);

      Benchmark.Benchmark_Reply.Decode
        (Buf (1 .. Cursor.Position), Dec);

      Check (Dec.Ok,                                        "reply_ok");
      Check (Dec.Throughput_Mbps = 100.25,                   "reply_double");
      Check (Dec.Bytes_Processed = 4_194_304,                "reply_uint64");
      Check (Dec.Result_Priority = Benchmark.Priority.CRITICAL, "reply_enum");
      Check (Dec.Result_Which = Result_Numeric_Result,       "reply_oneof");
      Check (Dec.Numeric_Result = -999,                      "reply_num_val");
   end Test_Reply;

begin
   Put_Line ("benchmark_oneof_test: all-types round-trip");
   Test_All_Types;
   Test_Reply;
   Put_Line (Natural'Image (Pass_Count) & " passed,"
             & Natural'Image (Fail_Count) & " failed.");
   if Fail_Count > 0 then
      Put_Line ("SOME TESTS FAILED");
   end if;
end Benchmark_Oneof_Test;
