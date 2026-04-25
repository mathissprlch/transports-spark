--  Grpc_Core.Status — gRPC canonical status codes.
--
--  Source: grpc/grpc — `include/grpcpp/impl/codegen/status_code_enum.h`
--  (and the equivalent in every language binding). 17 codes, stable
--  since gRPC 1.0. Not on IANA — it's a project-defined registry,
--  carried by the `grpc-status` trailer header in every response.
--
--  Wire form: ASCII decimal in the trailing HEADERS frame's
--  grpc-status field. The Hpack layer above reads it as a string;
--  this enum + From_String / To_String pair gives a typed Ada API.

package Grpc_Core.Status
with SPARK_Mode
is

   type Code is
     (OK,                   --  0
      Cancelled,            --  1
      Unknown,              --  2
      Invalid_Argument,     --  3
      Deadline_Exceeded,    --  4
      Not_Found,            --  5
      Already_Exists,       --  6
      Permission_Denied,    --  7
      Resource_Exhausted,   --  8
      Failed_Precondition,  --  9
      Aborted,              -- 10
      Out_Of_Range,         -- 11
      Unimplemented,        -- 12
      Internal,             -- 13
      Unavailable,          -- 14
      Data_Loss,            -- 15
      Unauthenticated);     -- 16

   for Code use
     (OK                  => 0,
      Cancelled           => 1,
      Unknown             => 2,
      Invalid_Argument    => 3,
      Deadline_Exceeded   => 4,
      Not_Found           => 5,
      Already_Exists      => 6,
      Permission_Denied   => 7,
      Resource_Exhausted  => 8,
      Failed_Precondition => 9,
      Aborted             => 10,
      Out_Of_Range        => 11,
      Unimplemented       => 12,
      Internal            => 13,
      Unavailable         => 14,
      Data_Loss           => 15,
      Unauthenticated     => 16);

   --  Parse `grpc-status` trailer value (ASCII decimal, 1-2 chars).
   --  Returns OK/True on success, OK/False on malformed input or
   --  out-of-range value (caller treats as Unknown).
   procedure From_String
     (S    : String;
      C    : out Code;
      Valid : out Boolean);

   --  Format Code as ASCII decimal into Buf; Last is the last
   --  filled index. Buf must be at least 2 chars.
   procedure To_String
     (C    : Code;
      Buf  : out String;
      Last : out Natural)
   with Pre => Buf'Length >= 2;

end Grpc_Core.Status;
