--  GRPC.Deadline
--
--  Parses and emits the grpc-timeout header. Format per the gRPC spec:
--    <up-to-8-digit-int> <H | M | S | m | u | n>
--  e.g. "100m" = 100 ms, "30M" = 30 minutes, "1S" = 1 second.

package GRPC.Deadline
  with Pure
is

   --  Returns the duration encoded by S. Raises Constraint_Error on
   --  malformed input or an unrecognized unit.
   function Parse_Timeout (S : String) return Duration;

   --  Encodes D as a grpc-timeout value. Picks the smallest unit that
   --  keeps the magnitude under 99_999_999.
   function Format_Timeout (D : Duration) return String;

end GRPC.Deadline;
