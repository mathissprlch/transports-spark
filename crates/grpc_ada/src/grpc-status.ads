--  GRPC.Status — gRPC status codes per
--  https://github.com/grpc/grpc/blob/master/doc/statuscodes.md

package GRPC.Status
  with Pure
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
      Aborted,              --  10
      Out_Of_Range,         --  11
      Unimplemented,        --  12
      Internal,             --  13
      Unavailable,          --  14
      Data_Loss,            --  15
      Unauthenticated);     --  16

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

   --  Decimal representation, used in the grpc-status header value.
   function To_String (C : Code) return String;
   function From_String (S : String) return Code;
   --  From_String raises Constraint_Error on values outside 0..16.

end GRPC.Status;
