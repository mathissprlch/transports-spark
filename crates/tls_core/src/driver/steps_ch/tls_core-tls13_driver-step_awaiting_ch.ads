package Tls_Core.Tls13_Driver.Step_Awaiting_Ch
  with SPARK_Mode
is

   procedure Handle
     (D        : in out Driver;
      In_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   with
     Pre  =>
       In_Bytes'First = 1
       and then In_Bytes'Length <= 16640 + 5
       and then Out_Buf'First = 1
       and then Out_Buf'Length >= 4096,
     Post => Out_Last in 0 .. Out_Buf'Last;

end Tls_Core.Tls13_Driver.Step_Awaiting_Ch;
