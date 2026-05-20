package Tls_Core.Tls13_Driver.Step_Hrr
with SPARK_Mode
is

   procedure Handle_Sh_Or_Hrr
     (D        : in out Driver;
      In_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural);

   procedure Handle_Ch_2
     (D        : in out Driver;
      In_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural);

end Tls_Core.Tls13_Driver.Step_Hrr;
