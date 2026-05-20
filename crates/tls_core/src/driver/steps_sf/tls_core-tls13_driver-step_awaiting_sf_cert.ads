package Tls_Core.Tls13_Driver.Step_Awaiting_Sf_Cert
with SPARK_Mode
is

   procedure Handle
     (D        : in out Driver;
      In_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural);

end Tls_Core.Tls13_Driver.Step_Awaiting_Sf_Cert;
