package Tls_Core.Tls13_Driver.Step_Awaiting_Ch_Cert
with SPARK_Mode
is

   --  Cert-mode server: drive Awaiting_CH -> Awaiting_Cf.
   --
   --  Pre bounds (matching what Step's Pre guarantees + what every
   --  caller actually passes):
   --
   --  * In_Bytes'First = 1 and at most one TLS record + framing
   --    (16640 = 16384 plaintext + 256 padding/AEAD overhead per
   --     RFC 8446 §5.2; +5 for the record header).
   --  * Out_Buf'First = 1 and >= 4096 to fit the full cert-mode
   --    server flight (SH + EE + Cert + CertVerify + SF; cert chain
   --    is the bulk at <=2 KiB + 32B AEAD tag).
   procedure Handle
     (D        : in out Driver;
      In_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   with
     Pre =>
       In_Bytes'First = 1
       and then In_Bytes'Length <= 16640 + 5
       and then Out_Buf'First = 1
       and then Out_Buf'Length >= 4096;

end Tls_Core.Tls13_Driver.Step_Awaiting_Ch_Cert;
