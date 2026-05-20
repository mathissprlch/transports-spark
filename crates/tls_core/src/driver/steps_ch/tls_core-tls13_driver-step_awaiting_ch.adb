with Tls_Core.Tls13_Driver.Step_Awaiting_Ch_Cert;
with Tls_Core.Tls13_Driver.Step_Awaiting_Ch_Psk;

package body Tls_Core.Tls13_Driver.Step_Awaiting_Ch
with SPARK_Mode
is

   procedure Handle
     (D        : in out Driver;
      In_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   is
   begin
      if D.Mode = Cert_Mode then
         Step_Awaiting_Ch_Cert.Handle (D, In_Bytes, Out_Buf, Out_Last);
      else
         Step_Awaiting_Ch_Psk.Handle (D, In_Bytes, Out_Buf, Out_Last);
      end if;
   end Handle;

end Tls_Core.Tls13_Driver.Step_Awaiting_Ch;
