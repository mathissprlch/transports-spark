with Tls_Core.Suites;

package Tls_Core.Hello_Rflx
with SPARK_Mode
is

   subtype Random_Bytes is Octet_Array (1 .. 32);

   procedure Decode_Server_Hello_Fields
     (In_Bytes        : Octet_Array;
      Random          : out Random_Bytes;
      Suite_Code      : out Tls_Core.Suites.U16;
      Sid_First       : out Natural;
      Sid_Last        : out Natural;
      Ext_First       : out Natural;
      Ext_Last        : out Natural;
      OK              : out Boolean)
   with
     Pre => In_Bytes'First = 1 and then In_Bytes'Length >= 40;

end Tls_Core.Hello_Rflx;
