with Tls_Core.Key_Sched;
with Tls_Core.Sha256;
with Tls_Core.Suites;

package Tls_Core.Psk_Binder
with SPARK_Mode
is

   subtype Binder_Bytes is Tls_Core.Key_Sched.Max_Digest;

   procedure Compute
     (PSK                    : Octet_Array;
      Truncated_Client_Hello : Octet_Array;
      Out_Binder             : out Binder_Bytes;
      Is_Resumption          : Boolean := False;
      Suite                  : Tls_Core.Suites.Cipher_Suite_Id :=
        Tls_Core.Suites.Chacha20_Poly1305_Sha256)
   with
     Pre =>
       PSK'Length = 32
       and then PSK'Last < Integer'Last - 1024
       and then Truncated_Client_Hello'First = 1
       and then Truncated_Client_Hello'Last
                  < Integer'Last - Tls_Core.Sha256.Block_Length
       and then Truncated_Client_Hello'Length <= Natural'Last - 9 - 64;

   function Verify
     (Computed : Binder_Bytes;
      Received : Binder_Bytes) return Boolean;

end Tls_Core.Psk_Binder;
