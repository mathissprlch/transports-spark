package body Tls_Core.Aes_Hw
  with SPARK_Mode
is

   --  v0.5 stub: forwards to the pure-Ada path. v0.6 replaces these
   --  bodies with pragma Import bindings to AES-NI / ARM Crypto
   --  Extensions.

   procedure Hw_Full_Round
     (S     : in out Tls_Core.Aes_Core.Block;
      RK    : Octet_Array;
      Round : Tls_Core.Aes_Core.Round_Index) is
   begin
      Tls_Core.Aes_Core.Sub_Bytes (S);
      Tls_Core.Aes_Core.Shift_Rows (S);
      Tls_Core.Aes_Core.Mix_Columns (S);
      Tls_Core.Aes_Core.Add_Round_Key (S, RK, Round);
   end Hw_Full_Round;

   procedure Hw_Final_Round
     (S     : in out Tls_Core.Aes_Core.Block;
      RK    : Octet_Array;
      Round : Tls_Core.Aes_Core.Round_Index) is
   begin
      Tls_Core.Aes_Core.Sub_Bytes (S);
      Tls_Core.Aes_Core.Shift_Rows (S);
      Tls_Core.Aes_Core.Add_Round_Key (S, RK, Round);
   end Hw_Final_Round;

end Tls_Core.Aes_Hw;
