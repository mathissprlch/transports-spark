package Tls_Core.Ext_Walk_Rflx
  with SPARK_Mode
is

   procedure Find_Key_Share_X25519
     (Ext_Bytes       : Octet_Array;
      Key_Share_First : out Natural;
      Key_Share_Last  : out Natural;
      Found           : out Boolean)
   with Pre => Ext_Bytes'First = 1 and then Ext_Bytes'Length >= 4;

   procedure Find_Sig_Algs
     (Ext_Bytes      : Octet_Array;
      Sig_Algs_First : out Natural;
      Sig_Algs_Last  : out Natural;
      Found          : out Boolean)
   with Pre => Ext_Bytes'First = 1 and then Ext_Bytes'Length >= 4;

   procedure Find_Key_Share_X25519_Sh
     (Ext_Bytes       : Octet_Array;
      Key_Share_First : out Natural;
      Key_Share_Last  : out Natural;
      Found           : out Boolean)
   with
     Pre  => Ext_Bytes'First = 1 and then Ext_Bytes'Length >= 4,
     Post =>
       (if Found
        then
          Key_Share_First >= 1
          and then Key_Share_Last <= Ext_Bytes'Length
          and then Key_Share_Last - Key_Share_First + 1 = 32);

   procedure Find_Psk_Fields
     (Ext_Bytes      : Octet_Array;
      Identity_First : out Natural;
      Identity_Last  : out Natural;
      Binder_First   : out Natural;
      Binder_Last    : out Natural;
      Truncated_Last : out Natural;
      Found          : out Boolean)
   with Pre => Ext_Bytes'First = 1 and then Ext_Bytes'Length >= 4;

end Tls_Core.Ext_Walk_Rflx;
