package Tls_Core.Ext_Walk_Rflx
with SPARK_Mode
is

   --  All four finders delegate to the internal Walk_Find, whose Pre
   --  requires Ext_Bytes'Last < Natural'Last / 2 so the byte-offset
   --  arithmetic in the RFLX extension walk cannot overflow Natural.
   --  Carrying that bound on each public finder lets gnatprove
   --  discharge the delegated Walk_Find precondition at the call site.

   procedure Find_Key_Share_X25519
     (Ext_Bytes       : Octet_Array;
      Key_Share_First : out Natural;
      Key_Share_Last  : out Natural;
      Found           : out Boolean)
   with
     Pre => Ext_Bytes'First = 1 and then Ext_Bytes'Length >= 4
            and then Ext_Bytes'Last < Natural'Last / 2;

   procedure Find_Sig_Algs
     (Ext_Bytes      : Octet_Array;
      Sig_Algs_First : out Natural;
      Sig_Algs_Last  : out Natural;
      Found          : out Boolean)
   with
     Pre => Ext_Bytes'First = 1 and then Ext_Bytes'Length >= 4
            and then Ext_Bytes'Last < Natural'Last / 2;

   procedure Find_Key_Share_X25519_Sh
     (Ext_Bytes       : Octet_Array;
      Key_Share_First : out Natural;
      Key_Share_Last  : out Natural;
      Found           : out Boolean)
   with
     Pre => Ext_Bytes'First = 1 and then Ext_Bytes'Length >= 4
            and then Ext_Bytes'Last < Natural'Last / 2,
     Post =>
       (if Found then
          Key_Share_First >= 1
          and then Key_Share_Last <= Ext_Bytes'Length
          and then Key_Share_Last - Key_Share_First + 1 = 32);

   procedure Find_Psk_Fields
     (Ext_Bytes       : Octet_Array;
      Identity_First  : out Natural;
      Identity_Last   : out Natural;
      Binder_First    : out Natural;
      Binder_Last     : out Natural;
      Truncated_Last  : out Natural;
      Found           : out Boolean)
   with
     Pre => Ext_Bytes'First = 1 and then Ext_Bytes'Length >= 4
            and then Ext_Bytes'Last < Natural'Last / 2;

end Tls_Core.Ext_Walk_Rflx;
