package Tls_Core.Ext_Walk_Rflx
with SPARK_Mode
is

   --  All four finders delegate to the internal Walk_Find, whose Pre
   --  requires Ext_Bytes'Last < Natural'Last / 2 so the byte-offset
   --  arithmetic in the RFLX extension walk cannot overflow Natural.
   --  Carrying that bound on each public finder lets gnatprove
   --  discharge the delegated Walk_Find precondition at the call site.

   --  Functional predicate (RFC 8446 §4.2.8 KeyShareEntry): True iff
   --  Ext_Bytes (First .. Last) is exactly the 32-byte value of a
   --  KeyShareEntry whose 4-byte header — immediately preceding the
   --  value — is group = x25519 (0x001D) and length = 32 (0x0020).
   --  The key-share finders below carry this as their functional Post,
   --  so a True result genuinely delimits an x25519 key share, not
   --  merely "some 32 bytes".
   function Spec_Is_X25519_Key_Share
     (Ext_Bytes : Octet_Array; First, Last : Natural) return Boolean
   is
     (First >= 5
      and then Last <= Ext_Bytes'Length
      and then First <= Last
      and then Last - First = 31           --  i.e. exactly 32 bytes
      and then Natural (Ext_Bytes (First - 4)) = 16#00#
      and then Natural (Ext_Bytes (First - 3)) = 16#1D#
      and then Natural (Ext_Bytes (First - 2)) = 16#00#
      and then Natural (Ext_Bytes (First - 1)) = 16#20#)
   with Ghost,
        Pre => Ext_Bytes'First = 1;

   procedure Find_Key_Share_X25519
     (Ext_Bytes       : Octet_Array;
      Key_Share_First : out Natural;
      Key_Share_Last  : out Natural;
      Found           : out Boolean)
   with
     Pre => Ext_Bytes'First = 1 and then Ext_Bytes'Length >= 4
            and then Ext_Bytes'Last < Natural'Last / 2,
     Post =>
       (if Found then
          Spec_Is_X25519_Key_Share
            (Ext_Bytes, Key_Share_First, Key_Share_Last));

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
          Spec_Is_X25519_Key_Share
            (Ext_Bytes, Key_Share_First, Key_Share_Last));

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
