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
            and then Ext_Bytes'Last < Natural'Last / 2,
     Post =>
       (if Found then
          Sig_Algs_First >= 3
          and then Sig_Algs_Last <= Ext_Bytes'Length
          and then Sig_Algs_First <= Sig_Algs_Last
          --  At least one 2-byte SignatureScheme.
          and then Sig_Algs_Last - Sig_Algs_First + 1 >= 2
          --  Functional (RFC 8446 §4.2.3 SignatureSchemeList): the u16
          --  length prefix immediately preceding the returned body
          --  equals the body's byte-length.
          and then Natural (Ext_Bytes (Sig_Algs_First - 2)) * 256
                   + Natural (Ext_Bytes (Sig_Algs_First - 1))
                   = Sig_Algs_Last - Sig_Algs_First + 1);

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
            and then Ext_Bytes'Last < Natural'Last / 2,
     Post =>
       (if Found then
          Binder_First >= 2
          and then Binder_Last <= Ext_Bytes'Length
          and then Binder_First <= Binder_Last
          --  A binder is an HMAC output: at least 32 bytes.
          and then Binder_Last - Binder_First + 1 >= 32
          --  Functional (RFC 8446 §4.2.11.2 PskBinderEntry): the u8
          --  length octet immediately preceding the returned binder
          --  equals the binder's byte-length.
          and then Natural (Ext_Bytes (Binder_First - 1))
                   = Binder_Last - Binder_First + 1
          --  Truncated_Last is the byte before the binders list — the
          --  truncation point for the §4.4.1 binder transcript hash —
          --  and therefore precedes the binder value itself.
          and then Truncated_Last < Binder_First);

end Tls_Core.Ext_Walk_Rflx;
