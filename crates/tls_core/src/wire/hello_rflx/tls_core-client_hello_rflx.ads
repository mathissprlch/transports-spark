--  Tls_Core.Client_Hello_Rflx — RFLX-backed ClientHello parser
--  with miTLS-style functional Posts.
--
--  Spec mirror: miTLS src/tls/MiTLS.Parsers.ClientHello
--  Standard:    RFC 8446 §4.1.2

package Tls_Core.Client_Hello_Rflx
  with SPARK_Mode
is

   use type Tls_Core.Octet;

   subtype Random_Bytes is Octet_Array (1 .. 32);

   --  RFC 8446 §4.1.2 ClientHello byte layout ghost specs.
   --  Each function computes its field value from In_Bytes directly.
   --  Variable-offset fields chain through prior length fields.

   function CH_Random (B : Octet_Array) return Random_Bytes
   is (B (3 .. 34))
   with Ghost, Pre => B'First = 1 and then B'Length >= 42;

   function CH_Sid_Len (B : Octet_Array) return Natural
   is (Natural (B (35)))
   with
     Ghost,
     Pre => B'First = 1 and then B'Length >= 42 and then B (35) <= 32;

   function CH_Suites_Len_Off (B : Octet_Array) return Positive
   is (36 + CH_Sid_Len (B))
   with
     Ghost,
     Pre => B'First = 1 and then B'Length >= 42 and then B (35) <= 32;

   function CH_Suites_Len (B : Octet_Array) return Natural
   is (Natural (B (CH_Suites_Len_Off (B)))
       * 256
       + Natural (B (CH_Suites_Len_Off (B) + 1)))
   with
     Ghost,
     Pre =>
       B'First = 1
       and then B'Length >= 42
       and then B (35) <= 32
       and then CH_Suites_Len_Off (B) + 1 <= B'Last;

   function CH_Suites_First (B : Octet_Array) return Positive
   is (CH_Suites_Len_Off (B) + 2)
   with
     Ghost,
     Pre =>
       B'First = 1
       and then B'Length >= 42
       and then B (35) <= 32
       and then CH_Suites_Len_Off (B) + 1 <= B'Last;

   function CH_Valid (B : Octet_Array) return Boolean
   is (B (1) = 16#03#
       and then B (2) = 16#03#
       and then B (35) <= 32
       and then CH_Suites_Len_Off (B) + 1 <= B'Last
       and then CH_Suites_Len (B) >= 2
       and then CH_Suites_Len (B) mod 2 = 0)
   with Ghost, Pre => B'First = 1 and then B'Length >= 42;

   procedure Decode_Client_Hello_Fields
     (In_Bytes     : Octet_Array;
      Random       : out Random_Bytes;
      Sid_First    : out Natural;
      Sid_Last     : out Natural;
      Suites_First : out Natural;
      Suites_Last  : out Natural;
      Ext_First    : out Natural;
      Ext_Last     : out Natural;
      OK           : out Boolean)
   with
     Pre  => In_Bytes'First = 1 and then In_Bytes'Length >= 42,
     Post =>
       (if OK
        then
          CH_Valid (In_Bytes)
          and then Random = CH_Random (In_Bytes)
          and then Suites_First = CH_Suites_First (In_Bytes)
          and then Suites_Last
                   = CH_Suites_First (In_Bytes)
                     + CH_Suites_Len (In_Bytes)
                     - 1);

   procedure Encode_Client_Hello_Core
     (Random   : Random_Bytes;
      Suites   : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   with
     Pre  =>
       Out_Buf'First = 1
       and then Out_Buf'Length >= 256
       and then Suites'Length in 2 .. 200
       and then Suites'Length mod 2 = 0,
     Post =>
       Out_Last = 37 + Suites'Length
       and then Out_Buf (35) = 0
       and then CH_Valid (Out_Buf)
       and then CH_Random (Out_Buf) = Random
       and then CH_Suites_Len (Out_Buf) = Suites'Length
       and then CH_Suites_First (Out_Buf) = 38;

   procedure Lemma_CH_Round_Trip (Random : Random_Bytes; Suites : Octet_Array)
   with
     Ghost,
     Pre => Suites'Length in 2 .. 200 and then Suites'Length mod 2 = 0;

   procedure Decode_Client_Hello_Psk
     (In_Bytes        : Octet_Array;
      Random          : out Random_Bytes;
      Sid_First       : out Natural;
      Sid_Last        : out Natural;
      Suites_First    : out Natural;
      Suites_Last     : out Natural;
      Identity_First  : out Natural;
      Identity_Last   : out Natural;
      Binder_First    : out Natural;
      Binder_Last     : out Natural;
      Key_Share_First : out Natural;
      Key_Share_Last  : out Natural;
      Truncated_Last  : out Natural;
      OK              : out Boolean)
   with
     Pre  => In_Bytes'First = 1 and then In_Bytes'Length >= 42,
     Post =>
       (if OK
        then
          CH_Valid (In_Bytes)
          and then Random = CH_Random (In_Bytes)
          and then Suites_First = CH_Suites_First (In_Bytes)
          and then Suites_Last
                   = CH_Suites_First (In_Bytes)
                     + CH_Suites_Len (In_Bytes)
                     - 1);

   procedure Decode_Client_Hello_Cert
     (In_Bytes        : Octet_Array;
      Random          : out Random_Bytes;
      Sid_First       : out Natural;
      Sid_Last        : out Natural;
      Suites_First    : out Natural;
      Suites_Last     : out Natural;
      Sig_Algs_First  : out Natural;
      Sig_Algs_Last   : out Natural;
      Key_Share_First : out Natural;
      Key_Share_Last  : out Natural;
      OK              : out Boolean)
   with
     Pre  => In_Bytes'First = 1 and then In_Bytes'Length >= 42,
     Post =>
       (if OK
        then
          CH_Valid (In_Bytes)
          and then Random = CH_Random (In_Bytes)
          and then Suites_First = CH_Suites_First (In_Bytes)
          and then Suites_Last
                   = CH_Suites_First (In_Bytes) + CH_Suites_Len (In_Bytes) - 1
          --  Index bounds: every "First/Last" output, when not
          --  signalling "absent" (= 0), lies within In_Bytes'Range.
          --  Lets downstream callers prove `Field_F + Off` doesn't
          --  overflow when offsetting into the parent record.
          and then Sid_First in 0 .. In_Bytes'Last
          and then Sid_Last in 0 .. In_Bytes'Last
          and then (if Sid_First > 0
                    then
                      Sid_Last >= Sid_First - 1
                      and then Sid_Last - Sid_First + 1 <= 32)
          and then Sig_Algs_First in 0 .. In_Bytes'Last
          and then Sig_Algs_Last in 0 .. In_Bytes'Last
          and then Key_Share_First in 0 .. In_Bytes'Last
          and then Key_Share_Last in 0 .. In_Bytes'Last
          and then (if Key_Share_First > 0
                    then
                      Key_Share_Last >= Key_Share_First
                      and then Key_Share_Last - Key_Share_First + 1 = 32));

end Tls_Core.Client_Hello_Rflx;
