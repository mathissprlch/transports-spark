--  Tls_Core.Client_Hello_Rflx — RFLX-backed ClientHello parser
--  with miTLS-style functional Posts.
--
--  Spec mirror: miTLS src/tls/MiTLS.Parsers.ClientHello
--  Standard:    RFC 8446 §4.1.2

with Tls_Core.Suites;

package Tls_Core.Client_Hello_Rflx
with SPARK_Mode
is

   use type Tls_Core.Octet;
   use type Tls_Core.Suites.U16;

   subtype Random_Bytes is Octet_Array (1 .. 32);

   --  RFC 8446 §4.1.2 ClientHello byte layout ghost specs.
   --  Each function computes its field value from In_Bytes directly.
   --  Variable-offset fields chain through prior length fields.

   function CH_Random (B : Octet_Array) return Random_Bytes is
     (B (3 .. 34))
   with Ghost,
        Pre => B'First = 1 and then B'Length >= 42;

   function CH_Sid_Len (B : Octet_Array) return Natural is
     (Natural (B (35)))
   with Ghost,
        Pre => B'First = 1 and then B'Length >= 42
               and then B (35) <= 32;

   function CH_Suites_Len_Off (B : Octet_Array) return Positive is
     (36 + CH_Sid_Len (B))
   with Ghost,
        Pre => B'First = 1 and then B'Length >= 42
               and then B (35) <= 32;

   function CH_Suites_Len (B : Octet_Array) return Natural is
     (Natural (B (CH_Suites_Len_Off (B))) * 256
      + Natural (B (CH_Suites_Len_Off (B) + 1)))
   with Ghost,
        Pre => B'First = 1 and then B'Length >= 42
               and then B (35) <= 32
               and then CH_Suites_Len_Off (B) + 1 <= B'Last;

   function CH_Suites_First (B : Octet_Array) return Positive is
     (CH_Suites_Len_Off (B) + 2)
   with Ghost,
        Pre => B'First = 1 and then B'Length >= 42
               and then B (35) <= 32
               and then CH_Suites_Len_Off (B) + 1 <= B'Last;

   function CH_Valid (B : Octet_Array) return Boolean is
     (B (1) = 16#03# and then B (2) = 16#03#
      and then B (35) <= 32
      and then CH_Suites_Len_Off (B) + 1 <= B'Last
      and then CH_Suites_Len (B) >= 2
      and then CH_Suites_Len (B) mod 2 = 0)
   with Ghost,
        Pre => B'First = 1 and then B'Length >= 42;

   procedure Decode_Client_Hello_Fields
     (In_Bytes      : Octet_Array;
      Random        : out Random_Bytes;
      Sid_First     : out Natural;
      Sid_Last      : out Natural;
      Suites_First  : out Natural;
      Suites_Last   : out Natural;
      Ext_First     : out Natural;
      Ext_Last      : out Natural;
      OK            : out Boolean)
   with
     Pre  => In_Bytes'First = 1 and then In_Bytes'Length >= 42,
     Post =>
       (if OK then
          CH_Valid (In_Bytes)
          and then Random = CH_Random (In_Bytes)
          and then Suites_First = CH_Suites_First (In_Bytes)
          and then Suites_Last =
            CH_Suites_First (In_Bytes)
              + CH_Suites_Len (In_Bytes) - 1);

   procedure Decode_Client_Hello_Psk
     (In_Bytes          : Octet_Array;
      Random            : out Random_Bytes;
      Sid_First         : out Natural;
      Sid_Last          : out Natural;
      Suites_First      : out Natural;
      Suites_Last       : out Natural;
      Identity_First    : out Natural;
      Identity_Last     : out Natural;
      Binder_First      : out Natural;
      Binder_Last       : out Natural;
      Key_Share_First   : out Natural;
      Key_Share_Last    : out Natural;
      Truncated_Last    : out Natural;
      OK                : out Boolean)
   with
     Pre  => In_Bytes'First = 1 and then In_Bytes'Length >= 42,
     Post =>
       (if OK then
          CH_Valid (In_Bytes)
          and then Random = CH_Random (In_Bytes)
          and then Suites_First = CH_Suites_First (In_Bytes)
          and then Suites_Last =
            CH_Suites_First (In_Bytes)
              + CH_Suites_Len (In_Bytes) - 1);

end Tls_Core.Client_Hello_Rflx;
