--  Tls_Core.Hello_Rflx — RFLX-backed ServerHello parser with
--  miTLS-style functional Posts.
--
--  Spec mirror: miTLS src/tls/MiTLS.Parsers.ServerHello
--  The ghost functions define what each parsed field SHOULD be
--  as a direct function of the input bytes (RFC 8446 §4.1.3).
--  The Posts bind the procedure outputs to those specs.

with Tls_Core.Suites;

package Tls_Core.Hello_Rflx
with SPARK_Mode
is

   use type Tls_Core.Octet;
   use type Tls_Core.Suites.U16;

   subtype Random_Bytes is Octet_Array (1 .. 32);

   function Spec_Sid_Len (B : Octet_Array) return Natural is
     (Natural (B (35)))
   with Ghost,
        Pre => B'First = 1 and then B'Length >= 40
               and then B (35) <= 32;

   function Spec_Suite_Offset (B : Octet_Array) return Positive is
     (36 + Spec_Sid_Len (B))
   with Ghost,
        Pre => B'First = 1 and then B'Length >= 40
               and then B (35) <= 32
               and then 36 + Natural (B (35)) + 1 <= B'Last;

   function Spec_Suite_Code (B : Octet_Array)
     return Tls_Core.Suites.U16
   is
     (Tls_Core.Suites.U16 (B (Spec_Suite_Offset (B))) * 256
      + Tls_Core.Suites.U16 (B (Spec_Suite_Offset (B) + 1)))
   with Ghost,
        Pre => B'First = 1 and then B'Length >= 40
               and then B (35) <= 32
               and then 36 + Natural (B (35)) + 1 <= B'Last;

   function Spec_Random (B : Octet_Array) return Random_Bytes is
     (B (3 .. 34))
   with Ghost,
        Pre => B'First = 1 and then B'Length >= 40;

   function Spec_Valid (B : Octet_Array) return Boolean is
     (B (1) = 16#03# and then B (2) = 16#03#
      and then B (35) <= 32
      and then 36 + Natural (B (35)) + 4 <= B'Last
      and then B (Spec_Suite_Offset (B) + 2) = 0)
   with Ghost,
        Pre => B'First = 1 and then B'Length >= 40;

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
     Pre  => In_Bytes'First = 1 and then In_Bytes'Length >= 40,
     Post =>
       (if OK then
          Spec_Valid (In_Bytes)
          and then Random = Spec_Random (In_Bytes)
          and then Suite_Code = Spec_Suite_Code (In_Bytes));

   procedure Decode_Server_Hello_Key_Share
     (In_Bytes        : Octet_Array;
      Key_Share_First : out Natural;
      Key_Share_Last  : out Natural;
      OK              : out Boolean)
   with
     Pre  => In_Bytes'Length >= 40,
     Post =>
       (if OK then
          Key_Share_First in In_Bytes'Range
          and then Key_Share_Last in In_Bytes'Range
          and then Key_Share_Last - Key_Share_First + 1 = 32);

end Tls_Core.Hello_Rflx;
