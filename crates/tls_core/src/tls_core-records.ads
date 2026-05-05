--  Tls_Core.Records — TLS 1.3 record-layer wire envelope (RFC 8446 §5.1).
--
--  Thin Ada wrapper over the RecordFlux-generated `Record_Layer.Plaintext`
--  message. Encode produces TLS 1.3 record-on-the-wire bytes; Decode
--  parses them back.

with RFLX.Record_Layer;
with RFLX.RFLX_Builtin_Types;

package Tls_Core.Records
with SPARK_Mode => Off
is

   use type RFLX.RFLX_Builtin_Types.Bytes_Ptr;

   --  Mirror of the RFLX Content_Type enum, exported here so the
   --  Ada API is self-contained.
   type Content_Type is
     (Invalid,
      Change_Cipher_Spec,
      Alert,
      Handshake,
      Application_Data);

   --  Encode a TLSPlaintext into Buffer. Caller must supply
   --  Buffer with capacity >= 5 + Fragment'Length.
   procedure Encode
     (Buffer    : in out RFLX.RFLX_Builtin_Types.Bytes_Ptr;
      Last      : out Natural;
      Type_Of   : Content_Type;
      Fragment  : Octet_Array)
   with Pre =>
       Buffer /= null
       and then Fragment'Length <= 16384
       and then Buffer'Length >= 5 + Fragment'Length;

   --  Decode a TLSPlaintext from the first record at Buffer'First.
   --  On success: Type_Of, Fragment_First .. Fragment_Last name the
   --  payload bytes inside Buffer (no copy). Sets OK=False if the
   --  bytes don't parse.
   procedure Decode
     (Buffer         : in out RFLX.RFLX_Builtin_Types.Bytes_Ptr;
      Last           : Natural;
      OK             : out Boolean;
      Type_Of        : out Content_Type;
      Fragment_First : out Natural;
      Fragment_Last  : out Natural)
   with Pre => Buffer /= null and then Last >= 5;

end Tls_Core.Records;
