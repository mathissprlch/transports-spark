--  Tls_Core.Channel_Aes256 — TLS 1.3 record-layer endpoint
--  specialised to TLS_AES_256_GCM_SHA384.

with Tls_Core.Aead_Aes256_Gcm;
with Tls_Core.Record_Layer;
with Tls_Core.Traffic_Keys_Aes256_Sha384;
with Tls_Core.Key_Schedule_Sha384;

package Tls_Core.Channel_Aes256
with SPARK_Mode
is

   subtype Key_Type is Tls_Core.Traffic_Keys_Aes256_Sha384.Aead_Key;
   subtype Tag_Type is Tls_Core.Aead_Aes256_Gcm.Tag_Array;

   Inner_Type_Change_Cipher_Spec : constant Octet := 16#14#;
   Inner_Type_Alert              : constant Octet := 16#15#;
   Inner_Type_Handshake          : constant Octet := 16#16#;
   Inner_Type_Application_Data   : constant Octet := 16#17#;

   type Direction is record
      Stream : Tls_Core.Record_Layer.Stream;
      Key    : Key_Type := (others => 0);
   end record;

   procedure Init
     (D      : out Direction;
      Secret : Tls_Core.Key_Schedule_Sha384.Secret);

   procedure Send
     (D          : in out Direction;
      Plaintext  : Octet_Array;
      Inner_Type : Octet;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural)
   with Pre =>
     Plaintext'Length in 0 .. 16384
     and then Out_Buf'Length >= 5 + Plaintext'Length + 1 + 16
     and then Out_Buf'First = 1;

   procedure Receive
     (D          : in out Direction;
      In_Buf     : Octet_Array;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural;
      Inner_Type : out Octet;
      OK         : out Boolean)
   with Pre =>
     In_Buf'Length >= 5
     and then In_Buf'First = 1
     and then Out_Buf'First = 1
     and then Out_Buf'Length >= In_Buf'Length;

end Tls_Core.Channel_Aes256;
