with Tls_Core.Aead_Channel;
with Tls_Core.Channel;
with Tls_Core.Hkdf;
with Tls_Core.Hkdf_Sha256;
with Tls_Core.Key_Schedule;
with Tls_Core.Record_Layer;
with Tls_Core.Sha256;

package Tls_Core.Tls13_Driver.Helpers
with SPARK_Mode
is

   Rec_Type_Handshake : constant Octet := 16#16#;
   Rec_Type_Alert     : constant Octet := 16#15#;

   Hs_Type_CH          : constant Octet := 16#01#;
   Hs_Type_SH          : constant Octet := 16#02#;
   Hs_Type_EE          : constant Octet := 16#08#;
   Hs_Type_Cert        : constant Octet := 16#0B#;
   Hs_Type_Cert_Verify : constant Octet := 16#0F#;
   Hs_Type_Finished    : constant Octet := 16#14#;

   procedure Hkdf_Expand_Label_Sha256
     is new Tls_Core.Hkdf.Expand_Label
       (Hash_Length      => Tls_Core.Sha256.Hash_Length,
        Max_Info         => 512,
        Spec_Hmac_Expand => Tls_Core.Hkdf_Sha256.Spec_HKDF_Expand,
        Hmac_Expand      => Tls_Core.Hkdf_Sha256.Hmac_Expand);

   procedure Prime_Driver_Defaults (D : in out Driver);

   procedure Build_Plaintext_Alert
     (Level       : Octet;
      Description : Octet;
      Out_Buf     : out Octet_Array;
      Out_Last    : out Natural)
   with
     Pre => Out_Buf'First = 1 and then Out_Buf'Length >= 7;

   procedure Build_Encrypted_Alert
     (Dir         : in out Tls_Core.Aead_Channel.Direction;
      Level       : Octet;
      Description : Octet;
      Out_Buf     : out Octet_Array;
      Out_Last    : out Natural)
   with
     Pre =>
       Out_Buf'First = 1
       and then Out_Buf'Length >= 5 + 2 + 1 + 16
       and then (case Dir.Suite is
                   when Tls_Core.Suites.Chacha20_Poly1305_Sha256 => True,
                   when Tls_Core.Suites.Aes_128_Gcm_Sha256 =>
                     Tls_Core.Record_Layer.Seq_Of (Dir.Aes128.Stream)
                       < Tls_Core.Record_Layer.Seq_Number'Last,
                   when Tls_Core.Suites.Aes_256_Gcm_Sha384 =>
                     Tls_Core.Record_Layer.Seq_Of (Dir.Aes256.Stream)
                       < Tls_Core.Record_Layer.Seq_Number'Last);

   procedure Fail_Plaintext
     (D           : in out Driver;
      Description : Octet;
      Out_Buf     : out Octet_Array;
      Out_Last    : out Natural)
   with
     Pre => Out_Buf'First = 1 and then Out_Buf'Length >= 7;

   procedure Fail_Encrypted
     (D           : in out Driver;
      Description : Octet;
      Out_Buf     : out Octet_Array;
      Out_Last    : out Natural)
   with
     Pre => Out_Buf'First = 1 and then Out_Buf'Length >= 5 + 2 + 1 + 16;

   procedure Encode_Hs_Message
     (Msg_Type   : Octet;
      Body_Bytes : Octet_Array;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural)
   with
     Pre =>
       Out_Buf'First = 1
       and then Body_Bytes'Length <= Natural'Last - 4
       and then Out_Buf'Length >= 4 + Body_Bytes'Length,
     Post =>
       Out_Last = 4 + Body_Bytes'Length;

   procedure Wrap_Tls_Plaintext
     (Hs_Bytes : Octet_Array;
      Out_Buf  : out Octet_Array;
      Out_Last : out Natural)
   with
     Pre =>
       Out_Buf'First = 1
       and then Hs_Bytes'Length <= Natural'Last - 5
       and then Out_Buf'Length >= 5 + Hs_Bytes'Length,
     Post =>
       Out_Last = 5 + Hs_Bytes'Length;

   procedure Ensure_App_Out_Dir (D : in out Driver)
   with
     Pre =>
       App_Secrets_Set (D)
       and then (Selected_Suite (D) = Tls_Core.Suites.Chacha20_Poly1305_Sha256
                 or else Selected_Suite (D) = Tls_Core.Suites.Aes_128_Gcm_Sha256);

end Tls_Core.Tls13_Driver.Helpers;
