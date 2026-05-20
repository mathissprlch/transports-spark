package body Tls_Core.Aead_Channel
  with SPARK_Mode
is

   ---------------------------------------------------------------------
   --  Init_Sha256 — dispatch to Channel.Init or Channel_Aes128.Init.
   ---------------------------------------------------------------------

   procedure Init_Sha256
     (D      : out Direction;
      Suite  : Cipher_Suite_Id;
      Secret : Tls_Core.Key_Schedule.Secret) is
   begin
      case Suite is
         when Chacha20_Poly1305_Sha256 =>
            D := Direction'(Suite => Chacha20_Poly1305_Sha256, Cha => <>);
            Tls_Core.Channel.Init (D.Cha, Secret);

         when Aes_128_Gcm_Sha256       =>
            D := Direction'(Suite => Aes_128_Gcm_Sha256, Aes128 => <>);
            Tls_Core.Channel_Aes128.Init (D.Aes128, Secret);

         when Aes_256_Gcm_Sha384       =>
            --  Excluded by Pre.
            raise Program_Error;
      end case;
   end Init_Sha256;

   ---------------------------------------------------------------------
   --  Init_Sha384 — dispatch to Channel_Aes256.Init.
   ---------------------------------------------------------------------

   procedure Init_Sha384
     (D : out Direction; Secret : Tls_Core.Key_Schedule_Sha384.Secret) is
   begin
      D := Direction'(Suite => Aes_256_Gcm_Sha384, Aes256 => <>);
      Tls_Core.Channel_Aes256.Init (D.Aes256, Secret);
   end Init_Sha384;

   ---------------------------------------------------------------------
   --  Send — dispatch on D.Suite.
   ---------------------------------------------------------------------

   procedure Send
     (D          : in out Direction;
      Plaintext  : Octet_Array;
      Inner_Type : Octet;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural) is
   begin
      case D.Suite is
         when Chacha20_Poly1305_Sha256 =>
            Tls_Core.Channel.Send
              (D.Cha, Plaintext, Inner_Type, Out_Buf, Out_Last);

         when Aes_128_Gcm_Sha256       =>
            Tls_Core.Channel_Aes128.Send
              (D.Aes128, Plaintext, Inner_Type, Out_Buf, Out_Last);

         when Aes_256_Gcm_Sha384       =>
            Tls_Core.Channel_Aes256.Send
              (D.Aes256, Plaintext, Inner_Type, Out_Buf, Out_Last);
      end case;
   end Send;

   ---------------------------------------------------------------------
   --  Receive — dispatch on D.Suite.
   ---------------------------------------------------------------------

   procedure Receive
     (D          : in out Direction;
      In_Buf     : Octet_Array;
      Out_Buf    : out Octet_Array;
      Out_Last   : out Natural;
      Inner_Type : out Octet;
      OK         : out Boolean) is
   begin
      case D.Suite is
         when Chacha20_Poly1305_Sha256 =>
            Tls_Core.Channel.Receive
              (D.Cha, In_Buf, Out_Buf, Out_Last, Inner_Type, OK);

         when Aes_128_Gcm_Sha256       =>
            Tls_Core.Channel_Aes128.Receive
              (D.Aes128, In_Buf, Out_Buf, Out_Last, Inner_Type, OK);

         when Aes_256_Gcm_Sha384       =>
            Tls_Core.Channel_Aes256.Receive
              (D.Aes256, In_Buf, Out_Buf, Out_Last, Inner_Type, OK);
      end case;
   end Receive;

   ---------------------------------------------------------------------
   --  Rotate_Sha256 — RFC 8446 §7.2 in-place rekey.
   --
   --  We re-Init the active variant's Direction from the new secret;
   --  the underlying Channel.Init / Channel_Aes128.Init both reset
   --  Stream.Seq to 0 and re-derive (key, iv) per §7.3, so the post
   --  on D.Suite (preserved) is the only contract we need here.
   ---------------------------------------------------------------------

   procedure Rotate_Sha256
     (D : in out Direction; New_Secret : Tls_Core.Key_Schedule.Secret) is
   begin
      case D.Suite is
         when Chacha20_Poly1305_Sha256 =>
            Tls_Core.Channel.Init (D.Cha, New_Secret);

         when Aes_128_Gcm_Sha256       =>
            Tls_Core.Channel_Aes128.Init (D.Aes128, New_Secret);

         when Aes_256_Gcm_Sha384       =>
            --  Excluded by Pre.
            raise Program_Error;
      end case;
   end Rotate_Sha256;

   ---------------------------------------------------------------------
   --  Rotate_Sha384 — same shape, SHA-384 variant.
   ---------------------------------------------------------------------

   procedure Rotate_Sha384
     (D : in out Direction; New_Secret : Tls_Core.Key_Schedule_Sha384.Secret)
   is
   begin
      Tls_Core.Channel_Aes256.Init (D.Aes256, New_Secret);
   end Rotate_Sha384;

end Tls_Core.Aead_Channel;
