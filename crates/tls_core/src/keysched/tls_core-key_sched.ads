with Tls_Core.Aead_Channel;
with Tls_Core.Record_Layer;
with Tls_Core.Suites;
with Tls_Core.Transcript;
with Tls_Core.Transcript_Sha384;

package Tls_Core.Key_Sched
with SPARK_Mode
is
   use type Tls_Core.Suites.Cipher_Suite_Id;
   use type Tls_Core.Record_Layer.Seq_Number;

   Max_Hash_Len : constant := 48;
   subtype Hash_Len_Range is Positive range 32 .. Max_Hash_Len;
   subtype Max_Secret is Octet_Array (1 .. Max_Hash_Len);
   subtype Max_Digest is Octet_Array (1 .. Max_Hash_Len);

   function Hash_Len
     (Suite : Tls_Core.Suites.Cipher_Suite_Id) return Hash_Len_Range
   is (case Suite is
         when Tls_Core.Suites.Chacha20_Poly1305_Sha256
            | Tls_Core.Suites.Aes_128_Gcm_Sha256 => 32,
         when Tls_Core.Suites.Aes_256_Gcm_Sha384 => 48);

   procedure Derive_Handshake_Secrets
     (Suite        : Tls_Core.Suites.Cipher_Suite_Id;
      PSK          : Octet_Array;
      Ecdhe_Shared : Octet_Array;
      Th_After_Sh  : Max_Digest;
      C_Hs_Sec    : out Max_Secret;
      S_Hs_Sec    : out Max_Secret;
      Hs_Secret    : out Max_Secret)
   with
     Pre => PSK'Length in 32 | 48
       and then PSK'Last < Integer'Last - 1024
       and then Ecdhe_Shared'Length = 32
       and then Ecdhe_Shared'Last < Integer'Last - 1024;

   procedure Derive_App_Secrets
     (Suite       : Tls_Core.Suites.Cipher_Suite_Id;
      Hs_Secret   : Max_Secret;
      Th_After_Sf : Max_Digest;
      App_C_Ap   : out Max_Secret;
      App_S_Ap   : out Max_Secret;
      Master_Sec : out Max_Secret);

   procedure Build_Finished
     (Suite           : Tls_Core.Suites.Cipher_Suite_Id;
      Base_Key        : Max_Secret;
      Transcript_Hash : Max_Digest;
      Out_Verify      : out Max_Digest);

   procedure Derive_Resumption_Master_Secret
     (Suite             : Tls_Core.Suites.Cipher_Suite_Id;
      Master_Secret     : Max_Secret;
      Th_After_Cf       : Max_Digest;
      Resumption_Secret : out Max_Secret);

   procedure Transcript_Append
     (Suite   : Tls_Core.Suites.Cipher_Suite_Id;
      Ctx_256 : in out Tls_Core.Transcript.Accumulator;
      Ctx_384 : in out Tls_Core.Transcript_Sha384.Accumulator;
      Message : Octet_Array)
   with Pre => Message'Last < Integer'Last - 128;

   procedure Transcript_Snapshot
     (Suite    : Tls_Core.Suites.Cipher_Suite_Id;
      Ctx_256  : Tls_Core.Transcript.Accumulator;
      Ctx_384  : Tls_Core.Transcript_Sha384.Accumulator;
      Out_Hash : out Max_Digest);

   procedure Init_Hs_Channel
     (Suite  : Tls_Core.Suites.Cipher_Suite_Id;
      Dir    : out Tls_Core.Aead_Channel.Direction;
      Secret : Max_Secret)
   with Pre => not Dir'Constrained,
        Post =>
          Dir.Suite = Suite
          and then (case Suite is
            when Tls_Core.Suites.Chacha20_Poly1305_Sha256 => True,
            when Tls_Core.Suites.Aes_128_Gcm_Sha256 =>
              Tls_Core.Record_Layer.Seq_Of (Dir.Aes128.Stream) = 0,
            when Tls_Core.Suites.Aes_256_Gcm_Sha384 =>
              Tls_Core.Record_Layer.Seq_Of (Dir.Aes256.Stream) = 0);

end Tls_Core.Key_Sched;
