with Tls_Core.Aead_Channel;
with Tls_Core.Key_Schedule;
with Tls_Core.Sha256;
with Tls_Core.Suites;
with Tls_Core.Transcript;
with Tls_Core.Transcript_Sha384;

package Tls_Core.Key_Sched
with SPARK_Mode
is

   procedure Derive_Handshake_Secrets
     (Suite        : Tls_Core.Suites.Cipher_Suite_Id;
      PSK          : Octet_Array;
      Ecdhe_Shared : Octet_Array;
      Th_After_Sh  : Tls_Core.Sha256.Digest;
      C_Hs_Sec    : out Tls_Core.Key_Schedule.Secret;
      S_Hs_Sec    : out Tls_Core.Key_Schedule.Secret;
      Hs_Secret    : out Tls_Core.Key_Schedule.Secret)
   with
     Pre => PSK'Length = 32 and then Ecdhe_Shared'Length = 32;

   procedure Derive_App_Secrets
     (Suite      : Tls_Core.Suites.Cipher_Suite_Id;
      Hs_Secret  : Tls_Core.Key_Schedule.Secret;
      Th_After_Sf : Tls_Core.Sha256.Digest;
      App_C_Ap   : out Tls_Core.Key_Schedule.Secret;
      App_S_Ap   : out Tls_Core.Key_Schedule.Secret;
      Master_Sec : out Tls_Core.Key_Schedule.Secret);

   procedure Build_Finished
     (Suite           : Tls_Core.Suites.Cipher_Suite_Id;
      Base_Key        : Tls_Core.Key_Schedule.Secret;
      Transcript_Hash : Tls_Core.Sha256.Digest;
      Out_Verify      : out Tls_Core.Sha256.Digest);

   procedure Derive_Resumption_Master_Secret
     (Suite             : Tls_Core.Suites.Cipher_Suite_Id;
      Master_Secret     : Tls_Core.Key_Schedule.Secret;
      Th_After_Cf       : Tls_Core.Sha256.Digest;
      Resumption_Secret : out Tls_Core.Key_Schedule.Secret);

   procedure Transcript_Append
     (Suite   : Tls_Core.Suites.Cipher_Suite_Id;
      Ctx_256 : in out Tls_Core.Transcript.Accumulator;
      Ctx_384 : in out Tls_Core.Transcript_Sha384.Accumulator;
      Message : Octet_Array);

   procedure Transcript_Snapshot
     (Suite    : Tls_Core.Suites.Cipher_Suite_Id;
      Ctx_256  : Tls_Core.Transcript.Accumulator;
      Ctx_384  : Tls_Core.Transcript_Sha384.Accumulator;
      Out_Hash : out Tls_Core.Sha256.Digest);

   procedure Init_Hs_Channel
     (Suite  : Tls_Core.Suites.Cipher_Suite_Id;
      Dir    : out Tls_Core.Aead_Channel.Direction;
      Secret : Tls_Core.Key_Schedule.Secret);

end Tls_Core.Key_Sched;
