--  Tls_Core.Finished — TLS 1.3 Finished message MAC (RFC 8446 §4.4.4).
--
--    finished_key = HKDF-Expand-Label(BaseKey, "finished", "", Hash.length)
--    verify_data  = HMAC(finished_key,
--      Transcript-Hash(Handshake context, Certificate*, CertificateVerify*))
--
--  Where BaseKey is:
--    * server_handshake_traffic_secret  for the server's Finished
--    * client_handshake_traffic_secret  for the client's Finished
--
--  miTLS reference: src/tls/MiTLS.HandshakeMessages.fst (the
--  Finished message body) + src/tls/MiTLS.KeySchedule.fst
--  (`finished_key` derivation).

with Tls_Core.Sha256;
with Tls_Core.Key_Schedule;

package Tls_Core.Finished
  with SPARK_Mode
is

   subtype Verify_Data is Tls_Core.Sha256.Digest;
   --  HMAC-SHA-256 output, 32 bytes — matches RFC 8446 §4.4.4
   --  for the SHA-256 cipher suites.

   --  Compute the verify_data for a given base key + transcript
   --  hash. The "finished" label per RFC 8446 §7.1 is just
   --  "finished" in ASCII (no Tls13_Prefix prefix is added by us;
   --  it is added by Hkdf.Expand_Label).
   --
   --  Functional content checked end-to-end via RFC 8448 vectors at
   --  the handshake-driver level.
   procedure Compute
     (Base_Key        : Tls_Core.Key_Schedule.Secret;
      Transcript_Hash : Tls_Core.Sha256.Digest;
      Out_Verify      : out Verify_Data);

end Tls_Core.Finished;
