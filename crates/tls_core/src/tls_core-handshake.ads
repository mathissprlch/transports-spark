--  Tls_Core.Handshake — PSK-only handshake driver (RFC 8446 §2.2 +
--  the §7.1 key schedule projected onto PSK_KE-only mode).
--
--  This package composes every primitive landed in v0.5 into a
--  full handshake-secret derivation tree:
--
--    PSK    --HKDF-Extract(0)-->   Early_Secret
--    Early_Secret  --Derive("derived")-->   Derived_1
--    Derived_1     --HKDF-Extract(0_32)-->  Handshake_Secret
--    Handshake_Secret --Derive("c hs traffic", CH||SH)-->
--                                     client_handshake_traffic_secret
--    Handshake_Secret --Derive("s hs traffic", CH||SH)-->
--                                     server_handshake_traffic_secret
--    Handshake_Secret --Derive("derived", "")-->  Derived_2
--    Derived_2 --HKDF-Extract(0_32)-->  Master_Secret
--    Master_Secret --Derive("c ap traffic", CH..SF)-->
--                                     client_application_traffic_secret
--    Master_Secret --Derive("s ap traffic", CH..SF)-->
--                                     server_application_traffic_secret
--
--  The driver runs both client and server in-process against the
--  same PSK and the same recorded ClientHello / ServerHello
--  transcript, verifying both sides reach identical traffic
--  secrets and that the Finished MACs cross-verify.
--
--  miTLS reference: src/tls/MiTLS.KS.fst (`ks_state` tree). Our
--  Run_Loopback procedure mirrors the F\* state-transition log
--  for the PSK_KE branch.

with Tls_Core.Key_Schedule;

package Tls_Core.Handshake
with SPARK_Mode
is

   --  TLS 1.3 traffic secrets, RFC 8446 §7.1. Names follow the
   --  RFC's typeset ("c hs traffic", etc.).
   type Traffic_Secrets is record
      Client_Handshake : Tls_Core.Key_Schedule.Secret;
      Server_Handshake : Tls_Core.Key_Schedule.Secret;
      Client_App       : Tls_Core.Key_Schedule.Secret;
      Server_App       : Tls_Core.Key_Schedule.Secret;
   end record;

   --  Compute the full PSK_KE traffic-secret tree from a 32-byte
   --  pre-shared key plus the recorded ClientHello and
   --  ServerHello byte sequences (header-included Handshake bodies).
   procedure Derive_Psk_Secrets
     (PSK            : Octet_Array;
      Client_Hello   : Octet_Array;
      Server_Hello   : Octet_Array;
      Server_Finished : Octet_Array;
      Out_Secrets    : out Traffic_Secrets)
   with Pre =>
       PSK'Length = 32
       and then Client_Hello'Length <= 1024
       and then Server_Hello'Length <= 1024
       and then Server_Finished'Length <= 1024
       and then Client_Hello'Last < Integer'Last - 1024
       and then Server_Hello'Last < Integer'Last - 1024
       and then Server_Finished'Last < Integer'Last - 1024;

end Tls_Core.Handshake;
