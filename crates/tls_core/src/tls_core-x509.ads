--  Tls_Core.X509 — minimal X.509 v3 certificate parser.
--
--  Scope is narrow: parse Ed25519 self-signed certificates of the
--  shape produced by
--
--      openssl req -x509 -newkey ed25519 -nodes -days 365 \
--          -subj "/CN=test" -outform DER -out test.der
--
--  The TLS 1.3 server-cert verification path (RFC 8446 §4.4.3) needs
--  three things out of a leaf certificate:
--
--    1. The TBS bytes — the to-be-signed inner SEQUENCE, byte-exact.
--       This is the message that Ed25519 verifies the signature
--       over. Returned as absolute indices Tbs_First..Tbs_Last into
--       the input slice.
--
--    2. The 32-byte Ed25519 public key, lifted from the
--       SubjectPublicKeyInfo BIT STRING (after the leading
--       "unused bits" byte, which is 0 for Ed25519).
--
--    3. The 64-byte Ed25519 signature, lifted from the trailing
--       Certificate.signatureValue BIT STRING (same convention).
--
--  We do NOT validate chains, parse issuer/subject/validity beyond
--  locating them in the TBS structure, or accept anything other than
--  the Ed25519 OID 1.3.101.112 (DER: 06 03 2B 65 70). Any deviation
--  from the well-known Ed25519 cert shape sets OK := False.
--
--  RFC 5280 §4.1 — Certificate ::= SEQUENCE {
--      tbsCertificate       TBSCertificate,
--      signatureAlgorithm   AlgorithmIdentifier,
--      signatureValue       BIT STRING }
--
--  RFC 8410 §3 — Ed25519 SubjectPublicKeyInfo and
--  signatureAlgorithm both carry id-Ed25519 with no parameters.

package Tls_Core.X509
with SPARK_Mode
   --  DER parsing has too many byte-fiddling cases to push above
   --  silver; the Ed25519 verify caller is the proof boundary.
is

   subtype Public_Key is Octet_Array (1 .. 32);
   subtype Signature  is Octet_Array (1 .. 64);

   --  Parse an Ed25519 self-signed X.509 certificate. On success:
   --    Tbs_First .. Tbs_Last  — absolute indices into Der naming
   --                              the TBS bytes (inclusive),
   --    Pub_Key                — 32-byte Ed25519 public key,
   --    Sig                    — 64-byte Ed25519 signature,
   --    OK                     — True.
   --  On any deviation (wrong OID, bad TLV, truncation, etc.) sets
   --  OK := False; the out values are then meaningless.
   --
   --  Imperative Post: when OK is True the TBS slice indices are
   --  inside Der.
   procedure Parse_Ed25519_Cert
     (Der        : Octet_Array;
      Tbs_First  : out Natural;
      Tbs_Last   : out Natural;
      Pub_Key    : out Public_Key;
      Sig        : out Signature;
      OK         : out Boolean)
   with Post =>
     (if OK then
        Tbs_First in Der'Range
        and then Tbs_Last in Der'Range
        and then Tbs_First <= Tbs_Last);

end Tls_Core.X509;
