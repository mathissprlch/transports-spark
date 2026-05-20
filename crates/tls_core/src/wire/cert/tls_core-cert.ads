--  Tls_Core.Cert — general X.509 v3 certificate parser used for the
--  TLS 1.3 cert-mode handshake (RFC 8446 §4.4.2).
--
--  Where Tls_Core.X509 is Ed25519-only and Tls_Core.X509_Spki only
--  parses the SubjectPublicKeyInfo section, this module walks an
--  entire RFC 5280 §4.1 Certificate and returns spans into the
--  caller's DER buffer for every field cert-chain validation needs:
--
--    1. The TBS region (signed message for parent's signature)
--    2. The SubjectPublicKeyInfo region (forwarded to X509_Spki)
--    3. The signatureAlgorithm OID region of the OUTER cert
--       (so the caller can pick the verify primitive)
--    4. The signatureValue bytes (after the unused-bits prefix)
--    5. The issuer Name region
--    6. The subject Name region
--    7. The SubjectAltName extension (for hostname matching)
--
--  v0.5 supports the following signatureAlgorithm OIDs in the OUTER
--  Certificate.signatureAlgorithm field — i.e. the algorithm the
--  PARENT used to sign this cert:
--
--    ecdsa-with-SHA256       1.2.840.10045.4.3.2
--    rsassaPss               1.2.840.113549.1.1.10  (PSS-SHA256)
--
--  Other algorithms set Sig_Alg = Unknown which the caller treats as
--  "cannot validate."
--
--  Standard:    RFC 5280 §4.1, RFC 5912 (sig OIDs), RFC 5480 (ECDSA).
--  Spec mirror: miTLS src/parsers/MiTLS.Parsers.X509.Certificate.fst
--               (parser-combinator pattern; ranges over a fixed buffer).

package Tls_Core.Cert
  with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   --  Signature-algorithm enum the OUTER cert was signed with. v0.5
   --  recognises the two algorithms openssl/mbedTLS/Go default to
   --  for ECDSA-P256 + RSA-PSS leaves; everything else is Unknown.
   type Signature_Alg is (Unknown, Ecdsa_With_Sha256, Rsa_Pss_Sha256);

   --  All field positions are absolute indices into the DER buffer
   --  the caller passed to Parse. When OK is False every field is
   --  meaningless and must not be read.
   --
   --  Indices are inclusive: e.g. Tbs_First .. Tbs_Last names the
   --  bytes of the tbsCertificate SEQUENCE *including* its outer
   --  tag+length header (because that's what the parent signs).
   --
   --  San_Present = False means the cert has no SubjectAltName
   --  extension; San_First/Last are then 0 and must not be read.
   type Parsed_Cert is record
      Tbs_First : Natural := 0;
      Tbs_Last  : Natural := 0;

      Spki_First : Natural := 0;  --  SubjectPublicKeyInfo SEQUENCE
      Spki_Last  : Natural := 0;  --  (with its outer tag+length)

      Sig_Alg : Signature_Alg := Unknown;

      --  Raw signature value bytes (after the leading "unused bits"
      --  byte of the BIT STRING; for ECDSA this is the DER-encoded
      --  Ecdsa-Sig-Value SEQUENCE { r INTEGER, s INTEGER }; for
      --  RSA-PSS this is the 256-byte big-endian signature).
      Sig_First : Natural := 0;
      Sig_Last  : Natural := 0;

      Issuer_First : Natural := 0;
      Issuer_Last  : Natural := 0;

      Subject_First : Natural := 0;
      Subject_Last  : Natural := 0;

      --  Body of the SubjectAltName OCTET STRING, i.e. the inner
      --  SEQUENCE OF GeneralName. Walk Tls_Core.Cert.Match_DNS_SAN
      --  to test whether a DNS-name is present.
      San_Present : Boolean := False;
      San_First   : Natural := 0;
      San_Last    : Natural := 0;
   end record;

   ---------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Parse a DER-encoded X.509 v3 certificate.
   --
   --  Standard:    RFC 5280 §4.1
   --  Spec mirror: miTLS src/parsers/MiTLS.Parsers.X509.Certificate.fst
   --
   --  Functional:  range-shape Post on every emitted index pair.
   --  Proven at:   gnatprove --level=2 (audit-clean per §0d)
   --
   --  Imperative Post: when OK is True every named span lies inside
   --  Der'Range and First <= Last; the SAN span is meaningful only
   --  when San_Present is True.
   ---------------------------------------------------------------------
   procedure Parse (Der : Octet_Array; P : out Parsed_Cert; OK : out Boolean)
   with
     Pre  =>
       Der'First = 1
       and then Der'Length >= 16
       and then Der'Last < Integer'Last - 16,
     Post =>
       (if OK
        then
          P.Tbs_First in Der'Range
          and then P.Tbs_Last in Der'Range
          and then P.Tbs_First <= P.Tbs_Last
          and then P.Spki_First in Der'Range
          and then P.Spki_Last in Der'Range
          and then P.Spki_First <= P.Spki_Last
          and then P.Sig_First in Der'Range
          and then P.Sig_Last in Der'Range
          and then P.Sig_First <= P.Sig_Last
          and then P.Issuer_First in Der'Range
          and then P.Issuer_Last in Der'Range
          and then P.Issuer_First <= P.Issuer_Last
          and then P.Subject_First in Der'Range
          and then P.Subject_Last in Der'Range
          and then P.Subject_First <= P.Subject_Last
          and then (if P.San_Present
                    then
                      P.San_First in Der'Range
                      and then P.San_Last in Der'Range
                      and then P.San_First <= P.San_Last));

   ---------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Match a DNS hostname against the SAN body.
   --
   --  Standard:    RFC 5280 §4.2.1.6 (subjectAltName GeneralName
   --               choice [2] dNSName), RFC 6125 §6.4 (matching).
   --  Functional:  imperative Boolean over the SAN GeneralName list.
   --  Proven at:   gnatprove --level=2 (audit-clean per §0d)
   --
   --  Walks `San_Body` (the body of the SubjectAltName OCTET STRING,
   --  i.e. SEQUENCE OF GeneralName) and returns True if any
   --  dNSName GeneralName matches `Hostname` byte-for-byte
   --  case-insensitively.
   --
   --  Wildcards (RFC 6125 §6.4.3) are NOT supported in v0.5; we match
   --  exact DNS labels only. IP-address SANs are also out of scope:
   --  this is a hostname matcher.
   ---------------------------------------------------------------------
   function Match_DNS_SAN
     (San_Body : Octet_Array; Hostname : Octet_Array) return Boolean
   with
     Pre =>
       San_Body'First = 1
       and then Hostname'First = 1
       and then San_Body'Last < Integer'Last - 16
       and then Hostname'Last < Integer'Last - 16;

end Tls_Core.Cert;
