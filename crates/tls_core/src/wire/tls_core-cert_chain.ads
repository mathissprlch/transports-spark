--  Tls_Core.Cert_Chain — TLS 1.3 certificate-chain validation.
--
--  Walks an end-entity-first chain of DER certificates (leaf, then
--  zero or more intermediates), verifies each link's signature
--  against the next-up issuer's public key, and terminates if the
--  topmost cert is signed by a trusted root cert held in the
--  caller-supplied trust store.
--
--  v0.5 scope (production-default per docs/conventions.md §0a):
--    * Signature algorithms recognised:
--        ecdsa-with-SHA256       (RFC 5480 §2.1.2)
--        rsassaPss with SHA-256  (RFC 8017 §A.2.3 — rsa_pss_rsae_sha256
--                                 wire form, but sigAlg OID is bare
--                                 rsassaPss; we accept the canonical
--                                 SHA-256 parameters by signature
--                                 length only at this v0.5 stage)
--    * Public-key types recognised: ECDSA-P256, RSA-2048
--    * No path-length / basic-constraints / EKU enforcement (those
--      remain "open functional-correctness gap, v0.6+" per §0b)
--    * No CRL / OCSP / online revocation (out of scope at v0.5)
--    * No validity-window check (no real clock in this crate;
--      callers may add their own using the parsed validity span)
--
--  Standard:    RFC 5280 §6 (path validation), RFC 8446 §4.4.2.
--  Spec mirror: miTLS src/MITLS.Cert.fst — single-issuer chain
--               walker with trust-anchor termination.

with Interfaces;
with Tls_Core.Cert;

package Tls_Core.Cert_Chain
with SPARK_Mode
is

   pragma Warnings (Off, "array aggregate using () is an obsolescent syntax");

   --  Maximum supported chain depth (leaf + intermediates). Real
   --  Web PKI chains rarely exceed 4; we cap at 6 to be generous
   --  while keeping the validator's working-set bounded.
   Max_Chain_Depth : constant := 6;

   --  Maximum supported number of trust-store roots. The trust store
   --  is just an array of DER cert buffers held by the caller — we
   --  carry references via byte ranges into a flat blob, so the
   --  caller doesn't pay the cost of N separate heap allocations.
   Max_Trust_Roots : constant := 8;

   --  A single chain entry: a slice of an "all-cert-DER-bytes"
   --  buffer the caller assembles. First/Last are absolute indices
   --  into that buffer; First <= Last and both fall in the buffer.
   --
   --  We pass the indices as Naturals rather than Octet_Array slices
   --  because Ada slices of an external buffer tie the data to one
   --  particular cursor; indices keep the validator's working-set
   --  flat and SPARK-friendly.
   type Chain_Entry is record
      First : Natural := 0;
      Last  : Natural := 0;
   end record;

   type Chain_Array is array (1 .. Max_Chain_Depth) of Chain_Entry;

   type Chain is record
      Count   : Natural := 0;
      Entries : Chain_Array := (others => (others => 0));
   end record;

   --  A trust-store root entry — same indexed-into-flat-buffer shape
   --  as a chain entry.
   type Trust_Entry is record
      First : Natural := 0;
      Last  : Natural := 0;
   end record;

   type Trust_Array is array (1 .. Max_Trust_Roots) of Trust_Entry;

   type Trust_Store is record
      Count   : Natural := 0;
      Entries : Trust_Array := (others => (others => 0));
   end record;

   --  Validation outcomes. Specific failure modes are reported so
   --  callers can map to the right TLS alert (RFC 8446 §6.2):
   --    bad_certificate, unsupported_certificate, certificate_revoked,
   --    certificate_expired, certificate_unknown, illegal_parameter,
   --    unknown_ca.
   type Validation_Result is
     (OK_Validated,
      Bad_Cert_Format,
      Unsupported_Sig_Alg,
      Unsupported_Key_Type,
      Bad_Signature,
      Unknown_CA);

   ---------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Validate a presented end-entity certificate
   --  chain against a trust store.
   --
   --  Standard:    RFC 5280 §6.1
   --  Spec mirror: miTLS src/MITLS.Cert.fst : verify_chain
   --
   --  The chain is leaf-first: Entries (1) is the end-entity cert,
   --  Entries (2..Count) are intermediate CAs, deepest last. The
   --  function:
   --
   --    1. parses each cert in the chain
   --    2. for i = 1 .. Count-1:
   --         verify Entries (i).TBS signature using
   --         Entries (i+1).SPKI as the issuer key
   --    3. verify Entries (Count).TBS signature against EVERY root
   --       in the trust store and accept if any match
   --
   --  Returns OK_Validated only if all signature checks pass and the
   --  topmost cert chains to a trust-store root.
   --
   --  Functional Post: when Result = OK_Validated, Count >= 1 and
   --  every chain entry's range lies inside All_Certs.
   ---------------------------------------------------------------------
   procedure Validate_Chain
     (All_Certs   : Octet_Array;
      Chain_In    : Chain;
      Trust       : Trust_Store;
      Result      : out Validation_Result;
      Leaf_Parsed : out Tls_Core.Cert.Parsed_Cert)
   with
     Pre  =>
       All_Certs'First = 1
       and then All_Certs'Length >= 16
       and then All_Certs'Last < Integer'Last - 16
       and then Chain_In.Count in 1 .. Max_Chain_Depth
       and then Trust.Count in 0 .. Max_Trust_Roots
       and then (for all I in 1 .. Chain_In.Count =>
                    Chain_In.Entries (I).First in All_Certs'Range
                    and then Chain_In.Entries (I).Last in All_Certs'Range
                    and then Chain_In.Entries (I).First
                             <= Chain_In.Entries (I).Last)
       and then (for all I in 1 .. Trust.Count =>
                    Trust.Entries (I).First in All_Certs'Range
                    and then Trust.Entries (I).Last in All_Certs'Range
                    and then Trust.Entries (I).First
                             <= Trust.Entries (I).Last);

   ---------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Verify a TLS 1.3 CertificateVerify signature
   --  against a leaf certificate's SubjectPublicKey.
   --
   --  Standard:    RFC 8446 §4.4.3
   --  Spec mirror: miTLS src/MITLS.Handshake.fst : verify_cert_verify
   --
   --  Inputs:
   --    Leaf_Der        — the leaf cert DER bytes
   --    Leaf_Parsed     — parser output for the leaf (give us SPKI span)
   --    Sig_Scheme      — RFC 8446 §4.2.3 SignatureScheme code point
   --                      (0x0403 ecdsa_secp256r1_sha256,
   --                       0x0804 rsa_pss_rsae_sha256)
   --    Signed_Content  — the 64-spaces || prefix || 0x00 || hash
   --                      buffer built by Cert_Verify.Build_Signed_Content
   --    Signature       — the body of the CertificateVerify signature
   --                      field (DER ECDSA-Sig-Value or 256-byte RSA-PSS)
   --
   --  OK is True iff Sig_Scheme is in v0.5 scope, the leaf's SPKI
   --  matches that scheme, the signature parses, AND the underlying
   --  primitive (Ecdsa_P256.Verify / Rsa_Pss.Verify_Sha256) returns
   --  True.
   ---------------------------------------------------------------------
   procedure Verify_Cert_Verify
     (Leaf_Der       : Octet_Array;
      Leaf_Parsed    : Tls_Core.Cert.Parsed_Cert;
      Sig_Scheme     : Interfaces.Unsigned_16;
      Signed_Content : Octet_Array;
      Signature      : Octet_Array;
      OK             : out Boolean)
   with
     Pre =>
       Leaf_Der'First = 1
       and then Leaf_Der'Length >= 16
       and then Leaf_Der'Last < Integer'Last - 16
       and then Signed_Content'First = 1
       and then Signed_Content'Length in 1 .. 256
       and then Signature'First = 1
       and then Signature'Length in 1 .. 1024
       and then Leaf_Parsed.Spki_First in Leaf_Der'Range
       and then Leaf_Parsed.Spki_Last in Leaf_Der'Range
       and then Leaf_Parsed.Spki_First <= Leaf_Parsed.Spki_Last;

   --  RFC 8446 SignatureScheme code points used in v0.5.
   Sig_Ecdsa_Secp256r1_Sha256 : constant Interfaces.Unsigned_16 := 16#0403#;
   Sig_Rsa_Pss_Rsae_Sha256    : constant Interfaces.Unsigned_16 := 16#0804#;

   ---------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Full server-cert authentication step.
   --
   --  Standard:    RFC 8446 §4.4.2 + §4.4.3 + RFC 5280 §6.1
   --  Spec mirror: miTLS src/MITLS.Handshake.Server.Authenticate.fst
   --
   --  Pipelines together everything a TLS 1.3 client does between
   --  receiving Certificate + CertificateVerify and accepting that
   --  the peer is who they claim:
   --
   --    a) Parse the leaf cert at Chain_In.Entries (1) and validate
   --       the entire chain against the trust store.
   --    b) If a non-empty Hostname is supplied, require the leaf cert
   --       to carry a SubjectAltName extension with a matching
   --       dNSName entry (RFC 6125 §6.4 exact match — no wildcards
   --       in v0.5).
   --    c) Build the RFC 8446 §4.4.3 signed-content from the running
   --       Transcript_Hash (CH..Cert) and Verify_Cert_Verify the
   --       signature in Sig_Body against the leaf's SPKI.
   --
   --  Result reports the first failure; OK_Validated only when all
   --  three steps succeed.
   --
   --  This is the procedure the TLS 1.3 driver calls when it has
   --  received Certificate + CertificateVerify in the server flight.
   ---------------------------------------------------------------------
   procedure Authenticate_Server
     (All_Certs       : Octet_Array;
      Chain_In        : Chain;
      Trust           : Trust_Store;
      Hostname        : Octet_Array;
      Sig_Scheme      : Interfaces.Unsigned_16;
      Sig_Body        : Octet_Array;
      Transcript_Hash : Octet_Array;
      Result          : out Validation_Result)
   with
     Pre =>
       All_Certs'First = 1
       and then All_Certs'Length >= 16
       and then All_Certs'Last < Integer'Last - 16
       and then Chain_In.Count in 1 .. Max_Chain_Depth
       and then Trust.Count in 0 .. Max_Trust_Roots
       and then (for all I in 1 .. Chain_In.Count =>
                    Chain_In.Entries (I).First in All_Certs'Range
                    and then Chain_In.Entries (I).Last in All_Certs'Range
                    and then Chain_In.Entries (I).First
                             <= Chain_In.Entries (I).Last)
       and then (for all I in 1 .. Trust.Count =>
                    Trust.Entries (I).First in All_Certs'Range
                    and then Trust.Entries (I).Last in All_Certs'Range
                    and then Trust.Entries (I).First
                             <= Trust.Entries (I).Last)
       and then Hostname'First = 1
       and then Hostname'Last < Integer'Last - 16
       and then Sig_Body'First = 1
       and then Sig_Body'Length in 1 .. 1024
       and then Sig_Body'Last < Integer'Last - 256
       and then Transcript_Hash'First = 1
       and then Transcript_Hash'Length in 1 .. 64
       and then Transcript_Hash'Last < Integer'Last - 128;

end Tls_Core.Cert_Chain;
