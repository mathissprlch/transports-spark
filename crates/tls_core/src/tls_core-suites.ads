--  Tls_Core.Suites — TLS 1.3 negotiation constants and lookup
--  tables (RFC 8446 §B.4 cipher suites, §4.2.7 named groups,
--  §4.2.3 signature schemes, §4.2 extension types).
--
--  Pure-data SPARK module: just `Unsigned_16` constants and
--  table-lookup functions. The handshake driver pulls
--  human-readable names from these for logging / errors and uses
--  the constants to build / parse the wire formats.
--
--  v0.5 negotiation surface (what we accept on the wire):
--      cipher suites:  0x1301 TLS_AES_128_GCM_SHA256
--                      0x1302 TLS_AES_256_GCM_SHA384
--                      0x1303 TLS_CHACHA20_POLY1305_SHA256
--      named groups:   0x0017 secp256r1   (NIST P-256, RFC 8422)
--                      0x001D x25519      (RFC 7748)
--      sig schemes:    0x0403 ecdsa_secp256r1_sha256
--                      0x0807 ed25519
--                      0x0804 rsa_pss_rsae_sha256
--                      0x0805 rsa_pss_rsae_sha384

with Interfaces;

package Tls_Core.Suites
with SPARK_Mode
is

   use type Interfaces.Unsigned_16;

   subtype U16 is Interfaces.Unsigned_16;

   ---------------------------------------------------------------------
   --  Cipher suites — RFC 8446 §B.4
   ---------------------------------------------------------------------

   TLS_AES_128_GCM_SHA256       : constant U16 := 16#1301#;
   TLS_AES_256_GCM_SHA384       : constant U16 := 16#1302#;
   TLS_CHACHA20_POLY1305_SHA256 : constant U16 := 16#1303#;

   function Is_Supported_Suite (Code : U16) return Boolean
   is (Code = TLS_AES_128_GCM_SHA256
       or else Code = TLS_AES_256_GCM_SHA384
       or else Code = TLS_CHACHA20_POLY1305_SHA256);

   ---------------------------------------------------------------------
   --  Named groups — RFC 8446 §4.2.7 / RFC 8422 §5.1.1
   ---------------------------------------------------------------------

   Group_Secp256r1 : constant U16 := 16#0017#;
   Group_X25519    : constant U16 := 16#001D#;

   function Is_Supported_Group (Code : U16) return Boolean
   is (Code = Group_Secp256r1 or else Code = Group_X25519);

   --  Public-key length on the wire for each group. For secp256r1
   --  this is the SEC1 uncompressed encoding (1 + 32 + 32 = 65); for
   --  x25519 the raw 32-byte u-coordinate.
   function Group_Public_Length (Code : U16) return Natural
   is (case Code is
         when Group_Secp256r1 => 65,
         when Group_X25519    => 32,
         when others          => 0);

   ---------------------------------------------------------------------
   --  Signature schemes — RFC 8446 §4.2.3
   ---------------------------------------------------------------------

   Sig_Ecdsa_Secp256r1_Sha256 : constant U16 := 16#0403#;
   Sig_Rsa_Pss_Rsae_Sha256    : constant U16 := 16#0804#;
   Sig_Rsa_Pss_Rsae_Sha384    : constant U16 := 16#0805#;
   Sig_Rsa_Pss_Rsae_Sha512    : constant U16 := 16#0806#;
   Sig_Ed25519                : constant U16 := 16#0807#;

   function Is_Supported_Sig (Code : U16) return Boolean
   is (Code = Sig_Ecdsa_Secp256r1_Sha256
       or else Code = Sig_Rsa_Pss_Rsae_Sha256
       or else Code = Sig_Rsa_Pss_Rsae_Sha384
       or else Code = Sig_Ed25519);

   ---------------------------------------------------------------------
   --  Extension types — RFC 8446 §4.2 (selected; not exhaustive)
   ---------------------------------------------------------------------

   Ext_Server_Name              : constant U16 := 16#0000#;
   Ext_Supported_Groups         : constant U16 := 16#000A#;
   Ext_Signature_Algorithms     : constant U16 := 16#000D#;
   Ext_Application_Layer_Protocol_Negotiation : constant U16 := 16#0010#;
   Ext_Pre_Shared_Key           : constant U16 := 16#0029#;
   Ext_Supported_Versions       : constant U16 := 16#002B#;
   Ext_Psk_Key_Exchange_Modes   : constant U16 := 16#002D#;
   Ext_Key_Share                : constant U16 := 16#0033#;

   ---------------------------------------------------------------------
   --  Hash length implied by a cipher suite (the suffix in the name).
   --  Drives the HKDF transcript-hash size in the key schedule.
   ---------------------------------------------------------------------

   function Suite_Hash_Length (Code : U16) return Natural
   is (case Code is
         when TLS_AES_128_GCM_SHA256       => 32,
         when TLS_AES_256_GCM_SHA384       => 48,
         when TLS_CHACHA20_POLY1305_SHA256 => 32,
         when others                       => 0);

   --  AEAD key length implied by a cipher suite.
   function Suite_Key_Length (Code : U16) return Natural
   is (case Code is
         when TLS_AES_128_GCM_SHA256       => 16,
         when TLS_AES_256_GCM_SHA384       => 32,
         when TLS_CHACHA20_POLY1305_SHA256 => 32,
         when others                       => 0);

   --  AEAD nonce length is 12 for every TLS 1.3 cipher suite (RFC
   --  8446 §5.3, “The same as the AEAD’s N_MIN; for all listed
   --  suites this is 12 bytes”).
   Suite_Nonce_Length : constant Natural := 12;

end Tls_Core.Suites;
