--  Tls_Core.Hkdf_Label_Sha384 — TLS 1.3 §7.1 HKDF-Expand-Label
--  specialised to HMAC-SHA-384.
--
--  The generic Tls_Core.Hkdf.Expand_Label takes Hmac_Expand as a
--  formal; instantiating against Tls_Core.Hkdf_Sha384.Hmac_Expand
--  gives the SHA-384 flavour used by TLS_AES_256_GCM_SHA384.

with Tls_Core.Hkdf;
with Tls_Core.Hkdf_Sha384;
pragma Elaborate_All (Tls_Core.Hkdf);

package Tls_Core.Hkdf_Label_Sha384
with SPARK_Mode
is

   procedure Expand_Label
     is new Tls_Core.Hkdf.Expand_Label
       (Hash_Length      => Tls_Core.Hkdf_Sha384.Hash_Length,
        Spec_Hmac_Expand => Tls_Core.Hkdf_Sha384.Spec_HKDF_Expand,
        Hmac_Expand      => Tls_Core.Hkdf_Sha384.Hmac_Expand);

end Tls_Core.Hkdf_Label_Sha384;
