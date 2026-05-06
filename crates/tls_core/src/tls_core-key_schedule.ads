--  Tls_Core.Key_Schedule — TLS 1.3 key schedule (RFC 8446 §7.1).
--
--    HKDF-Extract(salt, IKM)           = HMAC-Hash(salt, IKM)
--    Derive-Secret(Secret, Label, Msgs) =
--        HKDF-Expand-Label(Secret, Label, Hash(Msgs), Hash.length)
--
--  Composes slice 1 (Tls_Core.Hkdf.Expand_Label) and slice 7
--  (Sha256 + Hmac_Sha256 + Hkdf_Sha256) into the operations
--  RFC 8446 calls out by name. The full key-derivation tree
--  (§7.1 figure: Early Secret -> Handshake Secret -> Master
--  Secret with their many traffic-secret offshoots) is composed
--  by the handshake state machine in slice 6 by chaining these
--  primitives.
--
--  miTLS reference (project-everest/mitls-fstar):
--    src/tls/MiTLS.HKDF.fst         (`extract`, `derive_secret`)
--    src/tls/MiTLS.KS.fst           (KS.ks_state — the tree state)
--
--  miTLS' `derive_secret` is exactly the composition we instantiate
--  here; the F* `expand_spec` postcondition rides through.

with Tls_Core.Sha256;

package Tls_Core.Key_Schedule
with SPARK_Mode
is

   subtype Secret is Tls_Core.Sha256.Digest;
   --  All TLS 1.3 traffic / handshake / master secrets are HashLen
   --  bytes — 32 for the SHA-256 cipher suites we target.

   --  HKDF-Extract per RFC 5869 §2.2: HMAC over (salt, IKM).
   --  TLS 1.3 §7.1 fixes salt to either the previous derived
   --  secret or 32 zero bytes; IKM is either the PSK, the (EC)DHE
   --  shared secret, or 32 zero bytes.
   --  Abstract RFC 8446 §7.1 / RFC 5869 §2.2 Extract.
   function Spec_Extract
     (Salt : Octet_Array; IKM : Octet_Array) return Secret
   with Ghost;

   procedure Extract
     (Salt   : Octet_Array;
      IKM    : Octet_Array;
      Out_PRK : out Secret)
   with
     Pre =>
       Salt'Length = Tls_Core.Sha256.Hash_Length
       and then IKM'Length in 0 .. 1024
       and then Salt'Last < Integer'Last - 1024
       and then IKM'Last < Integer'Last - 1024,
     Post => Out_PRK = Spec_Extract (Salt, IKM);

   --  Derive-Secret per RFC 8446 §7.1: compute the SHA-256 of the
   --  transcript Messages, then HKDF-Expand-Label with that hash
   --  as the context.
   --  Abstract RFC 8446 §7.1 Derive-Secret.
   function Spec_Derive_Secret
     (Secret_In : Secret;
      Label     : Octet_Array;
      Messages  : Octet_Array) return Secret
   with Ghost;

   procedure Derive_Secret
     (Secret_In : Secret;
      Label     : Octet_Array;
      Messages  : Octet_Array;
      Out_Secret : out Secret)
   with
     Pre =>
       Label'Length in 1 .. 249
       and then Label'Last < Integer'Last - 256
       and then Messages'Last
                  < Integer'Last - Tls_Core.Sha256.Block_Length,
     Post => Out_Secret = Spec_Derive_Secret (Secret_In, Label, Messages);

private

   pragma Warnings (Off, "no entities of * are referenced");
   --  Body uses Interfaces; the spec just needs the type.
   pragma Warnings (On, "no entities of * are referenced");

end Tls_Core.Key_Schedule;
