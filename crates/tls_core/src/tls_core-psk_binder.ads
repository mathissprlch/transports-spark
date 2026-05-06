--  Tls_Core.Psk_Binder — RFC 8446 §4.2.11.2 PSK binder computation.
--
--  An external pre-shared key in TLS 1.3 is authenticated via a
--  binder field in the ClientHello's pre_shared_key extension:
--
--      Early_Secret  = HKDF-Extract(0_32, PSK)
--      binder_key    = HKDF-Expand-Label(Early_Secret, "ext binder", "", 32)
--      finished_key  = HKDF-Expand-Label(binder_key,  "finished",   "", 32)
--      partial_hash  = SHA-256(Truncate(ClientHello))    -- CH minus binders
--      binder        = HMAC-SHA-256(finished_key, partial_hash)
--
--  ("Truncate" per §4.2.11.2: the ClientHello bytes up to but not
--  including the binders portion of the pre_shared_key extension.)
--
--  This helper computes binder bytes from PSK + truncated CH; the
--  caller is responsible for splicing the result into the right
--  byte offset of the on-wire ClientHello.
--
--  Pinned via the Spec_* / pragma Assume pattern matching the rest
--  of the crate (Tls_Core.Sha256.Spec_Hash, Hmac.Spec_Hmac, etc.).

with Tls_Core.Sha256;

package Tls_Core.Psk_Binder
with SPARK_Mode
is

   subtype Binder_Bytes is Octet_Array (1 .. 32);

   --  Abstract spec function — same trust pattern as the rest.
   function Spec_Binder
     (PSK              : Octet_Array;
      Truncated_Client_Hello : Octet_Array)
      return Binder_Bytes
   with Ghost;

   --  Compute the 32-byte binder for an external PSK over the
   --  truncated ClientHello bytes (CH up to but not including the
   --  binders portion of the pre_shared_key extension).
   procedure Compute
     (PSK                    : Octet_Array;
      Truncated_Client_Hello : Octet_Array;
      Out_Binder             : out Binder_Bytes)
   with
     Pre =>
       PSK'Length = 32
       and then PSK'Last < Integer'Last - 1024
       and then Truncated_Client_Hello'Last
                  < Integer'Last - Tls_Core.Sha256.Block_Length,
     Post =>
       Out_Binder = Spec_Binder (PSK, Truncated_Client_Hello);

   --  Constant-time binder check used on the server side. True iff
   --  Computed_Binder = Expected_Binder.
   function Verify
     (Computed : Binder_Bytes;
      Received : Binder_Bytes) return Boolean;

private

   pragma Warnings (Off, "no entities of * are referenced");
   pragma Warnings (On,  "no entities of * are referenced");

end Tls_Core.Psk_Binder;
