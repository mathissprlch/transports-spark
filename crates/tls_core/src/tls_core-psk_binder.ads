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

with Tls_Core.Sha256;

package Tls_Core.Psk_Binder
with SPARK_Mode
is

   subtype Binder_Bytes is Octet_Array (1 .. 32);

   --  Compute the 32-byte binder for an external PSK over the
   --  truncated ClientHello bytes (CH up to but not including the
   --  binders portion of the pre_shared_key extension).
   --
   --  RFC 8448 PSK vectors at the handshake-driver level provide
   --  the functional check; no Post is asserted here.
   procedure Compute
     (PSK                    : Octet_Array;
      Truncated_Client_Hello : Octet_Array;
      Out_Binder             : out Binder_Bytes)
   with
     Pre =>
       PSK'Length = 32
       and then PSK'Last < Integer'Last - 1024
       and then Truncated_Client_Hello'First = 1
       and then Truncated_Client_Hello'Last
                  < Integer'Last - Tls_Core.Sha256.Block_Length
       and then Truncated_Client_Hello'Length <= Natural'Last - 9 - 64;

   --  Constant-time binder check used on the server side. True iff
   --  Computed_Binder = Expected_Binder.
   function Verify
     (Computed : Binder_Bytes;
      Received : Binder_Bytes) return Boolean;

private

   pragma Warnings (Off, "no entities of * are referenced");
   pragma Warnings (On,  "no entities of * are referenced");

end Tls_Core.Psk_Binder;
