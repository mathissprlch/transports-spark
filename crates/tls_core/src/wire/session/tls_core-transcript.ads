--  Tls_Core.Transcript — TLS 1.3 transcript-hash accumulator.
--
--  Source: RFC 8446 §4.4.1 — The Transcript Hash.
--
--    Transcript-Hash(M1, M2, ..., MN) =
--        Hash(M1 || M2 || ... || MN)
--
--  In TLS 1.3 the transcript is a running concatenation of
--  Handshake messages (with their type+u24-length headers, NOT
--  the record-layer envelope around them). Each message is fed
--  through Tls_Core.Sha256.Update; Snapshot returns the current
--  Hash without finalizing, so the same Transcript object can
--  keep accumulating after a snapshot.
--
--  Snapshot is the only thing the rest of the handshake needs:
--  it goes into Derive-Secret to bind a key to a particular
--  prefix of the transcript (e.g., "ClientHello..ServerHello"
--  for handshake-traffic secrets, "ClientHello..server Finished"
--  for application-traffic secrets).
--
--  miTLS reference: src/tls/MiTLS.HandshakeLog.fst keeps the
--  same running-hash structure; our Snapshot mirrors miTLS'
--  `transcript` ghost projection.

with Interfaces;
with Tls_Core.Sha256;

package Tls_Core.Transcript
  with SPARK_Mode
is

   use type Interfaces.Unsigned_64;

   type Accumulator is private;

   procedure Init (T : out Accumulator);

   --  Append a handshake message (with its 4-byte type+u24-length
   --  header) to the running hash.
   procedure Append (T : in out Accumulator; Message : Octet_Array)
   with
     Pre =>
       Tls_Core.Sha256.Total_Length (Inner (T))
       <= Interfaces.Unsigned_64'Last - Interfaces.Unsigned_64 (Message'Length)
       and then Message'Last < Integer'Last - Tls_Core.Sha256.Block_Length;

   --  Snapshot the current Transcript-Hash without disturbing T.
   --  Caller can keep appending and snapshot again later.
   procedure Snapshot
     (T : Accumulator; Out_Digest : out Tls_Core.Sha256.Digest);

   --  Ghost projection used in the Pre on Append.
   function Inner (T : Accumulator) return Tls_Core.Sha256.Context
   with Ghost;

private

   pragma Warnings (Off, "no entities of * are referenced");
   pragma Warnings (On, "no entities of * are referenced");

   type Accumulator is record
      Ctx : Tls_Core.Sha256.Context;
   end record;

   function Inner (T : Accumulator) return Tls_Core.Sha256.Context
   is (T.Ctx);

end Tls_Core.Transcript;
