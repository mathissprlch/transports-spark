--  Tls_Core — SPARK TLS 1.3 (RFC 8446) building blocks.
--
--  Pure Ada/SPARK. No FFI. No C bindings. Wire formats are
--  generated from RecordFlux specs in ../specs; cryptographic
--  primitives (when they land) are also pure Ada.
--
--  miTLS (project-everest/mitls-fstar) is read as a reference
--  source for the lemmas/invariants every wrapper carries; we do
--  not vendor or link any miTLS artefact. Each wrapper points to
--  the F* file whose proof obligations it mirrors.
--
--  See ../docs/v0.5-tls-plan.md for the layered architecture and
--  slicing strategy.

with Interfaces;

package Tls_Core
with SPARK_Mode
is

   subtype Octet is Interfaces.Unsigned_8;
   type Octet_Array is array (Positive range <>) of Octet;

end Tls_Core;
