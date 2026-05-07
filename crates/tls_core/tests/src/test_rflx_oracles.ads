--  Test_Rflx_Oracles — RecordFlux-driven cross-check oracle for
--  Tls_Core's hand-rolled HKDF-Expand-Label info-bytes encoder.
--
--  Test-only. Production tls_core has zero RFLX runtime dependency;
--  this lives in tests/src/ exclusively. The .rflx specs in
--  ../../specs/ remain canonical design artefacts.
--
--  Why: when a new label or context shape lands, RFC test vectors
--  don't always cover the combination. The RFLX-generated
--  serializer is the wire spec by construction; cross-checking
--  against it catches bugs that no published vector would.

with Tls_Core;
with Interfaces;
with RFLX.RFLX_Builtin_Types;

package Test_Rflx_Oracles
is

   procedure Build_Info_Bytes_Via_Rflx
     (Length  : Interfaces.Unsigned_16;
      Label   : Tls_Core.Octet_Array;
      Context : Tls_Core.Octet_Array;
      Buffer  : in out RFLX.RFLX_Builtin_Types.Bytes_Ptr;
      Last    : out Natural);

end Test_Rflx_Oracles;
