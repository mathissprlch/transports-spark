--  Http2_Core.Hpack — HPACK header compression (RFC 7541).
--
--  Source: RFC 7541 — HPACK: Header Compression for HTTP/2,
--  IETF Standard, May 2015.
--
--  Scope (per ../specs/SCOPE.md):
--  - Static table only (RFC 7541 Appendix A, 61 entries).
--  - Dynamic table size advertised as 0
--    (SETTINGS_HEADER_TABLE_SIZE=0); peer dynamic-table indices
--    >= 62 are PROTOCOL_ERROR.
--  - Huffman codec (Appendix B) hand-written, no dynamic state.
--  - Literal-with-incremental-indexing represents values we want
--    the peer NOT to add to its dynamic table; we never add to
--    ours, so all literals we emit are "never-indexed" form.
--
--  Layered files:
--  - Static_Table — Appendix A entries, lookup helpers.
--  - Huffman      — Appendix B codec (TBD).
--  - Encoder      — header-field → wire bytes (TBD).
--  - Decoder      — wire bytes → header-field (TBD).
--
--  The wire formats themselves (integer prefix encoding §5.1,
--  string literal §5.2, header field representation §6) live in
--  the RecordFlux specs at ../specs/hpack_*.rflx, generated into
--  ../generated/, and consumed by the Encoder/Decoder bodies.

package Http2_Core.Hpack is

   --  Maximum number of header fields per request (bounded; v0.2
   --  scope says "no per-RPC heap"). Sized for the gRPC header set:
   --  pseudo-headers (:method, :path, :scheme, :authority, :status)
   --  plus content-type, te, grpc-timeout, grpc-encoding, user-agent,
   --  grpc-status, grpc-message, plus reasonable application headers.
   Max_Headers : constant := 32;

   --  Maximum byte length of a single header name or value. Most
   --  gRPC header values are short; the long ones are :path or
   --  user-agent. 256 fits all standard cases.
   Max_Header_Length : constant := 256;

end Http2_Core.Hpack;
