--  Http2_Core.Hpack — HPACK header compression (RFC 7541).
--
--  Source: RFC 7541 — HPACK: Header Compression for HTTP/2,
--  IETF Standard, May 2015.
--
--  Scope:
--  - Static table (RFC 7541 Appendix A, 61 entries) plus a
--    dynamic table on the decode path so peers may use indexed
--    representations and Literal-with-Incremental-Indexing
--    (§6.2.1) to compress repeated headers.
--  - Encoder emits only static-indexed + Literal-Without-Indexing
--    forms; we never add to our send-side dynamic table, so we
--    don't carry one. Peer's SETTINGS_HEADER_TABLE_SIZE for our
--    direction is moot.
--  - Huffman codec (Appendix B) hand-written, no dynamic state.
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

with Interfaces;

with Http2_Core.Hpack_Dynamic_Table;

package Http2_Core.Hpack
with SPARK_Mode
is

   package Dynamic_Table renames Http2_Core.Hpack_Dynamic_Table;

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

   --  One header field as a (name, value) pair. Both fields are
   --  bounded fixed-size buffers with explicit Last counters — same
   --  no-heap convention mqtt_core's wire types use.
   type Header_Field is record
      Name       : String (1 .. Max_Header_Length) := (others => ' ');
      Name_Last  : Natural := 0;
      Value      : String (1 .. Max_Header_Length) := (others => ' ');
      Value_Last : Natural := 0;
   end record;

   type Header_Block is array (Positive range <>) of Header_Field;

   --  Byte sequence type used by Encode and Decode. Local to keep
   --  the public Hpack API free of RFLX runtime types.
   subtype Octet is Interfaces.Unsigned_8;
   type Octet_Array is array (Positive range <>) of Octet;

   --  Construct a Header_Field from Ada strings.
   function Make_Header
     (Name  : String;
      Value : String)
      return Header_Field
   with Pre  => Name'Length in 1 .. Max_Header_Length
                and then Value'Length in 0 .. Max_Header_Length,
        Post => Make_Header'Result.Name_Last  = Name'Length
                and then Make_Header'Result.Value_Last = Value'Length;

   --  Encode `Headers` to an HPACK header block fragment per RFC 7541
   --  §6. v0.2 emission discipline (per ../specs/SCOPE.md):
   --    * If (Name, Value) match a static-table row exactly → emit
   --      §6.1 Indexed Header Field referencing that row.
   --    * Else if Name matches a static-table row → emit §6.2.3
   --      Literal Never Indexed with the name index + literal value.
   --    * Else → emit §6.2.3 with literal name + literal value.
   --  All literals are H=0 (raw); we never index into our (size-0)
   --  dynamic table.
   procedure Encode
     (Headers     : Header_Block;
      Output      : in out Octet_Array;
      Output_Last : out Natural;
      Output_OK   : out Boolean)
   with Pre => Output'Length >= 1;

   procedure Encode_With_Table
     (Headers       : Header_Block;
      Encoder_Table : in out Dynamic_Table.Table;
      Output        : in out Octet_Array;
      Output_Last   : out Natural;
      Output_OK     : out Boolean)
   with Pre => Output'Length >= 1;

   --  Decode an HPACK header block fragment per RFC 7541 §6 into
   --  `Headers`. Acceptance discipline:
   --    * §6.1 with index 1..61 → look up static table.
   --    * §6.1 with index >= 62 → look up Decoder_State (offset
   --      by -61). PROTOCOL_ERROR if out of range.
   --    * §6.2.1 (0x40, incremental-indexing) → decode name + value,
   --      add to Decoder_State.
   --    * §6.2.2 (0x00, without-indexing) and §6.2.3 (0x10,
   --      never-indexed) → decode name + value, do NOT add.
   --    * §6.3 dynamic-table-size update → call
   --      Decoder_State.Set_Max_Size with the new bound.
   --  Headers'Length is the caller-allocated capacity;
   --  Headers_Last reports the count actually decoded.
   procedure Decode
     (Input         : Octet_Array;
      Headers       : in out Header_Block;
      Headers_Last  : out Natural;
      Output_OK     : out Boolean;
      Decoder_State : in out Dynamic_Table.Table)
   with Pre => Headers'Length >= 1;

end Http2_Core.Hpack;
