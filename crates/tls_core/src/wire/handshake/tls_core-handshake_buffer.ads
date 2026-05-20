--  Tls_Core.Handshake_Buffer — multi-record handshake-message
--  reassembler.
--
--  Source: RFC 8446 §5.1 (Record Layer):
--
--      Handshake messages MUST NOT be interleaved with other record
--      types.  That is, if a handshake message is split over two or
--      more records, there MUST NOT be any other records between them.
--
--      Handshake messages MUST NOT span key changes.  Implementations
--      MUST verify that all messages immediately preceding a key
--      change align with a record boundary; if not, then they MUST
--      terminate the connection with an "unexpected_message" alert.
--
--  And §4 (Handshake Protocol):
--
--      struct {
--          HandshakeType msg_type;    /* 1 byte */
--          uint24 length;             /* 3 bytes — body length */
--          select (HandshakeType) { ... } body;
--      } Handshake;
--
--  The §5.1 record-fragment cap is 2^14 == 16384 octets. Real cert
--  chains (e.g. RSA-2048 server cert + intermediate(s) + root anchor
--  hint) routinely exceed that limit and are split across multiple
--  TLSPlaintext / TLSCiphertext records by the producing peer.
--
--  This reassembler buffers inbound handshake-channel content (the
--  fragment payload from a TLSPlaintext record, or the decrypted
--  inner plaintext from a TLSCiphertext record after the §5.2
--  trailer-byte strip) and surfaces complete handshake messages to
--  the driver one at a time. The same buffer also handles the
--  packed case where a single record carries multiple full
--  handshake messages.
--
--  Bounded memory is enforced by a fixed-size internal buffer
--  (Max_Buf == 64 KiB by default — covers cert chains up to ~63 KiB
--  including their handshake header). Push_Record_Bytes reports
--  overflow rather than truncating, so the driver can fail the
--  connection cleanly (RFC 8446 §6 "decode_error" / "internal_error"
--  is the legitimate response).
--
--  miTLS reference: src/tls/MiTLS.HandshakeReader.fst — the same
--  "accumulate inbound bytes, peek length header, dispatch when
--  whole" pattern. We mirror the state shape (buffer + used count)
--  in plain SPARK without the dependent-type machinery.

package Tls_Core.Handshake_Buffer
  with SPARK_Mode
is

   --  Reassembly cap. 64 KiB is well above what production peers
   --  actually emit (a typical full chain is 5–15 KiB) and below
   --  the §4 protocol-level uint24 length cap (16 MiB) — the cap
   --  is a defence against an attacker advertising a large length
   --  in a fake handshake header to exhaust memory.
   Max_Buf : constant := 65_536;

   --  Minimum bytes to even start parsing a handshake message
   --  header (HandshakeType + uint24 length).
   Header_Len : constant := 4;

   type Buffer is private;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Initialise an empty reassembly buffer.
   --
   --  Standard:    RFC 8446 §5.1 (Record Layer reassembly state).
   --  Spec mirror: miTLS src/tls/MiTLS.HandshakeReader.fst : init
   --
   --  Functional: Used (B) = 0 after Init; subsequent Push grows it.
   --  Proven at:  gnatprove --level=2 (audit-clean).
   --------------------------------------------------------------------
   procedure Init (B : out Buffer)
   with Post => Used (B) = 0;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Append one record's handshake-channel
   --                       payload to the reassembly buffer.
   --
   --  Standard:    RFC 8446 §5.1.
   --  Spec mirror: miTLS HandshakeReader.fst : push_fragment
   --
   --  Pre:    new content fits within Max_Buf (otherwise OK = False
   --          and B is unchanged — caller's job to fail the
   --          connection per RFC 8446 §6).
   --  Post:   If OK then Used (B) = Used (B'Old) + Bytes'Length;
   --          else      Used (B) = Used (B'Old).
   --  Proven at:  gnatprove --level=2 (audit-clean).
   --------------------------------------------------------------------
   procedure Push_Record_Bytes
     (B : in out Buffer; Bytes : Octet_Array; OK : out Boolean)
   with
     Pre  => Bytes'Length <= Max_Buf,
     Post =>
       (if OK
        then Used (B) = Used (B'Old) + Bytes'Length
        else Used (B) = Used (B'Old));

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Test whether a complete handshake message
   --                       is currently held in the buffer.
   --
   --  Standard:    RFC 8446 §4 (Handshake header layout).
   --
   --  Returns True iff Used (B) >= 4 + body_length, where body_length
   --  is decoded from the buffered uint24 starting at index 2. Until
   --  we have at least 4 bytes the header itself isn't fully buffered
   --  and we return False.
   --
   --  Proven at:  gnatprove --level=2 (audit-clean).
   --------------------------------------------------------------------
   function Has_Complete_Message (B : Buffer) return Boolean;

   --------------------------------------------------------------------
   --  [VERIFIED — AoRTE]  Pop the next complete handshake message
   --                       (header + body) into Out_Buf, slide the
   --                       remaining bytes left.
   --
   --  Standard:    RFC 8446 §4 + §5.1.
   --  Spec mirror: miTLS HandshakeReader.fst : pop_message
   --
   --  Pre:   Has_Complete_Message (B) and then Out_Buf is large
   --         enough to hold 4 + body_length octets.
   --  Post:  Out_Last is the count of octets written (== 4 +
   --         body_length); the buffer's Used count is reduced by
   --         that same amount; the leftover bytes (which may be the
   --         start of the next handshake message) are slid down.
   --
   --  No body: a malformed / oversized header is the caller's
   --  problem to detect via Peek_Body_Length before promising the
   --  Pre — the Pre is a function of buffer state and cannot fail
   --  silently.
   --
   --  Proven at:  gnatprove --level=2 (audit-clean).
   --------------------------------------------------------------------
   procedure Pop_Complete_Message
     (B : in out Buffer; Out_Buf : out Octet_Array; Out_Last : out Natural)
   with
     Pre  =>
       Has_Complete_Message (B)
       and then Out_Buf'First = 1
       and then Out_Buf'Length >= Header_Len + Peek_Body_Length (B),
     Post =>
       Out_Last = Header_Len + Peek_Body_Length (B'Old)
       and then Used (B) = Used (B'Old) - Out_Last
       and then Out_Last <= Out_Buf'Last;

   --  Buffered-bytes count. Ghost-friendly (used in Pre/Post above).
   function Used (B : Buffer) return Natural;

   --  Decode the uint24 body length stored at offset 2..4 of the
   --  buffer. Only meaningful when at least 4 bytes are buffered;
   --  returns 0 in the under-buffered case so callers can use it
   --  freely in Has_Complete_Message and Pre clauses without
   --  an extra guard.
   function Peek_Body_Length (B : Buffer) return Natural
   with Post => Peek_Body_Length'Result <= 16#FF_FF_FF#;

private

   --  Backing storage. Index range starts at 1; only Used'Result
   --  octets in the prefix are meaningful.
   type Storage_Array is array (1 .. Max_Buf) of Octet;

   type Buffer is record
      Data : Storage_Array := (others => 0);
      Len  : Natural := 0;
   end record
   with Predicate => Len <= Max_Buf;

   function Used (B : Buffer) return Natural
   is (B.Len);

   function Peek_Body_Length (B : Buffer) return Natural
   is (if B.Len < Header_Len
       then 0
       else
         Natural (B.Data (2))
         * 65_536
         + Natural (B.Data (3)) * 256
         + Natural (B.Data (4)));

   function Has_Complete_Message (B : Buffer) return Boolean
   is (B.Len >= Header_Len
       and then Peek_Body_Length (B) <= B.Len - Header_Len);

end Tls_Core.Handshake_Buffer;
