--  Grpc_Core.Framing — gRPC length-prefixed message framing.
--
--  Source: gRPC over HTTP/2 protocol spec, §"Length-Prefixed-Message"
--  (https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md).
--
--  Each gRPC message inside an HTTP/2 DATA frame body is prefixed
--  with a fixed 5-byte header:
--
--    +-+-------------------------------------------------------+
--    |C|             Message Length (32-bit BE)                |
--    +-+-------------------------------------------------------+
--    |              Message Bytes (Length octets)              |
--    +---------------------------------------------------------+
--
--  C — compression flag (1 byte). 0 = uncompressed, 1 = compressed
--      using the encoding declared in the grpc-encoding request
--      header. v0.2 emits and accepts only C=0; if a peer sends
--      C != 0 we decode it as a length-prefixed payload but mark
--      the message as compressed (caller decides whether to fail).
--
--  Length — message size in bytes, big-endian. v0.2 cap matches
--      Http2_Core.Connection.Buffer_Capacity (16 KB) so a single
--      DATA frame holds one message; larger messages would need
--      multi-frame reassembly.
--
--  v0.2 limitation: one message per DATA frame, no streaming
--  multi-message reads. Server-streaming / client-streaming RPCs
--  will need an iterator-style API; deferred.

with RFLX.RFLX_Types;
with RFLX.RFLX_Builtin_Types;
use type RFLX.RFLX_Types.Index;

package Grpc_Core.Framing
with SPARK_Mode
is

   --  Wrap `Message` with the 5-byte gRPC frame header at
   --  Buffer'First. Output_Last is the index of the last byte
   --  written; total framed length = Message'Length + 5.
   procedure Encode
     (Buffer       : in out RFLX.RFLX_Types.Bytes;
      Message      : RFLX.RFLX_Types.Bytes;
      Output_Last  : out RFLX.RFLX_Types.Index;
      Output_OK    : out Boolean)
   with Pre => Buffer'Length >= 5 + Message'Length;

   --  Decode the 5-byte gRPC frame header at Buffer'First, copy
   --  the message bytes into `Message` (caller-sized), set
   --  Compressed_Flag to the C bit, and Message_Last to the index
   --  of the last copied byte. Output_OK = False if the header
   --  declares a length that doesn't fit in the input buffer or
   --  the caller's Message buffer.
   procedure Decode
     (Input            : RFLX.RFLX_Types.Bytes;
      Message          : in out RFLX.RFLX_Types.Bytes;
      Message_Length   : out RFLX.RFLX_Types.Length;
      Compressed_Flag  : out Boolean;
      Output_OK        : out Boolean)
   with
     Pre =>
       Input'Length >= 5
       --  Bound Message'First so the slice arithmetic
       --  `Message'First + Index(Len) - 1` cannot overflow
       --  Index'Base. Real callers always pass Message'First = 1.
       --  Bound Message'Last so the slice end-index can be
       --  computed without overflowing Index'Base. Real callers
       --  always pass Message starting near 1 with modest length.
       and then Message'Last < RFLX.RFLX_Types.Index'Last;

end Grpc_Core.Framing;
