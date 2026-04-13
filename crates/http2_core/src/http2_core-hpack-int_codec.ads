--  Http2_Core.Hpack.Int_Codec — RFC 7541 §5.1 integer encoding.
--
--  Source: RFC 7541 §5.1 — Integer Representation.
--
--  HPACK integers are variable-length. The first byte's high bits
--  carry a representation discriminator (set by the caller); the
--  low N bits carry either the integer value (if it fits) or all
--  1s indicating that continuation bytes follow. Each continuation
--  byte has a 1-bit "more bytes" flag (high bit) plus 7 value bits
--  in little-endian-by-byte form.
--
--  Prefix size N is parameter to encode/decode: 7 bits for Indexed
--  Header Field (§6.1), 6 for Literal With Incremental Indexing
--  (§6.2.1), 5 for Dynamic Table Size Update (§6.3), 4 for Literal
--  Without/Never Indexed (§6.2.2/§6.2.3).
--
--  Bounded for v0.2: max integer value 2**21 - 1 ≈ 2M, comfortably
--  larger than every header table index, fragment length, or
--  table-size value we'll ever transmit. Three continuation bytes
--  cover this range. Larger inputs are rejected.

with Interfaces;

package Http2_Core.Hpack.Int_Codec
with SPARK_Mode
is

   subtype Octet is Interfaces.Unsigned_8;
   type Octet_Array is array (Positive range <>) of Octet;

   --  Permitted prefix widths per HPACK representation.
   subtype Prefix_Bits is Natural range 4 .. 7;

   --  Encode `Value` with an `N`-bit prefix into `Output`. The high
   --  (8 - N) bits of the first byte are NOT touched — the caller
   --  has already placed the representation discriminator there.
   --  Output_Last is the last written index. Output_OK = False if
   --  the buffer was too small to fit the encoding.
   procedure Encode
     (Value       : Natural;
      N           : Prefix_Bits;
      Output      : in out Octet_Array;
      Output_Last : out Natural;
      Output_OK   : out Boolean)
   with Pre  => Output'Length >= 1
                and then Value <= 2 ** 21 - 1,
        Post => (if Output_OK then
                   Output_Last in Output'First .. Output'Last);

   --  Decode an integer from `Input` starting at `First`, reading
   --  the N-bit prefix from `Input(First)` and continuation bytes
   --  from First+1 onward as needed. Sets Last to the index of the
   --  final byte consumed; Value to the decoded integer.
   --  Output_OK = False if input too short, malformed (5+ continuation
   --  bytes), or if value exceeds the bounded 2**21 cap.
   procedure Decode
     (Input     : Octet_Array;
      First     : Positive;
      N         : Prefix_Bits;
      Value     : out Natural;
      Last      : out Natural;
      Output_OK : out Boolean)
   with Pre  => First in Input'Range,
        Post => (if Output_OK then Last in First .. Input'Last
                 else Last = First - 1);

end Http2_Core.Hpack.Int_Codec;
