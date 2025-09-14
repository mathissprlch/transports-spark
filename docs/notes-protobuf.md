# Notes: Protocol Buffers wire format

Reading <https://protobuf.dev/programming-guides/encoding/>.

## Tag

Each field on the wire is preceded by a tag:

```
tag = (field_number << 3) | wire_type
```

The tag is encoded as a varint, so small field numbers (1–15) fit in one byte
of tag — that's why hot fields should be numbered low.

## Wire types

```
0  VARINT          int32, int64, uint32, uint64, bool, enum, sint32, sint64
1  I64             fixed64, sfixed64, double
2  LEN             string, bytes, message, packed-repeated
3  SGROUP          deprecated (groups, start)
4  EGROUP          deprecated (groups, end)
5  I32             fixed32, sfixed32, float
```

We'll support 0, 1, 2, 5. Groups (3, 4) are deprecated and we won't emit
them; if encountered while decoding we skip them politely.

## Varint

Little-endian, base-128. Each byte's MSB is a continuation flag. Up to 10
bytes for a 64-bit unsigned. Negative int32/int64 values are encoded as
10-byte varints (two's-complement extended to 64 bits) — wasteful, hence
sint32/sint64 with ZigZag.

```
encode(n):
  while n >= 0x80:
    emit (n & 0x7F) | 0x80
    n >>= 7
  emit n
```

## ZigZag

For sint32/sint64. Folds sign into the LSB so small magnitudes stay small:

```
zigzag32(n) = (n << 1) ^ (n >> 31)
zigzag64(n) = (n << 1) ^ (n >> 63)
```

In Ada, the right-shift on signed values needs to be arithmetic
(sign-extending). Easiest way: do the math on the unsigned representation,
then reinterpret. Will use `Unchecked_Conversion` between e.g.
`Interfaces.Integer_32` and `Interfaces.Unsigned_32`.

## Length-delimited (wire type 2)

```
[varint length][bytes...]
```

Used for strings, byte arrays, sub-messages, and packed repeated primitives.

## Packed repeated

In proto3 (and editions=2023 default), repeated primitive fields are encoded
packed: a single LEN field whose bytes are the concatenation of the values.
Decoder must handle both packed and unpacked forms (interop with old
encoders).

## Fixed32 / Fixed64

Little-endian. 4 or 8 bytes literal. Easy.

## What I'll write

```
package Protobuf.Wire is
   subtype Octet is Ada.Streams.Stream_Element;

   --  Tag
   procedure Encode_Tag (Field_Number : Field_Number_Type;
                         Wire         : Wire_Type;
                         Buffer       : in out Buffers.Buffer);
   procedure Decode_Tag (Buffer       : in out Buffers.Buffer;
                         Field_Number : out Field_Number_Type;
                         Wire         : out Wire_Type);

   --  Varint
   procedure Encode_Varint (V : Interfaces.Unsigned_64; Buffer : ...);
   procedure Decode_Varint (Buffer : ...; V : out Interfaces.Unsigned_64);

   --  ZigZag
   function ZigZag_Encode_32 (V : Interfaces.Integer_32)
                              return Interfaces.Unsigned_32;
   function ZigZag_Decode_32 (V : Interfaces.Unsigned_32)
                              return Interfaces.Integer_32;
   --  ... and 64-bit variants ...

   --  Fixed
   procedure Encode_Fixed_32 (V : Interfaces.Unsigned_32; Buffer : ...);
   procedure Encode_Fixed_64 (V : Interfaces.Unsigned_64; Buffer : ...);

   --  Length-delimited
   procedure Encode_Length_Delim (Bytes : Stream_Element_Array; Buffer : ...);
   procedure Decode_Length_Delim (Buffer : ...; Length : out Natural);
end Protobuf.Wire;
```

`Buffer` will be a small abstraction in `Protobuf.IO` that wraps a
`Stream_Element_Array` with a cursor for both read and write. Bounded; no
heap allocation.

## Edge cases to remember

- Varint with 11+ bytes is malformed.
- Length on LEN fields can in principle be huge — clamp to a sane max (we
  pick 64 MiB at the API boundary).
- Unknown field numbers must be skipped, not erroneous (gRPC depends on
  this for forward compatibility).
- A field may appear multiple times on the wire — the last value wins for
  scalars, all values are appended for repeated.
