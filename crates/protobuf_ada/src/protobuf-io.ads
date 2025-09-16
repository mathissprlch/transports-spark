--  Protobuf.IO
--
--  Bounded byte cursors over an Octet_Array. Used by Protobuf.Wire and
--  the descriptor decoder. No heap allocation, no hidden state — the
--  caller owns the buffer and passes it on every call.

with Ada.Streams;

package Protobuf.IO
  with Pure
is
   subtype Octet        is Ada.Streams.Stream_Element;
   subtype Octet_Count  is Ada.Streams.Stream_Element_Count;
   subtype Octet_Offset is Ada.Streams.Stream_Element_Offset;
   subtype Octet_Array  is Ada.Streams.Stream_Element_Array;

   --  Make + - * etc. on Stream_Element_Offset and its subtypes directly
   --  visible without forcing callers to write `Ada.Streams."+"`.
   use type Ada.Streams.Stream_Element_Offset;

   --  Read side ---------------------------------------------------------

   type Read_Cursor is record
      Position : Octet_Count := 0;     --  bytes consumed from the buffer
   end record;

   function Available
     (C      : Read_Cursor;
      Buffer : Octet_Array) return Octet_Count
     with Inline;
   --  Number of bytes left to read.

   procedure Read_Octet
     (C      : in out Read_Cursor;
      Buffer : Octet_Array;
      Value  : out Octet)
     with Pre  => Available (C, Buffer) >= 1,
          Post => C.Position = C.Position'Old + 1;

   procedure Read_Octets
     (C      : in out Read_Cursor;
      Buffer : Octet_Array;
      Into   : out Octet_Array)
     with Pre  => Available (C, Buffer) >= Into'Length,
          Post => C.Position = C.Position'Old + Into'Length;

   procedure Skip
     (C      : in out Read_Cursor;
      Buffer : Octet_Array;
      Count  : Octet_Count)
     with Pre  => Available (C, Buffer) >= Count,
          Post => C.Position = C.Position'Old + Count;

   --  Write side --------------------------------------------------------

   type Write_Cursor is record
      Position : Octet_Count := 0;     --  bytes written to the buffer
   end record;

   function Free
     (C      : Write_Cursor;
      Buffer : Octet_Array) return Octet_Count
     with Inline;
   --  Number of bytes the buffer still has room for.

   procedure Write_Octet
     (C      : in out Write_Cursor;
      Buffer : in out Octet_Array;
      Value  : Octet)
     with Pre  => Free (C, Buffer) >= 1,
          Post => C.Position = C.Position'Old + 1;

   procedure Write_Octets
     (C      : in out Write_Cursor;
      Buffer : in out Octet_Array;
      From   : Octet_Array)
     with Pre  => Free (C, Buffer) >= From'Length,
          Post => C.Position = C.Position'Old + From'Length;

end Protobuf.IO;
