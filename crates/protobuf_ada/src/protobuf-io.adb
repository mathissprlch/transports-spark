package body Protobuf.IO is

   ---------------
   --  Read side --

   function Available
     (C      : Read_Cursor;
      Buffer : Octet_Array) return Octet_Count
   is
   begin
      return Buffer'Length - C.Position;
   end Available;

   procedure Read_Octet
     (C      : in out Read_Cursor;
      Buffer : Octet_Array;
      Value  : out Octet)
   is
   begin
      Value := Buffer (Buffer'First + Octet_Offset (C.Position));
      C.Position := C.Position + 1;
   end Read_Octet;

   procedure Read_Octets
     (C      : in out Read_Cursor;
      Buffer : Octet_Array;
      Into   : out Octet_Array)
   is
      First : constant Octet_Offset :=
        Buffer'First + Octet_Offset (C.Position);
   begin
      Into := Buffer (First .. First + Octet_Offset (Into'Length) - 1);
      C.Position := C.Position + Into'Length;
   end Read_Octets;

   procedure Skip
     (C      : in out Read_Cursor;
      Buffer : Octet_Array;
      Count  : Octet_Count)
   is
      pragma Unreferenced (Buffer);
   begin
      C.Position := C.Position + Count;
   end Skip;

   function Take_Slice
     (C      : in out Read_Cursor;
      Buffer : Octet_Array;
      Length : Octet_Count) return Octet_Array
   is
      First : constant Octet_Offset :=
        Buffer'First + Octet_Offset (C.Position);
   begin
      C.Position := C.Position + Length;
      return Buffer (First .. First + Octet_Offset (Length) - 1);
   end Take_Slice;

   ----------------
   --  Write side --

   function Free
     (C      : Write_Cursor;
      Buffer : Octet_Array) return Octet_Count
   is
   begin
      return Buffer'Length - C.Position;
   end Free;

   procedure Write_Octet
     (C      : in out Write_Cursor;
      Buffer : in out Octet_Array;
      Value  : Octet)
   is
   begin
      Buffer (Buffer'First + Octet_Offset (C.Position)) := Value;
      C.Position := C.Position + 1;
   end Write_Octet;

   procedure Write_Octets
     (C      : in out Write_Cursor;
      Buffer : in out Octet_Array;
      From   : Octet_Array)
   is
      First : constant Octet_Offset :=
        Buffer'First + Octet_Offset (C.Position);
   begin
      Buffer (First .. First + Octet_Offset (From'Length) - 1) := From;
      C.Position := C.Position + From'Length;
   end Write_Octets;

end Protobuf.IO;
