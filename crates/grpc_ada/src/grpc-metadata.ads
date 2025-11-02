--  GRPC.Metadata
--
--  ASCII and binary headers attached to a gRPC request or response.
--  Keys ending in "-bin" carry binary values; on the wire those values
--  are base64-encoded but stored here as raw bytes (callers don't see
--  the encoding).

with Ada.Containers.Vectors;
with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;

package GRPC.Metadata is

   type Entry_Kind is (ASCII_Value, Binary_Value);

   type Entry_Type is record
      Kind  : Entry_Kind := ASCII_Value;
      Key   : Unbounded_String;
      Value : Unbounded_String;     --  raw bytes if Binary_Value
   end record;

   package Entry_Vectors is
     new Ada.Containers.Vectors (Positive, Entry_Type);

   subtype Headers is Entry_Vectors.Vector;

   procedure Add_ASCII (H : in out Headers; Key, Value : String);
   procedure Add_Binary (H : in out Headers; Key : String;
                         Value : Unbounded_String);

   --  First match (case-insensitive on Key per HTTP/2). Empty result
   --  if not present.
   function Get_First (H : Headers; Key : String) return Unbounded_String;

   function Has (H : Headers; Key : String) return Boolean;

   --  -bin keys must use Add_Binary; this enforces the convention.
   function Is_Binary_Key (Key : String) return Boolean;

end GRPC.Metadata;
