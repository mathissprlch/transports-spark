--  Protobuf.Descriptor
--
--  Hand-written subset of google/protobuf/descriptor.proto, the schema
--  protoc uses to describe a parsed .proto file. We decode these messages
--  to drive code generation in protoc-gen-grpc-ada.
--
--  Subset chosen to cover what the gRPC plugin actually consumes:
--    file name, package, syntax
--    messages: name, fields, nested types, enums
--    fields: name, number, label, type, type_name
--    enums: name, values (name + number)
--    services: name, methods (name, input, output, streaming flags)
--
--  Anything else we encounter is silently skipped via Protobuf.Wire.Skip_Field.

with Ada.Containers.Vectors;
with Ada.Strings.Unbounded;
with Interfaces;
with Protobuf.IO;

package Protobuf.Descriptor is

   subtype Name is Ada.Strings.Unbounded.Unbounded_String;

   --  FieldDescriptorProto.Type — values match the proto enum.
   type Field_Type is
     (Type_Unknown,
      Type_Double,    --  1
      Type_Float,     --  2
      Type_Int64,     --  3
      Type_UInt64,    --  4
      Type_Int32,     --  5
      Type_Fixed64,   --  6
      Type_Fixed32,   --  7
      Type_Bool,      --  8
      Type_String,    --  9
      Type_Group,     --  10 (deprecated)
      Type_Message,   --  11
      Type_Bytes,     --  12
      Type_UInt32,    --  13
      Type_Enum,      --  14
      Type_SFixed32,  --  15
      Type_SFixed64,  --  16
      Type_SInt32,    --  17
      Type_SInt64);   --  18
   for Field_Type use
     (Type_Unknown   => 0,
      Type_Double    => 1,
      Type_Float     => 2,
      Type_Int64     => 3,
      Type_UInt64    => 4,
      Type_Int32     => 5,
      Type_Fixed64   => 6,
      Type_Fixed32   => 7,
      Type_Bool      => 8,
      Type_String    => 9,
      Type_Group     => 10,
      Type_Message   => 11,
      Type_Bytes     => 12,
      Type_UInt32    => 13,
      Type_Enum      => 14,
      Type_SFixed32  => 15,
      Type_SFixed64  => 16,
      Type_SInt32    => 17,
      Type_SInt64    => 18);

   --  FieldDescriptorProto.Label
   type Field_Label is
     (Label_Unknown,
      Label_Optional,  --  1
      Label_Required,  --  2
      Label_Repeated); --  3
   for Field_Label use
     (Label_Unknown  => 0,
      Label_Optional => 1,
      Label_Required => 2,
      Label_Repeated => 3);

   ----------------------------------------------------------------
   --  FieldDescriptorProto

   type Field_Descriptor is record
      Field_Name : Name;
      Number     : Interfaces.Integer_32 := 0;
      Label      : Field_Label := Label_Unknown;
      Field_Kind : Field_Type  := Type_Unknown;
      Type_Name  : Name;       --  for messages and enums; ".pkg.Type" form
      Packed     : Boolean := False;
   end record;

   package Field_Vectors is
     new Ada.Containers.Vectors (Positive, Field_Descriptor);

   ----------------------------------------------------------------
   --  EnumValueDescriptorProto + EnumDescriptorProto

   type Enum_Value is record
      Value_Name : Name;
      Number     : Interfaces.Integer_32 := 0;
   end record;

   package Enum_Value_Vectors is
     new Ada.Containers.Vectors (Positive, Enum_Value);

   type Enum_Descriptor is record
      Enum_Name : Name;
      Values    : Enum_Value_Vectors.Vector;
   end record;

   package Enum_Vectors is
     new Ada.Containers.Vectors (Positive, Enum_Descriptor);

   ----------------------------------------------------------------
   --  DescriptorProto (a message type). Recursive via nested_type.

   type Message_Descriptor;
   type Message_Descriptor_Access is access all Message_Descriptor;

   package Message_Vectors is
     new Ada.Containers.Vectors (Positive, Message_Descriptor_Access);

   type Message_Descriptor is record
      Message_Name : Name;
      Fields       : Field_Vectors.Vector;
      Nested_Types : Message_Vectors.Vector;
      Enums        : Enum_Vectors.Vector;
   end record;

   ----------------------------------------------------------------
   --  MethodDescriptorProto + ServiceDescriptorProto

   type Method_Descriptor is record
      Method_Name      : Name;
      Input_Type       : Name;
      Output_Type      : Name;
      Client_Streaming : Boolean := False;
      Server_Streaming : Boolean := False;
   end record;

   package Method_Vectors is
     new Ada.Containers.Vectors (Positive, Method_Descriptor);

   type Service_Descriptor is record
      Service_Name : Name;
      Methods      : Method_Vectors.Vector;
   end record;

   package Service_Vectors is
     new Ada.Containers.Vectors (Positive, Service_Descriptor);

   ----------------------------------------------------------------
   --  FileDescriptorProto

   type File_Descriptor is record
      File_Name    : Name;
      Package_Name : Name;
      Syntax       : Name;     --  "proto2"|"proto3"|"editions"; "" if absent
      Messages  : Message_Vectors.Vector;
      Enums     : Enum_Vectors.Vector;
      Services  : Service_Vectors.Vector;
   end record;

   package File_Vectors is
     new Ada.Containers.Vectors (Positive, File_Descriptor);

   ----------------------------------------------------------------
   --  FileDescriptorSet (the top-level message protoc emits).

   type File_Descriptor_Set is record
      Files : File_Vectors.Vector;
   end record;

   --  Top-level entry point: decode a raw FileDescriptorSet (as emitted by
   --  `protoc --descriptor_set_out=` or as the file_descriptor_set field
   --  of a CodeGeneratorRequest). Raises Protobuf.Wire.Wire_Format_Error
   --  on malformed input; ignores fields we don't model.
   procedure Decode
     (Buffer : Protobuf.IO.Octet_Array;
      Result : out File_Descriptor_Set);

end Protobuf.Descriptor;

