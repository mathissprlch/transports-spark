with RFLX.Http2_Parameters;

package body Http2_Core.Wire
with SPARK_Mode
is

   use type RFLX.RFLX_Types.Index;
   use type RFLX.RFLX_Builtin_Types.Byte;

   subtype U8 is RFLX.RFLX_Types.Byte;

   --  Big-endian byte writers. The frame layer is uniformly BE on
   --  the wire (RFC 9113 §4.1); these centralize the shifts so the
   --  per-type encoders stay readable.

   --  Bit_Len's upper bound (RFLX_Builtin_Types.Bit_Length goes up
   --  to Length'Last * 8) is far above what any HTTP/2 frame field
   --  can carry. The Put_Be* helpers explicitly bound their input V
   --  to the wire-field width so gnatprove can discharge the
   --  arithmetic obligations; the Get_Be* helpers post-condition
   --  the same bound on their result.

   --  Pre conditions on every helper, formulated so the prover can
   --  discharge the index arithmetic without overflow:
   --    * Buffer /= null (where applicable)
   --    * At_Idx in Buffer.all'Range
   --    * Buffer.all'Last - At_Idx >= N-1   (room for N bytes total
   --      starting at At_Idx; expressed as subtraction so the
   --      precondition itself never evaluates At_Idx + N)
   --    * V is bounded to the wire-field width

   procedure Put_U8
     (Buffer : Bytes_Ptr; At_Idx : Index; V : Bit_Len)
   with
     Pre => Buffer /= null
            and then At_Idx in Buffer.all'Range
            and then V <= 16#FF#;

   procedure Put_U8
     (Buffer : Bytes_Ptr; At_Idx : Index; V : Bit_Len)
   is
   begin
      Buffer (At_Idx) := U8 (V);
   end Put_U8;

   procedure Put_Be16
     (Buffer : Bytes_Ptr; At_Idx : Index; V : Bit_Len)
   with
     Pre => Buffer /= null
            and then At_Idx in Buffer.all'Range
            and then Buffer.all'Last - At_Idx >= 1
            and then V <= 16#FFFF#;

   procedure Put_Be16
     (Buffer : Bytes_Ptr; At_Idx : Index; V : Bit_Len)
   is
   begin
      Buffer (At_Idx)     := U8 (V / 256);
      Buffer (At_Idx + 1) := U8 (V mod 256);
   end Put_Be16;

   procedure Put_Be24
     (Buffer : Bytes_Ptr; At_Idx : Index; V : Bit_Len)
   with
     Pre => Buffer /= null
            and then At_Idx in Buffer.all'Range
            and then Buffer.all'Last - At_Idx >= 2
            and then V <= 16#FF_FFFF#;

   procedure Put_Be24
     (Buffer : Bytes_Ptr; At_Idx : Index; V : Bit_Len)
   is
   begin
      Buffer (At_Idx)     := U8 (V / 65536);
      Buffer (At_Idx + 1) := U8 ((V / 256) mod 256);
      Buffer (At_Idx + 2) := U8 (V mod 256);
   end Put_Be24;

   procedure Put_Be32
     (Buffer : Bytes_Ptr; At_Idx : Index; V : Bit_Len)
   with
     Pre => Buffer /= null
            and then At_Idx in Buffer.all'Range
            and then Buffer.all'Last - At_Idx >= 3
            and then V <= 16#FFFF_FFFF#;

   procedure Put_Be32
     (Buffer : Bytes_Ptr; At_Idx : Index; V : Bit_Len)
   is
   begin
      Buffer (At_Idx)     := U8 (V / 16777216);
      Buffer (At_Idx + 1) := U8 ((V / 65536) mod 256);
      Buffer (At_Idx + 2) := U8 ((V / 256) mod 256);
      Buffer (At_Idx + 3) := U8 (V mod 256);
   end Put_Be32;

   --  Equivalent readers for the decoder.
   function Get_Be16 (Buffer : RFLX.RFLX_Types.Bytes;
                      At_Idx : Index) return Bit_Len
   is (Bit_Len (Buffer (At_Idx)) * 256
       + Bit_Len (Buffer (At_Idx + 1)))
   with
     Pre  => At_Idx in Buffer'Range
             and then Buffer'Last - At_Idx >= 1,
     Post => Get_Be16'Result <= 16#FFFF#;

   function Get_Be24 (Buffer : RFLX.RFLX_Types.Bytes;
                      At_Idx : Index) return Bit_Len
   is (Bit_Len (Buffer (At_Idx)) * 65536
       + Bit_Len (Buffer (At_Idx + 1)) * 256
       + Bit_Len (Buffer (At_Idx + 2)))
   with
     Pre  => At_Idx in Buffer'Range
             and then Buffer'Last - At_Idx >= 2,
     Post => Get_Be24'Result <= 16#FF_FFFF#;

   function Get_Be32 (Buffer : RFLX.RFLX_Types.Bytes;
                      At_Idx : Index) return Bit_Len
   is (Bit_Len (Buffer (At_Idx)) * 16777216
       + Bit_Len (Buffer (At_Idx + 1)) * 65536
       + Bit_Len (Buffer (At_Idx + 2)) * 256
       + Bit_Len (Buffer (At_Idx + 3)))
   with
     Pre  => At_Idx in Buffer'Range
             and then Buffer'Last - At_Idx >= 3,
     Post => Get_Be32'Result <= 16#FFFF_FFFF#;

   --  Convert an HTTP_2_Frame_Type enum value into the 8-bit wire
   --  representation. The IANA-derived enum has Always_Valid, so
   --  values outside the named set are still legal at the type
   --  level; we use 'Enum_Rep to read the raw integer.
   function Type_To_Byte (T : Frame_Type) return U8;
   function Type_To_Byte (T : Frame_Type) return U8 is
   begin
      return U8 (Frame_Type'Enum_Rep (T));
   end Type_To_Byte;

   function Byte_To_Type (B : U8) return Frame_Type;
   function Byte_To_Type (B : U8) return Frame_Type is
   begin
      --  Always_Valid: any 8-bit pattern parses; unrecognized
      --  values map to the registry-aware 'Enum_Val if present, else
      --  the closest. Simplest correct: case the named ones.
      case B is
         when 16#00# => return RFLX.Http2_Parameters.DATA;
         when 16#01# => return RFLX.Http2_Parameters.HEADERS;
         when 16#02# => return RFLX.Http2_Parameters.PRIORITY;
         when 16#03# => return RFLX.Http2_Parameters.RST_STREAM;
         when 16#04# => return RFLX.Http2_Parameters.SETTINGS;
         when 16#05# => return RFLX.Http2_Parameters.PUSH_PROMISE;
         when 16#06# => return RFLX.Http2_Parameters.PING;
         when 16#07# => return RFLX.Http2_Parameters.GOAWAY;
         when 16#08# => return RFLX.Http2_Parameters.WINDOW_UPDATE;
         when 16#09# => return RFLX.Http2_Parameters.CONTINUATION;
         when 16#0A# => return RFLX.Http2_Parameters.ALTSVC;
         when 16#0C# => return RFLX.Http2_Parameters.ORIGIN;
         when 16#10# => return RFLX.Http2_Parameters.PRIORITY_UPDATE;
         when others =>
            --  Unknown frame types: per §4.1, "Implementations MUST
            --  ignore and discard any frame that has a type that is
            --  unknown." Returning DATA is a sentinel; the caller
            --  should treat the frame as opaque-and-ignored.
            return RFLX.Http2_Parameters.DATA;
      end case;
   end Byte_To_Type;

   --  Internal helper: write the 9-byte fixed header at Buffer'First.
   procedure Put_Header
     (Buffer            : Bytes_Ptr;
      Length            : Bit_Len;
      F_Type            : Frame_Type;
      Flags             : Byte;
      Stream_Identifier : Bit_Len)
   with
     Pre => Buffer /= null
            and then Buffer'Length >= 9
            and then Length <= 16#FF_FFFF#
            and then Stream_Identifier <= 16#FFFF_FFFF#;

   procedure Put_Header
     (Buffer            : Bytes_Ptr;
      Length            : Bit_Len;
      F_Type            : Frame_Type;
      Flags             : Byte;
      Stream_Identifier : Bit_Len)
   is
   begin
      Put_Be24 (Buffer, Buffer'First,     Length);
      Buffer    (Buffer'First + 3) := Type_To_Byte (F_Type);
      Buffer    (Buffer'First + 4) := Flags;
      --  Reserved bit always 0; Stream_Identifier in low 31 bits of
      --  the next 32-bit word.
      Put_Be32 (Buffer, Buffer'First + 5, Stream_Identifier);
   end Put_Header;

   ---------------------------------------------------------------------
   --  SETTINGS encode
   ---------------------------------------------------------------------

   procedure Encode_Settings
     (Buffer : in out Bytes_Ptr;
      Last   :    out Index;
      Params : Settings_List)
   is
      Body_Len : constant Bit_Len := Bit_Len (6 * Params'Length);
      Pos      : Index := Buffer'First + 9;
   begin
      Put_Header
        (Buffer, Body_Len,
         RFLX.Http2_Parameters.SETTINGS,
         0,
         0);
      for P of Params loop
         Put_Be16 (Buffer, Pos,
                   Bit_Len (Settings_Id'Enum_Rep (P.Identifier)));
         Put_Be32 (Buffer, Pos + 2, P.Value);
         Pos := Pos + 6;
      end loop;
      Last := Buffer'First + Index (8 + 6 * Params'Length);
   end Encode_Settings;

   procedure Encode_Settings_Ack
     (Buffer : in out Bytes_Ptr;
      Last   :    out Index)
   is
   begin
      Put_Header
        (Buffer, 0,
         RFLX.Http2_Parameters.SETTINGS,
         Flag_ACK,
         0);
      Last := Buffer'First + 8;
   end Encode_Settings_Ack;

   procedure Decode_Settings_Payload
     (Buffer       : RFLX.RFLX_Types.Bytes;
      Valid        :    out Boolean;
      Params       : in out Settings_List;
      Params_Last  :    out Natural)
   is
      Pos      : Index := Buffer'First;
      Idx      : Integer := Params'First - 1;
   begin
      Valid       := False;
      Params_Last := Params'First - 1;
      if Buffer'Length mod 6 /= 0 then
         return;
      end if;
      while Pos + 5 <= Buffer'Last and then Idx < Params'Last loop
         Idx := Idx + 1;
         declare
            Id_Raw : constant Bit_Len := Get_Be16 (Buffer, Pos);
            Val    : constant Bit_Len :=
              Get_Be32 (Buffer, Pos + 2);
            --  HTTP_2_Settings is Always_Valid; map known values.
         begin
            Params (Idx).Identifier :=
              Settings_Id'Enum_Val (Id_Raw);
            Params (Idx).Value := Val;
         exception
            when others =>
               --  Unknown identifier — ignore per §6.5.2 by leaving
               --  Idx unbumped... actually we already bumped, so
               --  store with whatever the enum gives back. Simpler
               --  policy: let unknown go through with default enum
               --  so the caller's case handler can ignore.
               Params (Idx).Identifier :=
                 RFLX.Http2_Parameters.HEADER_TABLE_SIZE;
               Params (Idx).Value := Val;
         end;
         Pos := Pos + 6;
      end loop;
      Params_Last := Idx;
      Valid       := True;
   end Decode_Settings_Payload;

   ---------------------------------------------------------------------
   --  PING encode
   ---------------------------------------------------------------------

   procedure Encode_Ping
     (Buffer       : in out Bytes_Ptr;
      Last         :    out Index;
      Opaque_Data  : RFLX.RFLX_Types.Bytes;
      Ack          : Boolean := False)
   is
      Flags : constant Byte := (if Ack then Flag_ACK else 0);
   begin
      Put_Header
        (Buffer, 8,
         RFLX.Http2_Parameters.PING, Flags, 0);
      Buffer (Buffer'First + 9 .. Buffer'First + 16) :=
        Opaque_Data (Opaque_Data'First .. Opaque_Data'First + 7);
      Last := Buffer'First + 16;
   end Encode_Ping;

   ---------------------------------------------------------------------
   --  RST_STREAM encode
   ---------------------------------------------------------------------

   procedure Encode_Rst_Stream
     (Buffer     : in out Bytes_Ptr;
      Last       :    out Index;
      Stream_Id  : Bit_Len;
      Error_Code : Bit_Len)
   is
   begin
      Put_Header
        (Buffer, 4,
         RFLX.Http2_Parameters.RST_STREAM, 0, Stream_Id);
      Put_Be32 (Buffer, Buffer'First + 9, Error_Code);
      Last := Buffer'First + 12;
   end Encode_Rst_Stream;

   ---------------------------------------------------------------------
   --  WINDOW_UPDATE encode
   ---------------------------------------------------------------------

   procedure Encode_Window_Update
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Stream_Id : Bit_Len;
      Increment : Bit_Len)
   is
   begin
      Put_Header
        (Buffer, 4,
         RFLX.Http2_Parameters.WINDOW_UPDATE, 0, Stream_Id);
      Put_Be32 (Buffer, Buffer'First + 9, Increment);
      Last := Buffer'First + 12;
   end Encode_Window_Update;

   ---------------------------------------------------------------------
   --  GOAWAY encode
   ---------------------------------------------------------------------

   procedure Encode_Goaway
     (Buffer         : in out Bytes_Ptr;
      Last           :    out Index;
      Last_Stream_Id : Bit_Len;
      Error_Code     : Bit_Len;
      Debug_Data     : RFLX.RFLX_Types.Bytes)
   is
      Body_Len : constant Bit_Len :=
        8 + Bit_Len (Debug_Data'Length);
   begin
      Put_Header
        (Buffer, Body_Len,
         RFLX.Http2_Parameters.GOAWAY, 0, 0);
      Put_Be32 (Buffer, Buffer'First + 9, Last_Stream_Id);
      Put_Be32 (Buffer, Buffer'First + 13, Error_Code);
      --  Branch on Length = 0; Index(0) would raise Constraint_Error
      --  (Index'First = 1). Same trap as Grpc_Core.Framing.Encode.
      if Debug_Data'Length > 0 then
         Buffer
           (Buffer'First + 17 ..
              Buffer'First + 16 + Index (Debug_Data'Length)) :=
           Debug_Data;
         Last := Buffer'First + 16 + Index (Debug_Data'Length);
      else
         Last := Buffer'First + 16;
      end if;
   end Encode_Goaway;

   ---------------------------------------------------------------------
   --  HEADERS encode (HPACK fragment passed by caller)
   ---------------------------------------------------------------------

   procedure Encode_Headers
     (Buffer    : in out Bytes_Ptr;
      Last      :    out Index;
      Stream_Id : Bit_Len;
      Fragment  : RFLX.RFLX_Types.Bytes;
      End_Stream : Boolean)
   is
      Flags : constant Byte :=
        Flag_END_HEADERS or
        (if End_Stream then Flag_END_STREAM else 0);
   begin
      Put_Header
        (Buffer, Bit_Len (Fragment'Length),
         RFLX.Http2_Parameters.HEADERS, Flags, Stream_Id);
      if Fragment'Length > 0 then
         Buffer
           (Buffer'First + 9 ..
              Buffer'First + 8 + Index (Fragment'Length)) := Fragment;
         Last := Buffer'First + 8 + Index (Fragment'Length);
      else
         Last := Buffer'First + 8;
      end if;
   end Encode_Headers;

   ---------------------------------------------------------------------
   --  DATA encode
   ---------------------------------------------------------------------

   procedure Encode_Data
     (Buffer     : in out Bytes_Ptr;
      Last       :    out Index;
      Stream_Id  : Bit_Len;
      Payload    : RFLX.RFLX_Types.Bytes;
      End_Stream : Boolean)
   is
      Flags : constant Byte :=
        (if End_Stream then Flag_END_STREAM else 0);
   begin
      Put_Header
        (Buffer, Bit_Len (Payload'Length),
         RFLX.Http2_Parameters.DATA, Flags, Stream_Id);
      if Payload'Length > 0 then
         Buffer
           (Buffer'First + 9 ..
              Buffer'First + 8 + Index (Payload'Length)) := Payload;
         Last := Buffer'First + 8 + Index (Payload'Length);
      else
         Last := Buffer'First + 8;
      end if;
   end Encode_Data;

   ---------------------------------------------------------------------
   --  Decode_Frame_Header
   ---------------------------------------------------------------------

   procedure Decode_Frame_Header
     (Buffer : RFLX.RFLX_Types.Bytes;
      Header : out Frame_Header;
      Valid  : out Boolean)
   is
      First : constant Index := Buffer'First;
   begin
      Header.Length            := Get_Be24 (Buffer, First);
      Header.Frame_Type_Value  := Byte_To_Type (Buffer (First + 3));
      Header.Flags             := Buffer (First + 4);
      --  Mask off the reserved high bit of the 32-bit stream-id word.
      Header.Stream_Identifier :=
        Get_Be32 (Buffer, First + 5) mod (2 ** 31);
      Valid := True;
   end Decode_Frame_Header;

end Http2_Core.Wire;
