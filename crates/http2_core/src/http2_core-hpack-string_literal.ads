--  Http2_Core.Hpack.String_Literal — RFC 7541 §5.2 string literal.
--
--  Source: RFC 7541 §5.2 — String Literal Representation.
--
--  Layout:
--    +---+---+---+---+---+---+---+---+
--    | H |    String Length (7+)     |
--    +---+---------------------------+
--    |  String Data (Length octets)  |
--    +-------------------------------+
--
--  H bit selects Huffman (1) or raw (0) encoding of the data
--  octets. Length is a 7-prefix-bit integer (§5.1) giving the byte
--  count of the encoded data, NOT the original character count.
--
--  v0.2 encoder always emits H=0 (raw); decoder must accept both.

with Interfaces;

package Http2_Core.Hpack.String_Literal
with SPARK_Mode
is

   subtype Octet is Interfaces.Unsigned_8;
   type Octet_Array is array (Positive range <>) of Octet;

   --  Encode `Input` as a §5.2 string literal with H=0 (raw).
   procedure Encode_Raw
     (Input       : Octet_Array;
      Output      : in out Octet_Array;
      Output_Last : out Natural;
      Output_OK   : out Boolean)
   with Pre => Output'Length >= 1
               and then Output'Last < Natural'Last
               and then Input'Last < Natural'Last;

   --  Decode a §5.2 string literal starting at Input(First). The
   --  decoded bytes are written into Output starting at its First.
   --  Sets:
   --    * Last       — last input byte consumed (length prefix +
   --                   data combined)
   --    * Output_Last — last output byte written
   --    * Output_OK   — False if input truncated, length exceeds
   --                   v0.2 cap, or Huffman decode fails
   procedure Decode
     (Input       : Octet_Array;
      First       : Positive;
      Output      : in out Octet_Array;
      Last        : out Natural;
      Output_Last : out Natural;
      Output_OK   : out Boolean)
   with Pre => First in Input'Range
               and then Output'Length >= 1
               and then Output'Last < Natural'Last
               and then Input'Last < Natural'Last;

end Http2_Core.Hpack.String_Literal;
