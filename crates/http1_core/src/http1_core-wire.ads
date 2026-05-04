--  Http1_Core.Wire — request parser + response builder.
--
--  Subset implemented (RFC 9112 §3, §4, §6):
--    * Request line: METHOD SP URI SP HTTP/1.1 CRLF
--    * Header field: Name ":" OWS Value OWS CRLF
--    * Empty CRLF terminates header section
--    * Body: only Content-Length-delimited; chunked is rejected
--      (501 by the server caller)
--    * No obs-fold (§5.2 says senders MUST NOT generate it; we
--      reject incoming obs-fold with 400)
--    * Header field name comparison is case-insensitive (§5.1)
--
--  Errors are surfaced via a Boolean Valid flag rather than
--  exceptions; the server caller decides how to respond.

with Ada.Streams;

package Http1_Core.Wire is

   subtype Octet is Ada.Streams.Stream_Element;
   subtype Octet_Array is Ada.Streams.Stream_Element_Array;
   subtype Octet_Offset is Ada.Streams.Stream_Element_Offset;

   Max_Headers          : constant := 32;
   Max_Header_Name_Len  : constant := 64;
   Max_Header_Value_Len : constant := 256;
   Max_Method_Len       : constant := 16;
   Max_Uri_Len          : constant := 256;

   type Header is record
      Name       : String (1 .. Max_Header_Name_Len) := (others => ' ');
      Name_Last  : Natural := 0;
      Value      : String (1 .. Max_Header_Value_Len) := (others => ' ');
      Value_Last : Natural := 0;
   end record;

   type Header_Block is array (1 .. Max_Headers) of Header;

   type Request is record
      Method      : String (1 .. Max_Method_Len) := (others => ' ');
      Method_Last : Natural := 0;
      Uri         : String (1 .. Max_Uri_Len) := (others => ' ');
      Uri_Last    : Natural := 0;
      Headers      : Header_Block;
      Headers_Last : Natural := 0;
      --  Where the body starts in the input stream (one past the
      --  end of the empty CRLF). Body bytes have not been read yet
      --  by Parse_Request_Head — the caller drives Receive() until
      --  Content-Length bytes are consumed.
      Header_Section_Last : Octet_Offset := 0;
      Content_Length      : Natural := 0;
      Has_Content_Length  : Boolean := False;
      Connection_Close    : Boolean := False;  --  per Connection: close
   end record;

   --  Parse the request line + header section from `Input` (bytes
   --  already received from the socket). Sets Valid := True if a
   --  complete header section ending in CRLF CRLF was found.
   --  Header_Section_Last in the result is the offset (relative
   --  to Input'First) of the byte AFTER the trailing CRLF.
   procedure Parse_Request_Head
     (Input : Octet_Array;
      Req   : out Request;
      Valid : out Boolean);

   --  Look up a header by case-insensitive name.
   --  Returns 0 if absent.
   function Find_Header
     (Headers      : Header_Block;
      Headers_Last : Natural;
      Name         : String) return Natural;

   --  Encode a response into Out_Buf:
   --    HTTP/1.1 <Status> <Reason> CRLF
   --    Header lines from Headers(1..Headers_Last)
   --    CRLF
   --    Body
   --
   --  Sets Out_Last to the index of the last byte written. Caller is
   --  responsible for sending Out_Buf(Out_Buf'First..Out_Last) on
   --  the socket. Always emits Content-Length and Connection: close.
   procedure Encode_Response
     (Out_Buf      : in out Octet_Array;
      Out_Last     : out Octet_Offset;
      Status       : Natural;
      Reason       : String;
      Headers      : Header_Block;
      Headers_Last : Natural;
      Body_Bytes   : Octet_Array);

   --  Build a header (helper for Handle_Request implementations).
   function Make_Header (Name : String; Value : String) return Header;

end Http1_Core.Wire;
