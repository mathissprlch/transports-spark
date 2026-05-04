--  Http2_Core.Hpack.Static_Table — RFC 7541 Appendix A.
--
--  Source: RFC 7541 — HPACK: Header Compression for HTTP/2,
--  IETF Standard, May 2015. Appendix A (page 27 in the official
--  text) defines a 61-entry static lookup table that has not
--  changed since publication.
--
--  Indexed-name-only entries (rows 1, 15, 17–61) have empty Value.
--  The HPACK Indexed Header Field representation (§6.1) takes a
--  1-based index into this table.
--
--  Both encoder and decoder reference these constants by their
--  RFC-numbered index. NO IANA conversion is possible — the table
--  is in RFC text, not a registry — so this file is hand-written
--  but with section-by-section provenance for audit. Re-checkable
--  against RFC 7541 §Appendix A by anyone in five minutes.

package Http2_Core.Hpack.Static_Table
with SPARK_Mode
is

   --  RFC 7541 §Appendix A — the table is exactly 61 entries.
   First_Index : constant := 1;
   Last_Index  : constant := 61;

   subtype Index is Positive range First_Index .. Last_Index;

   --  Look up the name string of static-table entry I into Buf;
   --  Last is the count of valid bytes in Buf. When I is out of
   --  range, Last = 0 (sentinel for "not in static table").
   procedure Get_Name
     (I    : Positive;
      Buf  : out String;
      Last : out Natural)
   with Pre  => Buf'Length >= Max_Header_Length
                and then Buf'Last < Natural'Last,
        Post => Last in 0 .. Max_Header_Length;

   --  Same shape for Value. Some entries (1, 15, 17..61) have an
   --  empty Value — Last = 0 in those cases.
   procedure Get_Value
     (I    : Positive;
      Buf  : out String;
      Last : out Natural)
   with Pre  => Buf'Length >= Max_Header_Length
                and then Buf'Last < Natural'Last,
        Post => Last in 0 .. Max_Header_Length;

   --  Reverse lookup used by the encoder. Searches for an exact
   --  (Name, Value) match first; if found, sets Found_Index and
   --  Exact_Match := True. Otherwise looks for the first row whose
   --  Name matches and sets Found_Index with Exact_Match := False.
   --  If no row's Name matches, Found_Index = 0 and Exact_Match
   --  := False.
   procedure Find
     (Name        : String;
      Value       : String;
      Found_Index : out Natural;
      Exact_Match : out Boolean);

end Http2_Core.Hpack.Static_Table;
