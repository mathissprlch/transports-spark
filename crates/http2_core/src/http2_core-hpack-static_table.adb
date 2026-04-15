package body Http2_Core.Hpack.Static_Table
with SPARK_Mode
is

   --  Internal record for the table.
   type Entry_Record is record
      Name       : String (1 .. Max_Header_Length) := (others => ' ');
      Name_Last  : Natural := 0;
      Value      : String (1 .. Max_Header_Length) := (others => ' ');
      Value_Last : Natural := 0;
   end record;

   type Table is array (Index) of Entry_Record;

   function Make
     (Name  : String;
      Value : String := "")
      return Entry_Record
   with Pre => Name'Length in 1 .. Max_Header_Length
               and then Value'Length in 0 .. Max_Header_Length;

   function Make
     (Name  : String;
      Value : String := "")
      return Entry_Record
   is
      Result : Entry_Record;
   begin
      Result.Name (1 .. Name'Length) := Name;
      Result.Name_Last               := Name'Length;
      if Value'Length > 0 then
         Result.Value (1 .. Value'Length) := Value;
      end if;
      Result.Value_Last              := Value'Length;
      return Result;
   end Make;

   --  RFC 7541 §Appendix A — the canonical 61-entry table.
   --  Values copied verbatim from Section 4 of the IETF text.
   Entries : constant Table :=
     ( 1 => Make (":authority"),
       2 => Make (":method",                     "GET"),
       3 => Make (":method",                     "POST"),
       4 => Make (":path",                       "/"),
       5 => Make (":path",                       "/index.html"),
       6 => Make (":scheme",                     "http"),
       7 => Make (":scheme",                     "https"),
       8 => Make (":status",                     "200"),
       9 => Make (":status",                     "204"),
      10 => Make (":status",                     "206"),
      11 => Make (":status",                     "304"),
      12 => Make (":status",                     "400"),
      13 => Make (":status",                     "404"),
      14 => Make (":status",                     "500"),
      15 => Make ("accept-charset"),
      16 => Make ("accept-encoding",             "gzip, deflate"),
      17 => Make ("accept-language"),
      18 => Make ("accept-ranges"),
      19 => Make ("accept"),
      20 => Make ("access-control-allow-origin"),
      21 => Make ("age"),
      22 => Make ("allow"),
      23 => Make ("authorization"),
      24 => Make ("cache-control"),
      25 => Make ("content-disposition"),
      26 => Make ("content-encoding"),
      27 => Make ("content-language"),
      28 => Make ("content-length"),
      29 => Make ("content-location"),
      30 => Make ("content-range"),
      31 => Make ("content-type"),
      32 => Make ("cookie"),
      33 => Make ("date"),
      34 => Make ("etag"),
      35 => Make ("expect"),
      36 => Make ("expires"),
      37 => Make ("from"),
      38 => Make ("host"),
      39 => Make ("if-match"),
      40 => Make ("if-modified-since"),
      41 => Make ("if-none-match"),
      42 => Make ("if-range"),
      43 => Make ("if-unmodified-since"),
      44 => Make ("last-modified"),
      45 => Make ("link"),
      46 => Make ("location"),
      47 => Make ("max-forwards"),
      48 => Make ("proxy-authenticate"),
      49 => Make ("proxy-authorization"),
      50 => Make ("range"),
      51 => Make ("referer"),
      52 => Make ("refresh"),
      53 => Make ("retry-after"),
      54 => Make ("server"),
      55 => Make ("set-cookie"),
      56 => Make ("strict-transport-security"),
      57 => Make ("transfer-encoding"),
      58 => Make ("user-agent"),
      59 => Make ("vary"),
      60 => Make ("via"),
      61 => Make ("www-authenticate"));

   procedure Get_Name
     (I    : Positive;
      Buf  : out String;
      Last : out Natural)
   is
   begin
      Buf := (others => ' ');
      if I in Index then
         Buf (Buf'First .. Buf'First + Entries (I).Name_Last - 1) :=
           Entries (I).Name (1 .. Entries (I).Name_Last);
         Last := Entries (I).Name_Last;
      else
         Last := 0;
      end if;
   end Get_Name;

   procedure Get_Value
     (I    : Positive;
      Buf  : out String;
      Last : out Natural)
   is
   begin
      Buf := (others => ' ');
      if I in Index and then Entries (I).Value_Last > 0 then
         Buf (Buf'First .. Buf'First + Entries (I).Value_Last - 1) :=
           Entries (I).Value (1 .. Entries (I).Value_Last);
         Last := Entries (I).Value_Last;
      else
         Last := 0;
      end if;
   end Get_Value;

   procedure Find
     (Name        : String;
      Value       : String;
      Found_Index : out Natural;
      Exact_Match : out Boolean)
   is
      Name_Only_Match : Natural := 0;
   begin
      for I in Index loop
         declare
            E : Entry_Record renames Entries (I);
         begin
            if E.Name_Last = Name'Length
              and then E.Name (1 .. E.Name_Last) = Name
            then
               if E.Value_Last = Value'Length
                 and then E.Value (1 .. E.Value_Last) = Value
               then
                  Found_Index := I;
                  Exact_Match := True;
                  return;
               elsif Name_Only_Match = 0 then
                  Name_Only_Match := I;
               end if;
            end if;
         end;
      end loop;
      Found_Index := Name_Only_Match;
      Exact_Match := False;
   end Find;

end Http2_Core.Hpack.Static_Table;
