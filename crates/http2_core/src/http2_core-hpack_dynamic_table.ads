--  Http2_Core.Hpack_Dynamic_Table — HPACK dynamic table (RFC 7541).
--
--  Source: RFC 7541 §2.3.2 (Dynamic Table) + §4 (Dynamic Table
--  Management) + §6.3 (Dynamic Table Size Update).
--
--  Layout: FIFO of (name, value) entries. New entries inserted at
--  the front (lowest "logical" index, which the wire calls 62 once
--  the 61-entry static table is offset). Eviction removes from the
--  rear when the total byte size would exceed Max_Size.
--
--  Each entry's size is `Name'Length + Value'Length + 32` per
--  §4.1; the +32 covers per-entry overhead the wire format does
--  not actually carry. Max_Size is what the peer most recently
--  set via SETTINGS_HEADER_TABLE_SIZE / §6.3 Dynamic Table Size
--  Update; default is 4096.

package Http2_Core.Hpack_Dynamic_Table
with SPARK_Mode
is

   --  Mirror of Hpack.Max_Header_Length. Kept independent here to
   --  avoid a Hpack -> Hpack_Dynamic_Table -> Hpack with-cycle.
   Max_Header_Length : constant := 256;

   --  Compile-time bound on entry count. Each entry is up to
   --  Max_Header_Length+Max_Header_Length+32 ~= 544 bytes; with the
   --  4096-byte default Max_Size that fits ~7 fully-loaded entries
   --  but ~30 typical short ones. 64 leaves headroom.
   Max_Entries : constant := 64;

   Default_Max_Size : constant := 4096;

   type Table is private;

   procedure Initialize
     (T        : out Table;
      Max_Size : Natural := Default_Max_Size);

   --  Append a new (Name, Value) entry. Evicts oldest entries from
   --  the rear until total size fits Max_Size; if the entry alone
   --  is bigger than Max_Size, the table is left empty and the
   --  entry is silently dropped (RFC §4.4 explicit allowance).
   procedure Add
     (T     : in out Table;
      Name  : String;
      Value : String);

   --  Apply a §6.3 Dynamic Table Size Update. Evicts oldest
   --  entries from the rear as needed to fit the new bound.
   procedure Set_Max_Size
     (T        : in out Table;
      Max_Size : Natural);

   --  Number of entries currently held.
   function Count (T : Table) return Natural;

   --  Look up a 1-based dynamic-table index (i.e., the wire index
   --  minus 61). Index=1 is the most recently added entry per
   --  §2.3.3. OK=False on out-of-range index. Caller-sized Name /
   --  Value buffers are filled.
   procedure Lookup
     (T          : Table;
      Index      : Positive;
      Name       : out String;
      Name_Last  : out Natural;
      Value      : out String;
      Value_Last : out Natural;
      OK         : out Boolean)
   with Pre => Name'Length >= Max_Header_Length
               and then Value'Length >= Max_Header_Length;

   procedure Find
     (T           : Table;
      Name        : String;
      Value       : String;
      Found_Index : out Natural;
      Exact_Match : out Boolean);
   --  Search by name+value. Found_Index is 1-based dynamic-table
   --  index (add 61 to get the wire index). 0 = not found.
   --  Exact_Match=True when both name and value match.

private

   --  Per-entry overhead from §4.1.
   Entry_Overhead : constant := 32;

   type Entry_Type is record
      Name       : String (1 .. Max_Header_Length) := (others => ' ');
      Name_Last  : Natural := 0;
      Value      : String (1 .. Max_Header_Length) := (others => ' ');
      Value_Last : Natural := 0;
   end record;

   subtype Slot_Index is Natural range 0 .. Max_Entries - 1;
   type Entry_Array is array (Slot_Index) of Entry_Type;

   type Table is record
      Entries    : Entry_Array;
      --  Ring discipline: Newest is the buffer slot of the most
      --  recently added entry; Count entries are valid going
      --  backwards (Newest, Newest-1, ..., wrapping mod
      --  Max_Entries). When Count=0 the ring is empty.
      Newest     : Slot_Index := 0;
      Item_Count     : Natural    := 0;
      Total_Size : Natural    := 0;
      Cap_Size  : Natural    := Default_Max_Size;
   end record;

end Http2_Core.Hpack_Dynamic_Table;
