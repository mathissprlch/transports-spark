package body Http2_Core.Hpack_Dynamic_Table
with SPARK_Mode
is

   procedure Initialize
     (T        : out Table;
      Max_Size : Natural := Default_Max_Size)
   is
   begin
      T.Newest     := 0;
      T.Item_Count     := 0;
      T.Total_Size := 0;
      T.Cap_Size  := Max_Size;
      T.Entries    := (others => (others => <>));
   end Initialize;

   --  Drop the OLDEST entry from the ring (the one at index
   --  Item_Count, i.e., the one farthest from Newest). No-op if empty.
   procedure Evict_Oldest (T : in out Table);
   procedure Evict_Oldest (T : in out Table) is
   begin
      if T.Item_Count = 0 then
         return;
      end if;
      declare
         Oldest_Slot : constant Slot_Index :=
           Slot_Index ((T.Newest + Max_Entries - (T.Item_Count - 1))
                       mod Max_Entries);
         Sz : constant Natural :=
           T.Entries (Oldest_Slot).Name_Last
           + T.Entries (Oldest_Slot).Value_Last
           + Entry_Overhead;
      begin
         if T.Total_Size >= Sz then
            T.Total_Size := T.Total_Size - Sz;
         else
            T.Total_Size := 0;
         end if;
         T.Entries (Oldest_Slot).Name_Last  := 0;
         T.Entries (Oldest_Slot).Value_Last := 0;
         T.Item_Count := T.Item_Count - 1;
      end;
   end Evict_Oldest;

   procedure Add
     (T     : in out Table;
      Name  : String;
      Value : String)
   is
      Want : constant Natural :=
        Name'Length + Value'Length + Entry_Overhead;
   begin
      --  Refuse oversized names/values that wouldn't fit our
      --  bounded buffers. The decoder is supposed to bound them
      --  before calling Add, but be defensive.
      if Name'Length > Max_Header_Length
        or else Value'Length > Max_Header_Length
      then
         return;
      end if;

      --  §4.4: if the new entry alone exceeds Max_Size, evict
      --  everything and don't add it.
      if Want > T.Cap_Size then
         while T.Item_Count > 0 loop
            Evict_Oldest (T);
         end loop;
         return;
      end if;

      --  Evict from the rear until the new entry fits.
      while T.Item_Count > 0
        and then T.Total_Size + Want > T.Cap_Size
      loop
         Evict_Oldest (T);
      end loop;

      --  Refuse if we've hit the hard slot cap before fitting
      --  byte-wise (shouldn't happen with sensible Max_Size, but
      --  defensive against malformed peers).
      if T.Item_Count >= Max_Entries then
         return;
      end if;

      declare
         New_Slot : constant Slot_Index :=
           (if T.Item_Count = 0 then 0
            else Slot_Index ((T.Newest + 1) mod Max_Entries));
      begin
         T.Entries (New_Slot).Name := (others => ' ');
         T.Entries (New_Slot).Name (1 .. Name'Length) := Name;
         T.Entries (New_Slot).Name_Last := Name'Length;
         T.Entries (New_Slot).Value := (others => ' ');
         if Value'Length > 0 then
            T.Entries (New_Slot).Value (1 .. Value'Length) := Value;
         end if;
         T.Entries (New_Slot).Value_Last := Value'Length;
         T.Newest     := New_Slot;
         T.Item_Count     := T.Item_Count + 1;
         T.Total_Size := T.Total_Size + Want;
      end;
   end Add;

   procedure Set_Max_Size
     (T        : in out Table;
      Max_Size : Natural)
   is
   begin
      T.Cap_Size := Max_Size;
      while T.Item_Count > 0 and then T.Total_Size > T.Cap_Size loop
         Evict_Oldest (T);
      end loop;
   end Set_Max_Size;

   function Count (T : Table) return Natural is
     (T.Item_Count);

   procedure Lookup
     (T          : Table;
      Index      : Positive;
      Name       : out String;
      Name_Last  : out Natural;
      Value      : out String;
      Value_Last : out Natural;
      OK         : out Boolean)
   is
   begin
      Name       := (others => ' ');
      Value      := (others => ' ');
      Name_Last  := 0;
      Value_Last := 0;
      OK         := False;
      if Index > T.Item_Count then
         return;
      end if;
      declare
         Slot : constant Slot_Index :=
           Slot_Index ((T.Newest + Max_Entries - (Index - 1))
                       mod Max_Entries);
      begin
         Name (Name'First ..
               Name'First + T.Entries (Slot).Name_Last - 1) :=
           T.Entries (Slot).Name (1 .. T.Entries (Slot).Name_Last);
         Name_Last := T.Entries (Slot).Name_Last;
         if T.Entries (Slot).Value_Last > 0 then
            Value (Value'First ..
                   Value'First + T.Entries (Slot).Value_Last - 1) :=
              T.Entries (Slot).Value
                (1 .. T.Entries (Slot).Value_Last);
         end if;
         Value_Last := T.Entries (Slot).Value_Last;
         OK := True;
      end;
   end Lookup;

   procedure Find
     (T           : Table;
      Name        : String;
      Value       : String;
      Found_Index : out Natural;
      Exact_Match : out Boolean)
   is
      Name_Match_Idx : Natural := 0;
   begin
      Found_Index := 0;
      Exact_Match := False;
      for I in 1 .. T.Item_Count loop
         declare
            Slot : constant Slot_Index :=
              Slot_Index ((T.Newest + Max_Entries - (I - 1))
                          mod Max_Entries);
            E : Entry_Type renames T.Entries (Slot);
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
               elsif Name_Match_Idx = 0 then
                  Name_Match_Idx := I;
               end if;
            end if;
         end;
      end loop;
      Found_Index := Name_Match_Idx;
   end Find;

end Http2_Core.Hpack_Dynamic_Table;
