package body Mqtt_Core.Topics
with SPARK_Mode
is

   function Matches (Name : String; Filter : String) return Boolean is
      N : Integer := Name'First;    --  cursor in Name
      F : Integer := Filter'First;  --  cursor in Filter
   begin
      while F <= Filter'Last loop

         --  `#` must be terminal. Matches everything remaining
         --  (including empty), respecting the §4.7.1 rule that
         --  `home/#` also matches `home` (no trailing slash).
         if Filter (F) = '#' then
            return F = Filter'Last;
         end if;

         --  `+` matches exactly one topic level — every char in
         --  Name until the next `/` or end-of-name.
         if Filter (F) = '+' then
            --  Skip over Name's level.
            while N <= Name'Last and then Name (N) /= '/' loop
               N := N + 1;
            end loop;
            F := F + 1;
            --  Filter cursor now sits at either end-of-filter or
            --  at the `/` separating levels.
            if F > Filter'Last then
               --  Filter ended; Name must also be at end.
               return N > Name'Last;
            end if;
            --  Filter has more, expect `/` to align with Name.
            if Filter (F) = '/' and then N <= Name'Last
              and then Name (N) = '/'
            then
               F := F + 1;
               N := N + 1;
            else
               return False;
            end if;
         else
            --  Literal char — must match.
            if N > Name'Last then
               return False;
            end if;
            if Name (N) /= Filter (F) then
               return False;
            end if;
            N := N + 1;
            F := F + 1;
         end if;
      end loop;

      --  Filter exhausted: Name must also be exhausted.
      return N > Name'Last;
   end Matches;

end Mqtt_Core.Topics;
