package body GRPC.Deadline is

   function Parse_Timeout (S : String) return Duration is
   begin
      if S'Length < 2 then
         raise Constraint_Error with "grpc-timeout too short: " & S;
      end if;
      declare
         Number_Part : constant String := S (S'First .. S'Last - 1);
         Unit        : constant Character := S (S'Last);
         N           : constant Long_Long_Integer :=
           Long_Long_Integer'Value (Number_Part);
         Multiplier  : Duration;
      begin
         case Unit is
            when 'H' => Multiplier := 3600.0;
            when 'M' => Multiplier := 60.0;
            when 'S' => Multiplier := 1.0;
            when 'm' => Multiplier := 0.001;
            when 'u' => Multiplier := 0.000_001;
            when 'n' => Multiplier := 0.000_000_001;
            when others =>
               raise Constraint_Error
                 with "unknown grpc-timeout unit: " & Unit'Image;
         end case;
         return Duration (N) * Multiplier;
      end;
   end Parse_Timeout;

   function Format_Timeout (D : Duration) return String is
      Ns : constant Long_Long_Integer :=
        Long_Long_Integer (D * 1_000_000_000.0);
      type Pair is record
         Divisor : Long_Long_Integer;
         Unit    : Character;
      end record;
      --  Largest unit first: prefer "1H" over "3600S".
      Units : constant array (1 .. 6) of Pair :=
        [(3_600_000_000_000, 'H'),
         (   60_000_000_000, 'M'),
         (    1_000_000_000, 'S'),
         (        1_000_000, 'm'),
         (            1_000, 'u'),
         (                1, 'n')];
      function Img (X : Long_Long_Integer) return String is
         S : constant String := X'Image;
      begin
         return (if S (S'First) = ' '
                 then S (S'First + 1 .. S'Last) else S);
      end Img;
   begin
      for U of Units loop
         if Ns mod U.Divisor = 0
           and then abs (Ns / U.Divisor) < 100_000_000
         then
            return Img (Ns / U.Divisor) & U.Unit;
         end if;
      end loop;
      --  Fallback: nanoseconds even if it overflows the 8-digit limit.
      return Img (Ns) & 'n';
   end Format_Timeout;

end GRPC.Deadline;
