package body GRPC.Status is

   function To_String (C : Code) return String is
      Img : constant String := Code'Enum_Rep (C)'Image;
   begin
      --  Strip the leading space that 'Image inserts on non-negative ints.
      if Img'Length > 0 and then Img (Img'First) = ' ' then
         return Img (Img'First + 1 .. Img'Last);
      else
         return Img;
      end if;
   end To_String;

   function From_String (S : String) return Code is
      N : constant Integer := Integer'Value (S);
   begin
      if N not in 0 .. 16 then
         raise Constraint_Error with "grpc-status out of range: " & S;
      end if;
      return Code'Enum_Val (N);
   end From_String;

end GRPC.Status;
