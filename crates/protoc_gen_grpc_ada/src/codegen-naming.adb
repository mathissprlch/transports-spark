with Ada.Characters.Handling; use Ada.Characters.Handling;

package body Codegen.Naming is

   ------------------------
   -- To_Ada_Identifier --

   function To_Ada_Identifier (Source : String) return String is
      Result : Unbounded_String;

      function Need_Underscore_Before
        (Idx : Positive; S : String) return Boolean
      is
         Prev : Character;
      begin
         if Idx = S'First then
            return False;
         end if;
         Prev := S (Idx - 1);
         if Prev = '_' or else Prev = '-' or else Prev = '.' then
            return False;  --  delimiter handles the boundary
         end if;
         --  CamelCase boundary: lowercase|digit followed by uppercase
         if (Is_Lower (Prev) or else Is_Digit (Prev))
            and then Is_Upper (S (Idx))
         then
            return True;
         end if;
         return False;
      end Need_Underscore_Before;

   begin
      for I in Source'Range loop
         declare
            C : Character := Source (I);
         begin
            if C = '-' or else C = '.' then
               C := '_';
            end if;
            if Need_Underscore_Before (I, Source) then
               Append (Result, '_');
            end if;
            if I = Source'First then
               Append (Result, To_Upper (C));
            elsif I > Source'First and then Source (I - 1) = '_' then
               Append (Result, To_Upper (C));
            else
               Append (Result, C);
            end if;
         end;
      end loop;
      return To_String (Result);
   end To_Ada_Identifier;

   -------------------
   -- To_File_Stem --

   function To_File_Stem (Ada_Package : String) return String is
      Result : Unbounded_String;
   begin
      for I in Ada_Package'Range loop
         if Ada_Package (I) = '.' then
            Append (Result, '-');
         else
            Append (Result, To_Lower (Ada_Package (I)));
         end if;
      end loop;
      return To_String (Result);
   end To_File_Stem;

   ----------------------
   -- Package_To_Ada --

   function Package_To_Ada (Proto_Package : String) return Unbounded_String is
      Result : Unbounded_String;
      Buf    : Unbounded_String;
   begin
      for I in Proto_Package'Range loop
         if Proto_Package (I) = '.' then
            Append (Result, To_Ada_Identifier (To_String (Buf)));
            Append (Result, '.');
            Buf := Null_Unbounded_String;
         else
            Append (Buf, Proto_Package (I));
         end if;
      end loop;
      Append (Result, To_Ada_Identifier (To_String (Buf)));
      return Result;
   end Package_To_Ada;

end Codegen.Naming;
