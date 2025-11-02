with Ada.Characters.Handling; use Ada.Characters.Handling;

package body GRPC.Metadata is

   function Eq_Ignore_Case (A, B : String) return Boolean;

   function Eq_Ignore_Case (A, B : String) return Boolean is
   begin
      if A'Length /= B'Length then
         return False;
      end if;
      for I in 0 .. A'Length - 1 loop
         if To_Lower (A (A'First + I)) /= To_Lower (B (B'First + I)) then
            return False;
         end if;
      end loop;
      return True;
   end Eq_Ignore_Case;

   function Is_Binary_Key (Key : String) return Boolean is
   begin
      return Key'Length >= 4
        and then To_Lower (Key (Key'Last - 3 .. Key'Last)) = "-bin";
   end Is_Binary_Key;

   procedure Add_ASCII (H : in out Headers; Key, Value : String) is
      E : Entry_Type;
   begin
      if Is_Binary_Key (Key) then
         raise Program_Error
           with "use Add_Binary for -bin keys: " & Key;
      end if;
      E.Kind  := ASCII_Value;
      E.Key   := To_Unbounded_String (Key);
      E.Value := To_Unbounded_String (Value);
      H.Append (E);
   end Add_ASCII;

   procedure Add_Binary
     (H     : in out Headers;
      Key   : String;
      Value : Unbounded_String)
   is
      E : Entry_Type;
   begin
      if not Is_Binary_Key (Key) then
         raise Program_Error
           with "binary metadata key must end with -bin: " & Key;
      end if;
      E.Kind  := Binary_Value;
      E.Key   := To_Unbounded_String (Key);
      E.Value := Value;
      H.Append (E);
   end Add_Binary;

   function Get_First (H : Headers; Key : String) return Unbounded_String is
   begin
      for E of H loop
         if Eq_Ignore_Case (To_String (E.Key), Key) then
            return E.Value;
         end if;
      end loop;
      return Null_Unbounded_String;
   end Get_First;

   function Has (H : Headers; Key : String) return Boolean is
   begin
      for E of H loop
         if Eq_Ignore_Case (To_String (E.Key), Key) then
            return True;
         end if;
      end loop;
      return False;
   end Has;

end GRPC.Metadata;
