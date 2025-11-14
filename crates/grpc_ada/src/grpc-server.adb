package body GRPC.Server is

   procedure Register_Method
     (S       : in out Instance;
      Path    : String;
      Handler : Method_Handler)
   is
      Entry_To_Add : Method_Entry;
   begin
      Entry_To_Add.Path    := To_Unbounded_String (Path);
      Entry_To_Add.Handler := Handler;
      S.Methods.Append (Entry_To_Add);
   end Register_Method;

   procedure Configure_Listen
     (S       : in out Instance;
      Address : String;
      Port    : Positive)
   is
   begin
      S.Address := To_Unbounded_String (Address);
      S.Port    := Port;
   end Configure_Listen;

   function Lookup (S : Instance; Path : String) return Method_Handler is
   begin
      for E of S.Methods loop
         if To_String (E.Path) = Path then
            return E.Handler;
         end if;
      end loop;
      return null;
   end Lookup;

end GRPC.Server;
