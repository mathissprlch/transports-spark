with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;

package body Greeter_Impl is

   overriding procedure Say_Hello
     (Self     : in out Service;
      Request  : Helloworld.Hello_Request.T;
      Response : out Helloworld.Hello_Reply.T)
   is
      pragma Unreferenced (Self);
   begin
      Response.Message := To_Unbounded_String
        ("Hello, " & To_String (Request.Name) & "!");
   end Say_Hello;

end Greeter_Impl;
