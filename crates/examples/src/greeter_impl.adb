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

   overriding procedure Lots_Of_Replies
     (Self    : in out Service;
      Request : Helloworld.Hello_Request.T;
      Writer  : not null access
        Helloworld.Greeter.Lots_Of_Replies_Writer'Class)
   is
      pragma Unreferenced (Self, Request, Writer);
   begin
      null;
   end Lots_Of_Replies;

   overriding procedure Lots_Of_Greetings
     (Self     : in out Service;
      Request  : Helloworld.Hello_Request.T;
      Response : out Helloworld.Hello_Reply.T)
   is
      pragma Unreferenced (Self, Request, Response);
   begin
      null;
   end Lots_Of_Greetings;

   overriding procedure Bidi_Hello
     (Self    : in out Service;
      Request : Helloworld.Hello_Request.T;
      Writer  : not null access
        Helloworld.Greeter.Bidi_Hello_Writer'Class)
   is
      pragma Unreferenced (Self, Request, Writer);
   begin
      null;
   end Bidi_Hello;

end Greeter_Impl;
