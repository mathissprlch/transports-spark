with Helloworld.Greeter;
with Helloworld.Hello_Reply;
with Helloworld.Hello_Request;

package Greeter_Impl is

   type Service is new Helloworld.Greeter.Service with null record;

   overriding procedure Say_Hello
     (Self     : in out Service;
      Request  : Helloworld.Hello_Request.T;
      Response : out Helloworld.Hello_Reply.T);

   overriding procedure Lots_Of_Replies
     (Self    : in out Service;
      Request : Helloworld.Hello_Request.T;
      Writer  : not null access
        Helloworld.Greeter.Lots_Of_Replies_Writer'Class);

   overriding procedure Lots_Of_Greetings
     (Self     : in out Service;
      Request  : Helloworld.Hello_Request.T;
      Response : out Helloworld.Hello_Reply.T);

   overriding procedure Bidi_Hello
     (Self    : in out Service;
      Request : Helloworld.Hello_Request.T;
      Writer  : not null access
        Helloworld.Greeter.Bidi_Hello_Writer'Class);

end Greeter_Impl;
