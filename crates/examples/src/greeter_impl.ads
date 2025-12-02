--  User's Greeter service implementation. Subclasses the generated
--  abstract base in Helloworld.Greeter and overrides Say_Hello.

with Helloworld.Greeter;
with Helloworld.Hello_Reply;
with Helloworld.Hello_Request;

package Greeter_Impl is

   type Service is new Helloworld.Greeter.Service with null record;

   overriding procedure Say_Hello
     (Self     : in out Service;
      Request  : Helloworld.Hello_Request.T;
      Response : out Helloworld.Hello_Reply.T);

end Greeter_Impl;
