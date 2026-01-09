--  RouteGuide service implementation. Subclasses the generated abstract
--  base in Routeguide.Route_Guide and overrides List_Features.

with Routeguide.Rectangle;
with Routeguide.Route_Guide;

package Routeguide_Impl is

   type Service is new Routeguide.Route_Guide.Service with null record;

   overriding procedure List_Features
     (Self    : in out Service;
      Request : Routeguide.Rectangle.T;
      Writer  : not null access
                  Routeguide.Route_Guide.List_Features_Writer'Class);

end Routeguide_Impl;
