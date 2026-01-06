with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Interfaces; use Interfaces;
with Routeguide.Feature;

package body Routeguide_Impl is

   type Feature_Entry is record
      Name : Unbounded_String;
      Lat  : Interfaces.Integer_32;
      Lon  : Interfaces.Integer_32;
   end record;

   Catalog : constant array (Positive range <>) of Feature_Entry :=
     ((Name => To_Unbounded_String ("Patriots Path"),
       Lat  => 407_838_351, Lon => -746_148_697),
      (Name => To_Unbounded_String ("101 New Jersey 10"),
       Lat  => 408_122_808, Lon => -743_999_179),
      (Name => To_Unbounded_String ("U.S. 6"),
       Lat  => 413_628_156, Lon => -749_679_023),
      (Name => To_Unbounded_String ("5 Conventry Court"),
       Lat  => 419_999_544, Lon => -747_088_134));

   function In_Box
     (Lat, Lon : Interfaces.Integer_32;
      R        : Routeguide.Bounds.T) return Boolean
   is
      Lo_Lat : constant Integer_32 := Integer_32'Min (R.Lo_Lat, R.Hi_Lat);
      Hi_Lat : constant Integer_32 := Integer_32'Max (R.Lo_Lat, R.Hi_Lat);
      Lo_Lon : constant Integer_32 := Integer_32'Min (R.Lo_Lon, R.Hi_Lon);
      Hi_Lon : constant Integer_32 := Integer_32'Max (R.Lo_Lon, R.Hi_Lon);
   begin
      return Lat in Lo_Lat .. Hi_Lat and then Lon in Lo_Lon .. Hi_Lon;
   end In_Box;

   overriding procedure List_Features
     (Self    : in out Service;
      Request : Routeguide.Bounds.T;
      Writer  : not null access
                  Routeguide.Route_Guide.List_Features_Writer'Class)
   is
      pragma Unreferenced (Self);
   begin
      for E of Catalog loop
         if In_Box (E.Lat, E.Lon, Request) then
            declare
               F : Routeguide.Feature.T;
            begin
               F.Name := E.Name;
               F.Lat  := E.Lat;
               F.Lon  := E.Lon;
               Writer.Write (F);
            end;
         end if;
      end loop;
   end List_Features;

end Routeguide_Impl;
