--  Server-streaming client demo. Issues ListFeatures over a wide
--  bounding box and prints each feature as it arrives.

with Ada.Strings.Unbounded; use Ada.Strings.Unbounded;
with Ada.Text_IO;
with Interfaces; use Interfaces;

with GRPC.Channel;
with Routeguide.Feature;
with Routeguide.Rectangle;
with Routeguide.Route_Guide.Client;

procedure Listfeatures_Client is
   Channel : GRPC.Channel.Instance;
   Request : Routeguide.Rectangle.T;
   Reader  : Routeguide.Route_Guide.Client.List_Features_Reader;
   Feature : Routeguide.Feature.T;
   Got     : Boolean;
   Count   : Natural := 0;
begin
   GRPC.Channel.Initialize (Channel, "localhost", 50_052);

   --  Wide bounding box covering the whole hard-coded catalog.
   Request.Lo.Latitude  :=  400_000_000;
   Request.Lo.Longitude := -750_000_000;
   Request.Hi.Latitude  :=  420_000_000;
   Request.Hi.Longitude := -740_000_000;

   Routeguide.Route_Guide.Client.List_Features (Channel, Request, Reader);

   loop
      Routeguide.Route_Guide.Client.Read (Reader, Feature, Got);
      exit when not Got;
      Count := Count + 1;
      Ada.Text_IO.Put_Line
        ("  " & Count'Image & "  " & To_String (Feature.Name)
         & " @ " & Feature.Location.Latitude'Image
         & ", "  & Feature.Location.Longitude'Image);
   end loop;

   Ada.Text_IO.Put_Line ("done -" & Count'Image & " features");
end Listfeatures_Client;
