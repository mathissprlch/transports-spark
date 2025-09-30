with Ada.Command_Line;
with Ada.Text_IO;
with Test_Support;
with Tests.Wire;

procedure Test_Main is
begin
   Ada.Text_IO.Put_Line ("Tests.Wire");
   Tests.Wire.Run;

   Ada.Text_IO.New_Line;
   if Test_Support.All_Passed then
      Ada.Text_IO.Put_Line ("All tests passed.");
      Ada.Command_Line.Set_Exit_Status (0);
   else
      Ada.Text_IO.Put_Line
        ("FAILED: " & Natural'Image (Test_Support.Failures) & " tests");
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Test_Main;
