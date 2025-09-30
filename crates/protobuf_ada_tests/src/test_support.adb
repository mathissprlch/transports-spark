with Ada.Text_IO;

package body Test_Support is

   Failure_Count : Natural := 0;
   Test_Failed_This_Run : Boolean := False;

   procedure Assert
     (Condition : Boolean;
      Message   : String)
   is
   begin
      if not Condition then
         Ada.Text_IO.Put_Line ("    FAIL: " & Message);
         Test_Failed_This_Run := True;
      end if;
   end Assert;

   procedure Run_Test
     (Name : String;
      Body_Proc : access procedure)
   is
   begin
      Test_Failed_This_Run := False;
      Ada.Text_IO.Put_Line ("  " & Name);
      Body_Proc.all;
      if Test_Failed_This_Run then
         Failure_Count := Failure_Count + 1;
      end if;
   end Run_Test;

   function All_Passed return Boolean is (Failure_Count = 0);
   function Failures return Natural is (Failure_Count);

end Test_Support;
