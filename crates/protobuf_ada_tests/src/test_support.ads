--  Tiny assertion harness. We don't depend on AUnit yet — keeping the
--  dep tree to "AWS only" applies to runtime; for tests we still want
--  the freedom to add a framework later, but for now plain assertions
--  do the job and keep the test binary trivial.

package Test_Support is

   procedure Assert
     (Condition : Boolean;
      Message   : String);

   procedure Run_Test
     (Name : String;
      Body_Proc : access procedure);

   function All_Passed return Boolean;
   function Failures return Natural;

end Test_Support;
