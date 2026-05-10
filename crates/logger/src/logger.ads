package Logger is

   type Level is (Debug, Info, Warn, Error);

   Current_Level : Level := Debug;

   procedure Log (L : Level; Msg : String);
   pragma Inline (Log);

end Logger;
