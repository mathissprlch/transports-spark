with Ada.Text_IO;

package body Logger is

   procedure Log (L : Level; Msg : String) is
   begin
      if L >= Current_Level then
         case L is
            when Debug => Ada.Text_IO.Put_Line ("  [D] " & Msg);
            when Info  => Ada.Text_IO.Put_Line ("  [I] " & Msg);
            when Warn  => Ada.Text_IO.Put_Line ("  [W] " & Msg);
            when Error => Ada.Text_IO.Put_Line ("  [E] " & Msg);
         end case;
      end if;
   end Log;

end Logger;
