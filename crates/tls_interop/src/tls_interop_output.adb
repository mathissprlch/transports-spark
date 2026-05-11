with Ada.Strings.Fixed;
with Ada.Text_IO;

package body Tls_Interop_Output is

   use Ada.Text_IO;

   function Image_Time (D : Duration) return String is
      Ms : constant Integer := Integer (D * 1000.0);
      function Pad (S : String) return String is
      begin
         if S'Length >= 8 then return S (S'First .. S'First + 7); end if;
         return (1 .. 8 - S'Length => ' ') & S;
      end Pad;
   begin
      if Ms = 0 then
         return "       -";
      end if;
      declare
         Whole : constant Integer := Ms / 1000;
         Frac  : constant Integer := Ms mod 1000;
         W_Img : constant String := Ada.Strings.Fixed.Trim
                   (Integer'Image (Whole), Ada.Strings.Both);
         F_Img : constant String := (if Frac < 10 then "00"
                                     elsif Frac < 100 then "0" else "")
                   & Ada.Strings.Fixed.Trim
                       (Integer'Image (Frac), Ada.Strings.Both);
      begin
         return Pad (W_Img & "." & F_Img & " s");
      end;
   end Image_Time;

   procedure Md_Peer_Header (Peer : Peer_Kind) is
   begin
      Put_Line ("");
      Put_Line ("### " & Image (Peer));
      Put_Line ("");
      Put_Line
        ("| Feature                       | c2s"
         & "            | s2c            | Notes |");
      Put_Line
        ("|-------------------------------|--------"
         & "--------|----------------|-------|");
   end Md_Peer_Header;

   procedure Md_Feature_Row
     (Feature_Lbl : String;
      C2S_Result, S2C_Result : Cell_Result;
      C2S_Time,   S2C_Time   : Duration;
      Note : String)
   is
      function Pad (S : String; W : Natural) return String is
      begin
         if S'Length >= W then
            return S (S'First .. S'First + W - 1);
         end if;
         return S & (1 .. W - S'Length => ' ');
      end Pad;
      function Cell (R : Cell_Result; T : Duration) return String is
        ((case R is
            when Pass       => "PASS",
            when Fail       => "FAIL",
            when Xfail_Ada  => "XFAIL",
            when Not_Impl_3P => "NI-3P")
         & " "
         & (if R in Pass | Fail | Xfail_Ada
            then Image_Time (T) else "       -"));
   begin
      Put_Line
        ("| " & Pad (Feature_Lbl, 29)
         & " | " & Pad (Cell (C2S_Result, C2S_Time), 14)
         & " | " & Pad (Cell (S2C_Result, S2C_Time), 14)
         & " | " & Note & " |");
   end Md_Feature_Row;

   procedure Json_Peer_Feature
     (Peer : Peer_Kind;
      Feat : Feature_Kind;
      C2S_Result, S2C_Result : Cell_Result;
      C2S_Time,   S2C_Time   : Duration;
      Note : String)
   is
      use GNATCOLL.JSON;
      Row : constant JSON_Value := Create_Object;
      function Make_Side
        (R : Cell_Result; T : Duration) return JSON_Value
      is
         V : constant JSON_Value := Create_Object;
      begin
         V.Set_Field ("result", Image (R));
         V.Set_Field ("time_ms", Integer (T * 1000.0));
         return V;
      end Make_Side;
   begin
      Row.Set_Field ("peer",    Image (Peer));
      Row.Set_Field ("feature", Image (Feat));
      Row.Set_Field ("c2s",     Make_Side (C2S_Result, C2S_Time));
      Row.Set_Field ("s2c",     Make_Side (S2C_Result, S2C_Time));
      Row.Set_Field ("note",    Note);
      Append (Json_Rows, Row);
   end Json_Peer_Feature;

end Tls_Interop_Output;
