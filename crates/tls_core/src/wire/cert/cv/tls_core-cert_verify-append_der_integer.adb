separate (Tls_Core.Cert_Verify)
   procedure Append_Der_Integer
     (Value   : Octet_Array;
      Out_Buf : in out Octet_Array;
      Cursor  : in out Natural)
   is
      Cursor_Start  : constant Natural := Cursor;
      First_Nonzero : Natural := 1;
      Need_Pad      : Boolean;
      Body_Len      : Natural;
   begin
      while First_Nonzero <= 32
        and then Value (First_Nonzero) = 0
      loop
         pragma Loop_Invariant (First_Nonzero in 1 .. 32);
         First_Nonzero := First_Nonzero + 1;
      end loop;
      if First_Nonzero > 32 then
         --  All zeros: emit INTEGER 0x00 (tag + len 1 + 0x00).
         Out_Buf (Cursor + 1) := 16#02#;
         Out_Buf (Cursor + 2) := 16#01#;
         Out_Buf (Cursor + 3) := 16#00#;
         Cursor := Cursor + 3;
         return;
      end if;
      Need_Pad := (Value (First_Nonzero) and 16#80#) /= 0;
      Body_Len :=
        (32 - First_Nonzero + 1) + (if Need_Pad then 1 else 0);
      pragma Assert (Body_Len in 1 .. 33);
      Out_Buf (Cursor + 1) := 16#02#;
      Out_Buf (Cursor + 2) := Octet (Body_Len);
      Cursor := Cursor + 2;
      if Need_Pad then
         Cursor := Cursor + 1;
         Out_Buf (Cursor) := 16#00#;
      end if;
      pragma Assert
        (Cursor <= Cursor_Start + 3
         and then Cursor_Start + Body_Len + 2 <= Cursor_Start + 35);
      for I in First_Nonzero .. 32 loop
         pragma Loop_Invariant
           (I in First_Nonzero .. 32
            and then Cursor in Cursor_Start + 2 .. Cursor_Start + 34
            and then Cursor - Cursor_Start + (32 - I + 1) <= 35
            and then Cursor < Out_Buf'Last);
         Cursor := Cursor + 1;
         Out_Buf (Cursor) := Value (I);
      end loop;
      pragma Assert (Cursor in Cursor_Start + 3 .. Cursor_Start + 35);
   end Append_Der_Integer;
