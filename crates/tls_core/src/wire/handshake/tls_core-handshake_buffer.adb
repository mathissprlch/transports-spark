package body Tls_Core.Handshake_Buffer
  with SPARK_Mode
is

   ---------------------------------------------------------------------
   --  Init
   ---------------------------------------------------------------------

   procedure Init (B : out Buffer) is
   begin
      B.Data := [others => 0];
      B.Len := 0;
   end Init;

   ---------------------------------------------------------------------
   --  Push_Record_Bytes
   ---------------------------------------------------------------------

   procedure Push_Record_Bytes
     (B : in out Buffer; Bytes : Octet_Array; OK : out Boolean)
   is
      New_Len : Natural;
   begin
      if Bytes'Length = 0 then
         OK := True;
         return;
      end if;
      if Bytes'Length > Max_Buf - B.Len then
         --  Adding Bytes would overflow the cap; refuse.
         OK := False;
         return;
      end if;
      New_Len := B.Len + Bytes'Length;
      --  Copy element-by-element so SPARK can prove every index in
      --  range without needing to reason about a single big slice
      --  assignment that touches both Bytes' arbitrary 'First and
      --  Storage_Array's 1-based indexing.
      for I in 0 .. Bytes'Length - 1 loop
         pragma Loop_Invariant (B.Len = B.Len'Loop_Entry);
         pragma Loop_Invariant (I + 1 <= Bytes'Length);
         pragma Loop_Invariant (B.Len + I + 1 <= Max_Buf);
         B.Data (B.Len + I + 1) := Bytes (Bytes'First + I);
      end loop;
      B.Len := New_Len;
      OK := True;
   end Push_Record_Bytes;

   ---------------------------------------------------------------------
   --  Pop_Complete_Message
   ---------------------------------------------------------------------

   procedure Pop_Complete_Message
     (B : in out Buffer; Out_Buf : out Octet_Array; Out_Last : out Natural)
   is
      Body_Len  : constant Natural := Peek_Body_Length (B);
      Total     : constant Natural := Header_Len + Body_Len;
      Old_Len   : constant Natural := B.Len;
      Remaining : constant Natural := Old_Len - Total;
   begin
      Out_Buf := [others => 0];
      --  Copy header + body to caller buffer.
      for I in 1 .. Total loop
         pragma Loop_Invariant (B.Len = Old_Len);
         pragma Loop_Invariant (Total <= B.Len);
         pragma Loop_Invariant (Total <= Out_Buf'Last);
         Out_Buf (I) := B.Data (I);
      end loop;
      Out_Last := Total;

      --  Slide remaining bytes (Total + 1 .. B.Len) left to start
      --  at index 1. After the slide the new Used count is
      --  B.Len - Total.
      if Remaining > 0 then
         for I in 1 .. Remaining loop
            pragma Loop_Invariant (B.Len = Old_Len);
            pragma Loop_Invariant (Total + I <= B.Len);
            B.Data (I) := B.Data (Total + I);
         end loop;
      end if;
      --  Zero the now-unused tail so the buffer's contents
      --  outside the live prefix are deterministic — saves us
      --  from leaking stale handshake bytes if a later Push
      --  doesn't touch the same slot.
      for I in Remaining + 1 .. Old_Len loop
         pragma Loop_Invariant (B.Len = Old_Len);
         pragma Loop_Invariant (I <= Max_Buf);
         B.Data (I) := 0;
      end loop;
      B.Len := Remaining;
   end Pop_Complete_Message;

end Tls_Core.Handshake_Buffer;
