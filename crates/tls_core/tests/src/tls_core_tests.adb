--  tls_core_tests — first-slice unit tests for v0.5.
--
--  Two checks per scenario:
--    1. Build_Info_Bytes (hand-rolled, SPARK contracts) emits the
--       byte sequence the RFC 8446 §7.1 layout demands.
--    2. Build_Info_Bytes_Via_Rflx (RecordFlux serializer)
--       produces the IDENTICAL bytes for the same inputs. This
--       is our cross-check oracle for the contract.

with Ada.Text_IO;
with Ada.Command_Line;
with Tls_Core;
with Tls_Core.Hkdf;
with RFLX.RFLX_Builtin_Types;
with RFLX.RFLX_Types;

procedure Tls_Core_Tests is

   use Ada.Text_IO;
   use type Tls_Core.Octet;

   Pass : Natural := 0;
   Fail : Natural := 0;

   procedure Check (Label : String; OK : Boolean);
   procedure Check (Label : String; OK : Boolean) is
   begin
      if OK then
         Pass := Pass + 1;
         Put_Line ("  PASS " & Label);
      else
         Fail := Fail + 1;
         Put_Line ("  FAIL " & Label);
      end if;
   end Check;

   --  Compare two octet slices.
   function Equal (A, B : Tls_Core.Octet_Array) return Boolean;
   function Equal (A, B : Tls_Core.Octet_Array) return Boolean is
   begin
      if A'Length /= B'Length then
         return False;
      end if;
      for I in 0 .. A'Length - 1 loop
         if A (A'First + I) /= B (B'First + I) then
            return False;
         end if;
      end loop;
      return True;
   end Equal;

   --------------------------------------------------------------------
   --  Scenario 1 — label="hello", context empty, length=32.
   --
   --  Expected wire (RFC 8446 §7.1, big-endian u16 length, "tls13 "
   --  + label, then context-len + context):
   --    00 20                              -- u16 length = 32
   --    0B                                  -- |"tls13 "+label| = 11
   --    74 6C 73 31 33 20                  -- "tls13 "
   --    68 65 6C 6C 6F                     -- "hello"
   --    00                                  -- |context| = 0
   --------------------------------------------------------------------

   procedure Scenario_1;
   procedure Scenario_1 is
      Label    : constant Tls_Core.Octet_Array (1 .. 5) :=
        (16#68#, 16#65#, 16#6C#, 16#6C#, 16#6F#);
      Context  : constant Tls_Core.Octet_Array (1 .. 0) :=
        (others => 0);
      Out_Hand : Tls_Core.Octet_Array
        (1 .. Tls_Core.Hkdf.Info_Size (Label'Length, Context'Length));
      Out_Last : Natural;
      Expected : constant Tls_Core.Octet_Array (1 .. 15) :=
        (16#00#, 16#20#,
         16#0B#,
         16#74#, 16#6C#, 16#73#, 16#31#, 16#33#, 16#20#,
         16#68#, 16#65#, 16#6C#, 16#6C#, 16#6F#,
         16#00#);
   begin
      Put_Line ("scenario 1 — label=hello, context=empty, length=32");
      Tls_Core.Hkdf.Build_Info_Bytes
        (Length  => 32,
         Label   => Label,
         Context => Context,
         Output  => Out_Hand,
         Last    => Out_Last);
      Check ("hand-rolled length matches",
             Out_Last = Out_Hand'Last);
      Check ("hand-rolled bytes match RFC §7.1",
             Equal (Out_Hand, Expected));

      --  Cross-check via the RecordFlux serializer.
      declare
         Buf : RFLX.RFLX_Builtin_Types.Bytes_Ptr :=
           new RFLX.RFLX_Types.Bytes'(1 .. 64 => 0);
         Rflx_Last : Natural;
      begin
         Tls_Core.Hkdf.Build_Info_Bytes_Via_Rflx
           (Length  => 32,
            Label   => Label,
            Context => Context,
            Buffer  => Buf,
            Last    => Rflx_Last);
         declare
            Out_Rflx : Tls_Core.Octet_Array
              (1 .. Out_Hand'Length);
         begin
            for I in Out_Rflx'Range loop
               Out_Rflx (I) :=
                 Tls_Core.Octet (Buf.all (RFLX.RFLX_Types.Index (I)));
            end loop;
            Check
              ("rflx-encoded bytes equal hand-rolled bytes",
               Equal (Out_Hand, Out_Rflx));
         end;
      end;
   end Scenario_1;

   --------------------------------------------------------------------
   --  Scenario 2 — label="key", context=4 bytes 0xCA 0xFE 0xBA 0xBE,
   --  length=16. Exercises the non-empty-context branch.
   --
   --  Expected wire:
   --    00 10                                -- u16 length = 16
   --    09                                    -- |"tls13 "+label| = 9
   --    74 6C 73 31 33 20                    -- "tls13 "
   --    6B 65 79                              -- "key"
   --    04                                    -- |context| = 4
   --    CA FE BA BE                          -- context
   --------------------------------------------------------------------

   procedure Scenario_2;
   procedure Scenario_2 is
      Label    : constant Tls_Core.Octet_Array (1 .. 3) :=
        (16#6B#, 16#65#, 16#79#);
      Context  : constant Tls_Core.Octet_Array (1 .. 4) :=
        (16#CA#, 16#FE#, 16#BA#, 16#BE#);
      Out_Hand : Tls_Core.Octet_Array
        (1 .. Tls_Core.Hkdf.Info_Size (Label'Length, Context'Length));
      Out_Last : Natural;
      Expected : constant Tls_Core.Octet_Array (1 .. 17) :=
        (16#00#, 16#10#,
         16#09#,
         16#74#, 16#6C#, 16#73#, 16#31#, 16#33#, 16#20#,
         16#6B#, 16#65#, 16#79#,
         16#04#,
         16#CA#, 16#FE#, 16#BA#, 16#BE#);
   begin
      Put_Line ("scenario 2 — label=key, context=4B, length=16");
      Tls_Core.Hkdf.Build_Info_Bytes
        (Length  => 16,
         Label   => Label,
         Context => Context,
         Output  => Out_Hand,
         Last    => Out_Last);
      Check ("hand-rolled length matches",
             Out_Last = Out_Hand'Last);
      Check ("hand-rolled bytes match RFC §7.1",
             Equal (Out_Hand, Expected));

      declare
         Buf : RFLX.RFLX_Builtin_Types.Bytes_Ptr :=
           new RFLX.RFLX_Types.Bytes'(1 .. 64 => 0);
         Rflx_Last : Natural;
      begin
         Tls_Core.Hkdf.Build_Info_Bytes_Via_Rflx
           (Length  => 16,
            Label   => Label,
            Context => Context,
            Buffer  => Buf,
            Last    => Rflx_Last);
         declare
            Out_Rflx : Tls_Core.Octet_Array
              (1 .. Out_Hand'Length);
         begin
            for I in Out_Rflx'Range loop
               Out_Rflx (I) :=
                 Tls_Core.Octet (Buf.all (RFLX.RFLX_Types.Index (I)));
            end loop;
            Check
              ("rflx-encoded bytes equal hand-rolled bytes",
               Equal (Out_Hand, Out_Rflx));
         end;
      end;
   end Scenario_2;

begin
   Put_Line ("=== Tls_Core HKDF-Expand-Label info-encoding tests ===");
   Scenario_1;
   Scenario_2;
   New_Line;
   Put_Line ("Pass:" & Pass'Image & "  Fail:" & Fail'Image);
   if Fail > 0 then
      Ada.Command_Line.Set_Exit_Status (1);
   end if;
end Tls_Core_Tests;
