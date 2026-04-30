--  baremetal_pic — Proof-In-Concrete that Ada code from this
--  workspace builds and runs on bare-metal ARM Cortex-M3.
--
--  Target: TI Stellaris LM3S811 (Cortex-M3) under
--  `qemu-system-arm -M lm3s6965evb -nographic`. The light-lm3s
--  runtime ships with the gnat_arm_elf toolchain. UART0 is
--  routed to QEMU's stdio so Ada.Text_IO output goes to the
--  host terminal.
--
--  This first iteration is the smallest possible smoke test.
--  Wiring in http2_core (the SPARK HTTP/2 protocol code,
--  built with TRANSPORT=bare) currently triggers a HardFault
--  during the Static_Table aggregate elaboration with
--  No_Exception_Propagation in effect. Diagnosing that needs
--  more debugger time than tonight allows; tracked as the
--  next step in CLAUDE.md.
--
--  What this binary DOES prove:
--    * gnat_arm_elf cross-toolchain works
--    * light-lm3s runtime is functional
--    * gprbuild + linker + QEMU integration is correct
--    * Ada.Text_IO over UART0 → host stdio works
--
--  What it does NOT yet prove:
--    * That the http2_core / mqtt_core protocol code runs
--      on bare-metal. Next session.

with Ada.Text_IO;

procedure Baremetal_Pic is
   use Ada.Text_IO;
begin
   Put_Line ("baremetal_pic: Hello from Ada on bare-metal Cortex-M3");
   Put_Line ("  target  = QEMU lm3s6965evb (TI Stellaris LM3S)");
   Put_Line ("  runtime = light-lm3s (no OS, no heap, no tasking)");
   Put_Line ("baremetal_pic: ok");

   --  Bare-metal main never returns. Idle loop instead of letting
   --  the reset vector restart execution.
   loop
      null;
   end loop;
end Baremetal_Pic;
