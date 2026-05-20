package body Tls_Core.Handshake
  with SPARK_Mode
is

   procedure Derive_Psk_Secrets
     (PSK             : Octet_Array;
      Client_Hello    : Octet_Array;
      Server_Hello    : Octet_Array;
      Server_Finished : Octet_Array;
      Out_Secrets     : out Traffic_Secrets)
   is
      Zero32 : constant Octet_Array (1 .. 32) := [others => 0];
      Empty  : constant Octet_Array (1 .. 0) := [others => 0];

      --  Labels (bytes, no Tls13_Prefix — Hkdf.Expand_Label adds it).
      Derived_Label : constant Octet_Array (1 .. 7) :=
        [16#64#, 16#65#, 16#72#, 16#69#, 16#76#, 16#65#, 16#64#];
      C_Hs_Label    : constant Octet_Array (1 .. 12) :=
        [16#63#,
         16#20#,
         16#68#,
         16#73#,
         16#20#,
         16#74#,
         16#72#,
         16#61#,
         16#66#,
         16#66#,
         16#69#,
         16#63#];
      S_Hs_Label    : constant Octet_Array (1 .. 12) :=
        [16#73#,
         16#20#,
         16#68#,
         16#73#,
         16#20#,
         16#74#,
         16#72#,
         16#61#,
         16#66#,
         16#66#,
         16#69#,
         16#63#];
      C_Ap_Label    : constant Octet_Array (1 .. 12) :=
        [16#63#,
         16#20#,
         16#61#,
         16#70#,
         16#20#,
         16#74#,
         16#72#,
         16#61#,
         16#66#,
         16#66#,
         16#69#,
         16#63#];
      S_Ap_Label    : constant Octet_Array (1 .. 12) :=
        [16#73#,
         16#20#,
         16#61#,
         16#70#,
         16#20#,
         16#74#,
         16#72#,
         16#61#,
         16#66#,
         16#66#,
         16#69#,
         16#63#];

      Early_Secret     : Tls_Core.Key_Schedule.Secret;
      Derived_1        : Tls_Core.Key_Schedule.Secret;
      Handshake_Secret : Tls_Core.Key_Schedule.Secret;
      Derived_2        : Tls_Core.Key_Schedule.Secret;
      Master_Secret    : Tls_Core.Key_Schedule.Secret;

      --  Normalize transcript bytes into First=1 buffers so the
      --  concatenation result indices stay bounded by length only.
      Ch_Sh    :
        Octet_Array (1 .. Client_Hello'Length + Server_Hello'Length) :=
          (others => 0);
      Ch_Sh_Sf :
        Octet_Array
          (1
           .. Client_Hello'Length
              + Server_Hello'Length
              + Server_Finished'Length) := (others => 0);
   begin
      --  Pack CH || SH (slice assignment side-steps 'First+I overflow
      --  reasoning that gnatprove asks for).
      Ch_Sh (1 .. Client_Hello'Length) := Client_Hello;
      Ch_Sh
        (Client_Hello'Length
         + 1
         .. Client_Hello'Length + Server_Hello'Length) :=
        Server_Hello;

      --  Pack CH || SH || SF.
      Ch_Sh_Sf (1 .. Client_Hello'Length) := Client_Hello;
      Ch_Sh_Sf
        (Client_Hello'Length
         + 1
         .. Client_Hello'Length + Server_Hello'Length) :=
        Server_Hello;
      Ch_Sh_Sf
        (Client_Hello'Length
         + Server_Hello'Length
         + 1
         .. Client_Hello'Length
            + Server_Hello'Length
            + Server_Finished'Length) :=
        Server_Finished;

      --  Step 1: Early Secret.
      Tls_Core.Key_Schedule.Extract
        (Salt => Zero32, IKM => PSK, Out_PRK => Early_Secret);

      --  Step 2: derived = Derive(Early, "derived", "").
      Tls_Core.Key_Schedule.Derive_Secret
        (Secret_In  => Early_Secret,
         Label      => Derived_Label,
         Messages   => Empty,
         Out_Secret => Derived_1);

      --  Step 3: PSK_KE-only — (EC)DHE input is 32 zero bytes.
      Tls_Core.Key_Schedule.Extract
        (Salt => Derived_1, IKM => Zero32, Out_PRK => Handshake_Secret);

      --  Step 4: handshake-traffic secrets (transcript = CH..SH).
      Tls_Core.Key_Schedule.Derive_Secret
        (Secret_In  => Handshake_Secret,
         Label      => C_Hs_Label,
         Messages   => Ch_Sh,
         Out_Secret => Out_Secrets.Client_Handshake);
      Tls_Core.Key_Schedule.Derive_Secret
        (Secret_In  => Handshake_Secret,
         Label      => S_Hs_Label,
         Messages   => Ch_Sh,
         Out_Secret => Out_Secrets.Server_Handshake);

      --  Step 5: derived_2 = Derive(Handshake_Secret, "derived", "").
      Tls_Core.Key_Schedule.Derive_Secret
        (Secret_In  => Handshake_Secret,
         Label      => Derived_Label,
         Messages   => Empty,
         Out_Secret => Derived_2);

      --  Step 6: Master_Secret = HKDF-Extract(Derived_2, 0_32).
      Tls_Core.Key_Schedule.Extract
        (Salt => Derived_2, IKM => Zero32, Out_PRK => Master_Secret);

      --  Step 7: application-traffic secrets (transcript = CH..SF).
      Tls_Core.Key_Schedule.Derive_Secret
        (Secret_In  => Master_Secret,
         Label      => C_Ap_Label,
         Messages   => Ch_Sh_Sf,
         Out_Secret => Out_Secrets.Client_App);
      Tls_Core.Key_Schedule.Derive_Secret
        (Secret_In  => Master_Secret,
         Label      => S_Ap_Label,
         Messages   => Ch_Sh_Sf,
         Out_Secret => Out_Secrets.Server_App);
   end Derive_Psk_Secrets;

   ---------------------------------------------------------------------
   --  Derive_Ecdhe_Secrets — same shape as Derive_Psk_Secrets but
   --  with two changes per RFC 8446 §7.1 mode 3:
   --     Early_Secret    = HKDF-Extract(0, 0_32)   (no PSK)
   --     Handshake_Secret= HKDF-Extract(Derived_1, ECDHE_Shared)
   ---------------------------------------------------------------------

   procedure Derive_Ecdhe_Secrets
     (ECDHE_Shared    : Octet_Array;
      Client_Hello    : Octet_Array;
      Server_Hello    : Octet_Array;
      Server_Finished : Octet_Array;
      Out_Secrets     : out Traffic_Secrets)
   is
      Zero32 : constant Octet_Array (1 .. 32) := [others => 0];
      Empty  : constant Octet_Array (1 .. 0) := [others => 0];

      Derived_Label : constant Octet_Array (1 .. 7) :=
        [16#64#, 16#65#, 16#72#, 16#69#, 16#76#, 16#65#, 16#64#];
      C_Hs_Label    : constant Octet_Array (1 .. 12) :=
        [16#63#,
         16#20#,
         16#68#,
         16#73#,
         16#20#,
         16#74#,
         16#72#,
         16#61#,
         16#66#,
         16#66#,
         16#69#,
         16#63#];
      S_Hs_Label    : constant Octet_Array (1 .. 12) :=
        [16#73#,
         16#20#,
         16#68#,
         16#73#,
         16#20#,
         16#74#,
         16#72#,
         16#61#,
         16#66#,
         16#66#,
         16#69#,
         16#63#];
      C_Ap_Label    : constant Octet_Array (1 .. 12) :=
        [16#63#,
         16#20#,
         16#61#,
         16#70#,
         16#20#,
         16#74#,
         16#72#,
         16#61#,
         16#66#,
         16#66#,
         16#69#,
         16#63#];
      S_Ap_Label    : constant Octet_Array (1 .. 12) :=
        [16#73#,
         16#20#,
         16#61#,
         16#70#,
         16#20#,
         16#74#,
         16#72#,
         16#61#,
         16#66#,
         16#66#,
         16#69#,
         16#63#];

      Early_Secret     : Tls_Core.Key_Schedule.Secret;
      Derived_1        : Tls_Core.Key_Schedule.Secret;
      Handshake_Secret : Tls_Core.Key_Schedule.Secret;
      Derived_2        : Tls_Core.Key_Schedule.Secret;
      Master_Secret    : Tls_Core.Key_Schedule.Secret;

      Ch_Sh    :
        Octet_Array (1 .. Client_Hello'Length + Server_Hello'Length) :=
          (others => 0);
      Ch_Sh_Sf :
        Octet_Array
          (1
           .. Client_Hello'Length
              + Server_Hello'Length
              + Server_Finished'Length) := (others => 0);
   begin
      Ch_Sh (1 .. Client_Hello'Length) := Client_Hello;
      Ch_Sh
        (Client_Hello'Length
         + 1
         .. Client_Hello'Length + Server_Hello'Length) :=
        Server_Hello;
      Ch_Sh_Sf (1 .. Client_Hello'Length) := Client_Hello;
      Ch_Sh_Sf
        (Client_Hello'Length
         + 1
         .. Client_Hello'Length + Server_Hello'Length) :=
        Server_Hello;
      Ch_Sh_Sf
        (Client_Hello'Length
         + Server_Hello'Length
         + 1
         .. Client_Hello'Length
            + Server_Hello'Length
            + Server_Finished'Length) :=
        Server_Finished;

      --  Mode 3: Early_Secret = HKDF-Extract(0, 0_32).
      Tls_Core.Key_Schedule.Extract
        (Salt => Zero32, IKM => Zero32, Out_PRK => Early_Secret);

      Tls_Core.Key_Schedule.Derive_Secret
        (Secret_In  => Early_Secret,
         Label      => Derived_Label,
         Messages   => Empty,
         Out_Secret => Derived_1);

      --  Handshake_Secret = HKDF-Extract(Derived_1, ECDHE_Shared).
      Tls_Core.Key_Schedule.Extract
        (Salt => Derived_1, IKM => ECDHE_Shared, Out_PRK => Handshake_Secret);

      Tls_Core.Key_Schedule.Derive_Secret
        (Secret_In  => Handshake_Secret,
         Label      => C_Hs_Label,
         Messages   => Ch_Sh,
         Out_Secret => Out_Secrets.Client_Handshake);
      Tls_Core.Key_Schedule.Derive_Secret
        (Secret_In  => Handshake_Secret,
         Label      => S_Hs_Label,
         Messages   => Ch_Sh,
         Out_Secret => Out_Secrets.Server_Handshake);

      Tls_Core.Key_Schedule.Derive_Secret
        (Secret_In  => Handshake_Secret,
         Label      => Derived_Label,
         Messages   => Empty,
         Out_Secret => Derived_2);

      Tls_Core.Key_Schedule.Extract
        (Salt => Derived_2, IKM => Zero32, Out_PRK => Master_Secret);

      Tls_Core.Key_Schedule.Derive_Secret
        (Secret_In  => Master_Secret,
         Label      => C_Ap_Label,
         Messages   => Ch_Sh_Sf,
         Out_Secret => Out_Secrets.Client_App);
      Tls_Core.Key_Schedule.Derive_Secret
        (Secret_In  => Master_Secret,
         Label      => S_Ap_Label,
         Messages   => Ch_Sh_Sf,
         Out_Secret => Out_Secrets.Server_App);
   end Derive_Ecdhe_Secrets;

end Tls_Core.Handshake;
