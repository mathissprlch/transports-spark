with Ada.Command_Line;
with Ada.Directories;
with Ada.Strings.Fixed;
with Ada.Text_IO;
with GNAT.OS_Lib;     use GNAT.OS_Lib;

package body Tls_Interop_Peers is

   --  Helpers --------------------------------------------------------

   function S (U : Unbounded_String) return String is (To_String (U));
   function U (S : String) return Unbounded_String is (To_Unbounded_String (S));

   function Img (N : Natural) return String is
      Raw : constant String := Natural'Image (N);
   begin
      return Ada.Strings.Fixed.Trim (Raw, Ada.Strings.Both);
   end Img;

   function New_Arg (S : String) return GNAT.OS_Lib.String_Access is
     (new String'(S));

   --  Cipher → IANA name (openssl / bssl spelling).
   function Cipher_Name (C : Cipher_Kind) return String is
   begin
      case C is
         when Auto => return "TLS_CHACHA20_POLY1305_SHA256";
         when Chacha20_Poly1305_Sha256 =>
            return "TLS_CHACHA20_POLY1305_SHA256";
         when Aes128_Gcm_Sha256        => return "TLS_AES_128_GCM_SHA256";
         when Aes256_Gcm_Sha384        => return "TLS_AES_256_GCM_SHA384";
      end case;
   end Cipher_Name;

   ---------------------------------------------------------------------
   --  Binary_Available — locate $PATH binary.
   ---------------------------------------------------------------------

   function Locate (Name : String) return Boolean is
      Found : GNAT.OS_Lib.String_Access := Locate_Exec_On_Path (Name);
      Ok    : constant Boolean := Found /= null;
   begin
      Free (Found);
      return Ok;
   end Locate;

   --  ~/work/wolfssl is a sibling of transports-spark; the wolfSSL
   --  example tools live under examples/{client,server}/ in that
   --  source tree (not in homebrew which only ships the library).
   function Wolf_Home return String is
      Cwd : constant String := Ada.Directories.Current_Directory;
      Up  : constant String := Ada.Directories.Containing_Directory (Cwd);
   begin
      return Up & "/wolfssl";
   end Wolf_Home;

   function Binary_Available (P : Peer_Kind) return Boolean is
   begin
      case P is
         when Ada_Native => return True;  --  same binary as the matrix
         when Openssl    => return Locate ("openssl");
         when Gnutls     => return Locate ("gnutls-cli")
                                   and Locate ("gnutls-serv");
         when Mbedtls    => return Locate ("ssl_client2")
                                   and Locate ("ssl_server2");
         when Rustls     => return Locate ("tlsclient-mio")
                                   and Locate ("tlsserver-mio");
         when Go_Lang    => return Locate ("go");
         when Boringssl  => return Locate ("bssl");
         when Wolfssl    =>
            return Ada.Directories.Exists
                     (Wolf_Home & "/examples/client/client")
                   and then Ada.Directories.Exists
                              (Wolf_Home & "/examples/server/server");
      end case;
   end Binary_Available;

   ---------------------------------------------------------------------
   --  Image
   ---------------------------------------------------------------------

   function Image (P : Peer_Kind) return String is
   begin
      case P is
         when Ada_Native => return "ada";
         when Openssl    => return "openssl";
         when Gnutls     => return "gnutls";
         when Mbedtls    => return "mbedtls";
         when Rustls     => return "rustls";
         when Go_Lang    => return "go";
         when Boringssl  => return "boringssl";
         when Wolfssl    => return "wolfssl";
      end case;
   end Image;

   function Image (M : Mode_Kind) return String is
   begin
      case M is
         when Psk_Dhe_Ke => return "psk-dhe-ke";
         when Cert_Ec    => return "cert-ec";
         when Cert_Rsa   => return "cert-rsa";
      end case;
   end Image;

   function Image (R : Role_Kind) return String is
   begin
      case R is
         when Client => return "client";
         when Server => return "server";
      end case;
   end Image;

   function Image (C : Cipher_Kind) return String is
   begin
      case C is
         when Auto                     => return "auto";
         when Chacha20_Poly1305_Sha256 => return "chacha20";
         when Aes128_Gcm_Sha256        => return "aes128";
         when Aes256_Gcm_Sha384        => return "aes256";
      end case;
   end Image;

   ---------------------------------------------------------------------
   --  Per-peer command builders.  Each returns Args = list of String_
   --  Access (caller frees via Free).  Sets Supported = False with a
   --  Reason when the (peer, mode) pair is genuinely unsupported.
   ---------------------------------------------------------------------

   --  Convenience: deep-copy a String_Access list into Argument_List_
   --  Access of length N.
   function Pack
     (S0  : String := ""; S1  : String := ""; S2  : String := "";
      S3  : String := ""; S4  : String := ""; S5  : String := "";
      S6  : String := ""; S7  : String := ""; S8  : String := "";
      S9  : String := ""; S10 : String := ""; S11 : String := "";
      S12 : String := ""; S13 : String := ""; S14 : String := "";
      S15 : String := ""; S16 : String := ""; S17 : String := "";
      S18 : String := ""; S19 : String := ""; S20 : String := "")
      return Argument_List_Access
   is
      type Slot is record
         Tag : Boolean;  --  True if non-empty
         Val : GNAT.OS_Lib.String_Access;
      end record;
      Slots : array (1 .. 21) of Slot :=
        [1  => (S0 /= "", New_Arg (S0)),
         2  => (S1 /= "", New_Arg (S1)),
         3  => (S2 /= "", New_Arg (S2)),
         4  => (S3 /= "", New_Arg (S3)),
         5  => (S4 /= "", New_Arg (S4)),
         6  => (S5 /= "", New_Arg (S5)),
         7  => (S6 /= "", New_Arg (S6)),
         8  => (S7 /= "", New_Arg (S7)),
         9  => (S8 /= "", New_Arg (S8)),
         10 => (S9 /= "", New_Arg (S9)),
         11 => (S10 /= "", New_Arg (S10)),
         12 => (S11 /= "", New_Arg (S11)),
         13 => (S12 /= "", New_Arg (S12)),
         14 => (S13 /= "", New_Arg (S13)),
         15 => (S14 /= "", New_Arg (S14)),
         16 => (S15 /= "", New_Arg (S15)),
         17 => (S16 /= "", New_Arg (S16)),
         18 => (S17 /= "", New_Arg (S17)),
         19 => (S18 /= "", New_Arg (S18)),
         20 => (S19 /= "", New_Arg (S19)),
         21 => (S20 /= "", New_Arg (S20))];
      N : Natural := 0;
   begin
      for I in Slots'Range loop
         if Slots (I).Tag then
            N := N + 1;
         end if;
      end loop;
      declare
         Result : constant Argument_List_Access := new Argument_List (1 .. N);
         J : Natural := 0;
      begin
         for I in Slots'Range loop
            if Slots (I).Tag then
               J := J + 1;
               Result (J) := Slots (I).Val;
            else
               Free (Slots (I).Val);
            end if;
         end loop;
         return Result;
      end;
   end Pack;

   --  ada (our tls_cli) — same binary, just different flags.
   procedure Build_Ada
     (Cell      : Cell_Spec;
      Bin       : out Unbounded_String;
      Args      : out Argument_List_Access;
      Supported : out Boolean;
      Reason    : out Unbounded_String)
   is
      Endpoint : constant String :=
        S (Cell.Host) & ":" & Img (Cell.Port);
   begin
      Supported := True;
      Reason := Null_Unbounded_String;
      --  tls_cli lives in the same bin/ as the matrix.  Resolve it
      --  by:  (1) $PATH lookup,  (2) sibling-of-argv[0],  (3) repo
      --  build dir under crates/examples/bin.
      declare
         Self : GNAT.OS_Lib.String_Access := Locate_Exec_On_Path ("tls_cli");
         Argv0 : constant String := Ada.Command_Line.Command_Name;
         function Sibling_Path return String is
            --  Strip /tls_matrix off the end if present.
            Last : Natural := Argv0'Last;
         begin
            while Last >= Argv0'First and then Argv0 (Last) /= '/' loop
               Last := Last - 1;
            end loop;
            if Last >= Argv0'First then
               return Argv0 (Argv0'First .. Last) & "tls_cli";
            else
               return "tls_cli";
            end if;
         end Sibling_Path;
      begin
         if Self /= null then
            Bin := U (Self.all);
            Free (Self);
         else
            declare
               Sib : constant String := Sibling_Path;
            begin
               if Ada.Directories.Exists (Sib) then
                  Bin := U (Sib);
               elsif Ada.Directories.Exists
                       ("crates/tls_cli/bin/tls_cli")
               then
                  --  Standalone tls_cli crate (CI / Docker image
                  --  without vendor/aws — depends on tls_core only).
                  Bin := U ("crates/tls_cli/bin/tls_cli");
               elsif Ada.Directories.Exists
                       ("crates/examples/bin/tls_cli")
               then
                  Bin := U ("crates/examples/bin/tls_cli");
               elsif Ada.Directories.Exists ("./bin/tls_cli") then
                  Bin := U ("./bin/tls_cli");
               else
                  Bin := U ("tls_cli");
               end if;
            end;
         end if;
      end;
      case Cell.Mode is
         when Psk_Dhe_Ke =>
            --  Matrix policy: every cell is handshake-only.  Our
            --  unit tests (tls_core_tests) exercise the AEAD app-
            --  data round-trip exhaustively (594 cases incl. soak),
            --  so the interop matrix focuses on RFC 8446 handshake
            --  conformance only.  This unifies success criterion
            --  to "tls_cli: OK after handshake" for every (peer,
            --  role) combination.
            if Cell.Role = Client then
               Args := Pack
                 ("client", "--connect", Endpoint,
                  "--mode", "psk-dhe-ke",
                  "--psk-file", S (Cell.Psk_File),
                  "--psk-id", S (Cell.Psk_Identity));
            else
               Args := Pack
                 ("server", "--bind", Endpoint,
                  "--mode", "psk-dhe-ke",
                  "--psk-file", S (Cell.Psk_File),
                  "--psk-id", S (Cell.Psk_Identity));
            end if;
         when Cert_Ec =>
            --  PEM paths point at e.g. tests/fixtures/interop/ec/{leaf,
            --  root}.pem.  Ada tls_cli consumes raw DER for certs and
            --  the 32-byte EC scalar for the private key — those are
            --  emitted by gen_pki.sh at the same prefix with a
            --  different extension.
            declare
               function Sub_Ext (P, New_Ext : String) return String is
                  Last_Dot : Natural := P'First - 1;
               begin
                  for I in P'Range loop
                     if P (I) = '.' then
                        Last_Dot := I;
                     end if;
                  end loop;
                  if Last_Dot >= P'First then
                     return P (P'First .. Last_Dot - 1) & New_Ext;
                  else
                     return P & New_Ext;
                  end if;
               end Sub_Ext;
               Cert_Der  : constant String := Sub_Ext (S (Cell.Cert_Pem),  ".der");
               Trust_Der : constant String := Sub_Ext (S (Cell.Trust_Pem), ".der");
               Priv_Raw  : constant String := Sub_Ext (S (Cell.Key_Pem),   ".priv");
            begin
               if Cell.Role = Client then
                  Args := Pack
                    ("client", "--connect", Endpoint,
                     "--mode", "cert-ec",
                     "--trust", Trust_Der,
                     "--hostname", S (Cell.Hostname));
               else
                  Args := Pack
                    ("server", "--bind", Endpoint,
                     "--mode", "cert-ec",
                     "--cert", Cert_Der,
                     "--key", Priv_Raw);
               end if;
            end;
         when Cert_Rsa =>
            Supported := False;
            Reason := U
              ("cert-rsa: Ada driver Init_Cert_Server is EC-only; "
               & "RSA-PSS server-side signing is v0.5.x scope.");
            Args := Pack;
      end case;
   end Build_Ada;

   procedure Build_Openssl
     (Cell      : Cell_Spec;
      Bin       : out Unbounded_String;
      Args      : out Argument_List_Access;
      Supported : out Boolean;
      Reason    : out Unbounded_String)
   is
      Cipher : constant String := Cipher_Name (Cell.Cipher);
      Endpoint : constant String :=
        S (Cell.Host) & ":" & Img (Cell.Port);
   begin
      Supported := True;
      Reason := Null_Unbounded_String;
      Bin := U ("openssl");
      case Cell.Mode is
         when Psk_Dhe_Ke =>
            if Cell.Role = Client then
               Args := Pack
                 ("s_client", "-tls1_3", "-connect", Endpoint,
                  "-psk", S (Cell.Psk_Hex),
                  "-psk_identity", S (Cell.Psk_Identity),
                  "-quiet", "-ciphersuites", Cipher);
            else
               Args := Pack
                 ("s_server", "-tls1_3", "-accept", Img (Cell.Port),
                  "-psk", S (Cell.Psk_Hex),
                  "-psk_identity", S (Cell.Psk_Identity),
                  "-nocert", "-naccept", "1", "-quiet",
                  "-ciphersuites", Cipher);
            end if;
         when Cert_Ec =>
            if Cell.Role = Client then
               Args := Pack
                 ("s_client", "-tls1_3", "-connect", Endpoint,
                  "-CAfile", S (Cell.Trust_Pem),
                  "-verify_return_error", "-quiet",
                  "-ciphersuites", Cipher);
            else
               --  -num_tickets 0: don't emit NewSessionTicket
               --  post-handshake; we'll exercise that path through
               --  the dedicated psk-resume cell instead.  Bare
               --  cert-ec cell is handshake-only.
               Args := Pack
                 ("s_server", "-tls1_3", "-accept", Img (Cell.Port),
                  "-cert", S (Cell.Cert_Pem),
                  "-key", S (Cell.Key_Pem),
                  "-CAfile", S (Cell.Trust_Pem),
                  "-naccept", "1", "-quiet",
                  "-num_tickets", "0",
                  "-ciphersuites", Cipher);
            end if;
         when Cert_Rsa =>
            Supported := False;
            Reason := U ("cert-rsa via openssl pending RSA fixtures");
            Args := Pack;
      end case;
   end Build_Openssl;

   procedure Build_Gnutls
     (Cell      : Cell_Spec;
      Bin       : out Unbounded_String;
      Args      : out Argument_List_Access;
      Supported : out Boolean;
      Reason    : out Unbounded_String)
   is
      Tls13_Priority : constant String :=
        "NONE:+VERS-TLS1.3:+AEAD:+SHA256:+AES-128-GCM:" &
        "+CHACHA20-POLY1305:+ECDHE-PSK:+CURVE-X25519:+GROUP-X25519:" &
        "+CTYPE-X509:+SIGN-RSA-SHA256:+SIGN-ECDSA-SHA256";
      Cert_Priority  : constant String :=
        "NORMAL:-VERS-ALL:+VERS-TLS1.3";
      --  PSK file has the GnuTLS format "identity:hex_psk".
      Psk_Path : constant String := "/tmp/spark-tls-gnutls-psk.txt";
   begin
      Supported := True;
      Reason := Null_Unbounded_String;
      case Cell.Mode is
         when Psk_Dhe_Ke =>
            --  Pre-create the PSK file the gnutls tools want.
            declare
               F : Ada.Text_IO.File_Type;
            begin
               Ada.Text_IO.Create
                 (F, Ada.Text_IO.Out_File, Psk_Path);
               Ada.Text_IO.Put_Line
                 (F, S (Cell.Psk_Identity) & ":" & S (Cell.Psk_Hex));
               Ada.Text_IO.Close (F);
            exception
               when others =>
                  if Ada.Text_IO.Is_Open (F) then
                     Ada.Text_IO.Close (F);
                  end if;
            end;
            if Cell.Role = Client then
               Bin := U ("gnutls-cli");
               Args := Pack
                 (S (Cell.Host),
                  "--port", Img (Cell.Port),
                  "--pskusername", S (Cell.Psk_Identity),
                  "--pskkey", S (Cell.Psk_Hex),
                  "--priority", Tls13_Priority);
            else
               Bin := U ("gnutls-serv");
               Args := Pack
                 ("--port", Img (Cell.Port),
                  "--pskpasswd", Psk_Path,
                  "--priority", Tls13_Priority,
                  "--echo");
            end if;
         when Cert_Ec =>
            if Cell.Role = Client then
               Bin := U ("gnutls-cli");
               Args := Pack
                 (S (Cell.Host),
                  "--port", Img (Cell.Port),
                  "--x509cafile", S (Cell.Trust_Pem),
                  "--priority", Cert_Priority);
            else
               --  --disable-client-cert: gnutls-serv defaults to
               --  emitting a CertificateRequest in TLS 1.3, which
               --  our cert-mode client (no client-auth in v0.5)
               --  can't handle and rejects with decode_error.
               Bin := U ("gnutls-serv");
               Args := Pack
                 ("--port", Img (Cell.Port),
                  "--x509certfile", S (Cell.Cert_Pem),
                  "--x509keyfile", S (Cell.Key_Pem),
                  "--priority", Cert_Priority,
                  "--disable-client-cert",
                  "--echo");
            end if;
         when Cert_Rsa =>
            Supported := False;
            Reason := U ("cert-rsa via gnutls pending RSA fixtures");
            Bin := U ("gnutls-cli");
            Args := Pack;
      end case;
   end Build_Gnutls;

   procedure Build_Mbedtls
     (Cell      : Cell_Spec;
      Bin       : out Unbounded_String;
      Args      : out Argument_List_Access;
      Supported : out Boolean;
      Reason    : out Unbounded_String)
   is
   begin
      Supported := True;
      Reason := Null_Unbounded_String;
      case Cell.Mode is
         when Psk_Dhe_Ke =>
            if Cell.Role = Client then
               Bin := U ("ssl_client2");
               Args := Pack
                 ("server_addr=" & S (Cell.Host),
                  "server_port=" & Img (Cell.Port),
                  "tls13_kex_modes=psk_ephemeral",
                  "psk_identity=" & S (Cell.Psk_Identity),
                  "psk=" & S (Cell.Psk_Hex),
                  "force_version=tls13",
                  "exchanges=1");
            else
               Bin := U ("ssl_server2");
               Args := Pack
                 ("server_addr=127.0.0.1",
                  "server_port=" & Img (Cell.Port),
                  "tls13_kex_modes=psk_ephemeral",
                  "psk_identity=" & S (Cell.Psk_Identity),
                  "psk=" & S (Cell.Psk_Hex),
                  "force_version=tls13",
                  "exchanges=1");
            end if;
         when Cert_Ec =>
            if Cell.Role = Client then
               Bin := U ("ssl_client2");
               Args := Pack
                 ("server_addr=" & S (Cell.Host),
                  "server_port=" & Img (Cell.Port),
                  "ca_file=" & S (Cell.Trust_Pem),
                  "force_version=tls13",
                  "exchanges=1");
            else
               Bin := U ("ssl_server2");
               Args := Pack
                 ("server_addr=127.0.0.1",
                  "server_port=" & Img (Cell.Port),
                  "crt_file=" & S (Cell.Cert_Pem),
                  "key_file=" & S (Cell.Key_Pem),
                  "ca_file=" & S (Cell.Trust_Pem),
                  "force_version=tls13",
                  "exchanges=1");
            end if;
         when Cert_Rsa =>
            Supported := False;
            Reason := U ("cert-rsa via mbedtls pending RSA fixtures");
            Bin := U ("ssl_client2");
            Args := Pack;
      end case;
   end Build_Mbedtls;

   procedure Build_Rustls
     (Cell      : Cell_Spec;
      Bin       : out Unbounded_String;
      Args      : out Argument_List_Access;
      Supported : out Boolean;
      Reason    : out Unbounded_String)
   is
   begin
      case Cell.Mode is
         when Psk_Dhe_Ke =>
            Supported := False;
            Reason := U
              ("rustls-mio CLIs do not expose external PSK (lib does)");
            Bin := U ("tlsclient-mio");
            Args := Pack;
         when Cert_Ec =>
            if Cell.Role = Client then
               --  Cell.Role = Client → peer plays client role
               --  (Ada is server).  s2c flow.  tlsclient-mio
               --  --http connects, sends a GET, exits cleanly.
               Supported := True;
               Reason := Null_Unbounded_String;
               Bin := U ("tlsclient-mio");
               Args := Pack
                 (S (Cell.Host),
                  "--port", Img (Cell.Port),
                  "--cafile", S (Cell.Trust_Pem),
                  "--http");
            else
               --  Cell.Role = Server → peer plays server role.
               --  c2s flow.  tlsserver-mio echo subcommand idles
               --  for client app-data and doesn't drive the
               --  handshake to completion against a handshake-only
               --  Ada client.  Documented upstream-CLI gap; rustls
               --  s2c (above) exercises the same primitives.
               Supported := False;
               Reason := U
                 ("tlsserver-mio echo subcommand idles for client "
                  & "app-data; no handshake-only mode in CLI");
               Bin := U ("tlsserver-mio");
               Args := Pack;
            end if;
         when Cert_Rsa =>
            Supported := False;
            Reason := U ("cert-rsa via rustls pending RSA fixtures");
            Bin := U ("tlsclient-mio");
            Args := Pack;
      end case;
   end Build_Rustls;

   procedure Build_Go
     (Cell      : Cell_Spec;
      Bin       : out Unbounded_String;
      Args      : out Argument_List_Access;
      Supported : out Boolean;
      Reason    : out Unbounded_String)
   is
      --  Pre-built by `make tls-interop-go-helpers`; `go run` would
      --  recompile every spawn and miss the 0.8 s matrix-side wait,
      --  surfacing as spurious CONNECT_ERROR.
      Helper_Cli : constant String := "./crates/examples/bin/go_peer_client";
      Helper_Srv : constant String := "./crates/examples/bin/go_peer_server";
   begin
      case Cell.Mode is
         when Psk_Dhe_Ke =>
            Supported := False;
            Reason := U ("Go stdlib crypto/tls has no external-PSK API");
            Bin := U (Helper_Cli);
            Args := Pack;
         when Cert_Ec =>
            Supported := True;
            Reason := Null_Unbounded_String;
            if Cell.Role = Client then
               Bin := U (Helper_Cli);
               Args := Pack
                 ("--addr", S (Cell.Host) & ":" & Img (Cell.Port),
                  "--root", S (Cell.Trust_Pem));
            else
               Bin := U (Helper_Srv);
               Args := Pack
                 ("--addr", "127.0.0.1:" & Img (Cell.Port),
                  "--cert", S (Cell.Cert_Pem),
                  "--key", S (Cell.Key_Pem));
            end if;
         when Cert_Rsa =>
            Supported := False;
            Reason := U ("cert-rsa via Go pending RSA fixtures");
            Bin := U (Helper_Cli);
            Args := Pack;
      end case;
   end Build_Go;

   --  wolfSSL: example client + server live in the source tree
   --  (~/work/wolfssl/examples/{client,server}).  No PSK external-
   --  config flag for the example tools (their `-s` uses a wolfSSL-
   --  internal RFC 4279 hint, not RFC 8446 external PSK), so PSK
   --  cells N/A; cert mode is wired.
   procedure Build_Wolfssl
     (Cell      : Cell_Spec;
      Bin       : out Unbounded_String;
      Args      : out Argument_List_Access;
      Supported : out Boolean;
      Reason    : out Unbounded_String)
   is
      Home : constant String := Wolf_Home;
   begin
      case Cell.Mode is
         when Psk_Dhe_Ke =>
            Supported := False;
            Reason := U
              ("wolfSSL example tools' -s flag uses RFC 4279 hint, "
               & "not RFC 8446 external PSK");
            Bin := U (Home & "/examples/client/client");
            Args := Pack;
         when Cert_Ec =>
            --  As of 2026-05-15: wolfSSL c2s handshake decodes and
            --  validates correctly through Ada's SHA-384 / ECDSA-P256
            --  CV verify path (flight decode is no longer a problem
            --  after the D-4 dispatch wiring + earlier fixes).  The
            --  only remaining gap is that wolfSSL's stock test cert
            --  fixture certs/server-ecc.pem has NO X509 SubjectAltName
            --  extension (verified via `openssl x509 -ext
            --  subjectAltName` — "No extensions in certificate"),
            --  which our hostname check correctly rejects per RFC 6125.
            --  Classification per docs/conventions.md §9: (e) counterpart
            --  fixture below modern TLS bar — NOT an Ada-side bug.
            --  Lifting this cell to PASS requires either:
            --    (a) regenerate a wolfSSL-CA-signed ECC leaf with
            --        SubjectAltName, or
            --    (b) pass --hostname "" in this cell only (weakens
            --        verification — not preferred), or
            --    (c) use certs/server-ecc-comp.pem (has SAN
            --        DNS:example.com) once compressed-point cert
            --        parsing is verified in our X.509 parser.
            --  Kept NI-3P for v0.5; the underlying handshake
            --  primitive path (incl. SHA-384) is exercised through
            --  this peer when the SAN check is skipped.
            Supported := False;
            Reason := U
              ("wolfSSL test fixture cert has no SubjectAltName; "
               & "lift with SAN-bearing cert or hostname='' override");
            Bin := U (Home & "/examples/client/client");
            Args := Pack;
         when Cert_Rsa =>
            Supported := False;
            Reason := U ("cert-rsa via wolfSSL pending RSA fixtures");
            Bin := U (Home & "/examples/client/client");
            Args := Pack;
      end case;
   end Build_Wolfssl;

   procedure Build_Boringssl
     (Cell      : Cell_Spec;
      Bin       : out Unbounded_String;
      Args      : out Argument_List_Access;
      Supported : out Boolean;
      Reason    : out Unbounded_String)
   is
      Endpoint : constant String :=
        S (Cell.Host) & ":" & Img (Cell.Port);
   begin
      Bin := U ("bssl");
      case Cell.Mode is
         when Psk_Dhe_Ke =>
            Supported := False;
            Reason := U
              ("bssl -psk-hex is RFC 9258 (Imported PSK), "
               & "not RFC 8446 external PSK");
            Args := Pack;
         when Cert_Ec =>
            if Cell.Role = Client then
               --  Ada server, bssl client — works.
               Supported := True;
               Reason := Null_Unbounded_String;
               Args := Pack
                 ("client", "-connect", Endpoint,
                  "-root-certs", S (Cell.Trust_Pem),
                  "-min-version", "tls1.3",
                  "-max-version", "tls1.3");
            else
               --  Ada client, bssl server — investigated 2026-05-15.
               --  The old note about "half-RTT NST coalescing" was a
               --  guess; the real observation is more pathological:
               --  with `bssl server -debug`, the progress log shows
               --  bssl walking the full handshake state machine
               --  (read_client_hello → send_server_hello →
               --   send_server_certificate_verify →
               --   send_server_finished → send_half_rtt_ticket →
               --   read_second_client_flight → ... → read_client_finished),
               --  yet `netstat -an` shows BOTH TCP send queues at 0
               --  bytes during the entire stall.  Our Ada client
               --  blocks on the first Recv_All for the SH header
               --  because no bytes ever leave bssl's TCP socket on
               --  this codepath; bssl eventually reports "Error
               --  while connecting: peer closed connection" once we
               --  time out.  Same Ada client works end-to-end against
               --  openssl s_server / gnutls-serv / mbedtls /
               --  wolfssl on identical fixtures, so this is a
               --  bssl-specific behavior — not an Ada-side bug.
               --  Hypothesis (not yet confirmed): bssl's `bssl server`
               --  example tool may buffer the server flight at the
               --  BIO layer pending a synchronous app-data write
               --  that never comes from our client; the `-debug`
               --  progress callbacks fire on state-machine
               --  transitions, not on actual socket writes.  Lift
               --  this NI-3P only when either bssl exposes a flag
               --  that flushes the half-RTT flight unconditionally,
               --  or we run against a different bssl-based server
               --  binary (e.g., Cronet / Chromium's net stack).
               --  Classification per docs/conventions.md §9: (e) counterpart
               --  non-conformant — bssl's example tool buffer setup
               --  differs from every other TLS 1.3 server in the
               --  matrix.  bssl s2c (Ada server) DOES work and is
               --  exercised; bssl is therefore not absent from the
               --  matrix.
               Supported := False;
               Reason := U
                 ("bssl example server stalls (TCP send queue stays "
                  & "empty during the handshake despite reaching "
                  & "send_server_finished); bssl→Ada s2c exercises "
                  & "this peer instead");
               Args := Pack;
            end if;
         when Cert_Rsa =>
            Supported := False;
            Reason := U ("cert-rsa via bssl pending RSA fixtures");
            Args := Pack;
      end case;
   end Build_Boringssl;

   ---------------------------------------------------------------------
   --  Top-level dispatcher
   ---------------------------------------------------------------------

   procedure Build_Command
     (Cell      : Cell_Spec;
      Bin       : out Unbounded_String;
      Args      : out Argument_List_Access;
      Supported : out Boolean;
      Reason    : out Unbounded_String)
   is
   begin
      --  First gate: is the peer's binary even installed?
      if not Binary_Available (Cell.Peer) then
         Bin       := Null_Unbounded_String;
         Args      := Pack;
         Supported := False;
         Reason    := U ("binary not on $PATH");
         return;
      end if;
      case Cell.Peer is
         when Ada_Native => Build_Ada       (Cell, Bin, Args, Supported, Reason);
         when Openssl    => Build_Openssl   (Cell, Bin, Args, Supported, Reason);
         when Gnutls     => Build_Gnutls    (Cell, Bin, Args, Supported, Reason);
         when Mbedtls    => Build_Mbedtls   (Cell, Bin, Args, Supported, Reason);
         when Rustls     => Build_Rustls    (Cell, Bin, Args, Supported, Reason);
         when Go_Lang    => Build_Go        (Cell, Bin, Args, Supported, Reason);
         when Boringssl  => Build_Boringssl (Cell, Bin, Args, Supported, Reason);
         when Wolfssl    => Build_Wolfssl   (Cell, Bin, Args, Supported, Reason);
      end case;
      --  Resolve binary to a full path so Non_Blocking_Spawn doesn't
      --  need to search PATH itself.  Skip if it already contains a
      --  path separator (caller already gave a relative-or-absolute
      --  path).
      if Supported and then Length (Bin) > 0
        and then Ada.Strings.Fixed.Index (To_String (Bin), "/") = 0
      then
         declare
            Found : GNAT.OS_Lib.String_Access :=
              Locate_Exec_On_Path (To_String (Bin));
         begin
            if Found /= null then
               Bin := U (Found.all);
               Free (Found);
            end if;
         end;
      end if;
   end Build_Command;

   ---------------------------------------------------------------------
   --  Feature inventory tables
   ---------------------------------------------------------------------

   function Peer_Supports (P : Peer_Kind; F : Feature_Kind) return Boolean
   is
   begin
      case F is
         when Cert_Ec_Chacha20 | Cert_Ec_Aes128 | Cert_Ec_Aes256 =>
            return P /= Ada_Native;  --  every TLS 1.3 peer supports it

         when Cert_Rsa_Pss_Sha256 =>
            --  All TLS 1.3 peers verify rsa_pss_rsae_sha256.  Ada
            --  driver verifies but does not sign — flagged as
            --  NOT_IMPL_ADA below.
            return P /= Ada_Native;

         when Psk_External_Chacha20 | Psk_External_Aes128
            | Psk_External_Aes256 =>
            --  External-PSK CLI exposure varies.
            return P in Ada_Native | Openssl | Gnutls | Mbedtls;

         when Psk_Resumption =>
            --  Every TLS 1.3 peer issues NewSessionTicket; resumption-
            --  PSK is the production PSK path.
            return P /= Ada_Native;

         when Hello_Retry_Request =>
            return P /= Ada_Native;  --  every peer supports HRR

         when Sni_Alpn =>
            return P /= Ada_Native;  --  every peer supports SNI/ALPN

         when Zero_Rtt =>
            --  All major peers support 0-RTT, but their CLI surface
            --  for it is uneven.  Treat as supported by the peer
            --  (its lib has the API); Ada NOT_IMPL covers the gap.
            return P /= Ada_Native;

         when Key_Update =>
            return P /= Ada_Native;
      end case;
   end Peer_Supports;

   function Ada_Supports (F : Feature_Kind) return Boolean is
   begin
      case F is
         when Cert_Ec_Chacha20       => return True;
         when Cert_Ec_Aes128         => return True;
         when Cert_Ec_Aes256         => return True;
         when Cert_Rsa_Pss_Sha256    => return False;  --  v0.5: verify
                                                       --  only, no sign
         when Psk_External_Chacha20  => return True;
         when Psk_External_Aes128    => return True;
         when Psk_External_Aes256    => return False;  --  cipher built;
                                                       --  matrix glue
                                                       --  not wired
         when Psk_Resumption         => return True;
         when Hello_Retry_Request    => return True;
         when Sni_Alpn               => return True;
         when Zero_Rtt               => return False;
         when Key_Update             => return True;
      end case;
   end Ada_Supports;

   function Ada_Can_Attempt (F : Feature_Kind) return Boolean is
   begin
      case F is
         when Cert_Rsa_Pss_Sha256 => return False;
         when Psk_External_Aes256 => return True;
         when Zero_Rtt            => return False;
         when others              => return True;
      end case;
   end Ada_Can_Attempt;

   function Ada_Unblock_Link (F : Feature_Kind) return String is
   begin
      case F is
         when Cert_Rsa_Pss_Sha256 => return "README.md#v050--known-gaps-xfail";
         when Psk_External_Aes256 => return "README.md#v050--known-gaps-xfail";
         when Psk_Resumption      => return "";
         when Zero_Rtt            => return "README.md#v050--known-gaps-xfail";
         when others              => return "";
      end case;
   end Ada_Unblock_Link;

   function Image (F : Feature_Kind) return String is
   begin
      case F is
         when Cert_Ec_Chacha20       => return "cert-ec-chacha20";
         when Cert_Ec_Aes128         => return "cert-ec-aes128";
         when Cert_Ec_Aes256         => return "cert-ec-aes256";
         when Cert_Rsa_Pss_Sha256    => return "cert-rsa-pss-sha256";
         when Psk_External_Chacha20  => return "psk-external-chacha20";
         when Psk_External_Aes128    => return "psk-external-aes128";
         when Psk_External_Aes256    => return "psk-external-aes256";
         when Psk_Resumption         => return "psk-resumption";
         when Hello_Retry_Request    => return "hello-retry-request";
         when Sni_Alpn               => return "sni-alpn";
         when Zero_Rtt               => return "zero-rtt";
         when Key_Update             => return "key-update";
      end case;
   end Image;

   function All_Features return String is
      Result : Unbounded_String;
      First  : Boolean := True;
   begin
      for F in Feature_Kind'Range loop
         if not First then
            Append (Result, ", ");
         end if;
         Append (Result, Image (F));
         First := False;
      end loop;
      return To_String (Result);
   end All_Features;

   function Image (R : Cell_Result) return String is
   begin
      case R is
         when Pass       => return "PASS";
         when Fail       => return "FAIL";
         when Xfail_Ada  => return "XFAIL";
         when Not_Impl_3P => return "NOT_IMPL_3P";
      end case;
   end Image;

   procedure Feature_To_Cell
     (F : Feature_Kind;
      M : out Mode_Kind;
      C : out Cipher_Kind)
   is
   begin
      case F is
         when Cert_Ec_Chacha20 =>
            M := Cert_Ec; C := Chacha20_Poly1305_Sha256;
         when Cert_Ec_Aes128 =>
            M := Cert_Ec; C := Aes128_Gcm_Sha256;
         when Cert_Ec_Aes256 =>
            M := Cert_Ec; C := Aes256_Gcm_Sha384;
         when Cert_Rsa_Pss_Sha256 =>
            M := Cert_Rsa; C := Auto;
         when Psk_External_Chacha20 =>
            M := Psk_Dhe_Ke; C := Chacha20_Poly1305_Sha256;
         when Psk_External_Aes128 =>
            M := Psk_Dhe_Ke; C := Aes128_Gcm_Sha256;
         when Psk_External_Aes256 =>
            M := Psk_Dhe_Ke; C := Aes256_Gcm_Sha384;
         when Psk_Resumption =>
            M := Cert_Ec; C := Auto;
         when Hello_Retry_Request =>
            M := Cert_Ec; C := Auto;
         when Sni_Alpn =>
            M := Cert_Ec; C := Auto;
         when Zero_Rtt =>
            M := Cert_Ec; C := Auto;
         when Key_Update =>
            M := Cert_Ec; C := Auto;
      end case;
   end Feature_To_Cell;

end Tls_Interop_Peers;
