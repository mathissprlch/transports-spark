with Ada.Command_Line;
with Ada.Directories;
with Ada.Strings.Fixed;
with Ada.Text_IO;
with GNAT.OS_Lib;     use GNAT.OS_Lib;
pragma Warnings (Off, "no entities of ""GNAT.Strings"" are referenced");
with GNAT.Strings;
pragma Warnings (On, "no entities of ""GNAT.Strings"" are referenced");

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
        (1  => (S0 /= "", New_Arg (S0)),
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
         21 => (S20 /= "", New_Arg (S20)));
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
               Bin := U ("gnutls-serv");
               Args := Pack
                 ("--port", Img (Cell.Port),
                  "--x509certfile", S (Cell.Cert_Pem),
                  "--x509keyfile", S (Cell.Key_Pem),
                  "--priority", Cert_Priority,
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
            Supported := True;
            Reason := Null_Unbounded_String;
            if Cell.Role = Client then
               --  --http: tlsclient-mio sends a basic HTTP GET then
               --  exits cleanly on close.  Without this it reads
               --  stdin and blocks the matrix.
               Bin := U ("tlsclient-mio");
               Args := Pack
                 (S (Cell.Host),
                  "--port", Img (Cell.Port),
                  "--cafile", S (Cell.Trust_Pem),
                  "--http");
            else
               Bin := U ("tlsserver-mio");
               Args := Pack
                 ("--port", Img (Cell.Port),
                  "--certs", S (Cell.Cert_Pem),
                  "--key", S (Cell.Key_Pem),
                  "echo");
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
            Supported := True;
            Reason := Null_Unbounded_String;
            if Cell.Role = Client then
               Bin := U (Home & "/examples/client/client");
               Args := Pack
                 ("-h", S (Cell.Host),
                  "-p", Img (Cell.Port),
                  "-v", "4",                       --  TLS 1.3
                  "-A", S (Cell.Trust_Pem),
                  "-x");                           --  no client cert
            else
               Bin := U (Home & "/examples/server/server");
               Args := Pack
                 ("-p", Img (Cell.Port),
                  "-v", "4",
                  "-c", S (Cell.Cert_Pem),
                  "-k", S (Cell.Key_Pem),
                  "-d",                            --  no client auth
                  "-b");                           --  any interface
            end if;
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
               --  Ada client, bssl server — bssl emits a half-RTT
               --  NewSessionTicket coalesced into the server flight
               --  before the client sends Finished.  Our 5-record
               --  reader expects SH+EE+Cert+CV+SF, but bssl's SF
               --  record carries the NST inline; the SF parser then
               --  fails the flight.  bssl has no flag to disable
               --  half-RTT NST.  Documented as a known interop gap;
               --  bssl s2c (Ada server) does work and is exercised.
               Supported := False;
               Reason := U
                 ("bssl half-RTT NewSessionTicket coalescing not "
                  & "supported by 5-record reader; bssl→Ada server "
                  & "(s2c) exercises this peer instead");
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

end Tls_Interop_Peers;
