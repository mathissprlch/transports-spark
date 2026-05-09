// Tier D Go peer — TLS 1.3 cert-mode server.
//
// Invoked by tls_interop:
//   go run server.go --addr HOST:PORT --cert leaf.pem --key leaf.key [-n COUNT]
//
// Binds, accepts COUNT connections (default 1), completes the TLS 1.3
// handshake on each, and exits 0 on success.  -n 2 is used by the
// PSK resumption test (cert-ec → save ticket → psk-resume).
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
	"time"
)

func main() {
	addr := flag.String("addr", "", "host:port")
	certFile := flag.String("cert", "", "leaf cert PEM")
	keyFile := flag.String("key", "", "leaf private key PEM")
	count := flag.Int("n", 1, "number of connections to accept")
	flag.Parse()
	if *addr == "" || *certFile == "" || *keyFile == "" {
		fmt.Fprintln(os.Stderr, "usage: server --addr HOST:PORT --cert FILE --key FILE [-n COUNT]")
		os.Exit(2)
	}

	cert, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "LoadX509KeyPair:", err)
		os.Exit(2)
	}
	conf := &tls.Config{
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		Certificates: []tls.Certificate{cert},
	}

	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, "Listen:", err)
		os.Exit(2)
	}
	defer ln.Close()
	fmt.Println("go server: listening on", *addr)

	for i := 0; i < *count; i++ {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintln(os.Stderr, "Accept:", err)
			os.Exit(1)
		}
		tc := tls.Server(conn, conf)
		if err := tc.Handshake(); err != nil {
			fmt.Fprintln(os.Stderr, "handshake:", err)
			os.Exit(1)
		}
		fmt.Printf("go server: TLS 1.3 handshake #%d complete\n", i+1)
		// Brief delay so Go's post-handshake NewSessionTicket flushes
		// to the peer before we close the connection.
		time.Sleep(200 * time.Millisecond)
		tc.Close()
	}
}
