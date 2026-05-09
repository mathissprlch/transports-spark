// Tier D Go peer — TLS 1.3 cert-mode server.
//
// Invoked by tls_interop:
//   go run server.go --addr HOST:PORT --cert leaf.pem --key leaf.key
//
// Binds, accepts ONE connection, completes the TLS 1.3 handshake,
// and exits 0 on success.
package main

import (
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"os"
)

func main() {
	addr := flag.String("addr", "", "host:port")
	certFile := flag.String("cert", "", "leaf cert PEM")
	keyFile := flag.String("key", "", "leaf private key PEM")
	flag.Parse()
	if *addr == "" || *certFile == "" || *keyFile == "" {
		fmt.Fprintln(os.Stderr, "usage: server --addr HOST:PORT --cert FILE --key FILE")
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
	fmt.Println("go server: TLS 1.3 handshake complete")
	tc.Close()
}
