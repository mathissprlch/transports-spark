// Tier D Go peer — TLS 1.3 cert-mode client.
//
// Invoked by tls_interop:
//   go run client.go --addr HOST:PORT --root /path/to/root.pem
//
// Connects, completes the TLS 1.3 handshake against the Ada server,
// and exits 0 on success. Verifies the server cert against the
// supplied root.
package main

import (
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"os"
)

func main() {
	addr := flag.String("addr", "", "host:port")
	root := flag.String("root", "", "PEM file with one root CA cert")
	flag.Parse()
	if *addr == "" || *root == "" {
		fmt.Fprintln(os.Stderr, "usage: client --addr HOST:PORT --root FILE")
		os.Exit(2)
	}

	pem, err := os.ReadFile(*root)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read root:", err)
		os.Exit(2)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		fmt.Fprintln(os.Stderr, "AppendCertsFromPEM failed")
		os.Exit(2)
	}

	conf := &tls.Config{
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
		RootCAs:    pool,
		ServerName: "localhost",
	}
	c, err := tls.Dial("tcp", *addr, conf)
	if err != nil {
		fmt.Fprintln(os.Stderr, "tls.Dial:", err)
		os.Exit(1)
	}
	defer c.Close()
	if err := c.Handshake(); err != nil {
		fmt.Fprintln(os.Stderr, "handshake:", err)
		os.Exit(1)
	}
	fmt.Println("go client: TLS 1.3 handshake complete")
}
