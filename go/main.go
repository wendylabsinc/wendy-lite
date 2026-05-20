package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"log"
	"net"
	"os"
)

func main() {
	caCert, err := os.ReadFile("certs/ca.pem")
	if err != nil {
		log.Fatalf("failed to read CA certificate: %v", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		log.Fatal("failed to parse CA certificate")
	}

	serverCert, err := tls.LoadX509KeyPair("certs/server.pem", "certs/server-key.pem")
	if err != nil {
		log.Fatalf("failed to load server cert/key: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverCert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS12,
	}

	ln, err := tls.Listen("tcp", ":5566", tlsConfig)
	if err != nil {
		log.Fatalf("listen error: %v", err)
	}
	defer ln.Close()
	log.Println("mTLS socket server listening on :5566")

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConn(conn)
	}
}

func handleConn(conn net.Conn) {
	defer conn.Close()

	tlsConn := conn.(*tls.Conn)
	if err := tlsConn.Handshake(); err != nil {
		log.Printf("handshake error from %s: %v", conn.RemoteAddr(), err)
		return
	}

	state := tlsConn.ConnectionState()
	cn := ""
	org := ""
	if len(state.PeerCertificates) > 0 {
		cn = state.PeerCertificates[0].Subject.CommonName
		if len(state.PeerCertificates[0].Subject.Organization) > 0 {
			org = state.PeerCertificates[0].Subject.Organization[0]
		}
	}
	log.Printf("connected: %s (CN=%s, O=%s)", conn.RemoteAddr(), cn, org)

	fmt.Fprintf(conn, "hello, %s\n", cn)

	buf := make([]byte, 1024)
	for {
		n, err := conn.Read(buf)
		if n > 0 {
			log.Printf("rx from %s: %q", cn, buf[:n])
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("read error from %s: %v", cn, err)
			}
			break
		}
	}

	log.Printf("disconnected: %s (CN=%s)", conn.RemoteAddr(), cn)
}
