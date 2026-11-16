//go:build ignore

// An independent Go peer checks actual TLS PSK acceptance and cache-loss fallback.
package main

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	const tenant = "2558fd76-afc7-466e-9613-6b715296a526"
	const serverID = "00000000-0000-4000-8000-000000000004"
	const clientID = "00000000-0000-4000-8000-000000000005"
	dir, e := os.MkdirTemp("", "lite-resumption-")
	must(e)
	defer os.RemoveAll(dir)
	var rootKey crypto.Signer
	if os.Args[2] == "mldsa65" {
		rootKey, e = mldsa.GenerateKey(mldsa.MLDSA65())
	} else {
		rootKey, e = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	must(e)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, e := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	must(e)
	parsedRoot, e := x509.ParseCertificate(rootDER)
	must(e)
	leaf := func(id string, serial int64) (tls.Certificate, []byte) {
		var key crypto.Signer
		if os.Args[2] == "mldsa65" && id == clientID && os.Args[3] != "pair" {
			key, e = mldsa.GenerateKey(mldsa.MLDSA65())
		} else {
			key, e = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
		must(e)
		uri, e := url.Parse("spiffe://wendy.sh/tenant/" + tenant + "/device/" + id)
		must(e)
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: id}, NotBefore: root.NotBefore, NotAfter: root.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, URIs: []*url.URL{uri}}
		der, e := x509.CreateCertificate(rand.Reader, cert, root, key.Public(), rootKey)
		must(e)
		keyDER, e := x509.MarshalPKCS8PrivateKey(key)
		must(e)
		return tls.Certificate{Certificate: [][]byte{der, rootDER}, PrivateKey: key}, keyDER
	}
	server, keyDER := leaf(serverID, 2)
	client, clientKey := leaf(clientID, 3)
	for name, data := range map[string][]byte{"key.der": keyDER, "cert.der": append(server.Certificate[0], rootDER...), "root.der": rootDER} {
		must(os.WriteFile(filepath.Join(dir, name), data, 0600))
	}
	pool := x509.NewCertPool()
	pool.AddCert(parsedRoot)
	listener, e := net.Listen("tcp", "127.0.0.1:0")
	must(e)
	defer listener.Close()

	if os.Args[3] == "pair" {
		must(os.WriteFile(filepath.Join(dir, "peer-key.der"), clientKey, 0600))
		must(os.WriteFile(filepath.Join(dir, "peer-cert.der"), append(client.Certificate[0], rootDER...), 0600))
		child := func(key, cert, self, peer, role string) *exec.Cmd {
			cmd := exec.Command(os.Args[1], filepath.Join(dir, key), filepath.Join(dir, cert), filepath.Join(dir, "root.der"), strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), tenant, self, peer, role)
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr
			must(cmd.Start())
			return cmd
		}
		left := child("key.der", "cert.der", serverID, clientID, "pair-server")
		defer left.Process.Kill()
		right := child("peer-key.der", "peer-cert.der", clientID, serverID, "pair-client")
		defer right.Process.Kill()
		for round := 0; round < 6; round++ {
			must(listener.(*net.TCPListener).SetDeadline(time.Now().Add(15 * time.Second)))
			a, e := listener.Accept()
			must(e)
			b, e := listener.Accept()
			must(e)
			must(a.SetDeadline(time.Now().Add(15 * time.Second)))
			must(b.SetDeadline(time.Now().Add(15 * time.Second)))
			bytes := make(chan int64, 2)
			go func() { n, _ := io.Copy(a, b); a.(*net.TCPConn).CloseWrite(); bytes <- n }()
			go func() { n, _ := io.Copy(b, a); b.(*net.TCPConn).CloseWrite(); bytes <- n }()
			total := <-bytes
			total += <-bytes
			a.Close()
			b.Close()
			fmt.Printf("native_pair round=%d wire_bytes=%d\n", round, total)
		}
		must(left.Wait())
		must(right.Wait())
		return
	}
	cmd := exec.Command(os.Args[1], filepath.Join(dir, "key.der"), filepath.Join(dir, "cert.der"), filepath.Join(dir, "root.der"), strconv.Itoa(listener.Addr().(*net.TCPAddr).Port), tenant, serverID, clientID, os.Args[3])
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	must(cmd.Start())
	defer cmd.Process.Kill()
	config := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, ServerName: "localhost", RootCAs: pool, Certificates: []tls.Certificate{client}, NextProtos: []string{"wendy-local-mesh-ble/2"}, ClientSessionCache: tls.NewLRUClientSessionCache(8)}
	fingerprint := sha256.Sum256(rootDER)
	alias := "wendy-local-mesh-ble/2\x00WCI\x01" + string(fingerprint[:16])
	config.NextProtos = []string{alias, "wendy-local-mesh-ble/2"}
	rounds := 6
	nativeClient := os.Args[3] != "server"
	if nativeClient {
		config = &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			Certificates: []tls.Certificate{client}, ClientCAs: pool,
			ClientAuth: tls.RequireAndVerifyClientCert, NextProtos: []string{"wendy-local-mesh-ble/2"}}
		// Force initialization once: cloning an uninitialized Config would
		// give each test connection unrelated automatic ticket keys.
		var ticketKey [32]byte
		_, e = rand.Read(ticketKey[:])
		must(e)
		config.SetSessionTicketKeys([][32]byte{ticketKey})
		config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			chosen := config.Clone()
			chosen.GetConfigForClient = nil
			for _, protocol := range hello.SupportedProtos {
				if strings.HasPrefix(protocol, "wendy-local-mesh-ble/2\x00WCI\x01") {
					chosen.NextProtos = []string{protocol, "wendy-local-mesh-ble/2"}
					break
				}
			}
			return chosen, nil
		}
		{
			states := make(map[string]*tls.SessionState)
			config.WrapSession = func(_ tls.ConnectionState, state *tls.SessionState) ([]byte, error) {
				var handle [32]byte
				_, e := rand.Read(handle[:])
				if e != nil {
					return nil, e
				}
				states[string(handle[:])] = state
				return handle[:], nil
			}
			config.UnwrapSession = func(ticket []byte, _ tls.ConnectionState) (*tls.SessionState, error) {
				return states[string(ticket)], nil
			}
		}
	}
	for round := 0; round < rounds; round++ {
		must(listener.(*net.TCPListener).SetDeadline(time.Now().Add(15 * time.Second)))
		raw, e := listener.Accept()
		must(e)
		must(raw.SetDeadline(time.Now().Add(15 * time.Second)))
		roundConfig := config.Clone()
		var conn *tls.Conn
		if nativeClient {
			conn = tls.Server(raw, roundConfig)
		} else {
			conn = tls.Client(raw, roundConfig)
		}
		must(conn.Handshake())
		if conn.ConnectionState().DidResume != (round%2 == 1) {
			panic(fmt.Sprintf("round %d resumed=%t", round, conn.ConnectionState().DidResume))
		}
		message := make([]byte, 1)
		_, e = io.ReadFull(conn, message)
		must(e)
		if message[0] != 'x' {
			panic("wrong data")
		}
		_, e = conn.Write(message)
		must(e)
		fmt.Printf("round=%d resumed=%t\n", round, conn.ConnectionState().DidResume)
		conn.Close()
	}
	must(cmd.Wait())
}
