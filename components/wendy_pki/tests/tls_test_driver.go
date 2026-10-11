//go:build ignore

// Exercise the actual firmware TLS adapter against Go's independent TLS stack.
package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	directory, err := os.MkdirTemp("", "lite-tls-")
	must(err)
	defer os.RemoveAll(directory)
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	must(err)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	must(os.WriteFile(filepath.Join(directory, "root.pem"), rootPEM, 0600))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rootPEM)
	leaf := func(name string, expiry time.Time, usages []x509.ExtKeyUsage, uri string, issuer *ecdsa.PrivateKey) (tls.Certificate, []byte, []byte) {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(err)
		u, err := url.Parse(uri)
		must(err)
		template := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: expiry, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: usages, DNSNames: []string{"localhost"}, URIs: []*url.URL{u}}
		der, err := x509.CreateCertificate(rand.Reader, template, root, key.Public(), issuer)
		must(err)
		raw, err := x509.MarshalPKCS8PrivateKey(key)
		must(err)
		certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}, raw, certPEM
	}
	tenant := "spiffe://wendy.sh/tenant/2558fd76-afc7-466e-9613-6b715296a526/"
	_, keyDER, serverPEM := leaf("device", time.Now().Add(time.Hour), []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, tenant+"device/lite-test", rootKey)
	must(os.WriteFile(filepath.Join(directory, "key.der"), keyDER, 0600))
	must(os.WriteFile(filepath.Join(directory, "server.pem"), serverPEM, 0600))
	cases := []string{"valid", "wrong-tenant", "wrong-role", "wrong-eku", "expired", "untrusted", "no-client", "tls12", "truncate", "extra"}
	for _, name := range cases {
		expiry := time.Now().Add(time.Hour)
		usages := []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		uri := tenant + "operator/11111111-1111-4111-8111-111111111111"
		issuer := rootKey
		switch name {
		case "expired":
			expiry = time.Now().Add(-time.Minute)
		case "wrong-tenant":
			uri = strings.Replace(uri, "2558fd76", "3558fd76", 1)
		case "wrong-role":
			uri = tenant + "device/lite-test"
		case "wrong-eku":
			usages = []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		case "untrusted":
			issuer, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			must(err)
		}
		cert, _, _ := leaf("operator", expiry, usages, uri, issuer)
		mode := "reject"
		if name == "valid" || name == "truncate" || name == "extra" {
			mode = name
		}
		cmd := exec.Command(os.Args[1], filepath.Join(directory, "key.der"), filepath.Join(directory, "server.pem"), filepath.Join(directory, "root.pem"), mode)
		cmd.Stderr = os.Stderr
		stdout, err := cmd.StdoutPipe()
		must(err)
		must(cmd.Start())
		line, err := bufio.NewReader(stdout).ReadString('\n')
		must(err)
		conn, err := net.DialTimeout("tcp", "127.0.0.1:"+strings.TrimSpace(line), 3*time.Second)
		must(err)
		must(conn.SetDeadline(time.Now().Add(4 * time.Second)))
		cfg := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "localhost", Certificates: []tls.Certificate{cert}}
		if name == "no-client" {
			cfg.Certificates = nil
		}
		if name == "tls12" {
			cfg.MinVersion = tls.VersionTLS12
			cfg.MaxVersion = tls.VersionTLS12
		}
		client := tls.Client(conn, cfg)
		handshake := client.Handshake()
		if mode != "reject" {
			must(handshake)
			switch name {
			case "truncate":
				conn.Close()
			case "extra":
				_, err = client.Write([]byte("unexpected"))
				must(err)
			default:
				must(client.CloseWrite())
				var b [1]byte
				_, err = client.Read(b[:])
				if err != io.EOF {
					panic(fmt.Sprintf("expected close_notify, got %v", err))
				}
				must(conn.SetDeadline(time.Now().Add(4 * time.Second)))
				_, err = conn.Write([]byte("raw"))
				must(err)
			}
		}
		if mode == "reject" {
			if handshake == nil {
				var b [1]byte
				_, _ = client.Read(b[:])
			}
		}
		conn.Close()
		if err = cmd.Wait(); err != nil {
			panic(fmt.Sprintf("%s: %v", name, err))
		}
		fmt.Println("PASS", name)
	}
}
