//go:build ignore

// Generates disposable PKI fixtures and drives the production C verification
// and TLS client against Go's independent certificate/TLS implementation.
package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
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
	if len(os.Args) != 3 {
		panic("crypto_test tls_test")
	}
	dir, err := os.MkdirTemp("", "wendy-mesh-host-")
	must(err)
	defer os.RemoveAll(dir)
	tenant := "12345678-9abc-4def-8123-000000000001"
	device := "12345678-9abc-4def-8123-000000000002"
	router := "12345678-9abc-4def-8123-000000000003"
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "ephemeral mesh root"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(10 * time.Minute), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	must(err)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})

	retiredKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	retired := &x509.Certificate{SerialNumber: big.NewInt(888), Subject: pkix.Name{CommonName: "unused retired root"}, NotBefore: time.Now().Add(-2 * time.Hour), NotAfter: time.Now().Add(-time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	retiredDER, err := x509.CreateCertificate(rand.Reader, retired, retired, retiredKey.Public(), retiredKey)
	must(err)
	rootsWithRetired := append(append([]byte{}, rootPEM...), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: retiredDER})...)
	must(os.WriteFile(filepath.Join(dir, "roots.pem"), rootsWithRetired, 0600))
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rootPEM)
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	must(err)
	intermediate := &x509.Certificate{SerialNumber: big.NewInt(777), Subject: pkix.Name{CommonName: "review intermediate"}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(5 * time.Minute), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	intermediateDER, err := x509.CreateCertificate(rand.Reader, intermediate, root, intermediateKey.Public(), rootKey)
	must(err)
	intermediatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: intermediateDER})
	must(os.Setenv("EXPECTED_MESH_EXPIRY", fmt.Sprintf("%d", intermediate.NotAfter.Unix())))
	var deviceKey *ecdsa.PrivateKey
	certificate := func(name, tenant, device string, expired bool) tls.Certificate {
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(err)
		if name == "leaf" {
			deviceKey = key
		} else if name == "rebound" {
			key = deviceKey
		}
		uri, err := url.Parse("spiffe://wendy.sh/tenant/" + tenant + "/device/" + device)
		must(err)
		cert := &x509.Certificate{SerialNumber: big.NewInt(int64(len(name) + 2)), Subject: pkix.Name{CommonName: name}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(30 * time.Minute), KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}, URIs: []*url.URL{uri}}
		if expired {
			cert.NotAfter = time.Now().Add(-time.Minute)
		}
		der, err := x509.CreateCertificate(rand.Reader, cert, intermediate, key.Public(), intermediateKey)
		must(err)
		keyDER, err := x509.MarshalECPrivateKey(key)
		must(err)
		must(os.WriteFile(filepath.Join(dir, name+".der"), keyDER, 0600))
		chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), intermediatePEM...)
		chain = append(chain, rootPEM...)
		must(os.WriteFile(filepath.Join(dir, name+".pem"), chain, 0600))
		return tls.Certificate{Certificate: [][]byte{der, intermediateDER, rootDER}, PrivateKey: key}
	}
	certificate("leaf", tenant, device, false)
	reboundTenant := "12345678-9abc-4def-8123-000000000004"
	certificate("rebound", reboundTenant, device, false)
	must(os.Setenv("WENDY_MESH_REBOUND_CHAIN", filepath.Join(dir, "rebound.pem")))
	must(os.Setenv("WENDY_MESH_REBOUND_TENANT", reboundTenant))
	run := exec.Command(os.Args[1], filepath.Join(dir, "leaf.der"), filepath.Join(dir, "leaf.pem"), filepath.Join(dir, "roots.pem"), tenant, device)
	output, err := run.CombinedOutput()
	if err != nil {
		panic(fmt.Sprintf("C crypto: %v\n%s", err, output))
	}
	fmt.Print(string(output))
	good := certificate("router", tenant, router, false)
	wrong := certificate("wrong", tenant, device, false)
	foreign := certificate("foreign", device, router, false)
	expired := certificate("expired", tenant, router, true)
	for _, test := range []struct {
		name, alpn string
		cert       tls.Certificate
		version    uint16
		accept     bool
	}{
		{"valid", "wendy-local-mesh-leaf/3", good, tls.VersionTLS13, true},
		{"legacy-v2", "wendy-local-mesh-leaf/2", good, tls.VersionTLS13, false},
		{"wrong-router", "wendy-local-mesh-leaf/3", wrong, tls.VersionTLS13, false},
		{"wrong-tenant", "wendy-local-mesh-leaf/3", foreign, tls.VersionTLS13, false},
		{"wrong-alpn", "wendy-local-mesh-ble/3", good, tls.VersionTLS13, false},
		{"missing-alpn", "", good, tls.VersionTLS13, false},
		{"expired", "wendy-local-mesh-leaf/3", expired, tls.VersionTLS13, false},
		{"tls12", "wendy-local-mesh-leaf/3", good, tls.VersionTLS12, false},
	} {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		must(err)
		done := make(chan error, 1)
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				done <- err
				return
			}
			defer conn.Close()
			conn.SetDeadline(time.Now().Add(8 * time.Second))
			preface := make([]byte, 36)
			_, err = io.ReadFull(conn, preface)
			if err != nil {
				done <- err
				return
			}
			tu, _ := hex.DecodeString(strings.ReplaceAll(tenant, "-", ""))
			du, _ := hex.DecodeString(strings.ReplaceAll(device, "-", ""))
			expected := append(append([]byte("WML3"), tu...), du...)
			if !bytes.Equal(preface, expected) {
				done <- fmt.Errorf("bad preface")
				return
			}
			cfg := &tls.Config{MinVersion: test.version, MaxVersion: test.version, Certificates: []tls.Certificate{test.cert}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool, SessionTicketsDisabled: true}
			if test.alpn != "" {
				cfg.NextProtos = []string{test.alpn}
			}
			server := tls.Server(conn, cfg)
			err = server.Handshake()
			if test.accept && err == nil {
				st := server.ConnectionState()
				if st.Version != tls.VersionTLS13 || st.NegotiatedProtocol != "wendy-local-mesh-leaf/3" || st.DidResume || len(st.PeerCertificates) == 0 {
					err = fmt.Errorf("bad TLS state")
				}
			}
			if !test.accept {
				err = nil
			}
			done <- err
		}()
		expectation := "reject"
		if test.accept {
			expectation = "accept"
		}
		port := fmt.Sprint(listener.Addr().(*net.TCPAddr).Port)
		cmd := exec.Command(os.Args[2], filepath.Join(dir, "leaf.der"), filepath.Join(dir, "leaf.pem"), filepath.Join(dir, "roots.pem"), port, tenant, device, router, expectation)
		output, err := cmd.CombinedOutput()
		listener.Close()
		serverErr := <-done
		if err != nil || serverErr != nil {
			panic(fmt.Sprintf("%s: C=%v Go=%v output=%s", test.name, err, serverErr, output))
		}
		fmt.Println("PASS mesh TLS", test.name)
	}
}
