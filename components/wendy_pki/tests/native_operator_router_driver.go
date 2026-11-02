//go:build ignore

// Independent Go TLS client for native operator-router carrier admission.
package main

import (
	"bufio"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/mldsa"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
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
	dir, err := os.MkdirTemp("", "native-agent-normal-")
	must(err)
	defer os.RemoveAll(dir)
	profile := os.Args[2]
	newCAKey := func() crypto.Signer {
		if profile == "mldsa65" {
			key, err := mldsa.GenerateKey(mldsa.MLDSA65())
			must(err)
			return key
		}
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		must(err)
		return key
	}
	serial := int64(1)
	template := func(name string) *x509.Certificate {
		serial++
		return &x509.Certificate{SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: name},
			NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), BasicConstraintsValid: true}
	}
	rootKey := newCAKey()
	root := template("normal root")
	root.IsCA = true
	root.KeyUsage = x509.KeyUsageCertSign
	rootDER, err := x509.CreateCertificate(rand.Reader, root, root, rootKey.Public(), rootKey)
	must(err)
	rootPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: rootDER})
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(rootPEM)
	parent, issuer := root, rootKey
	chain := [][]byte{rootDER}
	for i := 0; i < 3; i++ {
		key := newCAKey()
		ca := template(fmt.Sprintf("normal intermediate %d", i))
		ca.IsCA = true
		ca.KeyUsage = x509.KeyUsageCertSign
		der, err := x509.CreateCertificate(rand.Reader, ca, parent, key.Public(), issuer)
		must(err)
		chain = append([][]byte{der}, chain...)
		parent, issuer = ca, key
	}
	leaf := func(role, id string) (tls.Certificate, []byte) {
		var key crypto.Signer
		var err error
		if profile == "mldsa65" && role == "operator" {
			key, err = mldsa.GenerateKey(mldsa.MLDSA65())
		} else {
			key, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		}
		must(err)
		cert := template("normal " + role)
		cert.KeyUsage = x509.KeyUsageDigitalSignature
		cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
		cert.DNSNames = []string{"localhost"}
		tenantID := "2558fd76-afc7-466e-9613-6b715296a526"
		if id == "wrong-tenant" {
			tenantID = "11111111-1111-4111-8111-111111111111"
		}
		if id == "expired" {
			cert.NotAfter = time.Now().Add(-time.Minute)
		}
		u, err := url.Parse("spiffe://wendy.sh/tenant/" + tenantID + "/" + role + "/" + id)
		must(err)
		cert.URIs = []*url.URL{u}
		signingParent, signingKey := parent, issuer
		if id == "untrusted" {
			signingParent, signingKey = cert, key
		}
		der, err := x509.CreateCertificate(rand.Reader, cert, signingParent, key.Public(), signingKey)
		must(err)
		keyDER, err := x509.MarshalPKCS8PrivateKey(key)
		must(err)
		return tls.Certificate{Certificate: append([][]byte{der}, chain...), PrivateKey: key}, keyDER
	}
	server, key := leaf("device", "00000000-0000-4000-8000-000000000004")
	var serverPEM []byte
	for _, der := range server.Certificate {
		serverPEM = append(serverPEM, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})...)
	}
	for name, data := range map[string][]byte{"key.der": key, "server.pem": serverPEM, "root.pem": rootPEM} {
		must(os.WriteFile(filepath.Join(dir, name), data, 0600))
	}
	for _, test := range []struct {
		name, role, id, alpn string
		valid                bool
		legacy               bool
	}{
		{"primary-operator", "operator", "alice_1", "wendy-net-operator-router/1", true, false},
		{"ordinary-device", "device", "00000000-0000-4000-8000-000000000005", "wendy-local-mesh-ble/2", true, false},
		{"wrong-tenant", "operator", "wrong-tenant", "wendy-net-operator-router/1", false, false},
		{"expired", "operator", "expired", "wendy-net-operator-router/1", false, false},
		{"untrusted", "operator", "untrusted", "wendy-net-operator-router/1", false, false},
		{"device-on-operator-role", "device", "00000000-0000-4000-8000-000000000005", "wendy-net-operator-router/1", false, false},
		{"operator-on-device-role", "operator", "alice_1", "wendy-local-mesh-ble/2", false, false},
		{"unavailable-router-role", "operator", "alice_1", "wendy-net-operator-router/1", false, true},
	} {
		client, _ := leaf(test.role, test.id)
		expected := "reject"
		if test.valid {
			expected = "accept"
		}
		if test.valid && test.role == "device" {
			expected = "device"
		}
		if test.legacy {
			expected = "leaf"
		}
		command := exec.Command(os.Args[1], filepath.Join(dir, "key.der"), filepath.Join(dir, "server.pem"), filepath.Join(dir, "root.pem"), expected)
		command.Stderr = os.Stderr
		stdout, err := command.StdoutPipe()
		must(err)
		must(command.Start())
		line, err := bufio.NewReader(stdout).ReadString('\n')
		must(err)
		raw, err := net.DialTimeout("tcp4", "127.0.0.1:"+strings.TrimSpace(line), time.Second)
		must(err)
		must(raw.SetDeadline(time.Now().Add(15 * time.Second)))
		secure := tls.Client(raw, &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13, RootCAs: pool, ServerName: "localhost", Certificates: []tls.Certificate{client}, NextProtos: []string{test.alpn}, SessionTicketsDisabled: true})
		err = secure.Handshake()
		var ack [1]byte
		if err == nil {
			_, err = io.ReadFull(secure, ack[:])
		}
		if test.valid {
			must(err)
			if ack[0] != 'A' {
				panic("missing authenticated acknowledgement")
			}
			if test.role == "device" {
				_ = secure.Close()
				must(command.Wait())
				fmt.Printf("PASS %s ordinary device with operator support enabled\n", profile)
				continue
			}
			hello := append([]byte{0xa2, 0x61, 'k', 0x75}, []byte("operator-router-hello")...)
			hello = append(hello, 0x61, 'n', 0x50)
			hello = append(hello, []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}...)
			send := func(kind byte, body []byte) {
				header := make([]byte, 5)
				header[0] = kind
				binary.BigEndian.PutUint32(header[1:], uint32(len(body)))
				for _, p := range [][]byte{header, body} {
					for _, b := range p {
						_, err := secure.Write([]byte{b})
						must(err)
					}
				}
			}
			receive := func(kind byte) []byte {
				header := make([]byte, 5)
				_, err := io.ReadFull(secure, header)
				must(err)
				if header[0] != kind {
					panic("wrong frame kind")
				}
				size := binary.BigEndian.Uint32(header[1:])
				if size > 128 {
					panic("oversized frame")
				}
				body := make([]byte, size)
				_, err = io.ReadFull(secure, body)
				must(err)
				return body
			}
			send(1, hello)
			ready := receive(1)
			if string(ready) != string(append([]byte{0xa1, 0x61, 'k', 0x75}, []byte("operator-router-ready")...)) {
				panic("wrong ready")
			}
			for _, kind := range []byte{4, 5} {
				body := []byte("routed-data")
				if kind == 5 {
					body = append([]byte{0, 0, 0, 11}, body...)
				}
				send(kind, body)
				if string(receive(kind)) != string(body) {
					panic("mux payload changed")
				}
			}
		} else if err == nil {
			panic("invalid carrier admitted: " + test.name)
		}
		_ = secure.Close()
		must(command.Wait())
		fmt.Printf("PASS %s operator-router %s\n", profile, test.name)
	}
}
